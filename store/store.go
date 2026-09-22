// Package store persists accepted audit events and their per-target delivery
// state to local append-only files, so events already acknowledged to
// producers survive process restarts and delivery status stays auditable.
//
// On-disk layout (all files inside one directory):
//
//	e<E>-s<N>.log          event segment of epoch E, segment N (JSON lines)
//	e<E>.ready             epoch E is the durably complete visible generation
//	state.log              append-only per-target delivery state transitions
//
// Every record is one JSON line written with a single write(2) call while
// holding the store lock, followed by fsync: readers therefore never observe a
// half-written line, and rotation never interleaves two records.
//
// Rotation (Rotate) only opens a new segment within the same epoch. Cleanup
// (Cleanup) writes the surviving events into a brand-new epoch, durably marks
// that epoch ready, and only then deletes the previous epoch. Both operations
// take the same exclusive lock, so they are serialized with a documented,
// deterministic outcome. A crash at any point leaves at least one complete
// readable epoch.
package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/highcumontoa/audit-log-router-go/event"
)

// segmentSoftLimit triggers an automatic rotation when the active segment
// grows past this size. Tests mostly rotate explicitly.
const segmentSoftLimit = 4 * 1024 * 1024

// Store is the durable local event store.
type Store struct {
	dir string

	mu      sync.RWMutex
	epoch   int
	seg     int
	segFile *os.File
	segSize int64
	nextSeq int64

	// events preserves insertion order for deterministic replay outputs.
	order    []string
	events   map[string]storedEvent
	delivery map[string]event.DeliveryRecord
}

type storedEvent struct {
	ev         event.Event
	targets    []string
	receivedAt time.Time
	seq        int64
}

// envelope is the JSON line written into event segments.
type envelope struct {
	Seq        int64       `json:"seq"`
	ReceivedAt time.Time   `json:"received_at"`
	Event      event.Event `json:"event"`
	Targets    []string    `json:"targets"`
}

// stateEnvelope is one JSON line of state.log.
type stateEnvelope struct {
	Kind    string                `json:"kind"` // "state" | "drop"
	Record  *event.DeliveryRecord `json:"record,omitempty"`
	EventID string                `json:"event_id,omitempty"`
}

// Open opens (creating if needed) the store directory and replays its
// append-only logs, rebuilding the in-memory index and delivery states.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: empty directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s := &Store{
		dir:      dir,
		events:   make(map[string]storedEvent),
		delivery: make(map[string]event.DeliveryRecord),
	}
	if err := s.replay(); err != nil {
		return nil, err
	}
	return s, nil
}

// replay rebuilds state from the newest complete epoch plus state.log.
func (s *Store) replay() error {
	epoch, err := newestReadyEpoch(s.dir)
	if err != nil {
		return err
	}
	s.epoch = epoch

	// A brand-new directory has no epoch yet: epoch 0 becomes implicitly
	// active and gets its ready marker on the first durable write.
	entries, err := listSegments(s.dir, epoch)
	if err != nil {
		return err
	}
	for _, seg := range entries {
		path := filepath.Join(s.dir, segmentName(epoch, seg))
		if _, err := replaySegment(path, s.ingestReplayed); err != nil {
			return err
		}
		if seg >= s.seg {
			s.seg = seg
		}
	}
	s.segSize = 0 // size only tracked for the open writable segment

	dropped := make(map[string]struct{})
	if err := replayStateLog(filepath.Join(s.dir, "state.log"), func(e stateEnvelope) error {
		switch e.Kind {
		case "state":
			if e.Record == nil {
				return nil
			}
			// States of dropped/unknown events are ignored: they may remain
			// in state.log from a crash window around compaction.
			if _, ok := s.events[e.Record.EventID]; !ok {
				return nil
			}
			if _, drop := dropped[e.Record.EventID]; drop {
				return nil
			}
			s.delivery[pairKey(e.Record.EventID, e.Record.Target)] = *e.Record
		case "drop":
			dropped[e.EventID] = struct{}{}
			if st, ok := s.events[e.EventID]; ok {
				delete(s.events, e.EventID)
				for _, t := range st.targets {
					delete(s.delivery, pairKey(e.EventID, t))
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if len(dropped) > 0 {
		kept := s.order[:0]
		for _, id := range s.order {
			if _, ok := dropped[id]; !ok {
				kept = append(kept, id)
			}
		}
		s.order = kept
	}

	// Open the active segment for appending.
	f, size, err := openForAppend(filepath.Join(s.dir, segmentName(s.epoch, s.seg)))
	if err != nil {
		return err
	}
	s.segFile = f
	s.segSize = size

	// First epoch on a fresh directory: make its readiness durable now.
	if epoch == 0 && len(entries) == 0 && len(dropped) == 0 {
		if err := s.touchReady(0); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ingestReplayed(env envelope) error {
	if env.Event.ID == "" {
		return errors.New("store: event without id during replay")
	}
	if _, dup := s.events[env.Event.ID]; dup {
		return fmt.Errorf("store: duplicate event id %q replayed", env.Event.ID)
	}
	s.events[env.Event.ID] = storedEvent{
		ev:         env.Event,
		targets:    append([]string(nil), env.Targets...),
		receivedAt: env.ReceivedAt,
		seq:        env.Seq,
	}
	s.order = append(s.order, env.Event.ID)
	if env.Seq >= s.nextSeq {
		s.nextSeq = env.Seq + 1
	}
	return nil
}

// Append durably persists an accepted event. A repeated event ID is detected
// and reported instead of being stored twice.
func (s *Store) Append(ev event.Event, targets []string, now time.Time) (bool, error) {
	if ev.ID == "" {
		return false, errors.New("store: event without id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, dup := s.events[ev.ID]; dup {
		return true, nil
	}
	if err := s.ensureWritable(); err != nil {
		return false, err
	}
	env := envelope{
		Seq:        s.nextSeq,
		ReceivedAt: now,
		Event:      ev,
		Targets:    append([]string(nil), targets...),
	}
	n, err := writeJSONLine(s.segFile, env)
	if err != nil {
		return false, err
	}
	s.segSize += int64(n)
	s.events[ev.ID] = storedEvent{
		ev:         ev,
		targets:    env.Targets,
		receivedAt: now,
		seq:        s.nextSeq,
	}
	s.order = append(s.order, ev.ID)
	s.nextSeq++
	if s.segSize >= segmentSoftLimit {
		if err := s.rotateLocked(); err != nil {
			return false, err
		}
	}
	return false, nil
}

// MarkDelivery persists a per-target delivery state transition.
func (s *Store) MarkDelivery(rec event.DeliveryRecord) error {
	if rec.EventID == "" || rec.Target == "" {
		return errors.New("store: delivery record missing identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[rec.EventID]; !ok {
		return fmt.Errorf("store: delivery for unknown event %q", rec.EventID)
	}
	env := stateEnvelope{Kind: "state", Record: &rec}
	if err := s.appendStateLocked(env); err != nil {
		return err
	}
	s.delivery[pairKey(rec.EventID, rec.Target)] = rec
	return nil
}

func (s *Store) appendStateLocked(env stateEnvelope) error {
	f, err := os.OpenFile(filepath.Join(s.dir, "state.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("store state open: %w", err)
	}
	defer f.Close()
	if _, err := writeJSONLine(f, env); err != nil {
		return err
	}
	return nil
}

// PendingDelivery pairs a stored event with one of its unresolved targets.
type PendingDelivery struct {
	Event  event.Event
	Target string
}

// PendingDeliveries returns persisted (event, target) pairs whose state is not
// terminal, in deterministic (sequence, target) order. It is used to
// rehydrate worker queues after a restart. Pairs never attempted are included
// too (no state record yet).
func (s *Store) PendingDeliveries() []PendingDelivery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := append([]string(nil), s.order...)
	sort.Slice(ids, func(i, j int) bool {
		return s.events[ids[i]].seq < s.events[ids[j]].seq
	})
	var out []PendingDelivery
	for _, id := range ids {
		st := s.events[id]
		targets := append([]string(nil), st.targets...)
		sort.Strings(targets)
		for _, t := range targets {
			rec, ok := s.delivery[pairKey(id, t)]
			if ok && (rec.State == event.StateDelivered || rec.State == event.StateDead) {
				continue
			}
			out = append(out, PendingDelivery{Event: st.ev, Target: t})
		}
	}
	return out
}

// DeliveryStatus returns the auditable state of one (event, target) pair.
func (s *Store) DeliveryStatus(eventID, target string) (event.DeliveryRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.delivery[pairKey(eventID, target)]
	return rec, ok
}

// AllDeliveryStatus returns a copy of every persisted delivery record.
func (s *Store) AllDeliveryStatus() []event.DeliveryRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]event.DeliveryRecord, 0, len(s.delivery))
	for _, rec := range s.delivery {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EventID != out[j].EventID {
			return out[i].EventID < out[j].EventID
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// EventCount returns how many events are currently retained.
func (s *Store) EventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// EventTargets returns the target names a retained event was routed to.
func (s *Store) EventTargets(id string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.events[id]
	if !ok {
		return nil, false
	}
	return append([]string(nil), st.targets...), true
}

// Event returns a copy of a retained event.
func (s *Store) Event(id string) (event.Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.events[id]
	if !ok {
		return event.Event{}, false
	}
	return st.ev, true
}

// Rotate closes the active segment and opens the next one within the same
// epoch. It is serialized against appends and cleanup by the exclusive lock.
func (s *Store) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateLocked()
}

func (s *Store) rotateLocked() error {
	if s.segFile != nil {
		if err := s.segFile.Sync(); err != nil {
			return fmt.Errorf("store rotate sync: %w", err)
		}
		if err := s.segFile.Close(); err != nil {
			return fmt.Errorf("store rotate close: %w", err)
		}
		s.segFile = nil
	}
	s.seg++
	f, size, err := openForAppend(filepath.Join(s.dir, segmentName(s.epoch, s.seg)))
	if err != nil {
		return err
	}
	s.segFile = f
	s.segSize = size
	if err := syncDir(s.dir); err != nil {
		return err
	}
	return nil
}

// ensureWritable makes sure a fresh epoch-0 directory is marked ready before
// the first record lands.
func (s *Store) ensureWritable() error {
	if s.segFile == nil {
		f, size, err := openForAppend(filepath.Join(s.dir, segmentName(s.epoch, s.seg)))
		if err != nil {
			return err
		}
		s.segFile = f
		s.segSize = size
	}
	if s.epoch == 0 {
		// Marker may be missing only on the very first writes; touch is
		// idempotent and cheap.
		if err := s.touchReady(0); err != nil {
			return err
		}
	}
	return nil
}

// CleanupReport explains exactly what a cleanup pass did.
type CleanupReport struct {
	Checked    int      `json:"checked"`
	ExpiredAge []string `json:"expired_age"`
	EvictedCap []string `json:"evicted_capacity"`
	Remaining  int      `json:"remaining"`
	OldEpoch   int      `json:"old_epoch"`
	NewEpoch   int      `json:"new_epoch"`
}

// Cleanup applies retention: removes events older than maxAge and evicts the
// oldest events beyond maxCount. Eviction order is deterministic: OccurredAt
// ascending, ties broken by the durable append sequence. The whole pass —
// including epoch compaction — runs under the exclusive lock, so concurrent
// rotation or ingestion can never interleave with a half-written generation.
func (s *Store) Cleanup(now time.Time, maxAge time.Duration, maxCount int) (CleanupReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := append([]string(nil), s.order...)
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.events[ids[i]], s.events[ids[j]]
		if !a.ev.OccurredAt.Equal(b.ev.OccurredAt) {
			return a.ev.OccurredAt.Before(b.ev.OccurredAt)
		}
		return a.seq < b.seq
	})

	rep := CleanupReport{Checked: len(ids), OldEpoch: s.epoch}
	removed := make(map[string]struct{})
	for _, id := range ids {
		if maxAge > 0 && now.Sub(s.events[id].ev.OccurredAt) > maxAge {
			rep.ExpiredAge = append(rep.ExpiredAge, id)
			removed[id] = struct{}{}
		}
	}
	if maxCount > 0 {
		surviving := make([]string, 0, len(ids))
		for _, id := range ids {
			if _, gone := removed[id]; !gone {
				surviving = append(surviving, id)
			}
		}
		if len(surviving) > maxCount {
			drop := len(surviving) - maxCount
			rep.EvictedCap = append(rep.EvictedCap, surviving[:drop]...)
			for _, id := range surviving[:drop] {
				removed[id] = struct{}{}
			}
		}
	}
	rep.Remaining = len(ids) - len(removed)

	if len(removed) == 0 {
		return rep, nil
	}

	if err := s.compactLocked(removed); err != nil {
		return rep, err
	}
	return rep, nil
}

// compactLocked writes survivors into a new epoch, marks it ready, records
// drop tombstones in state.log, and finally deletes the old epoch. The new
// generation is fully fsynced (and its ready marker durable) before any old
// byte disappears, so a crash can never expose a half-written survivor set.
func (s *Store) compactLocked(removed map[string]struct{}) error {
	newEpoch := s.epoch + 1
	newSegPath := filepath.Join(s.dir, segmentName(newEpoch, 0))
	f, err := os.OpenFile(newSegPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("store compact create: %w", err)
	}
	var size int64
	keptOrder := make([]string, 0, len(s.order)-len(removed))
	for _, id := range s.order {
		if _, gone := removed[id]; id == "" || gone {
			continue
		}
		st := s.events[id]
		env := envelope{
			Seq:        st.seq,
			ReceivedAt: st.receivedAt,
			Event:      st.ev,
			Targets:    append([]string(nil), st.targets...),
		}
		n, err := writeJSONLine(f, env)
		if err != nil {
			f.Close()
			return err
		}
		size += int64(n)
		keptOrder = append(keptOrder, id)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("store compact sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store compact close: %w", err)
	}
	if err := s.touchReady(newEpoch); err != nil {
		return err
	}

	// New generation is durable. Forget removed events in state.log, update
	// memory, then delete the previous epoch's bytes.
	dropIDs := make([]string, 0, len(removed))
	for id := range removed {
		dropIDs = append(dropIDs, id)
	}
	sort.Strings(dropIDs)
	sf, err := os.OpenFile(filepath.Join(s.dir, "state.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("store compact state open: %w", err)
	}
	for _, id := range dropIDs {
		env := stateEnvelope{Kind: "drop", EventID: id}
		if _, err := writeJSONLine(sf, env); err != nil {
			sf.Close()
			return err
		}
	}
	if err := sf.Sync(); err != nil {
		sf.Close()
		return fmt.Errorf("store compact state sync: %w", err)
	}
	if err := sf.Close(); err != nil {
		return err
	}

	for _, id := range dropIDs {
		if st, ok := s.events[id]; ok {
			for _, t := range st.targets {
				delete(s.delivery, pairKey(id, t))
			}
		}
		delete(s.events, id)
	}
	s.order = keptOrder

	oldEpoch := s.epoch
	oldSegs, err := listSegments(s.dir, oldEpoch)
	if err != nil {
		return err
	}
	if s.segFile != nil {
		_ = s.segFile.Close()
		s.segFile = nil
	}
	for _, seg := range oldSegs {
		if err := os.Remove(filepath.Join(s.dir, segmentName(oldEpoch, seg))); err != nil {
			return fmt.Errorf("store compact remove old segment: %w", err)
		}
	}
	if err := os.Remove(filepath.Join(s.dir, readyName(oldEpoch))); err != nil &&
		!os.IsNotExist(err) {
		return fmt.Errorf("store compact remove old marker: %w", err)
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}

	s.epoch = newEpoch
	s.seg = 0
	af, asz, err := openForAppend(filepath.Join(s.dir, segmentName(newEpoch, 0)))
	if err != nil {
		return err
	}
	s.segFile = af
	s.segSize = asz
	return nil
}

// Close flushes and closes all underlying files.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.segFile != nil {
		err := s.segFile.Close()
		s.segFile = nil
		return err
	}
	return nil
}

// Stats summarises the persisted state.
type Stats struct {
	Events     int   `json:"events"`
	Delivered  int   `json:"delivered"`
	Pending    int   `json:"pending"`
	Dead       int   `json:"dead"`
	StoreBytes int64 `json:"store_bytes"`
}

// Stats returns current store statistics used by tests and operators.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{Events: len(s.events)}
	totalPairs := 0
	for _, se := range s.events {
		totalPairs += len(se.targets)
	}
	for _, rec := range s.delivery {
		switch rec.State {
		case event.StateDelivered:
			st.Delivered++
		case event.StateDead:
			st.Dead++
		}
	}
	// Pending covers every non-terminal pair, including ones never attempted
	// (which have no state record yet).
	st.Pending = totalPairs - st.Delivered - st.Dead
	size, err := dirSize(s.dir)
	if err != nil {
		return st, err
	}
	st.StoreBytes = size
	return st, ctx.Err()
}

// ---------- on-disk helpers ----------

func pairKey(eventID, target string) string { return eventID + "\x00" + target }

func segmentName(epoch, seg int) string {
	return fmt.Sprintf("e%d-s%06d.log", epoch, seg)
}

func readyName(epoch int) string { return fmt.Sprintf("e%d.ready", epoch) }

func (s *Store) touchReady(epoch int) error {
	path := filepath.Join(s.dir, readyName(epoch))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("store ready marker: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// newestReadyEpoch finds the highest epoch with a ready marker. Returns 0 when
// the directory has no generations yet.
func newestReadyEpoch(dir string) (int, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "e*.ready"))
	if err != nil {
		return 0, err
	}
	epoch := -1
	for _, m := range matches {
		var e int
		if _, err := fmt.Sscanf(filepath.Base(m), "e%d.ready", &e); err != nil {
			continue
		}
		if e > epoch {
			epoch = e
		}
	}
	if epoch < 0 {
		return 0, nil
	}
	return epoch, nil
}

func listSegments(dir string, epoch int) ([]int, error) {
	prefix := fmt.Sprintf("e%d-s", epoch)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var segs []int
	for _, en := range entries {
		name := en.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		var seg int
		if _, err := fmt.Sscanf(name, prefix+"%d.log", &seg); err != nil {
			return nil, fmt.Errorf("store: unparsable segment file %q", name)
		}
		segs = append(segs, seg)
	}
	sort.Ints(segs)
	return segs, nil
}

func openForAppend(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, 0, fmt.Errorf("store open %s: %w", filepath.Base(path), err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// writeJSONLine serializes one record and writes it with a single write call.
// Callers must hold the store lock, so writes never interleave.
func writeJSONLine(f *os.File, v any) (int, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return 0, fmt.Errorf("store marshal: %w", err)
	}
	payload = append(payload, '\n')
	n, err := f.Write(payload)
	if err != nil {
		return n, fmt.Errorf("store write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return n, fmt.Errorf("store sync: %w", err)
	}
	return n, nil
}

func replaySegment(path string, handle func(envelope) error) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(scanner.Bytes(), &env); err != nil {
			return 0, fmt.Errorf("store %s line %d: corrupt record (half-written?): %w",
				filepath.Base(path), lineNo, err)
		}
		if err := handle(env); err != nil {
			return 0, err
		}
	}
	return lineNo, scanner.Err()
}

func replayStateLog(path string, handle func(stateEnvelope) error) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var env stateEnvelope
		if err := json.Unmarshal(scanner.Bytes(), &env); err != nil {
			return fmt.Errorf("store state.log line %d: corrupt record: %w", lineNo, err)
		}
		if err := handle(env); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func dirSize(dir string) (int64, error) {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		info, err := en.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}
