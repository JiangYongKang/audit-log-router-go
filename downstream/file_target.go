package downstream

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/highcumontoa/audit-log-router-go/event"
)

// FileTarget appends delivered events as JSON lines to a local file. The
// output file is an append-only log: across process restarts an event ID that
// was already recorded is recognised from the file and never appended again,
// so downstream duplicates can be identified and suppressed.
//
// Each record is serialized fully before a single write call, so a crashed
// process can leave at most one unreadably truncated final line; the replay
// pass detects and reports that line instead of handing a half-written record
// to readers.
type FileTarget struct {
	name string
	path string

	mu      sync.Mutex
	f       *os.File
	seen    map[string]struct{}
	counter int
}

// NewFileTarget opens (or creates) the append-only output file and replays
// existing event IDs so retries after restart remain idempotent.
func NewFileTarget(name, path string) (*FileTarget, error) {
	if name == "" {
		return nil, errors.New("file target: empty name")
	}
	if path == "" {
		return nil, errors.New("file target: empty path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("file target %s: %w", name, err)
		}
	}
	t := &FileTarget{
		name: name,
		path: path,
		seen: make(map[string]struct{}),
	}
	if err := t.replay(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("file target %s open: %w", name, err)
	}
	t.f = f
	return t, nil
}

// replay reads the JSONL file and rebuilds the delivered-ID set. A truncated
// final line (partial write from a crash) is reported instead of parsed.
func (t *FileTarget) replay() error {
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("file target %s replay: %w", t.name, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec event.Event
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("file target %s: corrupt record at line %d (half-written?): %w",
				t.name, lineNo, err)
		}
		if _, dup := t.seen[rec.ID]; dup {
			return fmt.Errorf("file target %s: duplicate event id %q at line %d",
				t.name, rec.ID, lineNo)
		}
		t.seen[rec.ID] = struct{}{}
		t.counter++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("file target %s replay: %w", t.name, err)
	}
	return nil
}

func (t *FileTarget) Name() string { return t.name }

// Deliver appends one event. A repeated event ID (same-process retry or
// restart replay) is recognised as a duplicate and reported via
// ErrDuplicateDelivery without writing the file a second time.
func (t *FileTarget) Deliver(ctx context.Context, ev event.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, dup := t.seen[ev.ID]; dup {
		return ErrDuplicateDelivery(ev.ID)
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("file target %s marshal: %w", t.name, err)
	}
	payload = append(payload, '\n')
	// A single Write to an O_APPEND descriptor plus fsync gives an
	// all-or-nothing line from a reader's perspective.
	if _, err := t.f.Write(payload); err != nil {
		return fmt.Errorf("file target %s write: %w", t.name, err)
	}
	if err := t.f.Sync(); err != nil {
		return fmt.Errorf("file target %s sync: %w", t.name, err)
	}
	t.seen[ev.ID] = struct{}{}
	t.counter++
	return nil
}

func (t *FileTarget) Healthy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.f != nil
}

func (t *FileTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f = nil
	return err
}

// DeliveredIDs returns a copy of the event IDs already present in the file.
func (t *FileTarget) DeliveredIDs() map[string]struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]struct{}, len(t.seen))
	for id := range t.seen {
		out[id] = struct{}{}
	}
	return out
}

// CountDelivered returns the number of delivered records in the file.
func (t *FileTarget) CountDelivered() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counter
}

// Path returns the output file path (used by tests to scan for leaks).
func (t *FileTarget) Path() string { return t.path }

// ErrDuplicateDelivery is returned when a target is asked to deliver an event
// ID it has already accepted.
type ErrDuplicateDelivery string

func (e ErrDuplicateDelivery) Error() string {
	return fmt.Sprintf("duplicate delivery suppressed for event id %q", string(e))
}
