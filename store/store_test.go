package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/event"
)

func mkEvent(id string, at time.Time) event.Event {
	return event.Event{ID: id, Type: "login", OccurredAt: at,
		Fields: map[string]string{"actor": "a", "action": "login"}}
}

func TestAppendRestartReplayAndPending(t *testing.T) {
	dir := t.TempDir()
	base := time.Now()

	s1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := s1.Append(mkEvent("e1", base), []string{"a", "b"}, base)
	if err != nil || dup {
		t.Fatalf("append e1: dup=%v err=%v", dup, err)
	}
	dup, err = s1.Append(mkEvent("e1", base), []string{"a", "b"}, base)
	if err != nil || !dup {
		t.Fatalf("duplicate append: dup=%v err=%v", dup, err)
	}
	if dup, err := s1.Append(mkEvent("e2", base.Add(time.Second)), []string{"a"}, base); err != nil || dup {
		t.Fatalf("append e2: dup=%v err=%v", dup, err)
	}
	if err := s1.MarkDelivery(event.DeliveryRecord{
		EventID: "e1", Target: "a", State: event.StateDelivered, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s1.MarkDelivery(event.DeliveryRecord{
		EventID: "e2", Target: "a", State: event.StateFailed, Attempts: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: state must be rebuilt from files.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.EventCount() != 2 {
		t.Fatalf("events after restart = %d", s2.EventCount())
	}
	pending := s2.PendingDeliveries()
	got := map[string]bool{}
	for _, p := range pending {
		got[p.Event.ID+"@"+p.Target] = true
	}
	if !got["e1@b"] || !got["e2@a"] {
		t.Fatalf("pending = %v", got)
	}
	if got["e1@a"] {
		t.Fatal("delivered pair must not be re-pending after restart")
	}
	rec, ok := s2.DeliveryStatus("e2", "a")
	if !ok || rec.Attempts != 2 || rec.State != event.StateFailed {
		t.Fatalf("state not rebuilt: %+v ok=%v", rec, ok)
	}
	t.Logf("key decision: after restart %d events, pending pairs=%v; delivered e1@a stays terminal",
		s2.EventCount(), pending)
}

func TestCleanupAgeAndCapacityDeterministic(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Five events at one-hour spacing; same-timestamp pair forced to tie-break
	// by durable sequence: e3b appended after e3a.
	ids := []string{"e0", "e1", "e2", "e3a", "e3b"}
	for i, id := range ids {
		at := now.Add(time.Duration(i-3) * time.Hour)
		if id == "e3b" {
			at = now.Add(0) // same OccurredAt as e3a (index 3 offset 0)
		}
		if dup, err := s.Append(mkEvent(id, at), []string{"x"}, now); err != nil || dup {
			t.Fatalf("append %s: %v %v", id, dup, err)
		}
	}

	// Cleanup at "now": ages are 3h,2h,1h,0,0. A 30-minute max age expires
	// exactly e0,e1,e2 and leaves the two zero-age (same-timestamp) events.
	rep, err := s.Cleanup(now, 30*time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExpiredAge) != 3 || rep.Remaining != 2 {
		t.Fatalf("age cleanup rep=%+v", rep)
	}
	t.Logf("key decision: age cleanup expired=%v remaining=%d", rep.ExpiredAge, rep.Remaining)

	// Capacity: retain 1; among the two same-age survivors, sequence order
	// must evict e3a before e3b.
	rep, err = s.Cleanup(now, 30*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.EvictedCap) != 1 || rep.EvictedCap[0] != "e3a" {
		t.Fatalf("capacity eviction=%v want [e3a]", rep.EvictedCap)
	}
	if rep.Remaining != 1 {
		t.Fatalf("remaining=%d", rep.Remaining)
	}
	if _, ok := s.Event("e3a"); ok {
		t.Fatal("evicted event still in index")
	}
	t.Logf("key decision: capacity evicted=%v by (OccurredAt,seq) order, survivor=e3b",
		rep.EvictedCap)

	// Compaction must survive a restart.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after compaction: %v", err)
	}
	defer s2.Close()
	if s2.EventCount() != 1 {
		t.Fatalf("events after compact+restart = %d", s2.EventCount())
	}
	if _, ok := s2.Event("e3b"); !ok {
		t.Fatal("survivor missing after compact+restart")
	}
	if _, ok := s2.Event("e0"); ok {
		t.Fatal("expired event reappeared after compact+restart")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "e0-*.log")); len(files) != 0 {
		t.Fatalf("old epoch segments not removed: %v", files)
	}
}

func TestRotationConcurrentWithCleanup(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const n = 200
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("e%04d", i)
		at := now.Add(time.Duration(i) * time.Second)
		if dup, err := s.Append(mkEvent(id, at), []string{"x"}, now); err != nil || dup {
			t.Fatalf("append %s: %v %v", id, dup, err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var rotErr error
	go func() { // rotate aggressively
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := s.Rotate(); err != nil {
				rotErr = err
				return
			}
		}
	}()
	var rep CleanupReport
	go func() { // cleanup concurrently: keep newest 50
		defer wg.Done()
		var err error
		rep, err = s.Cleanup(now.Add(n*time.Second), 0, 50)
		if err != nil {
			rotErr = err
		}
	}()
	wg.Wait()
	if rotErr != nil {
		t.Fatal(rotErr)
	}
	if rep.Remaining != 50 || rep.Checked != n {
		t.Fatalf("concurrent cleanup report=%+v", rep)
	}
	if s.EventCount() != 50 {
		t.Fatalf("event count=%d, want 50", s.EventCount())
	}

	// Reopen: no half-written state, no lost or double-counted survivor.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if s2.EventCount() != 50 {
		t.Fatalf("after restart count=%d", s2.EventCount())
	}
	pending := s2.PendingDeliveries()
	if len(pending) != 50 {
		t.Fatalf("pending after restart=%d want 50", len(pending))
	}
	seen := map[string]struct{}{}
	for _, p := range pending {
		if _, dup := seen[p.Event.ID]; dup {
			t.Fatalf("duplicate survivor %q", p.Event.ID)
		}
		seen[p.Event.ID] = struct{}{}
	}
	t.Logf("key decision: rotate+cleanup concurrent -> %d survivors, %d pending after restart, no dup/loss",
		s2.EventCount(), len(pending))
}

func TestCleanupNoOpDoesNotCompact(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	s, _ := Open(dir)
	defer s.Close()
	if dup, err := s.Append(mkEvent("e1", now), []string{"x"}, now); err != nil || dup {
		t.Fatal(err)
	}
	rep, err := s.Cleanup(now.Add(time.Hour), 48*time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExpiredAge) != 0 || len(rep.EvictedCap) != 0 || rep.NewEpoch != 0 {
		t.Fatalf("unnecessary compaction: %+v", rep)
	}
	st, err := s.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Events != 1 || st.Pending != 1 {
		t.Fatalf("stats=%+v", st)
	}
	_ = os.DirFS
}
