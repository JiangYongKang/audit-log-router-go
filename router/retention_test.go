package router

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/event"
	"github.com/highcumontoa/audit-log-router-go/rule"
)

// Assert the retention boundary through the router: age cleanup and capacity
// eviction produce an explainable report and a consistent auditable state.
func TestRouterRetentionBoundaries(t *testing.T) {
	r, ft, _ := newRouter(t, t.TempDir(), 0)
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// 10 events, oldest 2 beyond the 1-hour age window.
	for i := 0; i < 10; i++ {
		ev := mkLoginIDAt("ret", i, now.Add(time.Duration(i-9)*10*time.Minute))
		if res := r.Submit(ctx, ev); res.Status != event.StatusAccepted {
			t.Fatalf("submit %d: %+v", i, res)
		}
	}
	if !waitFor(2*time.Second, func() bool { return ft.CountDelivered() == 10 }) {
		t.Fatalf("file=%d", ft.CountDelivered())
	}

	// Capacity retention: keep newest 4 (MaxCount).
	cfg := testConfig()
	cfg.Retention = rule.RetentionRule{MaxCount: 4}
	if err := r.ReplaceRules(cfg); err != nil {
		t.Fatal(err)
	}
	rep, err := r.Cleanup(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Remaining != 4 || len(rep.EvictedCap) != 6 {
		t.Fatalf("capacity report=%+v", rep)
	}
	t.Logf("key decision: retention report checked=%d ageExpired=%v capacityEvicted=%d remaining=%d epoch %d->%d",
		rep.Checked, rep.ExpiredAge, len(rep.EvictedCap), rep.Remaining, rep.OldEpoch, rep.NewEpoch)

	// Evicted pairs disappear from the auditable status; survivors keep theirs.
	// Confirm an evicted ID is gone and a survivor present.
	if _, ok := r.DeliveryStatus("ret-0", "file"); ok {
		t.Fatal("evicted event still has auditable delivery status")
	}
	if _, ok := r.DeliveryStatus("ret-9", "file"); !ok {
		t.Fatal("newest survivor lost its delivery status")
	}
	st, _ := r.Store().Stats(ctx)
	if st.Events != 4 {
		t.Fatalf("stats events=%d want 4", st.Events)
	}
	t.Logf("key decision: post-cleanup stats events=%d delivered=%d pending=%d",
		st.Events, st.Delivered, st.Pending)

	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Assert rotation racing with ingestion and cleanup never loses, duplicates,
// or surfaces a half-written generation across a restart.
func TestRouterRotateConcurrentWithIngestCleanup(t *testing.T) {
	r, ft, _ := newRouter(t, t.TempDir(), 0)
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Retention = rule.RetentionRule{MaxCount: 300}
	if err := r.ReplaceRules(cfg); err != nil {
		t.Fatal(err)
	}

	const total = 300
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { // ingestion
		defer wg.Done()
		for i := 0; i < total; i++ {
			r.Submit(ctx, mkLoginIDAt("rot", i, time.Now()))
		}
	}()
	go func() { // aggressive rotation
		defer wg.Done()
		for i := 0; i < 25; i++ {
			if err := r.Rotate(); err != nil {
				t.Errorf("rotate: %v", err)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	go func() { // repeated cleanup keeping newest 300 (no-op-ish, exercises lock)
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if _, err := r.Cleanup(time.Now().Add(time.Hour)); err != nil {
				t.Errorf("cleanup: %v", err)
				return
			}
			time.Sleep(4 * time.Millisecond)
		}
	}()
	wg.Wait()

	if !waitFor(5*time.Second, func() bool { return ft.CountDelivered() == total }) {
		t.Fatalf("file delivered=%d want %d", ft.CountDelivered(), total)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}

	// Restart into the same directory and verify no loss / no half-written.
	r2, ft2, _ := newRouter(t, r.dir, 0)
	if err := r2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer r2.Shutdown(context.Background())
	if r2.Store().EventCount() != total {
		t.Fatalf("after restart events=%d want %d", r2.Store().EventCount(), total)
	}
	if ft2.CountDelivered() != total {
		t.Fatalf("file output after restart=%d (no duplication allowed)", ft2.CountDelivered())
	}
	t.Logf("key decision: rotate/ingest/cleanup concurrent -> %d events, %d file records, consistent after restart",
		r2.Store().EventCount(), ft2.CountDelivered())
}

func mkLoginIDAt(prefix string, i int, at time.Time) event.Event {
	ev := mkLogin(prefix+"-"+itoa9(i), "alice", "PW")
	ev.OccurredAt = at
	return ev
}

func itoa9(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
