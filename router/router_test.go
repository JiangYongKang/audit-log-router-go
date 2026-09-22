package router

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/downstream"
	"github.com/highcumontoa/audit-log-router-go/event"
	"github.com/highcumontoa/audit-log-router-go/rule"
)

// testConfig routes login events to two independent targets and masks secrets.
func testConfig() rule.Config {
	return rule.Config{
		RequiredFields: []string{"actor", "action"},
		FieldRules: []rule.FieldRule{
			{Field: "password", Action: rule.ActionMask, Replacement: "***"},
			{Field: "token", Action: rule.ActionRedact},
		},
		Retention: rule.RetentionRule{
			MaxAge: rule.FromTimeDuration(time.Minute), MaxCount: 10000,
		},
		Routes: []rule.RouteRule{
			{EventType: "login", Targets: []string{"file", "flaky"}},
			{EventType: "", Targets: []string{"file"}},
		},
	}
}

func fastCfg() Config {
	return Config{
		QueueCapacity:   2048,
		MaxAttempts:     6,
		RetryBackoff:    time.Millisecond,
		CleanupInterval: 0,
		EnqueueTimeout:  2 * time.Second,
	}
}

func mkLogin(id, actor, secret string) event.Event {
	return event.Event{
		ID: id, Type: "login", OccurredAt: time.Now(),
		Fields: map[string]string{
			"actor": actor, "action": "login",
			"password": secret, "token": "tok-" + secret,
		},
	}
}

// newRouter builds a router whose "file" target is a durable JSONL sink and
// whose "flaky" target injects failures.
func newRouter(t *testing.T, dir string, failFirst int) (*Router, *downstream.FileTarget, *downstream.FlakyTarget) {
	t.Helper()
	eng, err := rule.NewEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	ft, err := downstream.NewFileTarget("file", filepath.Join(dir, "file.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fk := downstream.NewFlakyTarget("flaky", failFirst)
	r, err := New(dir, eng, []downstream.Target{ft, fk}, fastCfg())
	if err != nil {
		t.Fatal(err)
	}
	return r, ft, fk
}

// waitFor blocks until cond is true or the deadline elapses.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// Assert: one target failing repeatedly must not block the other target,
// retries are bounded, and rejected submissions carry distinguishable reasons.
func TestFaultIsolationAndBoundedRetry(t *testing.T) {
	dir := t.TempDir()
	r, ft, fk := newRouter(t, dir, 100) // flaky fails all 6 attempts -> dead
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}

	res := r.Submit(ctx, mkLogin("e1", "alice", "SECRET-1"))
	if res.Status != event.StatusAccepted {
		t.Fatalf("submit: %+v", res)
	}

	// Missing required field: distinguishable rejection.
	bad := r.Submit(ctx, event.Event{ID: "e-bad", Type: "login",
		Fields: map[string]string{"actor": "bob"}})
	if bad.Status != event.StatusRejectedMissing ||
		!strings.Contains(bad.Reason, "missing required field: action") {
		t.Fatalf("bad submit = %+v", bad)
	}

	// The healthy target must still receive e1 promptly despite flaky failing.
	if !waitFor(2*time.Second, func() bool { return ft.CountDelivered() == 1 }) {
		t.Fatal("healthy target blocked by failing target")
	}
	// Flaky exhausts the bounded attempts and becomes auditable dead.
	if !waitFor(2*time.Second, func() bool {
		rec, ok := r.DeliveryStatus("e1", "flaky")
		return ok && rec.State == event.StateDead
	}) {
		rec, _ := r.DeliveryStatus("e1", "flaky")
		t.Fatalf("flaky not dead: %+v", rec)
	}
	rec, _ := r.DeliveryStatus("e1", "flaky")
	if rec.Attempts != 6 {
		t.Fatalf("attempts = %d, want bounded 6", rec.Attempts)
	}
	t.Logf("key decision: e1 delivered to file despite flaky failure; flaky dead after %d attempts (%s)",
		rec.Attempts, rec.LastError)

	// New events keep flowing to the healthy target.
	for i := 2; i <= 10; i++ {
		r.Submit(ctx, mkLogin(fmt.Sprintf("e%d", i), "alice", "SECRET"))
	}
	if !waitFor(2*time.Second, func() bool { return ft.CountDelivered() == 10 }) {
		t.Fatalf("healthy target delivered %d, want 10", ft.CountDelivered())
	}
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = fk
}

// Assert: a target that recovers receives its retried events exactly once,
// and repeated IDs never produce duplicates at the sink.
func TestRecoveryThenNoDuplicates(t *testing.T) {
	dir := t.TempDir()
	r, ft, fk := newRouter(t, dir, 2)
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 20; i++ {
		r.Submit(ctx, mkLogin(fmt.Sprintf("r%d", i), "alice", "PW"))
	}
	// Resubmit the same event ID concurrently: must be idempotent.
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Submit(ctx, mkLogin("r1", "alice", "PW")) }()
	}
	wg.Wait()

	if !waitFor(3*time.Second, func() bool {
		return ft.CountDelivered() == 20 && len(fk.AcceptedIDs()) == 20
	}) {
		t.Fatalf("delivery incomplete: file=%d flaky=%d", ft.CountDelivered(), len(fk.AcceptedIDs()))
	}
	if fk.DuplicateCount() != 0 {
		t.Fatalf("downstream saw %d duplicates", fk.DuplicateCount())
	}
	raw, _ := os.ReadFile(ft.Path())
	for i := 1; i <= 20; i++ {
		id := fmt.Sprintf("r%d", i)
		if strings.Count(string(raw), `"ID":"`+id+`"`) != 1 {
			t.Fatalf("%s not present exactly once in file output", id)
		}
	}
	if !strings.Contains(string(raw), `"password":"***"`) || strings.Contains(string(raw), "PW") {
		t.Fatal("masked secret missing or original value leaked into file target")
	}
	t.Logf("key decision: 20 events exactly once on both sinks after retries; masked output, no leak")
	if err := r.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Assert: events acknowledged before a simulated crash are still delivered
// afterwards (at least once), de-duplicated by event ID, and status is
// auditable through the replayed store.
func TestRestartRecovery(t *testing.T) {
	dir := t.TempDir()

	// Phase 1: accept events while flaky is unhealthy; shut down abruptly
	// after they are durable but before flaky deliveries succeed.
	func() {
		r, _, fk := newRouter(t, dir, 0)
		fk.SetHealthy(false)
		ctx := context.Background()
		if err := r.Start(ctx); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 15; i++ {
			res := r.Submit(ctx, mkLogin(fmt.Sprintf("p%d", i), "alice", "SECRET"))
			if res.Status != event.StatusAccepted {
				t.Fatalf("submit p%d: %+v", i, res)
			}
		}
		// Give the file worker time, then simulate process shutdown while
		// flaky pairs remain pending.
		if !waitFor(time.Second, func() bool {
			rec, ok := r.DeliveryStatus("p1", "file")
			return ok && rec.State == event.StateDelivered
		}) {
			t.Fatal("file delivery never recorded before shutdown")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := r.Shutdown(shutdownCtx); err != nil {
			t.Fatal(err)
		}
	}()

	// Phase 2: fresh process (new router, replayed store and output file).
	eng, err := rule.NewEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	ft, err := downstream.NewFileTarget("file", filepath.Join(dir, "file.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fk := downstream.NewFlakyTarget("flaky", 1)
	r, err := New(dir, eng, []downstream.Target{ft, fk}, fastCfg())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown(context.Background())

	if !waitFor(3*time.Second, func() bool {
		return len(fk.AcceptedIDs()) == 15
	}) {
		t.Fatalf("after restart flaky got %d/15", len(fk.AcceptedIDs()))
	}
	if ft.CountDelivered() != 15 {
		t.Fatalf("file target duplicated on restart: %d", ft.CountDelivered())
	}
	all := r.AllDeliveryStatus()
	delivered := 0
	for _, rec := range all {
		if rec.State == event.StateDelivered {
			delivered++
		}
	}
	if delivered != 30 {
		t.Fatalf("auditable delivered pairs = %d, want 30", delivered)
	}
	t.Logf("key decision: after restart 15 durable events rehydrated; flaky recovered %d, file stayed at 15 (dedup)",
		len(fk.AcceptedIDs()))
}

// Assert: rule changes apply to subsequent events while already-persisted
// events keep their fate, and concurrent high-volume submissions never leak
// an original secret into any downstream output.
func TestRuleReloadAndConcurrentNoLeak(t *testing.T) {
	dir := t.TempDir()
	r, ft, fk := newRouter(t, dir, 0)
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown(context.Background())

	const workers, perW = 16, 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perW; i++ {
				id := fmt.Sprintf("c-w%d-%d", w, i)
				secret := fmt.Sprintf("SUPERSECRET-%d-%d", w, i)
				res := r.Submit(ctx, mkLogin(id, "alice", secret))
				if res.Status != event.StatusAccepted {
					t.Errorf("submit %s: %+v", id, res)
					return
				}
			}
		}(w)
	}

	// Reload rules concurrently: swap password replacement and add a mask for
	// actor. Both old and new snapshot outcomes must be internally consistent.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			cfg := testConfig()
			if i%2 == 0 {
				cfg.FieldRules[0].Replacement = "###"
			}
			if err := r.ReplaceRules(cfg); err != nil {
				t.Errorf("replace: %v", err)
				return
			}
			time.Sleep(200 * time.Microsecond)
		}
		_ = r.ReplaceRules(testConfig()) // restore stable snapshot
	}()
	wg.Wait()

	total := workers * perW
	if !waitFor(20*time.Second, func() bool {
		return ft.CountDelivered() == total && len(fk.AcceptedIDs()) == total
	}) {
		t.Fatalf("delivery incomplete: file=%d flaky=%d want=%d",
			ft.CountDelivered(), len(fk.AcceptedIDs()), total)
	}

	// No original secret may appear in the durable output file.
	raw, err := os.ReadFile(ft.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for w := 0; w < workers; w++ {
		for i := 0; i < perW; i++ {
			secret := fmt.Sprintf("SUPERSECRET-%d-%d", w, i)
			if strings.Contains(text, secret) {
				t.Fatalf("LEAK: %s found in downstream output", secret)
			}
			if strings.Contains(text, "tok-SUPERSECRET") {
				t.Fatal("LEAK: redacted token fragment found in output")
			}
		}
	}
	// Masked value or replacement must appear; original key token removed.
	if !strings.Contains(text, `"password":"***"`) {
		t.Fatal("expected masked password placeholder in output")
	}
	if strings.Contains(text, `"token"`) {
		t.Fatal("redacted field name still present")
	}
	// Every flaky-accepted copy must likewise carry only masked data.
	for w := 0; w < workers; w++ {
		for i := 0; i < perW; i++ {
			id := fmt.Sprintf("c-w%d-%d", w, i)
			ev, ok := fk.AcceptedEvent(id)
			if !ok {
				t.Fatalf("flaky missing %s", id)
			}
			if _, hasToken := ev.Fields["token"]; hasToken {
				t.Fatalf("token leaked to flaky for %s", id)
			}
			if v := ev.Fields["password"]; v != "***" && v != "###" {
				t.Fatalf("password not masked for %s: %q", id, v)
			}
		}
	}
	t.Logf("key decision: %d concurrent events + 50 live reloads -> %d/%d delivered, zero secret leak",
		total, ft.CountDelivered(), len(fk.AcceptedIDs()))
}

// Assert: bounded queue overflow is explicit and auditable rather than
// unbounded buffering or silent blocking.
func TestQueueBackpressureIsAuditable(t *testing.T) {
	dir := t.TempDir()
	eng, _ := rule.NewEngine(testConfig())
	fk := downstream.NewFlakyTarget("flaky", 0)
	fk.SetHealthy(false) // park all deliveries; queue fills deterministically
	cfg := fastCfg()
	cfg.QueueCapacity = 5
	cfg.EnqueueTimeout = 50 * time.Millisecond
	r, err := New(filepath.Join(t.TempDir(), "s"),
		eng, []downstream.Target{fk}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = dir
	// Route only to flaky: use a config sending logins to flaky alone.
	rcfg := testConfig()
	rcfg.Routes = []rule.RouteRule{{EventType: "login", Targets: []string{"flaky"}}}
	if err := r.ReplaceRules(rcfg); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown(context.Background())

	dead := 0
	for i := 0; i < 20; i++ {
		res := r.Submit(ctx, mkLogin(fmt.Sprintf("b%d", i), "alice", "PW"))
		if res.Status != event.StatusAccepted {
			t.Fatalf("submit b%d rejected: %+v", i, res)
		}
	}
	if !waitFor(2*time.Second, func() bool {
		n := 0
		for i := 0; i < 20; i++ {
			if rec, ok := r.DeliveryStatus(fmt.Sprintf("b%d", i), "flaky"); ok &&
				rec.State == event.StateDead {
				n++
			}
		}
		dead = n
		return n > 0
	}) {
		t.Fatal("no overflow pair marked dead")
	}
	rec, _ := r.DeliveryStatus("b19", "flaky")
	t.Logf("key decision: queue cap 5 produced %d auditable dead/overflow pairs, last reason=%q",
		dead, rec.LastError)
}
