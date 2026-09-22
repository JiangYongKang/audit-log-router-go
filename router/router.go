// Package router wires the compliance engine, the durable store, the bounded
// per-target queues and the downstream targets into one auditable pipeline.
//
// Delivery semantics:
//   - Submission is acknowledged only after the event is durable in the store;
//     a process crash can therefore never lose an accepted event.
//   - Each (event, target) pair is delivered by a single dedicated worker and
//     retried at most MaxAttempts times with exponential backoff; a target
//     that stays unhealthy or whose queue is full never blocks the others.
//   - Delivery is de-duplicated by event ID on both sides: the worker refrains
//     from re-sending delivered pairs, and the targets themselves reject a
//     repeated ID, so downstream duplicates are identifiable and impossible
//     by construction.
//   - After MaxAttempts failures the pair becomes terminal "dead", which is a
//     visible, auditable outcome rather than an infinite retry.
//
// Logging never prints field values, only event IDs, target names and reasons,
// so masked originals cannot leak through operational logs.
package router

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/highcumontoa/audit-log-router-go/downstream"
	"github.com/highcumontoa/audit-log-router-go/event"
	"github.com/highcumontoa/audit-log-router-go/queue"
	"github.com/highcumontoa/audit-log-router-go/rule"
	"github.com/highcumontoa/audit-log-router-go/store"
)

// Config tunes the router pipeline.
type Config struct {
	// QueueCapacity is the maximum pending events per downstream target.
	QueueCapacity int
	// MaxAttempts caps retries per (event, target); exhausted pairs move to
	// the auditable "dead" state.
	MaxAttempts int
	// RetryBackoff is the base delay between retries; it doubles each time up
	// to 8x.
	RetryBackoff time.Duration
	// CleanupInterval runs retention passes automatically; zero disables the
	// loop and leaves cleanup to explicit Cleanup calls.
	CleanupInterval time.Duration
	// EnqueueTimeout bounds how long Submit waits for room in a saturated
	// per-target queue before the pair becomes terminal dead. Zero uses the
	// built-in default.
	EnqueueTimeout time.Duration
}

// defaultEnqueueTimeout is the production default for bounded backpressure.
const defaultEnqueueTimeout = 5 * time.Second

// Logger is the minimal logging surface used by the router. Implementations
// receive only identifiers and reasons, never event payloads.
type Logger interface {
	Printf(format string, args ...any)
}

// Router is the top-level pipeline.
type Router struct {
	dir   string
	store *store.Store
	eng   *rule.Engine
	cfg   Config
	log   Logger

	mu         sync.Mutex
	targets    map[string]downstream.Target
	queues     map[string]*queue.BoundedQueue
	started    bool
	wg         sync.WaitGroup
	cancelRoot context.CancelFunc
	rootCtx    context.Context
}

// New builds a router over a fresh/opened store, rule engine and targets.
func New(storeDir string, eng *rule.Engine, targets []downstream.Target, cfg Config) (*Router, error) {
	if eng == nil {
		return nil, errors.New("router: nil rule engine")
	}
	if cfg.QueueCapacity < 1 {
		cfg.QueueCapacity = 128
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 5
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 10 * time.Millisecond
	}
	if cfg.EnqueueTimeout <= 0 {
		cfg.EnqueueTimeout = defaultEnqueueTimeout
	}
	st, err := store.Open(storeDir)
	if err != nil {
		return nil, err
	}
	r := &Router{
		dir:     storeDir,
		store:   st,
		eng:     eng,
		cfg:     cfg,
		log:     log.New(os.Stderr, "[router] ", log.LstdFlags|log.Lmsgprefix),
		targets: make(map[string]downstream.Target),
		queues:  make(map[string]*queue.BoundedQueue),
	}
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if _, dup := seen[t.Name()]; dup {
			return nil, fmt.Errorf("router: duplicate target name %q", t.Name())
		}
		seen[t.Name()] = struct{}{}
		r.targets[t.Name()] = t
		r.queues[t.Name()] = queue.NewBoundedQueue(cfg.QueueCapacity)
	}
	return r, nil
}

// SetLogger overrides the default logger. Must be called before Start.
func (r *Router) SetLogger(l Logger) {
	if l != nil {
		r.log = l
	}
}

// Store exposes the underlying store (used by tests for stats/rotation).
func (r *Router) Store() *store.Store { return r.store }

// Dir returns the persistence directory (tests restart into it).
func (r *Router) Dir() string { return r.dir }

// Start launches one worker per target, rehydrates non-terminal pairs from the
// durable store, and optionally starts the retention loop.
func (r *Router) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return errors.New("router: already started")
	}
	r.started = true
	root, cancel := context.WithCancel(ctx)
	r.rootCtx = root
	r.cancelRoot = cancel
	r.mu.Unlock()

	for name := range r.targets {
		r.wg.Add(1)
		go r.worker(name, root)
	}
	r.rehydrate(root)

	if r.cfg.CleanupInterval > 0 {
		r.wg.Add(1)
		go r.cleanupLoop(root)
	}
	r.log.Printf("started: %d targets, queue capacity %d, max attempts %d",
		len(r.targets), r.cfg.QueueCapacity, r.cfg.MaxAttempts)
	return nil
}

// rehydrate refills queues from durable non-terminal deliveries in the order
// the store returns them (append sequence), skipping anything already marked
// terminal or currently queued.
func (r *Router) rehydrate(ctx context.Context) {
	pending := r.store.PendingDeliveries()
	restored := 0
	for _, pd := range pending {
		if err := ctx.Err(); err != nil {
			return
		}
		if !r.enqueue(pd.Target, pd.Event) {
			// Target unknown in THIS process. Record an auditable dead state
			// once, rather than silently dropping the persisted pair.
			r.markDeadOnce(pd.Event.ID, pd.Target,
				"target not registered in current process")
		} else {
			restored++
		}
	}
	if restored > 0 {
		r.log.Printf("rehydrated %d pending deliveries from durable store", restored)
	}
}

// Submit evaluates compliance, persists accepted events and enqueues per-target
// deliveries. It is safe for concurrent use.
func (r *Router) Submit(ctx context.Context, ev event.Event) event.IngestResult {
	verdict := r.eng.Evaluate(ev)
	if verdict.Status != event.StatusAccepted {
		r.log.Printf("reject event id=%q status=%s reason=%s",
			ev.ID, verdict.Status, verdict.Reason)
		return event.IngestResult{
			EventID: ev.ID,
			Status:  verdict.Status,
			Reason:  verdict.Reason,
		}
	}
	accepted := *verdict.Event
	now := time.Now()
	dup, err := r.store.Append(accepted, verdict.Targets, now)
	if err != nil {
		return event.IngestResult{
			EventID: ev.ID,
			Status:  event.StatusRejectedConflict,
			Reason:  "store error: " + err.Error(),
		}
	}
	if dup {
		r.log.Printf("duplicate submit recognized for event id=%q (idempotent accept)", ev.ID)
		return event.IngestResult{
			EventID:   ev.ID,
			Status:    event.StatusAccepted,
			Duplicate: true,
		}
	}
	r.log.Printf("accepted event id=%q type=%q masked=%v targets=%v",
		accepted.ID, accepted.Type, verdict.Masked, verdict.Targets)

	for _, target := range verdict.Targets {
		if _, ok := r.targets[target]; !ok {
			r.markDeadOnce(accepted.ID, target, "target not registered")
			continue
		}
		if !r.enqueueWithBackpressure(ctx, target, accepted) {
			// Bounded backpressure exhausted: the pair is a visible,
			// auditable terminal outcome rather than an unbounded buffer.
			r.markDeadOnce(accepted.ID, target,
				fmt.Sprintf("per-target queue full for %s (bounded backpressure exhausted)",
					r.cfg.EnqueueTimeout))
		}
	}
	return event.IngestResult{EventID: accepted.ID, Status: event.StatusAccepted}
}

// enqueue adds an event to a target's bounded queue. Each target has exactly
// one worker, so a pair already queued or being processed needs no extra
// in-memory single-flight table: de-duplication is enforced durably by the
// delivery state (MarkDelivery) and by the target itself. A pair already in a
// terminal state is skipped instead of enqueued again.
func (r *Router) enqueue(target string, ev event.Event) bool {
	q, ok := r.queues[target]
	if !ok {
		return false
	}
	if rec, known := r.store.DeliveryStatus(ev.ID, target); known &&
		(rec.State == event.StateDelivered || rec.State == event.StateDead) {
		return true
	}
	if err := q.Enqueue(ev); err != nil {
		r.log.Printf("enqueue failed event id=%q target=%s: %v", ev.ID, target, err)
		return false
	}
	return true
}

// backpressurePoll is the retry interval while waiting for queue room.
const backpressurePoll = time.Millisecond

// enqueueWithBackpressure retries enqueueing within a bounded window while the
// target drains, so a momentarily full queue does not permanently lose an
// already-durable event. It gives up (false) only after the timeout.
func (r *Router) enqueueWithBackpressure(ctx context.Context, target string, ev event.Event) bool {
	if r.enqueue(target, ev) {
		return true
	}
	deadline := time.NewTimer(r.cfg.EnqueueTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(backpressurePoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-ticker.C:
			if r.enqueue(target, ev) {
				return true
			}
		}
	}
}

func (r *Router) mark(rec event.DeliveryRecord) {
	rec.UpdatedAt = time.Now()
	if err := r.store.MarkDelivery(rec); err != nil {
		r.log.Printf("state persist failed event id=%q target=%s: %v",
			rec.EventID, rec.Target, err)
	}
}

func (r *Router) markDeadOnce(id, target, reason string) {
	if rec, known := r.store.DeliveryStatus(id, target); known &&
		(rec.State == event.StateDelivered || rec.State == event.StateDead) {
		return
	}
	attempts := 0
	if prev, known := r.store.DeliveryStatus(id, target); known {
		attempts = prev.Attempts
	}
	r.log.Printf("dead event id=%q target=%s attempts=%d reason=%s",
		id, target, attempts, reason)
	r.mark(event.DeliveryRecord{
		EventID: id, Target: target, State: event.StateDead,
		Attempts: attempts, LastError: reason,
	})
}

// worker is the single deliverer for one target. Per-target isolation means a
// failing target only accumulates its own bounded backlog.
func (r *Router) worker(name string, ctx context.Context) {
	defer r.wg.Done()
	q := r.queues[name]
	t := r.targets[name]
	r.log.Printf("worker start target=%s", name)
	for {
		ev, ok := q.Dequeue(ctx)
		if !ok {
			r.log.Printf("worker stop target=%s", name)
			return
		}
		r.deliverOne(ctx, name, t, q, ev)
	}
}

// deliverOne runs the bounded retry loop for one (event, target) pair.
func (r *Router) deliverOne(ctx context.Context, name string,
	t downstream.Target, q *queue.BoundedQueue, ev event.Event) {

	attempts := 0
	for {
		// Respect durable attempts recorded before a restart.
		if rec, known := r.store.DeliveryStatus(ev.ID, name); known && rec.Attempts > attempts {
			attempts = rec.Attempts
		}
		if attempts >= r.cfg.MaxAttempts {
			r.markDeadOnce(ev.ID, name,
				fmt.Sprintf("max attempts %d exhausted", r.cfg.MaxAttempts))
			return
		}

		if !t.Healthy() {
			// Unhealthy does not consume a delivery attempt; park briefly and
			// retry, but abort on shutdown.
			if !sleep(ctx, r.cfg.RetryBackoff) {
				// Shutdown while parked: the pair stays durable+pending and
				// is rehydrated on the next start.
				return
			}
			continue
		}

		attempts++
		err := t.Deliver(ctx, ev)
		if err == nil {
			r.log.Printf("delivered event id=%q target=%s attempts=%d", ev.ID, name, attempts)
			r.mark(event.DeliveryRecord{
				EventID: ev.ID, Target: name, State: event.StateDelivered,
				Attempts: attempts,
			})
			return
		}

		var dupErr downstream.ErrDuplicateDelivery
		if errors.As(err, &dupErr) {
			// The target already holds the event (e.g. restart replay): treat
			// as delivered, the duplicate was suppressed at the sink.
			r.log.Printf("duplicate recognized by target event id=%q target=%s", ev.ID, name)
			r.mark(event.DeliveryRecord{
				EventID: ev.ID, Target: name, State: event.StateDelivered,
				Attempts: attempts, LastError: err.Error(),
			})
			return
		}

		r.mark(event.DeliveryRecord{
			EventID: ev.ID, Target: name, State: event.StateFailed,
			Attempts: attempts, LastError: err.Error(),
		})
		if attempts >= r.cfg.MaxAttempts {
			r.markDeadOnce(ev.ID, name,
				fmt.Sprintf("max attempts %d exhausted: %v", r.cfg.MaxAttempts, err))
			return
		}
		r.log.Printf("delivery failed event id=%q target=%s attempt=%d/%d: %v",
			ev.ID, name, attempts, r.cfg.MaxAttempts, err)
		backoff := r.cfg.RetryBackoff << (attempts - 1)
		if !sleep(ctx, backoff) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ReplaceRules atomically validates and swaps the rule set. Events already
// persisted continue with their old routing fate; subsequent Submit calls use
// the new snapshot.
func (r *Router) ReplaceRules(cfg rule.Config) error {
	if err := r.eng.Replace(cfg); err != nil {
		r.log.Printf("rule reload rejected: %v", err)
		return err
	}
	r.log.Printf("rules replaced: %d field rules, %d routes, max_count=%d",
		len(cfg.FieldRules), len(cfg.Routes), cfg.Retention.MaxCount)
	return nil
}

// cleanupLoop runs retention periodically until shutdown.
func (r *Router) cleanupLoop(ctx context.Context) {
	defer r.wg.Done()
	tk := time.NewTicker(r.cfg.CleanupInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tk.C:
			rep, err := r.Cleanup(now)
			if err != nil {
				r.log.Printf("cleanup error: %v", err)
				continue
			}
			r.log.Printf("cleanup checked=%d expired=%d evicted=%d remaining=%d epoch %d->%d",
				rep.Checked, len(rep.ExpiredAge), len(rep.EvictedCap),
				rep.Remaining, rep.OldEpoch, rep.NewEpoch)
		}
	}
}

// Cleanup runs one retention pass using the active retention rule.
func (r *Router) Cleanup(now time.Time) (store.CleanupReport, error) {
	cfg := r.eng.Snapshot()
	return r.store.Cleanup(now, cfg.Retention.MaxAge.Std(), cfg.Retention.MaxCount)
}

// Rotate explicitly rotates the active store segment (tests use this to stress
// rotation concurrent with cleanup).
func (r *Router) Rotate() error { return r.store.Rotate() }

// DeliveryStatus exposes the auditable delivery state of one pair.
func (r *Router) DeliveryStatus(eventID, target string) (event.DeliveryRecord, bool) {
	return r.store.DeliveryStatus(eventID, target)
}

// AllDeliveryStatus returns all persisted delivery records.
func (r *Router) AllDeliveryStatus() []event.DeliveryRecord {
	return r.store.AllDeliveryStatus()
}

// Shutdown performs a graceful, ctx-bounded stop: it signals the retention
// loop and any retry backoff to abort, then lets every worker DRAIN its queue
// to completion before closing the queues and the store. Events still queued
// when the grace deadline expires remain durable in the store and are
// rehydrated on the next Start, so an acknowledged event is never lost.
func (r *Router) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return r.store.Close()
	}
	r.started = false
	cancel := r.cancelRoot
	queues := make([]*queue.BoundedQueue, 0, len(r.queues))
	for _, q := range r.queues {
		queues = append(queues, q)
	}
	r.mu.Unlock()

	// Stop the retention loop and interrupt retry/backoff sleeps, but do not
	// close the queues yet so workers can drain them.
	cancel()

	drained := make(chan struct{})
	go func() {
		for {
			remaining := 0
			for _, q := range queues {
				remaining += q.Len()
			}
			if remaining == 0 {
				close(drained)
				return
			}
			select {
			case <-ctx.Done():
				close(drained)
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()

	select {
	case <-drained:
	case <-ctx.Done():
		r.log.Printf("graceful drain incomplete, %d events remain durable for restart: %v",
			totalQueued(queues), ctx.Err())
	}
	// Now that workers have drained (or the deadline passed), release blocked
	// Dequeue calls so workers terminate.
	for _, q := range queues {
		q.Close()
	}

	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		r.log.Printf("shutdown worker wait interrupted: %v", ctx.Err())
	}
	for _, t := range r.targets {
		if err := t.Close(); err != nil {
			r.log.Printf("target close error target=%s: %v", t.Name(), err)
		}
	}
	return r.store.Close()
}

func totalQueued(qs []*queue.BoundedQueue) int {
	n := 0
	for _, q := range qs {
		n += q.Len()
	}
	return n
}
