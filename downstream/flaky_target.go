package downstream

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/highcumontoa/audit-log-router-go/event"
)

// FlakyTarget is an in-memory fault-injection target used by tests: it fails
// the first N deliveries for each event ID, can be switched unhealthy, and
// records what it ultimately accepted — with explicit duplicate detection.
type FlakyTarget struct {
	name string

	mu        sync.Mutex
	healthy   bool
	failFirst int
	attempts  map[string]int // attempts observed per event id
	accepted  map[string]event.Event
	dupes     int
}

// NewFlakyTarget creates a fault-injection target. failFirst is the number of
// Deliver calls that fail for each new event ID before one succeeds.
func NewFlakyTarget(name string, failFirst int) *FlakyTarget {
	return &FlakyTarget{
		name:      name,
		healthy:   true,
		failFirst: failFirst,
		attempts:  make(map[string]int),
		accepted:  make(map[string]event.Event),
	}
}

func (t *FlakyTarget) Name() string { return t.name }

// ErrTargetUnhealthy is returned while the fault switch is flipped off.
var ErrTargetUnhealthy = errors.New("downstream target unhealthy (fault injected)")

// Deliver fails the first failFirst attempts per event ID, rejects duplicate
// IDs that were already accepted, and otherwise accepts the event once.
func (t *FlakyTarget) Deliver(ctx context.Context, ev event.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.healthy {
		return ErrTargetUnhealthy
	}
	if _, ok := t.accepted[ev.ID]; ok {
		t.dupes++
		return ErrDuplicateDelivery(ev.ID)
	}
	t.attempts[ev.ID]++
	if t.attempts[ev.ID] <= t.failFirst {
		return fmt.Errorf("fault injected on attempt %d for event id %q",
			t.attempts[ev.ID], ev.ID)
	}
	t.accepted[ev.ID] = ev
	return nil
}

// SetHealthy toggles whether the target accepts deliveries.
func (t *FlakyTarget) SetHealthy(healthy bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.healthy = healthy
}

// FailFirst adjusts how many attempts per new event ID must fail.
func (t *FlakyTarget) FailFirst(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failFirst = n
}

func (t *FlakyTarget) Healthy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.healthy
}

func (t *FlakyTarget) Close() error { return nil }

// AcceptedIDs returns every event ID delivered exactly once by the target.
func (t *FlakyTarget) AcceptedIDs() map[string]struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]struct{}, len(t.accepted))
	for id := range t.accepted {
		out[id] = struct{}{}
	}
	return out
}

// AcceptedEvent returns the exact event copy the target accepted, so tests can
// assert masked fields (and the absence of original values).
func (t *FlakyTarget) AcceptedEvent(id string) (event.Event, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ev, ok := t.accepted[id]
	if ok {
		ev.Fields = cloneFields(ev.Fields)
	}
	return ev, ok
}

// DuplicateCount returns how many times an already-accepted event ID was
// delivered again (it must always stay zero).
func (t *FlakyTarget) DuplicateCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dupes
}

// AttemptCount returns how many delivery attempts were made for an event ID.
func (t *FlakyTarget) AttemptCount(id string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attempts[id]
}

func cloneFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
