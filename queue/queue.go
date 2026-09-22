// Package queue provides a bounded in-process per-target delivery queue with
// explicit backpressure limits. The queue never grows without bound: when its
// capacity is exhausted Enqueue fails with ErrFull instead of blocking
// forever, so the router can apply an explicit, auditable overflow policy.
package queue

import (
	"context"
	"sync"

	"github.com/highcumontoa/audit-log-router-go/event"
)

// ErrFull is returned when enqueueing would exceed the capacity.
var ErrFull = errQueueFull{}

type errQueueFull struct{}

func (errQueueFull) Error() string { return "delivery queue is full" }

// ErrQueueClosed is returned by Enqueue after the queue was closed.
var ErrQueueClosed = errQueueClosed{}

type errQueueClosed struct{}

func (errQueueClosed) Error() string { return "delivery queue is closed" }

// BoundedQueue is a per-target FIFO of events awaiting delivery.
type BoundedQueue struct {
	mu       sync.Mutex
	items    []event.Event
	capacity int
	closed   bool

	// waiters counts blocked Dequeue callers in the current generation.
	// signaled means the generation's channel was already closed. When the
	// last waiter of a signaled generation leaves (or when Enqueue finds no
	// waiter), a fresh generation is prepared so a later blocker cannot read
	// an already-closed channel.
	waiters  int
	signaled bool
	wake     chan struct{}
}

// NewBoundedQueue creates a queue with the given maximum length.
func NewBoundedQueue(capacity int) *BoundedQueue {
	if capacity < 1 {
		capacity = 1
	}
	return &BoundedQueue{
		items:    make([]event.Event, 0, capacity),
		capacity: capacity,
		wake:     make(chan struct{}),
	}
}

// armLocked prepares a fresh generation if the previous one was consumed.
// Caller holds mu.
func (q *BoundedQueue) armLocked() {
	if q.signaled && q.waiters == 0 {
		q.signaled = false
		q.wake = make(chan struct{})
	}
}

// Enqueue appends an event. It returns ErrFull when the queue reached its
// bound, ErrQueueClosed after Close.
func (q *BoundedQueue) Enqueue(ev event.Event) error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return ErrQueueClosed
	}
	if len(q.items) >= q.capacity {
		q.mu.Unlock()
		return ErrFull
	}
	q.items = append(q.items, ev)
	// A consumer may only have left a spent generation; replace it first so
	// the signal lands on a live channel.
	q.armLocked()
	if q.waiters > 0 && !q.signaled {
		q.signaled = true
		close(q.wake)
	}
	q.mu.Unlock()
	return nil
}

// Dequeue blocks FIFO until an event is available, the queue is closed, or
// ctx is cancelled. The boolean is false when no event will ever arrive.
func (q *BoundedQueue) Dequeue(ctx context.Context) (event.Event, bool) {
	q.mu.Lock()
	for {
		if len(q.items) > 0 {
			ev := q.items[0]
			q.items = q.items[1:]
			// Consuming an item doesn't consume a generation (a generation is
			// spent only when it was signaled); ensure the next blocker arms
			// cleanly when nobody else is waiting.
			q.armLocked()
			q.mu.Unlock()
			return ev, true
		}
		if q.closed || ctx.Err() != nil {
			q.armLocked()
			q.mu.Unlock()
			return event.Event{}, false
		}

		q.armLocked()
		q.waiters++
		wake := q.wake
		q.mu.Unlock()

		select {
		case <-wake:
		case <-ctx.Done():
		}

		q.mu.Lock()
		q.waiters--
		// Last member of a spent generation arms the next one.
		if q.signaled && q.waiters == 0 {
			q.signaled = false
			q.wake = make(chan struct{})
		}
		// loop re-checks items/closed/ctx under the lock
	}
}

// Len returns the current number of queued events.
func (q *BoundedQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Capacity returns the configured bound.
func (q *BoundedQueue) Capacity() int { return q.capacity }

// Close marks the queue drained; blocked Dequeue calls unblock with false.
// Enqueue is rejected afterwards. Close is idempotent.
func (q *BoundedQueue) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.armLocked()
	if q.waiters > 0 && !q.signaled {
		q.signaled = true
		close(q.wake)
	}
	q.mu.Unlock()
}
