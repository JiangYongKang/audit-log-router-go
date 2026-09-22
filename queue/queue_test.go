package queue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/event"
)

func TestBoundedOverflowIsExplicit(t *testing.T) {
	q := NewBoundedQueue(2)
	for i := 0; i < 2; i++ {
		if err := q.Enqueue(event.Event{ID: "e"}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := q.Enqueue(event.Event{ID: "overflow"}); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
	if q.Len() != 2 {
		t.Fatalf("len = %d", q.Len())
	}
	t.Log("key decision: overflow returns ErrFull instead of unbounded growth")
}

func TestDequeueFIFOAndClose(t *testing.T) {
	q := NewBoundedQueue(4)
	for _, id := range []string{"a", "b", "c"} {
		if err := q.Enqueue(event.Event{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	for _, want := range []string{"a", "b", "c"} {
		ev, ok := q.Dequeue(ctx)
		if !ok || ev.ID != want {
			t.Fatalf("got %v ok=%v, want %s", ev.ID, ok, want)
		}
	}
	q.Close()
	if _, ok := q.Dequeue(ctx); ok {
		t.Fatal("Dequeue after Close must return false")
	}
	if err := q.Enqueue(event.Event{}); err == nil {
		t.Fatal("Enqueue after Close must fail")
	}
}

func TestConcurrentEnqueueWithinBound(t *testing.T) {
	q := NewBoundedQueue(1000)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := q.Enqueue(event.Event{}); err != nil {
					t.Errorf("enqueue: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if q.Len() != 1000 {
		t.Fatalf("len = %d, want 1000", q.Len())
	}

	got := make(chan event.Event, 1000)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			ev, ok := q.Dequeue(context.Background())
			if !ok {
				return
			}
			got <- ev
		}
	}()
	select {
	case <-func() chan struct{} {
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		return done
	}():
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent drain deadlocked")
	}
	t.Logf("key decision: %d concurrent enqueues stayed within bound", 1000)
}
