package downstream

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/highcumontoa/audit-log-router-go/event"
)

func secretEvent(id string) event.Event {
	return event.Event{
		ID:     id,
		Type:   "login",
		Fields: map[string]string{"actor": "alice", "password": "***"},
	}
}

func TestFileTargetIdempotentAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	ctx := context.Background()

	t1, err := NewFileTarget("audit", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := t1.Deliver(ctx, secretEvent("e1")); err != nil {
		t.Fatal(err)
	}
	// Same-process retry must be suppressed as a duplicate.
	if err := t1.Deliver(ctx, secretEvent("e1")); !errors.As(err, new(ErrDuplicateDelivery)) {
		t.Fatalf("want ErrDuplicateDelivery, got %v", err)
	}
	if err := t1.Deliver(ctx, secretEvent("e2")); err != nil {
		t.Fatal(err)
	}
	if err := t1.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate restart: replay the output file.
	t2, err := NewFileTarget("audit", path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := t2.Deliver(ctx, secretEvent("e1")); !errors.As(err, new(ErrDuplicateDelivery)) {
		t.Fatalf("restart duplicate not recognized: %v", err)
	}
	if t2.CountDelivered() != 2 {
		t.Fatalf("count = %d, want 2", t2.CountDelivered())
	}
	if err := t2.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), `"ID":"e1"`); n != 1 {
		t.Fatalf("e1 appears %d times in output, want exactly 1", n)
	}
	t.Log("key decision: file target suppresses duplicates within process and after restart")
}

func TestFileTargetNoHalfWrittenLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	ft, err := NewFileTarget("audit", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ft.Deliver(context.Background(), secretEvent("e1")); err != nil {
		t.Fatal(err)
	}
	if err := ft.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a torn final write.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"ID":"partial","Fi` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if _, err := NewFileTarget("audit", path); err == nil {
		t.Fatal("expected corruption error for half-written final line")
	} else {
		t.Logf("key decision: torn line detected on replay: %v", err)
	}
}

func TestFlakyTargetRetryThenOnce(t *testing.T) {
	ft := NewFlakyTarget("siem", 2)
	ev := secretEvent("e1")
	ctx := context.Background()

	var attempts int
	for {
		attempts++
		err := ft.Deliver(ctx, ev)
		if err == nil {
			break
		}
		if attempts > 5 {
			t.Fatalf("never succeeded: %d attempts", attempts)
		}
	}
	if attempts != 3 {
		t.Fatalf("succeeded after %d attempts, want 3", attempts)
	}
	if err := ft.Deliver(ctx, ev); !errors.As(err, new(ErrDuplicateDelivery)) {
		t.Fatalf("duplicate after accept: %v", err)
	}
	if ft.DuplicateCount() != 1 {
		t.Fatalf("duplicate counter = %d", ft.DuplicateCount())
	}

	got, _ := ft.AcceptedEvent("e1")
	if got.Fields["password"] != "***" {
		t.Fatal("accepted copy must contain masked value")
	}
	t.Logf("key decision: flaky target needed %d attempts then accepted exactly once", attempts)
}

func TestFlakyTargetUnhealthyIsolation(t *testing.T) {
	ft := NewFlakyTarget("siem", 0)
	ft.SetHealthy(false)
	err := ft.Deliver(context.Background(), secretEvent("e9"))
	if !errors.Is(err, ErrTargetUnhealthy) {
		t.Fatalf("want ErrTargetUnhealthy, got %v", err)
	}
	if _, ok := ft.AcceptedIDs()["e9"]; ok {
		t.Fatal("unhealthy target must not accept events")
	}
}

func TestFileTargetConcurrentNoDuplicate(t *testing.T) {
	dir := t.TempDir()
	ft, err := NewFileTarget("audit", filepath.Join(dir, "o.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer ft.Close()

	const goroutines, perG = 8, 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				id := "g" + itoa(g) + "-" + itoa(i)
				if err := ft.Deliver(context.Background(), secretEvent(id)); err != nil {
					t.Errorf("deliver %s: %v", id, err)
					return
				}
			}
		}(g)
	}

	// Anchor one ID first, then hammer it concurrently: every retry must be
	// suppressed, never written twice.
	if err := ft.Deliver(context.Background(), secretEvent("anchor")); err != nil {
		t.Fatal(err)
	}
	barrier := make(chan struct{})
	var inner sync.WaitGroup
	for i := 0; i < 20; i++ {
		inner.Add(1)
		go func() {
			defer inner.Done()
			<-barrier
			err := ft.Deliver(context.Background(), secretEvent("anchor"))
			if err != nil && !errors.As(err, new(ErrDuplicateDelivery)) {
				t.Errorf("retry error: %v", err)
			}
		}()
	}
	close(barrier)
	inner.Wait()
	wg.Wait()

	want := goroutines*perG + 1
	if ft.CountDelivered() != want {
		t.Fatalf("delivered = %d, want %d", ft.CountDelivered(), want)
	}
	raw, err := os.ReadFile(ft.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"ID":"anchor"`) != 1 {
		t.Fatal("repeated ID written more than once under concurrency")
	}
	t.Logf("key decision: %d concurrent unique deliveries, repeated ID written once", want)
}

func itoa(n int) string {
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
