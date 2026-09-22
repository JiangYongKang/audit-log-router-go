package router_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/highcumontoa/audit-log-router-go/downstream"
	"github.com/highcumontoa/audit-log-router-go/event"
	"github.com/highcumontoa/audit-log-router-go/router"
	"github.com/highcumontoa/audit-log-router-go/rule"
)

// Example shows the end-to-end pipeline: a secret-bearing event is accepted,
// masked, delivered to two targets and left in an auditable state.
func Example() {
	dir, err := os.MkdirTemp("", "router-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	cfg := rule.Config{
		RequiredFields: []string{"actor", "action"},
		FieldRules: []rule.FieldRule{
			{Field: "password", Action: rule.ActionMask, Replacement: "***"},
		},
		Retention: rule.RetentionRule{MaxCount: 1000},
		Routes: []rule.RouteRule{
			{EventType: "login", Targets: []string{"audit-file", "siem"}},
		},
	}
	eng, err := rule.NewEngine(cfg)
	if err != nil {
		panic(err)
	}
	file, err := downstream.NewFileTarget("audit-file",
		filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		panic(err)
	}
	siem := downstream.NewFlakyTarget("siem", 1) // fail once, then accept

	r, err := router.New(filepath.Join(dir, "store"), eng,
		[]downstream.Target{file, siem},
		router.Config{
			QueueCapacity: 64, MaxAttempts: 3,
			RetryBackoff: time.Millisecond,
		})
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		panic(err)
	}

	res := r.Submit(ctx, event.Event{
		ID: "evt-1", Type: "login", OccurredAt: time.Now(),
		Fields: map[string]string{
			"actor": "alice", "action": "login", "password": "hunter2",
		},
	})
	fmt.Println("submit:", res.Status)

	// Wait briefly for the bounded retry to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec, ok := r.DeliveryStatus("evt-1", "siem")
		if ok && rec.State == event.StateDelivered {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec, _ := r.DeliveryStatus("evt-1", "audit-file")
	fmt.Println("audit-file:", rec.State)
	rec, _ = r.DeliveryStatus("evt-1", "siem")
	fmt.Println("siem:", rec.State, "attempts:", rec.Attempts)
	accepted, _ := siem.AcceptedEvent("evt-1")
	fmt.Println("masked password:", accepted.Fields["password"])

	shutdownCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := r.Shutdown(shutdownCtx); err != nil {
		panic(err)
	}
	// Output:
	// submit: accepted
	// audit-file: delivered
	// siem: delivered attempts: 2
	// masked password: ***
}
