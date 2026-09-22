package rule

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/event"
)

func baseConfig() Config {
	return Config{
		RequiredFields: []string{"actor", "action"},
		FieldRules: []FieldRule{
			{Field: "password", Action: ActionMask, Replacement: "***"},
			{Field: "ssn", Action: ActionRedact},
			{EventType: "login", Field: "actor", Action: ActionKeep},
		},
		Routes: []RouteRule{
			{EventType: "login", Targets: []string{"audit-file", "siem"}},
			{EventType: "", Targets: []string{"audit-file"}},
		},
	}
}

func TestEvaluateMaskingDoesNotMutateOriginal(t *testing.T) {
	eng, err := NewEngine(baseConfig())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	original := map[string]string{
		"actor": "alice", "action": "login", "password": "hunter2",
	}
	ev := event.Event{ID: "e1", Type: "login", Fields: original}
	v := eng.Evaluate(ev)
	if v.Status != event.StatusAccepted {
		t.Fatalf("status = %s (%s)", v.Status, v.Reason)
	}
	if got := v.Event.Fields["password"]; got != "***" {
		t.Fatalf("password = %q, want ***", got)
	}
	if _, present := v.Event.Fields["ssn"]; present {
		t.Fatal("ssn should be redacted")
	}
	// Original map and event must be untouched: the secret must still be
	// available to the producer but unable to travel via the verdict.
	if original["password"] != "hunter2" {
		t.Fatalf("original mutated: %q", original["password"])
	}
	if ev.Fields["password"] != "hunter2" {
		t.Fatalf("source event mutated: %q", ev.Fields["password"])
	}
	if got := v.Targets[0]; got != "audit-file" {
		t.Fatalf("targets = %v", v.Targets)
	}
	t.Logf("key decision: event e1 masked fields=%v routes=%v", v.Masked, v.Targets)
}

func TestEvaluateMissingFieldDistinguishable(t *testing.T) {
	eng, _ := NewEngine(baseConfig())
	v := eng.Evaluate(event.Event{ID: "e2", Type: "login",
		Fields: map[string]string{"actor": "bob"}})
	if v.Status != event.StatusRejectedMissing {
		t.Fatalf("status = %s", v.Status)
	}
	if !strings.Contains(v.Reason, "missing required field: action") {
		t.Fatalf("reason = %q", v.Reason)
	}
	t.Logf("key decision: reject e2 reason=%s", v.Reason)
}

func TestValidateConflicts(t *testing.T) {
	// required + global redact is an unsatisfiable conflict.
	cfg := baseConfig()
	cfg.RequiredFields = append(cfg.RequiredFields, "ssn")
	if _, err := NewEngine(cfg); !errors.Is(err, ErrRuleConflict) {
		t.Fatalf("want ErrRuleConflict, got %v", err)
	}
	t.Log("key decision: required+redact detected as ErrRuleConflict")

	// Duplicate conflicting rule for same scope.
	cfg = baseConfig()
	cfg.FieldRules = append(cfg.FieldRules,
		FieldRule{Field: "password", Action: ActionRedact})
	if _, err := NewEngine(cfg); !errors.Is(err, ErrRuleConflict) {
		t.Fatalf("want ErrRuleConflict for duplicate rule, got %v", err)
	}

	// Mask without replacement is invalid, not a conflict.
	cfg = baseConfig()
	cfg.FieldRules = []FieldRule{{Field: "x", Action: ActionMask}}
	if _, err := NewEngine(cfg); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("want ErrInvalidRule, got %v", err)
	}
}

func TestReplaceAtomicUnderConcurrency(t *testing.T) {
	eng, _ := NewEngine(baseConfig())
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() { // loader: alternating valid/invalid configs
		defer wg.Done()
		cfgA := baseConfig()
		cfgB := baseConfig()
		cfgB.FieldRules[0].Replacement = "###"
		for i := 0; i < 200; i++ {
			if err := eng.Replace(cfgB); err != nil {
				t.Errorf("Replace B: %v", err)
				return
			}
			if err := eng.Replace(cfgA); err != nil {
				t.Errorf("Replace A: %v", err)
				return
			}
		}
		close(stop)
	}()
	go func() { // readers must always observe one consistent snapshot
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			v := eng.Evaluate(event.Event{ID: "c", Type: "login", Fields: map[string]string{
				"actor": "a", "action": "login", "password": "p",
			}})
			if v.Status == event.StatusAccepted {
				m := v.Event.Fields["password"]
				if m != "***" && m != "###" {
					t.Errorf("torn snapshot, password = %q", m)
					return
				}
			}
		}
	}()
	wg.Wait()
	t.Log("key decision: concurrent reloads only expose complete snapshots")
}

func TestDefaultRouteFallback(t *testing.T) {
	eng, _ := NewEngine(baseConfig())
	v := eng.Evaluate(event.Event{ID: "e3", Type: "anything-else",
		OccurredAt: time.Now(), Fields: map[string]string{"actor": "x", "action": "y"}})
	if v.Status != event.StatusAccepted || len(v.Targets) != 1 || v.Targets[0] != "audit-file" {
		t.Fatalf("verdict=%+v targets=%v", v.Status, v.Targets)
	}
}
