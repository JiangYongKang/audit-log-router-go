package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

func TestValidateAndMask(t *testing.T) {
	p := &Policy{
		Version:        "v1",
		RequiredFields: []string{"action"},
		MaskRules: []MaskRule{
			{Field: "password"},
			{Field: "token", EventType: "login"},
		},
		RouteRules: []RouteRule{
			{EventType: "login", Targets: []string{"b", "a"}},
		},
	}
	eng, err := NewEngine(p)
	if err != nil {
		t.Fatalf("unexpected conflict: %v", err)
	}
	ev := event.Event{ID: "e1", Type: "login", Actor: "u", Timestamp: time.Now(),
		Fields: map[string]string{"action": "login", "password": "hunter2", "token": "tok"}}
	d := eng.Evaluate(ev)
	if !d.Accepted {
		t.Fatalf("expected accepted, reason=%s", d.Reason)
	}
	if got := d.Record.Fields["password"]; got != DefaultMask {
		t.Errorf("password=%q, want mask", got)
	}
	if got := d.Record.Fields["token"]; got != DefaultMask {
		t.Errorf("token=%q, want mask", got)
	}
	// 原始事件不得被改写。
	if ev.Fields["password"] != "hunter2" {
		t.Errorf("original event mutated: %v", ev.Fields)
	}
	if d.Record.PolicyVersion != "v1" || strings.Join(d.Record.Masked, ",") != "password,token" {
		t.Errorf("record meta wrong: %+v", d.Record)
	}
	if strings.Join(d.Targets, ",") != "a,b" {
		t.Errorf("targets should be sorted copy, got %v", d.Targets)
	}
	t.Logf("判定依据: 命中脱敏字段=%v 路由目标=%v", d.Record.Masked, d.Targets)
}

func TestRejectReasonsAreDistinguishable(t *testing.T) {
	eng, _ := NewEngine(&Policy{Version: "v1", RequiredFields: []string{"action"}})
	cases := []struct {
		name string
		ev   event.Event
		want event.RejectReason
	}{
		{"missing_id", event.Event{Type: "t", Actor: "u", Fields: map[string]string{"action": "x"}}, event.RejectMissingID},
		{"missing_type", event.Event{ID: "i", Actor: "u", Fields: map[string]string{"action": "x"}}, event.RejectMissingType},
		{"missing_actor", event.Event{ID: "i", Type: "t", Fields: map[string]string{"action": "x"}}, event.RejectMissingActor},
		{"missing_required", event.Event{ID: "i", Type: "t", Actor: "u"}, event.RejectMissingRequired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := eng.Evaluate(c.ev)
			if d.Accepted || d.Reason != c.want {
				t.Fatalf("got accepted=%v reason=%s, want reason=%s", d.Accepted, d.Reason, c.want)
			}
			t.Logf("拒绝原因可区分: reason=%s detail=%q", d.Reason, d.Detail)
		})
	}
}

func TestRuleConflictsRejected(t *testing.T) {
	cases := []struct {
		name string
		p    *Policy
	}{
		{"empty_version", &Policy{}},
		{"mask_conflict", &Policy{Version: "v", MaskRules: []MaskRule{
			{Field: "x", Mask: "A"}, {Field: "x", Mask: "B"},
		}}},
		{"route_conflict", &Policy{Version: "v", RouteRules: []RouteRule{
			{EventType: "login", Targets: []string{"a"}},
			{EventType: "login", Targets: []string{"b"}},
		}}},
		{"bad_duration", &Policy{Version: "v", RetentionAge: "not-a-duration"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewEngine(c.p)
			re, ok := err.(*event.RejectError)
			if !ok || re.Reason != event.RejectRuleConflict {
				t.Fatalf("want rule_conflict, got %v", err)
			}
			t.Logf("冲突被拒绝: detail=%q", re.Detail)
		})
	}
}

func TestLoadKeepsOldPolicyOnConflict(t *testing.T) {
	eng, _ := NewEngine(&Policy{Version: "v1", MaskRules: []MaskRule{{Field: "x", Mask: "A"}}})
	bad := &Policy{Version: "v2", MaskRules: []MaskRule{
		{Field: "x", Mask: "A"}, {Field: "x", Mask: "B"},
	}}
	if err := eng.Load(bad); err == nil {
		t.Fatal("expected conflict error")
	}
	if eng.Current().Version != "v1" {
		t.Fatalf("old policy must remain effective, got %s", eng.Current().Version)
	}
}
