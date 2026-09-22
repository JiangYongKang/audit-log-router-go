// Package rule implements the compliance decision layer: configurable
// masking rules, required-field rules, retention rules and event routing.
//
// The engine never mutates a caller-owned event: Evaluate works on a deep copy
// so that masked original values can never reach a downstream target through
// an aliased map. Engine methods also never log field values.
package rule

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/highcumontoa/audit-log-router-go/event"
)

// Action describes how a matching field value must be treated.
type Action string

const (
	// ActionMask replaces the field value with the configured replacement.
	ActionMask Action = "mask"
	// ActionRedact removes the field entirely from downstream copies.
	ActionRedact Action = "redact"
	// ActionKeep leaves the field untouched.
	ActionKeep Action = "keep"
)

// FieldRule binds a field name (optionally scoped to an event type) to an
// action. An empty EventType means the rule applies to every event type.
type FieldRule struct {
	EventType   string `json:"event_type,omitempty"`
	Field       string `json:"field"`
	Action      Action `json:"action"`
	Replacement string `json:"replacement,omitempty"` // used when Action == ActionMask
}

// Duration is a nanosecond duration used by retention configuration.
type Duration int64

// FromTimeDuration converts a time.Duration into a rule Duration.
func FromTimeDuration(d time.Duration) Duration { return Duration(d) }

// Std returns the value as time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// RetentionRule defines when events may be cleaned up.
type RetentionRule struct {
	// MaxAge events older than this duration must be removed. Zero disables
	// age-based retention.
	MaxAge Duration `json:"max_age_nanos"`
	// MaxCount caps the number of retained events; the oldest events are
	// evicted first. Zero disables count-based retention.
	MaxCount int `json:"max_count"`
}

// RouteRule binds an event type to a set of downstream target names. An empty
// EventType is the default route for event types without an explicit route.
type RouteRule struct {
	EventType string   `json:"event_type,omitempty"`
	Targets   []string `json:"targets"`
}

// Config is the complete, reloadable rule configuration.
type Config struct {
	RequiredFields []string      `json:"required_fields"`
	FieldRules     []FieldRule   `json:"field_rules"`
	Retention      RetentionRule `json:"retention"`
	Routes         []RouteRule   `json:"routes"`
}

// Sentinel errors giving distinguishable rejection reasons.
var (
	// ErrMissingField is wrapped when an event lacks a required field.
	ErrMissingField = errors.New("missing required field")
	// ErrRuleConflict is wrapped when two rules cannot both be satisfied.
	ErrRuleConflict = errors.New("conflicting rules")
	// ErrInvalidRule is wrapped when a rule definition itself is invalid.
	ErrInvalidRule = errors.New("invalid rule")
)

// verified is an immutable, validated snapshot of a Config.
type verified struct {
	cfg      Config
	conflict error // non-nil when the rule set is internally conflicting
}

// Validate checks internal consistency of a configuration. It returns an
// error wrapping ErrRuleConflict or ErrInvalidRule; the error text names the
// offending rule but never any event data.
func Validate(cfg Config) error {
	seenReq := make(map[string]struct{}, len(cfg.RequiredFields))
	for _, name := range cfg.RequiredFields {
		if name == "" {
			return fmt.Errorf("%w: empty required field name", ErrInvalidRule)
		}
		seenReq[name] = struct{}{}
	}

	type key struct{ eventType, field string }
	scoped := make(map[key]FieldRule, len(cfg.FieldRules))
	wild := make(map[string]FieldRule, len(cfg.FieldRules))
	for _, fr := range cfg.FieldRules {
		if fr.Field == "" {
			return fmt.Errorf("%w: empty field name", ErrInvalidRule)
		}
		switch fr.Action {
		case ActionMask:
			if fr.Replacement == "" {
				return fmt.Errorf("%w: mask rule for %q needs a replacement",
					ErrInvalidRule, fr.Field)
			}
		case ActionRedact, ActionKeep:
		default:
			return fmt.Errorf("%w: unknown action %q for %q",
				ErrInvalidRule, fr.Action, fr.Field)
		}
		// Conflicting declarations for the exact same scope are rejected.
		k := key{fr.EventType, fr.Field}
		var existing FieldRule
		var ok bool
		if fr.EventType == "" {
			existing, ok = wild[fr.Field]
		} else {
			existing, ok = scoped[k]
		}
		if ok && !rulesEquivalent(existing, fr) {
			return fmt.Errorf("%w: field %q bound to both %q and %q for type %q",
				ErrRuleConflict, fr.Field, existing.Action, fr.Action,
				scopeName(fr.EventType))
		}
		if fr.EventType == "" {
			wild[fr.Field] = fr
		} else {
			scoped[k] = fr
		}
		// A field that must be present cannot simultaneously be deleted from
		// every compliant output copy: required + always-redact is a conflict.
		if fr.Action == ActionRedact && fr.EventType == "" {
			if _, req := seenReq[fr.Field]; req {
				return fmt.Errorf("%w: field %q is required but globally redacted",
					ErrRuleConflict, fr.Field)
			}
		}
	}

	if cfg.Retention.MaxAge < 0 {
		return fmt.Errorf("%w: negative max age", ErrInvalidRule)
	}
	if cfg.Retention.MaxCount < 0 {
		return fmt.Errorf("%w: negative max count", ErrInvalidRule)
	}

	seenRoutes := make(map[string]struct{}, len(cfg.Routes))
	for _, rr := range cfg.Routes {
		if _, dup := seenRoutes[rr.EventType]; dup {
			return fmt.Errorf("%w: duplicate route for type %q",
				ErrRuleConflict, scopeName(rr.EventType))
		}
		seenRoutes[rr.EventType] = struct{}{}
		if len(rr.Targets) == 0 {
			return fmt.Errorf("%w: route for type %q has no targets",
				ErrInvalidRule, scopeName(rr.EventType))
		}
		for _, t := range rr.Targets {
			if t == "" {
				return fmt.Errorf("%w: empty target in route for type %q",
					ErrInvalidRule, scopeName(rr.EventType))
			}
		}
	}
	return nil
}

func rulesEquivalent(a, b FieldRule) bool {
	return a.Action == b.Action && a.Replacement == b.Replacement
}

func scopeName(eventType string) string {
	if eventType == "" {
		return "*"
	}
	return eventType
}

// Verdict is the result of evaluating one event against the active rules.
type Verdict struct {
	Event   *event.Event
	Status  event.Status
	Reason  string
	Masked  []string // names of fields that were masked/redacted
	Targets []string // resolved downstream target names
}

// Engine evaluates events against the currently active immutable snapshot of
// rules and supports atomic rule reloads.
type Engine struct {
	v atomic.Pointer[verified]
}

// NewEngine creates an engine from an initial configuration.
func NewEngine(cfg Config) (*Engine, error) {
	e := &Engine{}
	if err := e.Replace(cfg); err != nil {
		return nil, err
	}
	return e, nil
}

// Replace atomically swaps in a new configuration after validating it.
func (e *Engine) Replace(cfg Config) error {
	if err := Validate(cfg); err != nil {
		return err
	}
	v := &verified{cfg: cloneConfig(cfg)}
	e.v.Store(v)
	return nil
}

// snapshot returns the active verified configuration.
func (e *Engine) snapshot() *verified {
	return e.v.Load()
}

// Snapshot returns a deep copy of the active configuration.
func (e *Engine) Snapshot() Config {
	return cloneConfig(e.snapshot().cfg)
}

// Evaluate validates, masks and routes one event, returning a verdict. The
// event embedded in an accepting verdict is a deep copy: callers cannot
// accidentally leak an original value by mutating shared maps afterwards.
func (e *Engine) Evaluate(ev event.Event) Verdict {
	snap := e.snapshot()
	if snap == nil {
		return Verdict{
			Event:  &ev,
			Status: event.StatusRejectedConflict,
			Reason: "no rule configuration loaded",
		}
	}
	if snap.conflict != nil {
		return Verdict{
			Event:  &ev,
			Status: event.StatusRejectedConflict,
			Reason: snap.conflict.Error(),
		}
	}

	// 1) Required-field check produces a distinguishable, field-scoped reason.
	for _, name := range snap.cfg.RequiredFields {
		v, ok := ev.Fields[name]
		if !ok || v == "" {
			return Verdict{
				Event:  &ev,
				Status: event.StatusRejectedMissing,
				Reason: fmt.Sprintf("%s: %s", ErrMissingField, name),
			}
		}
	}

	// 2) Deep copy, then apply field rules. A type-scoped rule wins over the
	// wildcard rule for the same field; this precedence is fixed so the result
	// is independent of rule declaration order.
	out := ev
	out.Fields = make(map[string]string, len(ev.Fields))
	for k, val := range ev.Fields {
		out.Fields[k] = val
	}
	if ev.Targets != nil {
		out.Targets = append([]string(nil), ev.Targets...)
	}

	masked := []string{}
	names := make([]string, 0, len(snap.cfg.FieldRules))
	seen := make(map[string]struct{})
	for _, fr := range snap.cfg.FieldRules {
		if _, ok := seen[fr.Field]; ok {
			continue
		}
		seen[fr.Field] = struct{}{}
		names = append(names, fr.Field)
	}
	sort.Strings(names)
	for _, name := range names {
		fr, ok := resolveRule(snap.cfg.FieldRules, ev.Type, name)
		if !ok {
			continue
		}
		switch fr.Action {
		case ActionMask:
			if _, present := out.Fields[name]; present {
				out.Fields[name] = fr.Replacement
				masked = append(masked, name)
			}
		case ActionRedact:
			if _, present := out.Fields[name]; present {
				delete(out.Fields, name)
				masked = append(masked, name)
			}
		case ActionKeep:
		}
	}

	// 3) Resolve targets deterministically, de-duplicated.
	targets := resolveTargets(snap.cfg.Routes, ev.Type, ev.Targets)

	return Verdict{
		Event:   &out,
		Status:  event.StatusAccepted,
		Masked:  masked,
		Targets: targets,
	}
}

// resolveRule picks the type-scoped rule when present, else the wildcard rule.
func resolveRule(rules []FieldRule, eventType, field string) (FieldRule, bool) {
	var wildcard FieldRule
	hasWildcard := false
	for _, fr := range rules {
		if fr.Field != field {
			continue
		}
		if fr.EventType == eventType && eventType != "" {
			return fr, true
		}
		if fr.EventType == "" {
			wildcard, hasWildcard = fr, true
		}
	}
	return wildcard, hasWildcard
}

// resolveTargets returns a deterministic, de-duplicated target list. Explicit
// per-event targets win; otherwise the type route wins over the wildcard
// default route.
func resolveTargets(routes []RouteRule, eventType string, explicit []string) []string {
	var picked []string
	if len(explicit) > 0 {
		picked = explicit
	} else {
		var wildcard []string
		for _, rr := range routes {
			if rr.EventType == eventType && eventType != "" {
				picked = rr.Targets
				break
			}
			if rr.EventType == "" {
				wildcard = rr.Targets
			}
		}
		if picked == nil {
			picked = wildcard
		}
	}
	seen := make(map[string]struct{}, len(picked))
	out := make([]string, 0, len(picked))
	for _, t := range picked {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func cloneConfig(cfg Config) Config {
	cp := cfg
	cp.RequiredFields = append([]string(nil), cfg.RequiredFields...)
	cp.FieldRules = make([]FieldRule, len(cfg.FieldRules))
	for i, fr := range cfg.FieldRules {
		cp.FieldRules[i] = fr
	}
	cp.Routes = make([]RouteRule, len(cfg.Routes))
	for i, rr := range cfg.Routes {
		cp.Routes[i] = RouteRule{
			EventType: rr.EventType,
			Targets:   append([]string(nil), rr.Targets...),
		}
	}
	return cp
}
