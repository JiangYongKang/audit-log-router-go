// Package policy 负责脱敏与保留规则的加载、冲突校验与合规判定。
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

const DefaultMask = "***REDACTED***"

// MaskRule 声明某个字段命中脱敏。EventType 为空表示对所有事件类型生效。
type MaskRule struct {
	Field     string `json:"field"`
	EventType string `json:"event_type,omitempty"`
	// Mask 为空时使用 DefaultMask。
	Mask string `json:"mask,omitempty"`
}

// RouteRule 声明命中某事件类型时投递到哪些下游目标。
type RouteRule struct {
	EventType string   `json:"event_type"`
	Targets   []string `json:"targets"`
}

// Policy 是一份不可变的规则集合。
type Policy struct {
	Version        string      `json:"version"`
	RequiredFields []string    `json:"required_fields"`
	MaskRules      []MaskRule  `json:"mask_rules"`
	RouteRules     []RouteRule `json:"route_rules"`
	RetentionAge   string      `json:"retention_age"` // Go duration，如 "720h"
	RetentionCount int64       `json:"retention_count"`
	SegmentBytes   int64       `json:"segment_bytes"`
}

// ParseAge 解析保留期字符串。
func (p *Policy) ParseAge() (time.Duration, error) {
	if p.RetentionAge == "" {
		return 0, nil
	}
	return time.ParseDuration(p.RetentionAge)
}

// ValidatePolicy 校验规则自身的合法性与规则间冲突。
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "nil policy"}
	}
	if strings.TrimSpace(p.Version) == "" {
		return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "policy version is empty"}
	}
	if p.RetentionAge != "" {
		if _, err := p.ParseAge(); err != nil {
			return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "invalid retention_age: " + err.Error()}
		}
	}
	if p.RetentionCount < 0 || p.SegmentBytes < 0 {
		return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "retention_count/segment_bytes must be >= 0"}
	}

	// 冲突 1：同一 (字段, 事件类型) 被多条脱敏规则以不同替换值命中。
	type mk struct{ field, etype string }
	maskSeen := map[mk]string{}
	for _, m := range p.MaskRules {
		if strings.TrimSpace(m.Field) == "" {
			return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "mask rule with empty field"}
		}
		key := mk{m.Field, m.EventType}
		mask := m.Mask
		if mask == "" {
			mask = DefaultMask
		}
		if prev, ok := maskSeen[key]; ok && prev != mask {
			return &event.RejectError{Reason: event.RejectRuleConflict, Detail: fmt.Sprintf(
				"conflicting mask rules on field %q for event_type %q: %q vs %q", m.Field, m.EventType, prev, mask)}
		}
		maskSeen[key] = mask
	}

	// 冲突 2：同一事件类型存在互相矛盾的路由规则（目标集合不同）。
	type targetSet map[string]struct{}
	routeSeen := map[string]targetSet{}
	for _, r := range p.RouteRules {
		if strings.TrimSpace(r.EventType) == "" {
			return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "route rule with empty event_type"}
		}
		set := targetSet{}
		for _, t := range r.Targets {
			if strings.TrimSpace(t) == "" {
				return &event.RejectError{Reason: event.RejectRuleConflict, Detail: "route rule with empty target"}
			}
			set[t] = struct{}{}
		}
		if prev, ok := routeSeen[r.EventType]; ok {
			if !sameSet(prev, set) {
				return &event.RejectError{Reason: event.RejectRuleConflict, Detail: fmt.Sprintf(
					"conflicting route rules on event_type %q", r.EventType)}
			}
		}
		routeSeen[r.EventType] = set
	}
	return nil
}

func sameSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// Decision 是对单个事件的合规判定结果。
type Decision struct {
	Accepted bool
	Record   event.Record
	Targets  []string
	Reason   event.RejectReason
	Detail   string
}

// Engine 执行规则加载、冲突校验与判定。替换规则时先校验再原子切换。
type Engine struct {
	current *Policy
	// 预处理：事件类型 -> 字段 -> 替换值
	maskByType map[string]map[string]string
	routes     map[string][]string
}

// NewEngine 构造判定引擎；规则存在冲突时返回带原因的错误。
func NewEngine(p *Policy) (*Engine, error) {
	e := &Engine{}
	if err := e.Load(p); err != nil {
		return nil, err
	}
	return e, nil
}

// Load 原子替换规则：校验失败时保留旧规则不变。
func (e *Engine) Load(p *Policy) error {
	if err := ValidatePolicy(p); err != nil {
		return err
	}
	e.current = p
	e.maskByType = map[string]map[string]string{}
	e.routes = map[string][]string{}
	for _, m := range p.MaskRules {
		et := m.EventType
		if et == "" {
			et = "*"
		}
		if e.maskByType[et] == nil {
			e.maskByType[et] = map[string]string{}
		}
		mask := m.Mask
		if mask == "" {
			mask = DefaultMask
		}
		e.maskByType[et][m.Field] = mask
	}
	for _, r := range p.RouteRules {
		targets := append([]string(nil), r.Targets...)
		sort.Strings(targets)
		e.routes[r.EventType] = targets
	}
	return nil
}

func (e *Engine) Current() *Policy { return e.current }

// Validate 校验事件必需字段，返回可区分的拒绝原因。
func (e *Engine) Validate(ev event.Event) error {
	if strings.TrimSpace(ev.ID) == "" {
		return &event.RejectError{Reason: event.RejectMissingID, Detail: "event id is required"}
	}
	if strings.TrimSpace(ev.Type) == "" {
		return &event.RejectError{Reason: event.RejectMissingType, Detail: "event type is required"}
	}
	if strings.TrimSpace(ev.Actor) == "" {
		return &event.RejectError{Reason: event.RejectMissingActor, Detail: "event actor is required"}
	}
	for _, f := range e.current.RequiredFields {
		v, ok := ev.Fields[f]
		if !ok || strings.TrimSpace(v) == "" {
			return &event.RejectError{Reason: event.RejectMissingRequired,
				Detail: fmt.Sprintf("required field %q is missing or empty", f)}
		}
	}
	return nil
}

// Evaluate 执行合规判定：校验 -> 脱敏（拷贝，不改原始事件）-> 路由。
// 命中脱敏的字段被替换为占位符，Masked 记录被替换的字段名（排序，便于审计解释）。
func (e *Engine) Evaluate(ev event.Event) Decision {
	if err := e.Validate(ev); err != nil {
		re := err.(*event.RejectError)
		return Decision{Accepted: false, Reason: re.Reason, Detail: re.Detail}
	}

	// 深拷贝字段后再脱敏，原始 Event 不被修改。
	fields := make(map[string]string, len(ev.Fields))
	for k, v := range ev.Fields {
		fields[k] = v
	}
	maskedSet := map[string]struct{}{}
	apply := e.rulesFor(ev.Type)
	for field, repl := range apply {
		if _, ok := fields[field]; ok {
			fields[field] = repl
			maskedSet[field] = struct{}{}
		}
	}
	masked := make([]string, 0, len(maskedSet))
	for f := range maskedSet {
		masked = append(masked, f)
	}
	sort.Strings(masked)

	rec := event.Record{
		Event:         ev,
		PolicyVersion: e.current.Version,
		Masked:        masked,
	}
	rec.Fields = fields

	return Decision{
		Accepted: true,
		Record:   rec,
		Targets:  append([]string(nil), e.routes[ev.Type]...),
	}
}

// rules 返回某事件类型适用的脱敏规则：全局规则 + 类型专属规则（后者优先）。
func (e *Engine) rulesFor(eventType string) map[string]string {
	merged := map[string]string{}
	for k, v := range e.maskByType["*"] {
		merged[k] = v
	}
	for k, v := range e.maskByType[eventType] {
		merged[k] = v
	}
	return merged
}

// LoadFile 从 JSON 文件加载规则。
func LoadFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
