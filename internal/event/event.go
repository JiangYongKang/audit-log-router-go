package event

import (
	"encoding/json"
	"fmt"
	"time"
)

// Event 是采集到的原始审计事件。敏感原始值只存在于该结构中，
// 一旦经过合规判定，只允许脱敏后的 Record 离开判定边界。
type Event struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Actor     string            `json:"actor"`
	Source    string            `json:"source,omitempty"` // 事件来源（系统/通道标识），可用于合规冻结条件匹配
	Timestamp time.Time         `json:"ts"`
	Fields    map[string]string `json:"fields"`
}

// Record 是合规判定后落盘留存并可投递到下游的记录。
// Fields 中命中脱敏规则的字段已被替换为占位符。
type Record struct {
	Event
	PolicyVersion string   `json:"policy_version"`
	Masked        []string `json:"masked,omitempty"`
}

// Line 是 append-only 事件日志中的一行（JSON）。
type Line struct {
	Seq    int64  `json:"seq"`
	Record Record `json:"record"`
}

// RejectReason 描述事件被拒绝的可区分原因，保证处理结论可解释。
type RejectReason string

const (
	RejectNone            RejectReason = ""
	RejectMissingID       RejectReason = "missing_id"
	RejectMissingType     RejectReason = "missing_type"
	RejectMissingActor    RejectReason = "missing_actor"
	RejectMissingRequired RejectReason = "missing_required_field"
	RejectRuleConflict    RejectReason = "rule_conflict"
	RejectDuplicateID     RejectReason = "duplicate_id"
	// RejectCapacityLocked 表示留存容量已被合规冻结记录占满，新写入无法被保证保留。
	// 与其他拒绝原因可区分：只有解冻或提高容量上限后才能恢复写入。
	RejectCapacityLocked RejectReason = "capacity_locked"
)

// RejectError 携带被拒绝的原因与可读说明（说明中不得包含敏感原始值）。
type RejectError struct {
	Reason RejectReason
	Detail string
}

func (e *RejectError) Error() string {
	return fmt.Sprintf("event rejected (%s): %s", e.Reason, e.Detail)
}

// EncodeLine 把记录连同单调序号编码为一行 JSON（以 '\n' 结尾）。
func EncodeLine(seq int64, r Record) ([]byte, error) {
	b, err := json.Marshal(Line{Seq: seq, Record: r})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeLine 解析一行 JSON。
func DecodeLine(b []byte) (Line, error) {
	var ln Line
	if err := json.Unmarshal(b, &ln); err != nil {
		return Line{}, err
	}
	return ln, nil
}
