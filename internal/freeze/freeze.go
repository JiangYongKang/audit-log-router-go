// Package freeze 提供合规冻结（legal hold）能力：被冻结的记录不参与
// 保留期清理与容量挤出，解冻后按原规则重新参与。
//
// 持久化：所有改变冻结集合的操作以 append-only 形式写入 <dir>/freeze.log
// 并 fsync，进程重启后重放恢复，重启前后对同一批记录的结论一致；
// 重放时截断末尾半写行（与事件段相同的崩溃恢复语义）。
//
// 幂等：冻结集合是 ID 集合（set 语义）。重复冻结/解冻同一记录是 no-op，
// 不重复写日志、不重复计数。
//
// 锁序约定：允许 store 锁 -> freeze 锁；禁止 freeze 锁 -> store 锁。
// 因此所有按条件/按 ID 操作都先扫描 store（不持有 freeze 锁），再变更集合。
package freeze

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

const logName = "freeze.log"

// ErrEmptyCriteria 表示批量操作的条件为空（防止误操作全量冻结/解冻）。
var ErrEmptyCriteria = errors.New("freeze: empty criteria matches nothing; refusing batch operation")

// Criteria 描述批量冻结/解冻的匹配条件。零值字段不参与匹配；
// 时间边界为闭区间（含 From 与 To 时刻）。
type Criteria struct {
	Actor string    `json:"actor,omitempty"`
	Type  string    `json:"type,omitempty"`
	From  time.Time `json:"from,omitempty"`
	To    time.Time `json:"to,omitempty"`
}

// Matches 判断记录是否命中条件（所有非零字段同时满足）。
func (c Criteria) Matches(r event.Record) bool {
	if c.Actor != "" && r.Actor != c.Actor {
		return false
	}
	if c.Type != "" && r.Type != c.Type {
		return false
	}
	if !c.From.IsZero() && r.Timestamp.Before(c.From) {
		return false
	}
	if !c.To.IsZero() && r.Timestamp.After(c.To) {
		return false
	}
	return true
}

// IsZero 表示条件为空（不匹配任何记录，防止误操作全量冻结）。
func (c Criteria) IsZero() bool {
	return c.Actor == "" && c.Type == "" && c.From.IsZero() && c.To.IsZero()
}

// Report 解释一次冻结/解冻操作的结果（可审计）。
type Report struct {
	Op       string    // "freeze" | "unfreeze"
	Criteria *Criteria // 条件操作时生效
	Changed  []string  // 本次实际改变状态的记录 ID（升序，确定输出）
	Skipped  []string  // 按 ID 操作时未找到（冻结）或未处于冻结态（解冻）的 ID
}

// logEntry 是 freeze.log 中的一行：一次实际改变集合的操作。
type logEntry struct {
	Op       string    `json:"op"` // "freeze" | "unfreeze"
	IDs      []string  `json:"ids"`
	Criteria *Criteria `json:"criteria,omitempty"`
	Ts       time.Time `json:"ts"`
}

// Registry 维护冻结 ID 集合并持久化操作日志。
type Registry struct {
	mu     sync.Mutex
	frozen map[string]struct{}
	log    *os.File
}

// Open 打开（必要时创建）冻结注册表并重放操作日志。
func Open(dir string) (*Registry, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r := &Registry{frozen: map[string]struct{}{}}
	path := filepath.Join(dir, logName)

	// 重放：按序应用操作，截断末尾半写行。
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	var goodOffset int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var le logEntry
		if err := json.Unmarshal(line, &le); err != nil {
			break // 半写行：截断到上一个完整行末尾
		}
		goodOffset += int64(len(line)) + 1
		for _, id := range le.IDs {
			switch le.Op {
			case "freeze":
				r.frozen[id] = struct{}{}
			case "unfreeze":
				delete(r.frozen, id)
			}
		}
	}
	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > goodOffset {
		if err := f.Truncate(goodOffset); err != nil {
			f.Close()
			return nil, fmt.Errorf("truncate partial tail of %s: %w", path, err)
		}
	}
	if _, err := f.Seek(0, 2); err != nil {
		f.Close()
		return nil, err
	}
	r.log = f
	return r, nil
}

// Close 关闭操作日志文件。
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.log != nil {
		err := r.log.Close()
		r.log = nil
		return err
	}
	return nil
}

// IsFrozen 查询记录是否处于冻结态（冻结状态可核查）。
func (r *Registry) IsFrozen(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.frozen[id]
	return ok
}

// FrozenCount 返回当前冻结的记录数。
func (r *Registry) FrozenCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.frozen)
}

// FrozenIDs 返回当前冻结的记录 ID（升序，确定输出）。
func (r *Registry) FrozenIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.frozen))
	for id := range r.frozen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// FreezeIDs 按事件标识冻结记录；未在 store 中找到的 ID 计入 Skipped。
func (r *Registry) FreezeIDs(st *store.Store, ids ...string) (*Report, error) {
	existing, err := scanIDSet(st)
	if err != nil {
		return nil, err
	}
	rep := &Report{Op: "freeze"}
	var candidates []string
	for _, id := range ids {
		if existing[id] {
			candidates = append(candidates, id)
		} else {
			rep.Skipped = append(rep.Skipped, id)
		}
	}
	rep.Changed = r.apply(logEntry{Op: "freeze", Ts: time.Now()}, candidates)
	sort.Strings(rep.Skipped)
	return rep, nil
}

// UnfreezeIDs 按事件标识解冻记录；未处于冻结态的 ID 计入 Skipped。
func (r *Registry) UnfreezeIDs(ids ...string) (*Report, error) {
	rep := &Report{Op: "unfreeze"}
	r.mu.Lock()
	for _, id := range ids {
		if _, ok := r.frozen[id]; !ok {
			rep.Skipped = append(rep.Skipped, id)
		}
	}
	r.mu.Unlock()
	rep.Changed = r.apply(logEntry{Op: "unfreeze", Ts: time.Now()}, ids)
	sort.Strings(rep.Skipped)
	return rep, nil
}

// FreezeByCriteria 按条件批量冻结 store 中匹配的记录。
// 空条件返回 ErrEmptyCriteria，拒绝执行。
func (r *Registry) FreezeByCriteria(st *store.Store, c Criteria) (*Report, error) {
	if c.IsZero() {
		return nil, ErrEmptyCriteria
	}
	matched, err := scanMatching(st, c)
	if err != nil {
		return nil, err
	}
	rep := &Report{Op: "freeze", Criteria: &c}
	rep.Changed = r.apply(logEntry{Op: "freeze", Criteria: &c, Ts: time.Now()}, matched)
	return rep, nil
}

// UnfreezeByCriteria 按条件批量解冻 store 中匹配且已冻结的记录。
// 空条件返回 ErrEmptyCriteria，拒绝执行。
func (r *Registry) UnfreezeByCriteria(st *store.Store, c Criteria) (*Report, error) {
	if c.IsZero() {
		return nil, ErrEmptyCriteria
	}
	matched, err := scanMatching(st, c)
	if err != nil {
		return nil, err
	}
	rep := &Report{Op: "unfreeze", Criteria: &c}
	rep.Changed = r.apply(logEntry{Op: "unfreeze", Criteria: &c, Ts: time.Now()}, matched)
	return rep, nil
}

// apply 在集合上应用一次操作：只挑实际改变状态的 ID，写日志（fsync）后变更集合。
// 幂等：已处于目标状态的 ID 是 no-op，不写日志、不计数。
func (r *Registry) apply(le logEntry, ids []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var changed []string
	for _, id := range ids {
		_, frozen := r.frozen[id]
		if le.Op == "freeze" && !frozen {
			changed = append(changed, id)
		}
		if le.Op == "unfreeze" && frozen {
			changed = append(changed, id)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	sort.Strings(changed)
	le.IDs = changed
	b, err := json.Marshal(le)
	if err != nil {
		return nil // 不可达：结构固定可编码
	}
	if r.log != nil {
		if _, err := r.log.Write(append(b, '\n')); err == nil {
			r.log.Sync()
		}
	}
	for _, id := range changed {
		if le.Op == "freeze" {
			r.frozen[id] = struct{}{}
		} else {
			delete(r.frozen, id)
		}
	}
	return changed
}

// scanIDSet 扫描 store 中现存记录 ID（不持有 freeze 锁，遵守锁序）。
func scanIDSet(st *store.Store) (map[string]bool, error) {
	recs, err := st.ScanSeqs(context.Background(), 0, 0)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(recs))
	for _, rec := range recs {
		out[rec.ID] = true
	}
	return out, nil
}

// scanMatching 扫描 store 中命中条件的记录 ID（不持有 freeze 锁，遵守锁序）。
func scanMatching(st *store.Store, c Criteria) ([]string, error) {
	recs, err := st.ScanSeqs(context.Background(), 0, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rec := range recs {
		if c.Matches(rec) {
			out = append(out, rec.ID)
		}
	}
	return out, nil
}
