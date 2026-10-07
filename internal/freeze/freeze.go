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
//
// 因此所有需要核对「记录是否仍存在」的操作（按 ID/按条件冻结、按条件解冻）
// 都通过 store.RunLocked 把「扫描存在性 + 变更冻结集（含 fsync）」放进同一把
// store 临界区；清理侧同样在该临界区内完成「冻结判定 + 删除段」。
// 于是冻结与清理对同一条记录的结论只有两种可能：
//
//	冻结先于清理提交 → 清理判定时已冻结，段保留；
//	清理先于冻结提交 → 记录已不存在，冻结的存在性扫描查不到它（计入 Skipped）。
//
// 绝不会出现「冻结状态里有、留存数据里已删除」的矛盾结论。
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
	return r.sortedIDsLocked()
}

// WithSnapshot 在持有冻结锁期间，对当前冻结集合的一份拷贝执行 fn。
// 清理流程可把该调用放在 store.RunLocked 临界区内（锁序 store -> freeze），
// 从而保证一次清理的全部判定与删除期间冻结集合不发生变化。
func (r *Registry) WithSnapshot(fn func(frozen map[string]struct{}) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := make(map[string]struct{}, len(r.frozen))
	for id := range r.frozen {
		snap[id] = struct{}{}
	}
	return fn(snap)
}

func (r *Registry) sortedIDsLocked() []string {
	out := make([]string, 0, len(r.frozen))
	for id := range r.frozen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// FreezeIDs 按事件标识冻结记录；未在 store 中找到的 ID 计入 Skipped。
//
// 「存在性核对 + 集合变更」在同一把 store 临界区内完成：若记录此刻已被清理，
// 它不会进入冻结集合（避免冻结状态指向不存在的数据）；反之一旦冻结提交成功，
// 同临界区协议保证任何后续清理都必须跳过它。
func (r *Registry) FreezeIDs(st *store.Store, ids ...string) (*Report, error) {
	rep := &Report{Op: "freeze"}
	err := st.RunLocked(func() error {
		existing, err := scanIDSetLocked(st)
		if err != nil {
			return err
		}
		var candidates []string
		for _, id := range ids {
			if existing[id] {
				candidates = append(candidates, id)
			} else {
				rep.Skipped = append(rep.Skipped, id)
			}
		}
		changed, _, err := r.apply(logEntry{Op: "freeze", Ts: time.Now()}, candidates)
		if err != nil {
			return err
		}
		rep.Changed = changed
		sort.Strings(rep.Skipped)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// UnfreezeIDs 按事件标识解冻记录；未处于冻结态的 ID 计入 Skipped。
// 解冻不需要核对 store 中的存在性（被解冻目标只可能是已冻结的现存记录；
// 在本锁序协议下，已删除记录不可能留在冻结集合中）。
func (r *Registry) UnfreezeIDs(ids ...string) (*Report, error) {
	rep := &Report{Op: "unfreeze"}
	changed, skipped, err := r.apply(logEntry{Op: "unfreeze", Ts: time.Now()}, ids)
	if err != nil {
		return nil, err
	}
	rep.Changed = changed
	rep.Skipped = skipped
	sort.Strings(rep.Skipped)
	return rep, nil
}

// FreezeByCriteria 按条件批量冻结 store 中匹配的记录。
// 空条件返回 ErrEmptyCriteria，拒绝执行。
// 扫描匹配与集合变更在同一把 store 临界区内完成，与清理互斥。
func (r *Registry) FreezeByCriteria(st *store.Store, c Criteria) (*Report, error) {
	if c.IsZero() {
		return nil, ErrEmptyCriteria
	}
	rep := &Report{Op: "freeze", Criteria: &c}
	err := st.RunLocked(func() error {
		matched, err := scanMatchingLocked(st, c)
		if err != nil {
			return err
		}
		changed, _, err := r.apply(logEntry{Op: "freeze", Criteria: &c, Ts: time.Now()}, matched)
		if err != nil {
			return err
		}
		rep.Changed = changed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// UnfreezeByCriteria 按条件批量解冻 store 中匹配且已冻结的记录。
// 空条件返回 ErrEmptyCriteria，拒绝执行。
// 同样在 store 临界区内完成，保证「扫描到的记录集」与「解冻变更」之间
// 不会插入段删除。
func (r *Registry) UnfreezeByCriteria(st *store.Store, c Criteria) (*Report, error) {
	if c.IsZero() {
		return nil, ErrEmptyCriteria
	}
	rep := &Report{Op: "unfreeze", Criteria: &c}
	err := st.RunLocked(func() error {
		matched, err := scanMatchingLocked(st, c)
		if err != nil {
			return err
		}
		changed, _, err := r.apply(logEntry{Op: "unfreeze", Criteria: &c, Ts: time.Now()}, matched)
		if err != nil {
			return err
		}
		rep.Changed = changed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

// apply 在集合上应用一次操作：只挑实际改变状态的 ID，写日志（fsync）成功后
// 才变更内存集合。幂等：已处于目标状态的 ID 是 no-op，不写日志、不计数；
// 解冻时这类 ID 计入 skipped 返回给调用方。
//
// 若日志写入或 fsync 失败，返回错误且内存集合保持不变——进程不会带着
// 「未持久化的冻结/解冻」继续运行，重启后的结论必然与 freeze.log 一致。
func (r *Registry) apply(le logEntry, ids []string) (changed []string, skipped []string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		_, frozen := r.frozen[id]
		switch {
		case le.Op == "freeze" && !frozen:
			changed = append(changed, id)
		case le.Op == "unfreeze" && !frozen:
			skipped = append(skipped, id)
		case le.Op == "unfreeze" && frozen:
			changed = append(changed, id)
		}
	}
	if len(changed) == 0 {
		sort.Strings(skipped)
		return nil, skipped, nil
	}
	sort.Strings(changed)
	le.IDs = changed
	b, err := json.Marshal(le)
	if err != nil {
		return nil, nil, err // 不可达：结构固定可编码
	}
	if r.log != nil {
		if _, err := r.log.Write(append(b, '\n')); err != nil {
			return nil, nil, fmt.Errorf("write %s log: %w", le.Op, err)
		}
		if err := r.log.Sync(); err != nil {
			return nil, nil, fmt.Errorf("fsync %s log: %w", le.Op, err)
		}
	}
	for _, id := range changed {
		if le.Op == "freeze" {
			r.frozen[id] = struct{}{}
		} else {
			delete(r.frozen, id)
		}
	}
	return changed, skipped, nil
}

// scanIDSetLocked 扫描 store 中现存记录 ID。调用方必须已通过
// store.RunLocked 持有存储锁（遵守锁序 store -> freeze）。
func scanIDSetLocked(st *store.Store) (map[string]bool, error) {
	recs, err := st.ScanSeqsLocked(context.Background(), 0, 0)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(recs))
	for _, rec := range recs {
		out[rec.ID] = true
	}
	return out, nil
}

// scanMatchingLocked 扫描 store 中命中条件的记录 ID。调用方必须已持有存储锁。
func scanMatchingLocked(st *store.Store, c Criteria) ([]string, error) {
	recs, err := st.ScanSeqsLocked(context.Background(), 0, 0)
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
