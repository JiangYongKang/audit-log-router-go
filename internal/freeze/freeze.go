// Package freeze 提供合规冻结（legal hold）能力：被调查锁定的审计记录
// 不受保留期与容量清理影响，解冻后重新按原规则参与清理。
//
// 持久化：<dir>/freeze.log 是 append-only 的冻结状态日志（每行 fsync）。
// 进程重启时重放：同一 seq 的最后一个状态为准（frozen 压过 unfrozen），
// 半写行在打开时截断。
//
// 并发：Registry 自带互斥锁；router 的写入判定与 retention 的清理过程
// 共用该锁，保证「冻结/解冻/写入/清理」交叉时计数与状态自洽。
package freeze

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const logName = "freeze.log"

// Selector 描述批量冻结/解冻的匹配条件（各字段之间为 AND；空字段不参与匹配）。
type Selector struct {
	IDs    []string  // 可选：限定到这一批事件 ID
	Source string    // 可选：事件来源（event.Event.Source），空表示不限
	Type   string    // 可选：事件类型，空表示不限
	From   time.Time // 可选：事件时间下界（含），零值表示不限
	To     time.Time // 可选：事件时间上界（含），零值表示不限
	Actor  string    // 可选：事件操作者，空表示不限
}

// 单项处理状态（批量操作逐 ID 可解释）。
const (
	StatusFrozen   = "frozen"    // 本次新冻结
	StatusUnfrozen = "unfrozen"  // 本次新解冻
	StatusAlready  = "already"   // 目标状态本就成立，无变化
	StatusNotFound = "not_found" // 留存中找不到该 ID
)

// ItemResult 是单个事件 ID 的处理结果。
type ItemResult struct {
	ID     string `json:"id"`
	Seq    int64  `json:"seq"`
	Status string `json:"status"`
}

// Report 解释一次批量冻结/解冻操作。
type Report struct {
	Action  string       `json:"action"` // freeze | unfreeze
	Changed int          `json:"changed"`
	Skipped int          `json:"skipped"` // already / not_found
	Items   []ItemResult `json:"items"`
}

// Entry 是一条持久化的冻结状态记录。
type Entry struct {
	Seq       int64     `json:"seq"`
	EventID   string    `json:"event_id"`
	Frozen    bool      `json:"frozen"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RecordView 是冻结判定所需的最小记录视图（由 store 提供，避免循环依赖）。
type RecordView struct {
	Seq       int64
	ID        string
	Type      string
	Source    string
	Actor     string
	Timestamp time.Time
}

// Store 是 Registry 解析事件标识/条件所需的只读存储能力。
type Store interface {
	// LookupSeq 返回事件 ID 对应的序号；不存在返回 (0,false,nil)。
	LookupSeq(id string) (int64, bool, error)
	// ScanViews 返回当前全部留存记录的视图快照（含序号）。
	ScanViews() ([]RecordView, error)
}

// Registry 是合规冻结状态的唯一权威来源。
type Registry struct {
	mu      sync.Mutex
	st      Store
	f       *os.File
	bySeq   map[int64]Entry // seq -> 当前状态（frozen=true 才计数）
	idToSeq map[string]int64
}

// Open 打开（必要时创建）冻结日志并重放已有状态。
func Open(dir string, st Store) (*Registry, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	g := &Registry{
		st:      st,
		bySeq:   map[int64]Entry{},
		idToSeq: map[string]int64{},
	}
	path := filepath.Join(dir, logName)

	// 重放（截断半写行）。
	if err := g.replay(path); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	g.f = f
	return g, nil
}

// replay 逐行重放冻结日志：同一 seq 以最后一个状态为准；截断末尾半写行。
func (g *Registry) replay(path string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	var goodOffset int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if json.Unmarshal(line, &e) != nil || e.Seq <= 0 || e.EventID == "" {
			break // 半写行/非法行：截断到上一个完整行末尾
		}
		goodOffset += int64(len(line)) + 1
		g.apply(e)
	}
	fi, err := os.Stat(path)
	if err == nil && fi.Size() > goodOffset {
		if err := os.Truncate(path, goodOffset); err != nil {
			return err
		}
	}
	return sc.Err()
}

// apply 在重放时应用一条状态（调用方无需持锁，仅 Open 阶段使用）。
func (g *Registry) apply(e Entry) {
	if e.Frozen {
		g.bySeq[e.Seq] = e
		g.idToSeq[e.EventID] = e.Seq
	} else {
		delete(g.bySeq, e.Seq)
		delete(g.idToSeq, e.EventID)
	}
}

// Close 关闭冻结日志。
func (g *Registry) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.f != nil {
		err := g.f.Close()
		g.f = nil
		return err
	}
	return nil
}

// Guard 在冻结注册表互斥保护下执行 fn。Registry 为 nil 时直接执行
// （即未启用冻结能力时，写入与清理行为保持原样）。
func Guard(g *Registry, fn func() error) error {
	if g == nil {
		return fn()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return fn()
}

// FreezeByIDs 按事件标识加冻结。
func (g *Registry) FreezeByIDs(ids []string, at time.Time) (*Report, error) {
	return g.changeByIDs(ids, true, at)
}

// UnfreezeByIDs 按事件标识解冻。
func (g *Registry) UnfreezeByIDs(ids []string, at time.Time) (*Report, error) {
	return g.changeByIDs(ids, false, at)
}

func (g *Registry) changeByIDs(ids []string, wantFrozen bool, at time.Time) (*Report, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	action := StatusFrozen
	if !wantFrozen {
		action = StatusUnfrozen
	}
	rep := &Report{Action: action}
	seen := map[string]bool{} // 同一批次重复 ID 只处理一次
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		seq, ok, err := g.st.LookupSeq(id)
		if err != nil {
			return nil, err
		}
		if !ok {
			rep.Items = append(rep.Items, ItemResult{ID: id, Status: StatusNotFound})
			rep.Skipped++
			continue
		}
		st, err := g.transition(seq, id, wantFrozen, at)
		if err != nil {
			return nil, err
		}
		rep.Items = append(rep.Items, ItemResult{ID: id, Seq: seq, Status: st})
		if st == action {
			rep.Changed++
		} else {
			rep.Skipped++
		}
	}
	return rep, nil
}

// FreezeBySelector 按条件批量加冻结。
func (g *Registry) FreezeBySelector(sel Selector, at time.Time) (*Report, error) {
	return g.changeBySelector(sel, true, at)
}

// UnfreezeBySelector 按条件批量解冻。
func (g *Registry) UnfreezeBySelector(sel Selector, at time.Time) (*Report, error) {
	return g.changeBySelector(sel, false, at)
}

func (g *Registry) changeBySelector(sel Selector, wantFrozen bool, at time.Time) (*Report, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	action := StatusFrozen
	if !wantFrozen {
		action = StatusUnfrozen
	}
	rep := &Report{Action: action}

	idAllow := map[string]bool{}
	for _, id := range sel.IDs {
		if id != "" {
			idAllow[id] = true
		}
	}

	views, err := g.st.ScanViews()
	if err != nil {
		return nil, err
	}
	// 确定顺序：按 seq 升序处理，结论与日志可复现。
	sort.Slice(views, func(i, j int) bool { return views[i].Seq < views[j].Seq })
	for _, v := range views {
		if len(idAllow) > 0 && !idAllow[v.ID] {
			continue
		}
		if !matchSelector(v, sel) {
			continue
		}
		st, err := g.transition(v.Seq, v.ID, wantFrozen, at)
		if err != nil {
			return nil, err
		}
		rep.Items = append(rep.Items, ItemResult{ID: v.ID, Seq: v.Seq, Status: st})
		if st == action {
			rep.Changed++
		} else {
			rep.Skipped++
		}
	}
	return rep, nil
}

func matchSelector(v RecordView, sel Selector) bool {
	if sel.Source != "" && v.Source != sel.Source {
		return false
	}
	if sel.Type != "" && v.Type != sel.Type {
		return false
	}
	if sel.Actor != "" && v.Actor != sel.Actor {
		return false
	}
	if !sel.From.IsZero() && v.Timestamp.Before(sel.From) {
		return false
	}
	if !sel.To.IsZero() && v.Timestamp.After(sel.To) {
		return false
	}
	return true
}

// transition 把单个 seq 切换到目标状态并持久化；幂等：已是目标状态时返回 already。
// 调用方必须持有 g.mu。
func (g *Registry) transition(seq int64, id string, wantFrozen bool, at time.Time) (string, error) {
	_, isFrozen := g.bySeq[seq]
	if isFrozen == wantFrozen {
		// 幂等：重复冻结/重复解冻不重复计数、不重复落盘。
		return StatusAlready, nil
	}
	e := Entry{Seq: seq, EventID: id, Frozen: wantFrozen, UpdatedAt: at}
	if err := g.append(e); err != nil {
		return "", err
	}
	g.apply(e)
	if wantFrozen {
		return StatusFrozen, nil
	}
	return StatusUnfrozen, nil
}

// append 追加一条冻结状态并 fsync。调用方必须持有 g.mu。
func (g *Registry) append(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := g.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return g.f.Sync()
}

// IsFrozen 查询单个事件 ID 的冻结状态。
func (g *Registry) IsFrozen(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	seq, ok := g.idToSeq[id]
	if !ok {
		return false
	}
	_, frozen := g.bySeq[seq]
	return frozen
}

// IsFrozenSeq 查询单个序号的冻结状态。
func (g *Registry) IsFrozenSeq(seq int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, frozen := g.bySeq[seq]
	return frozen
}

// FrozenCount 返回当前被冻结记录数。
func (g *Registry) FrozenCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.FrozenCountLocked()
}

// FrozenCountLocked 与 FrozenCount 相同，但要求调用方已持有注册表锁
// （例如在 Guard 回调内），避免同 goroutine 重复加锁。
func (g *Registry) FrozenCountLocked() int { return len(g.bySeq) }

// FrozenSeqs 返回被冻结序号集合的拷贝（段清理判定用）。
func (g *Registry) FrozenSeqs() map[int64]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.FrozenSeqsLocked()
}

// FrozenSeqsLocked 与 FrozenSeqs 相同，但要求调用方已持有注册表锁。
func (g *Registry) FrozenSeqsLocked() map[int64]bool {
	out := make(map[int64]bool, len(g.bySeq))
	for seq := range g.bySeq {
		out[seq] = true
	}
	return out
}

// Entries 返回全部冻结条目快照（状态核查用，按 seq 升序）。
func (g *Registry) Entries() []Entry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Entry, 0, len(g.bySeq))
	for _, e := range g.bySeq {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// ExistenceChecker 判断某序号是否仍在留存中（由 store 实现）。
type ExistenceChecker interface {
	HasSeq(seq int64) bool
}

// Reconcile 移除「冻结日志里存在、但存储中已不存在」的条目，返回移除条数。
// 正常流程下清理永远不会删除被冻结记录，因此该值应为 0；它是跨重启/
// 手工删段等边界情况下保证计数自洽的保险。调用方必须已持有注册表锁
// （例如在 Guard 回调内），本方法不再重复加锁。
func (g *Registry) Reconcile(checker ExistenceChecker) int {
	removed := 0
	for _, e := range g.bySeq {
		if !checker.HasSeq(e.Seq) {
			delete(g.bySeq, e.Seq)
			delete(g.idToSeq, e.EventID)
			removed++
		}
	}
	return removed
}
