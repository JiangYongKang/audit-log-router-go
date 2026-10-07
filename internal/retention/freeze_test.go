package retention

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

func newFreezeRegistry(t *testing.T) *freeze.Registry {
	t.Helper()
	reg, err := freeze.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	return reg
}

// 含冻结记录的段：保留期与容量清理都必须跳过。
func TestSweepSkipsFrozenSegments(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	st := newStoreWithSegs(t, 2, []time.Time{old, old, old}) // 3 段全部超期
	defer st.Close()
	reg := newFreezeRegistry(t)

	// 冻结中间段的一条记录（s1-e0）。
	if _, err := reg.FreezeIDs(st, "s1-e0"); err != nil {
		t.Fatal(err)
	}

	logger := log.New(testLogWriter{t}, "[retention-test] ", 0)
	sw := New(st, time.Hour, 24*time.Hour, 1, 0) // 保留期+容量双重压力
	sw.SetFreezeHook(reg, logger)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// 段 0（封存、超期）被删；段 1（封存、含冻结记录）保留；段 2 是活动段，永不删除。
	if rep.DeletedCount != 2 || len(rep.DeletedSegments) != 1 {
		t.Fatalf("want 2 records / 1 seg deleted, got %+v", rep)
	}
	if !strings.Contains(rep.Reason, "kept_frozen_segments=") {
		t.Fatalf("reason must explain kept frozen segment: %q", rep.Reason)
	}
	if st.Count() != 4 {
		t.Fatalf("frozen segment and active segment must survive: count=%d want 4", st.Count())
	}
	if !reg.IsFrozen("s1-e0") {
		t.Fatal("freeze state must be untouched by sweep")
	}
	if !recordExists(st, "s1-e0") || !recordExists(st, "s1-e1") {
		t.Fatal("frozen segment records must survive")
	}
	if recordExists(st, "s0-e0") {
		t.Fatal("unfrozen expired sealed segment must be purged")
	}
	t.Logf("判定依据: 冻结段跳过清理, reason=%s", rep.Reason)
}

// 解冻后记录按原规则重新参与清理：不一解冻就丢，也不会永远清不掉。
func TestUnfreezeRestoresOriginalPurge(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	st := newStoreWithSegs(t, 2, []time.Time{old, now}) // 段0超期，段1(活动)最新
	defer st.Close()
	reg := newFreezeRegistry(t)

	if _, err := reg.FreezeIDs(st, "s0-e0"); err != nil {
		t.Fatal(err)
	}
	sw := New(st, time.Hour, 24*time.Hour, 0, 0)
	sw.SetFreezeHook(reg, nil)

	// 冻结中：超期段被保留。
	rep, _ := sw.Sweep(context.Background(), now)
	if rep.DeletedCount != 0 || st.Count() != 4 {
		t.Fatalf("frozen segment must survive age purge: %+v count=%d", rep, st.Count())
	}

	// 解冻：解冻本身不删除任何记录（不一解冻就丢）。
	if _, err := reg.UnfreezeIDs("s0-e0"); err != nil {
		t.Fatal(err)
	}
	if st.Count() != 4 {
		t.Fatalf("unfreeze itself must not delete anything: count=%d", st.Count())
	}

	// 再次清理：按原保留期规则删除（不会清不掉）。
	rep, _ = sw.Sweep(context.Background(), now)
	if rep.DeletedCount != 2 || st.Count() != 2 {
		t.Fatalf("after unfreeze, original age rule must apply: %+v count=%d", rep, st.Count())
	}
	t.Logf("判定依据: 冻结保留 -> 解冻不丢 -> 再清理按原规则删除, reason=%s", rep.Reason)
}

// 容量被冻结占满：无法回收到上限以下时给出确定、可解释的结论，且冻结记录不被挤掉。
func TestSweepCapacityUnreclaimableWhenFrozen(t *testing.T) {
	now := time.Now()
	// 4 段共 8 条：段0/段1 封存且全冻结，段2 封存未冻结，段3 为活动段。
	st := newStoreWithSegs(t, 2, []time.Time{now, now, now, now})
	defer st.Close()
	reg := newFreezeRegistry(t)

	// 冻结段0、段1全部记录（4 条），上限设为 3：最多只能挤出段2，仍超上限。
	if _, err := reg.FreezeIDs(st, "s0-e0", "s0-e1", "s1-e0", "s1-e1"); err != nil {
		t.Fatal(err)
	}
	logger := log.New(testLogWriter{t}, "[retention-test] ", 0)
	sw := New(st, time.Hour, 0, 3, 0)
	sw.SetFreezeHook(reg, logger)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// 段2（2条）被挤出；冻结段与活动段保留；结论中必须说明容量无法回收及原因。
	if rep.DeletedCount != 2 || st.Count() != 6 {
		t.Fatalf("only unfrozen sealed seg may be evicted: %+v count=%d", rep, st.Count())
	}
	if !strings.Contains(rep.Reason, "capacity_unreclaimable") {
		t.Fatalf("reason must state unreclaimable capacity: %q", rep.Reason)
	}
	for _, id := range []string{"s0-e0", "s0-e1", "s1-e0", "s1-e1"} {
		if !recordExists(st, id) {
			t.Fatalf("frozen record %s must not be evicted", id)
		}
	}
	if recordExists(st, "s2-e0") {
		t.Fatal("unfrozen sealed segment must be evicted first")
	}
	t.Logf("判定依据: 容量被冻结占满, reason=%s", rep.Reason)
}

// 重启后冻结状态恢复，对同一批记录的清理结论一致。
func TestFreezeRestartKeepsSameSweepDecision(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	dir := t.TempDir()
	// 3 段：段0 封存（含将被冻结的记录），段1 封存超期，段2 为活动段。
	st := newStoreWithSegs(t, 2, []time.Time{old, old, old})
	defer st.Close()

	reg, err := freeze.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.FreezeIDs(st, "s0-e1"); err != nil {
		t.Fatal(err)
	}
	reg.Close() // 模拟进程退出

	// 重启：重放 freeze.log。
	reg2, err := freeze.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	sw := New(st, time.Hour, 24*time.Hour, 0, 0)
	sw.SetFreezeHook(reg2, nil)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// 段0 含冻结记录 s0-e1 → 保留；段1 超期删除；段2 活动段保留。重启前后结论一致。
	if rep.DeletedCount != 2 || st.Count() != 4 {
		t.Fatalf("post-restart sweep decision wrong: %+v count=%d", rep, st.Count())
	}
	if !recordExists(st, "s0-e0") || !recordExists(st, "s0-e1") {
		t.Fatal("frozen segment must survive after restart")
	}
	if recordExists(st, "s1-e0") || recordExists(st, "s1-e1") {
		t.Fatal("unfrozen expired segment must be purged after restart")
	}
	t.Logf("判定依据: 重启后冻结状态恢复, 清理结论一致, reason=%s", rep.Reason)
}

// 冻结/解冻/写入/清理并发进行：任何时刻处于冻结态的记录都不得被清理，
// 计数自洽（Count 与扫描一致、无重复），并且冻结集合始终是现存记录的子集
// （不允许「冻结状态查得到、留存数据已删除」的矛盾结论）。
func TestConcurrentFreezeSweepAppend(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	defer st.Close()
	reg := newFreezeRegistry(t)
	sw := New(st, time.Millisecond, 0, 60, 1) // 小容量+小段，频繁轮转与挤出
	sw.SetFreezeHook(reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 写入与冻结/解冻 goroutine 用 wg 等待；清理 goroutine 依赖 ctx 退出，单独等待。
	var wg sync.WaitGroup
	// 写入。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				if _, err := st.Append(mkRecAt(fmt.Sprintf("w%d-%d", w, i), time.Now())); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(w)
	}
	// 并发冻结/解冻（对前缀确定的记录反复操作，验证幂等不自相矛盾）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			id := fmt.Sprintf("w0-%d", i%30)
			rep, err := reg.FreezeIDs(st, id)
			if err != nil {
				t.Errorf("freeze %s: %v", id, err)
				return
			}
			// 成功冻结的 ID 必须是现存记录（真正的关键不变量由清理循环校验）；
			// Skipped 可能是「已被清理」或「尚未写入」，二者都合法。
			for _, ch := range rep.Changed {
				if !recordExists(st, ch) {
					t.Errorf("freeze reports %s changed but record missing", ch)
					return
				}
			}
			if i%3 == 0 {
				if _, err := reg.UnfreezeIDs(id); err != nil {
					t.Errorf("unfreeze %s: %v", id, err)
					return
				}
			}
		}
	}()
	// 并发清理：每次清理后做一次原子一致性校验（store 锁 + 冻结锁，锁序
	// store -> freeze）：当前冻结的记录必须全部存活、计数一致、无重复，
	// 且冻结集合是现存数据的子集（不允许「冻结状态查得到、留存数据已删除」）。
	var sweepErr error
	var smu sync.Mutex
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		for ctx.Err() == nil {
			if _, err := sw.Sweep(ctx, time.Now()); err != nil {
				// 停止信号导致的取消是正常退出，不是清理失败。
				if ctx.Err() != nil {
					return
				}
				smu.Lock()
				sweepErr = err
				smu.Unlock()
				return
			}
			if err := assertStateConsistent(st, reg); err != nil {
				smu.Lock()
				sweepErr = err
				smu.Unlock()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	cancel()
	<-sweepDone

	smu.Lock()
	err := sweepErr
	smu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// 终态再做一次完整自洽校验。
	if err := assertStateConsistent(st, reg); err != nil {
		t.Fatal(err)
	}
	// 此时所有 worker 已停止：冻结计数与 ID 集合数量必须一致（计数不漂移）。
	if int64(reg.FrozenCount()) != int64(len(reg.FrozenIDs())) {
		t.Fatalf("freeze count drift: FrozenCount=%d len(FrozenIDs)=%d",
			reg.FrozenCount(), len(reg.FrozenIDs()))
	}
	t.Logf("判定依据: 并发冻结/清理/写入后 count=%d 无重复, 冻结中的 %d 条全部存活且与留存数据一致",
		st.Count(), reg.FrozenCount())
}

// assertStateConsistent 在同一把 store 临界区内、并全程持有冻结锁快照地校验
// （锁序 store -> freeze）：
//  1. 扫描记录数与 store.Count 一致（计数不漂移、无丢数据）；
//  2. 记录 ID 无重复；
//  3. 每个处于冻结态的 ID 都在现存记录中（冻结状态与留存数据不自相矛盾）。
//
// 两把锁同时持有期间：冻结/解冻无法插入（冻结锁），清理删除/轮转无法插入
// （store 锁），所以「冻结集合 ⊆ 现存记录」是在一个真实的联合原子视图上判定的。
// 注意回调内不得再调用 Registry 的任何加锁方法（Go 互斥锁不可重入）。
func assertStateConsistent(st *store.Store, reg *freeze.Registry) error {
	return st.RunLocked(func() error {
		return reg.WithSnapshot(func(frozen map[string]struct{}) error {
			recs, err := st.ScanSeqsLocked(context.Background(), 0, 0)
			if err != nil {
				return err
			}
			cnt := st.CountLocked()
			if int64(len(recs)) != cnt {
				return fmt.Errorf("count drift: scan=%d Count=%d", len(recs), cnt)
			}
			existing := make(map[string]bool, len(recs))
			for _, r := range recs {
				if existing[r.ID] {
					return fmt.Errorf("duplicate record %s after concurrent sweep", r.ID)
				}
				existing[r.ID] = true
			}
			for id := range frozen {
				if !existing[id] {
					return fmt.Errorf("contradiction: frozen record %s no longer exists in store", id)
				}
			}
			return nil
		})
	})
}

func recordExists(st *store.Store, id string) bool {
	recs, err := st.ScanSeqs(context.Background(), 0, 0)
	if err != nil {
		return false
	}
	for _, r := range recs {
		if r.ID == id {
			return true
		}
	}
	return false
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
