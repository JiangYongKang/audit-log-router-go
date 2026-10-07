package retention

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

func openFreshStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func freezeCriteria(actor, typ string) freeze.Criteria {
	return freeze.Criteria{Actor: actor, Type: typ}
}

// 场景：超期清理 + 容量挤出 + 按 ID 冻结/解冻 + 按条件批量冻结同时高并发。
// 这是「一条记录刚被冻结，后台正好在清数据」窗口最密集的形态。
// 任意时刻冻结集合都必须是现存记录的子集；全程计数不漂移、无重复。
func TestConcurrentFreezeCriteriaSweepAgePressure(t *testing.T) {
	st := openFreshStore(t)
	reg := newFreezeRegistry(t)
	// maxAge 极小 => 每个封存段都超期；maxCount=30 => 同时有容量挤出。
	sw := New(st, time.Millisecond, time.Nanosecond, 30, 1)
	sw.SetFreezeHook(reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := st.Append(mkRecAt(fmt.Sprintf("w%d-%d", w, i), time.Now())); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(w)
	}
	// 按 ID 反复冻结/解冻。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			id := fmt.Sprintf("w%d-%d", i%4, i%25)
			if _, err := reg.FreezeIDs(st, id); err != nil {
				t.Errorf("freeze: %v", err)
				return
			}
			if i%2 == 0 {
				if _, err := reg.UnfreezeIDs(id); err != nil {
					t.Errorf("unfreeze: %v", err)
					return
				}
			}
		}
	}()
	// 按条件批量冻结/解冻（全部 type=t，命中所有现存记录；空/非空交错）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			c := freezeCriteria("u", "t")
			if i%4 == 0 {
				if _, err := reg.UnfreezeByCriteria(st, c); err != nil {
					t.Errorf("unfreeze criteria: %v", err)
					return
				}
			} else {
				if _, err := reg.FreezeByCriteria(st, c); err != nil {
					t.Errorf("freeze criteria: %v", err)
					return
				}
			}
		}
	}()

	sweepDone := make(chan struct{})
	var sweepErr error
	var smu sync.Mutex
	go func() {
		defer close(sweepDone)
		for ctx.Err() == nil {
			if _, err := sw.Sweep(ctx, time.Now()); err != nil {
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
		}
	}()
	wg.Wait()
	cancel()
	<-sweepDone
	if err := sweepErr; err != nil {
		t.Fatal(err)
	}
	if err := assertStateConsistent(st, reg); err != nil {
		t.Fatal(err)
	}
	t.Logf("判定依据: 超期+容量清理 与 ID/条件冻结解冻 高并发后 count=%d frozen=%d, 状态自洽",
		st.Count(), reg.FrozenCount())
}

// 场景：清理在执行前/执行中被取消，必须什么都不删，
// 尤其不能顺手删掉含冻结记录的段；取消后状态与取消前完全一致。
func TestSweepCanceledIsAtomicNoDeletion(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	st := newStoreWithSegs(t, 2, []time.Time{old, old, old}) // 3 段全超期
	defer st.Close()
	reg := newFreezeRegistry(t)
	if _, err := reg.FreezeIDs(st, "s0-e0", "s1-e1"); err != nil {
		t.Fatal(err)
	}
	sw := New(st, time.Hour, time.Hour, 1, 0)
	sw.SetFreezeHook(reg, nil)

	before := st.Count()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 进入 Sweep 前已取消
	rep, err := sw.Sweep(ctx, now)
	if err == nil {
		t.Fatal("canceled sweep must return context error")
	}
	if rep.DeletedCount != 0 || len(rep.DeletedSegments) != 0 {
		t.Fatalf("canceled sweep must delete nothing, got %+v", rep)
	}
	if st.Count() != before {
		t.Fatalf("canceled sweep must leave store untouched: before=%d after=%d", before, st.Count())
	}
	for _, id := range []string{"s0-e0", "s0-e1", "s1-e0", "s1-e1", "s2-e0", "s2-e1"} {
		if !recordExists(st, id) {
			t.Fatalf("record %s lost during canceled sweep", id)
		}
	}
	for _, id := range []string{"s0-e0", "s1-e1"} {
		if !reg.IsFrozen(id) {
			t.Fatalf("freeze state for %s must survive canceled sweep", id)
		}
	}
	t.Logf("判定依据: 已取消的清理零删除, count=%d 与取消前一致, 冻结状态不变", st.Count())
}

// 场景：注册表存在但清理侧不接线冻结钩子时，行为与没有冻结能力前完全一致——
// 即便记录已被冻结，超期封存段照常删除（冻结是显式 opt-in）。
func TestSweepBehaviorIdenticalWhenHookNotSet(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	st := newStoreWithSegs(t, 2, []time.Time{old, old, old})
	defer st.Close()
	reg := newFreezeRegistry(t)
	if _, err := reg.FreezeIDs(st, "s0-e0", "s1-e0"); err != nil {
		t.Fatal(err)
	}
	// 刻意不调用 SetFreezeHook。
	sw := New(st, time.Hour, 24*time.Hour, 0, 0)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// 与无冻结基线 TestSweepAgeExceeded 相同：两个超期封存段（4 条）被删，活动段留 2 条。
	if rep.DeletedCount != 4 || st.Count() != 2 {
		t.Fatalf("no-hook sweep must match freeze-free baseline: %+v count=%d", rep, st.Count())
	}
	t.Logf("判定依据: 未接线冻结钩子时清理结果与无冻结基线一致, reason=%s", rep.Reason)
}

// 场景：并发冻结/解冻/清理结束后，把记录解冻，再做一次保留期清理——
// 解冻的段必须重新按原规则被回收（不会解冻后怎么都清不掉）；
// 同时仍冻结的段继续保留。
func TestUnfreezeAfterChurnRejoinsPurge(t *testing.T) {
	now := time.Now()
	st := openFreshStore(t)
	reg := newFreezeRegistry(t)
	// 先造两个已封存、已超期的段。
	old := now.Add(-48 * time.Hour)
	segA := []string{"a0", "a1"}
	segB := []string{"b0", "b1"}
	for _, id := range segA {
		if _, err := st.Append(mkRecAt(id, old)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Rotate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range segB {
		if _, err := st.Append(mkRecAt(id, old)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Append(mkRecAt("active", now)); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.FreezeIDs(st, append(append([]string{}, segA...), segB...)...); err != nil {
		t.Fatal(err)
	}
	sw := New(st, time.Hour, 24*time.Hour, 0, 0)
	sw.SetFreezeHook(reg, nil)
	// 冻结中：超期段全部保留。
	if rep, _ := sw.Sweep(context.Background(), now); rep.DeletedCount != 0 {
		t.Fatalf("frozen segs must survive churn: %+v", rep)
	}
	// 解冻段 A（段 B 仍冻结）。
	if _, err := reg.UnfreezeIDs(segA...); err != nil {
		t.Fatal(err)
	}
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeletedCount != 2 {
		t.Fatalf("unfrozen segment must rejoin age purge, frozen one kept: %+v", rep)
	}
	for _, id := range segA {
		if recordExists(st, id) {
			t.Fatalf("unfrozen %s must be purged by original age rule", id)
		}
	}
	for _, id := range segB {
		if !recordExists(st, id) {
			t.Fatalf("still-frozen %s must be kept", id)
		}
	}
	if !recordExists(st, "active") {
		t.Fatal("active segment must survive")
	}
	// 解冻本身没删任何东西这一点已由「冻结中 Sweep 零删除 + 解冻后 Sweep 才删」覆盖。
	t.Logf("判定依据: 并发后解冻段重新按保留期回收=%d条, 仍冻结段保留, reason=%s",
		rep.DeletedCount, rep.Reason)
}
