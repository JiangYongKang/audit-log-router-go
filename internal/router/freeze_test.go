package router

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/policy"
	"github.com/highcumontoa/audit-log-router-go/internal/retention"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

// holdFixture 是挂配合规冻结能力的测试环境。
type holdFixture struct {
	dir    string
	engine *policy.Engine
	st     *store.Store
	hold   *freeze.Registry
	router *Router
}

func newHoldFixture(t *testing.T, cap int64) *holdFixture {
	t.Helper()
	dir := t.TempDir()
	eng, err := policy.NewEngine(testPolicy("v1"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := freeze.Open(dir, st)
	if err != nil {
		t.Fatal(err)
	}
	r := New(eng, st, Config{QueueSize: 16, MaxRetries: 1, RetryBackoff: time.Millisecond})
	r.WithFreeze(hold, cap)
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &holdFixture{dir: dir, engine: eng, st: st, hold: hold, router: r}
}

func (f *holdFixture) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f.router.Stop(ctx)
	f.hold.Close()
	f.st.Close()
}

func (f *holdFixture) ingestN(t *testing.T, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := event.Event{
			ID: fmt.Sprintf("%s-%d", prefix, i), Type: "login", Actor: "alice",
			Source:    "loadtest",
			Timestamp: time.Now(),
			Fields:    map[string]string{"action": "login"},
		}
		if err := f.router.Ingest(context.Background(), ev); err != nil {
			t.Fatalf("ingest %s: %v", ev.ID, err)
		}
	}
}

// 场景：容量被冻结占满 -> 新写入收到可区分的 capacity_locked 拒绝，
// 不会悄悄丢失；解冻后写入恢复。
func TestIngestRejectedWhenCapacityFrozen(t *testing.T) {
	const cap = 3
	f := newHoldFixture(t, cap)
	defer f.close()
	f.ingestN(t, cap, "e") // 3 条占满容量上限

	// 未冻结时：容量满仍允许写入（普通超限由 sweeper 回收，不阻塞采集）。
	extra := event.Event{ID: "e-extra", Type: "login", Actor: "a", Timestamp: time.Now(),
		Fields: map[string]string{"action": "login"}}
	if err := f.router.Ingest(context.Background(), extra); err != nil {
		t.Fatalf("without freeze, over-cap write must be accepted: %v", err)
	}

	// 冻结 cap 条记录 -> 冻结数达到硬上限。
	rep, err := f.router.FreezeBySelector(freeze.Selector{
		IDs: []string{"e-0", "e-1", "e-2"},
	})
	if err != nil || rep.Changed != 3 {
		t.Fatalf("freeze: %+v err=%v", rep, err)
	}

	blocked := event.Event{ID: "e-blocked", Type: "login", Actor: "a", Timestamp: time.Now(),
		Fields: map[string]string{"action": "login"}}
	err = f.router.Ingest(context.Background(), blocked)
	var re *event.RejectError
	if !errors.As(err, &re) || re.Reason != event.RejectCapacityLocked {
		t.Fatalf("want capacity_locked rejection, got %v", err)
	}
	// 被拒记录确实没有落盘（不是悄悄丢，是明确拒收）。
	if _, ok, _ := f.st.LookupSeq("e-blocked"); ok {
		t.Fatal("capacity_locked record must not be persisted")
	}
	st := f.router.Stats()
	if st.CapacityLocked < 1 {
		t.Fatalf("CapacityLocked stat=%d want >=1", st.CapacityLocked)
	}
	t.Logf("场景[容量被冻结占满] 拒绝原因=%s detail=%q; stats.capacity_locked=%d", re.Reason, re.Detail, st.CapacityLocked)

	// 解冻一条 -> 冻结数低于上限，写入恢复。
	if _, err := f.router.UnfreezeByIDs([]string{"e-0"}); err != nil {
		t.Fatal(err)
	}
	recover := event.Event{ID: "e-recover", Type: "login", Actor: "a", Timestamp: time.Now(),
		Fields: map[string]string{"action": "login"}}
	if err := f.router.Ingest(context.Background(), recover); err != nil {
		t.Fatalf("after unfreeze write must recover, got %v", err)
	}
	t.Log("场景[解冻后写入恢复] e-recover 已接收")
}

// 场景：冻结/解冻与高频写入、周期性清理并发进行，计数与状态必须自洽：
//   - 全程处于冻结态的记录在任何时刻都不会被清理删除（即使容量紧张）；
//   - 注册表中每一个冻结条目都必须对应仍留存的记录（计数自洽）；
//   - 已解冻且被清走的记录再次冻结时得到 not_found，而不是幽灵条目；
//   - 无重复 ID 落盘。
func TestConcurrentFreezeSweepIngest(t *testing.T) {
	const cap = 40
	f := newHoldFixture(t, cap)
	defer f.close()

	// 预置 30 条记录并封存多个段。
	f.ingestN(t, 30, "base")
	for i := 0; i < 30; i++ {
		if i%5 == 4 {
			f.st.Rotate()
		}
	}

	// pinned：全程冻结、永不应被清理的一批（分散在多个段中）。
	pinned := []string{"base-0", "base-5", "base-10", "base-15", "base-20", "base-25"}
	if rep, err := f.hold.FreezeByIDs(pinned, time.Now()); err != nil || rep.Changed != len(pinned) {
		t.Fatalf("pin freeze: %+v err=%v", rep, err)
	}
	// churn：另一批被并发地反复冻结/解冻。
	churn := []string{"base-2", "base-8", "base-12", "base-22"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sw := retention.New(f.st, 5*time.Millisecond, 0, 25, 1).WithFreeze(f.hold)
	sw.Start(ctx)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// writer：持续写入（容量上限不会被冻结占满，故不应出现写入拒绝）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			ev := event.Event{ID: fmt.Sprintf("w-%d", i), Type: "login", Actor: "a",
				Source: "race", Timestamp: time.Now(), Fields: map[string]string{"action": "login"}}
			if err := f.router.Ingest(ctx, ev); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				t.Errorf("unexpected ingest error: %v", err)
				return
			}
			i++
		}
	}()

	// freezer：反复冻结/解冻 churn 集合。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 60; j++ {
			select {
			case <-stop:
				return
			default:
			}
			if j%2 == 0 {
				f.hold.FreezeByIDs(churn, time.Now())
			} else {
				f.hold.UnfreezeBySelector(freeze.Selector{IDs: churn}, time.Now())
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// verifier：并发期间不断核查不变量——冻结条目必须对应存活记录。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, e := range f.hold.Entries() {
				if !f.st.HasSeq(e.Seq) {
					t.Errorf("invariant broken: frozen id=%q seq=%d no longer in store", e.EventID, e.Seq)
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	time.Sleep(400 * time.Millisecond)
	close(stop)
	cancel()
	sw.Stop()
	wg.Wait()

	// 再做一次 Sweep：全程冻结的 pinned 必须全部存活。
	purge, err := sw.Sweep(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recs, err := f.st.ScanSeqs(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	seenID := map[string]bool{}
	frozenAlive := map[string]bool{}
	for _, r := range recs {
		if seenID[r.ID] {
			t.Fatalf("duplicate record after concurrent ops: %s", r.ID)
		}
		seenID[r.ID] = true
		if f.hold.IsFrozen(r.ID) {
			frozenAlive[r.ID] = true
		}
	}
	for _, id := range pinned {
		if !seenID[id] {
			t.Fatalf("pinned(frozen throughout) %s was purged during concurrent sweep", id)
		}
	}
	// 计数自洽：注册表冻结数 == 留存中实际冻结数。
	if f.hold.FrozenCount() != len(frozenAlive) {
		t.Fatalf("freeze count inconsistent: registry=%d alive=%d", f.hold.FrozenCount(), len(frozenAlive))
	}
	// churn 中若有记录在解冻窗口被清走，重新冻结必须得到 not_found，
	// 注册表不得出现幽灵冻结条目。
	rep, _ := f.hold.FreezeByIDs(churn, time.Now())
	var notFound int
	for _, it := range rep.Items {
		if it.Status == freeze.StatusNotFound {
			notFound++
		}
	}
	for _, e := range f.hold.Entries() {
		if !f.st.HasSeq(e.Seq) {
			t.Fatalf("ghost freeze entry after re-freeze: %+v", e)
		}
	}
	// 稳态：总数不超过 cap（冻结是地板，普通记录被持续挤出）。
	if int64(f.st.Count()) > cap {
		t.Fatalf("post-sweep count=%d exceeds cap=%d (unbounded growth?)", f.st.Count(), cap)
	}
	t.Logf("场景[冻结/清理/写入并发] pinned存活=%d 注册表冻结=%d=留存冻结  churn重冻not_found=%d 总留存=%d/%d 最后清理=%s",
		len(pinned), f.hold.FrozenCount(), notFound, f.st.Count(), cap, purge.Reason)
}

// 场景：通过 Router API 做条件冻结/解冻，状态可核查（Entries）。
func TestRouterFreezeAPIAndInspect(t *testing.T) {
	f := newHoldFixture(t, 100)
	defer f.close()
	now := time.Now()
	for i := 0; i < 6; i++ {
		ev := event.Event{ID: fmt.Sprintf("v-%d", i), Type: "login", Actor: "bob",
			Source: "gw", Timestamp: now.Add(time.Duration(i) * time.Minute),
			Fields: map[string]string{"action": "login"}}
		if err := f.router.Ingest(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := f.router.FreezeBySelector(freeze.Selector{Source: "gw", From: now, To: now.Add(2 * time.Minute)})
	if err != nil || rep.Changed != 3 {
		t.Fatalf("freeze selector: %+v err=%v", rep, err)
	}
	entries := f.hold.Entries()
	if len(entries) != 3 {
		t.Fatalf("entries=%d want 3: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if !e.Frozen || e.EventID == "" {
			t.Fatalf("entry not inspectable: %+v", e)
		}
	}
	// 全量解冻后注册表归零。
	ur, err := f.router.UnfreezeBySelector(freeze.Selector{Source: "gw"})
	if err != nil || ur.Changed != 3 {
		t.Fatalf("unfreeze selector: %+v err=%v", ur, err)
	}
	if f.hold.FrozenCount() != 0 {
		t.Fatalf("frozen count=%d want 0", f.hold.FrozenCount())
	}
	t.Logf("场景[Router条件冻结/核查/解冻] 冻结时条目=%v", entryIDs(entries))
}

func entryIDs(es []freeze.Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.EventID)
	}
	return out
}
