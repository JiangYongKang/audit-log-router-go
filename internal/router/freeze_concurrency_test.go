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
	"github.com/highcumontoa/audit-log-router-go/internal/retention"
)

// 端到端并发：持续写入（带容量门控）+ 后台清理（小段轮转+容量挤出）
// + 冻结/解冻同时进行。要求：
//   - 不死锁、无竞态；
//   - 被拒写入只能是 capacity_frozen（可区分），不出现静默丢失；
//   - 运行结束后冻结集合是现存记录子集，计数自洽；
//   - 解冻并清理后，可重新写入。
func TestConcurrentIngestFreezeSweep(t *testing.T) {
	reg, err := freeze.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	f := newFixture(t, Config{
		QueueSize: 64, MaxRetries: 1, RetryBackoff: time.Millisecond,
		MaxCount: 40, IsFrozen: reg.IsFrozen,
	})
	defer f.close(t)
	ctx := context.Background()

	sw := retention.New(f.st, time.Millisecond, 0, 40, 1)
	sw.SetFreezeHook(reg, nil)
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	sw.Start(sctx)
	defer sw.Stop()

	const writers, per = 4, 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	var accepted, capRejected, otherRejected int64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				id := fmt.Sprintf("c-w%d-%d", w, i)
				err := f.router.Ingest(ctx, mkEventWithPassword(id))
				switch {
				case err == nil:
					mu.Lock()
					accepted++
					mu.Unlock()
				default:
					var re *event.RejectError
					if errors.As(err, &re) && re.Reason == event.RejectCapacityFrozen {
						mu.Lock()
						capRejected++
						mu.Unlock()
					} else {
						mu.Lock()
						otherRejected++
						t.Errorf("unexpected ingest error for %s: %v", id, err)
						mu.Unlock()
						return
					}
				}
			}
		}(w)
	}
	// 冻结/解冻已写入的记录（ID 可能尚未落盘，Skipped 合法）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 80; i++ {
			id := fmt.Sprintf("c-w%d-%d", i%writers, i%per)
			_, _ = reg.FreezeIDs(f.st, id)
			if i%2 == 0 {
				_, _ = reg.UnfreezeIDs(id)
			}
		}
	}()
	wg.Wait()
	scancel()
	sw.Stop()

	mu.Lock()
	t.Logf("判定依据: 并发结束 accepted=%d capacity_frozen拒绝=%d 其他拒绝=%d storeCount=%d frozen=%d",
		accepted, capRejected, otherRejected, f.st.Count(), reg.FrozenCount())
	mu.Unlock()

	// 冻结集合必须是现存记录子集。
	recs, err := f.st.ScanSeqs(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	existing := map[string]bool{}
	for _, r := range recs {
		existing[r.ID] = true
	}
	for _, id := range reg.FrozenIDs() {
		if !existing[id] {
			t.Fatalf("frozen record %s missing from store after churn", id)
		}
	}

	// 全部解冻后按容量规则回收，随后必须能重新写入（不能解冻后怎么都清不掉/写不进）。
	frozen := reg.FrozenIDs()
	if len(frozen) > 0 {
		if _, err := reg.UnfreezeIDs(frozen...); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := sw.Sweep(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.router.Ingest(ctx, mkEventWithPassword("c-final")); err != nil {
		t.Fatalf("ingest must recover after unfreeze+reclaim: %v (sweep=%+v)", err, rep)
	}
	t.Logf("判定依据: 解冻回收后写入恢复, sweepDeleted=%d", rep.DeletedCount)
}
