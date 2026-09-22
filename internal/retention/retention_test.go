package retention

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

func mkRecAt(id string, ts time.Time) event.Record {
	return event.Record{Event: event.Event{
		ID: id, Type: "t", Actor: "u", Timestamp: ts,
		Fields: map[string]string{"action": "x"},
	}, PolicyVersion: "v1"}
}

func newStoreWithSegs(t *testing.T, perSeg int, times []time.Time) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for si, ts := range times {
		for i := 0; i < perSeg; i++ {
			st.Append(mkRecAt(fmt.Sprintf("s%d-e%d", si, i), ts))
		}
		if si < len(times)-1 {
			st.Rotate()
		}
	}
	return st
}

func TestSweepAgeExceeded(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-1 * time.Hour)
	st := newStoreWithSegs(t, 3, []time.Time{old, old, recent})
	defer st.Close()

	sw := New(st, time.Hour, 24*time.Hour, 0, 0)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeletedCount != 6 || len(rep.DeletedSegments) != 2 {
		t.Fatalf("want 6 records / 2 segs deleted, got %+v", rep)
	}
	if st.Count() != 3 {
		t.Fatalf("remaining count=%d want 3", st.Count())
	}
	t.Logf("清理依据(最旧优先): %s", rep.Reason)
}

func TestSweepCountExceededOldestFirst(t *testing.T) {
	now := time.Now()
	st := newStoreWithSegs(t, 2, []time.Time{now, now, now, now})
	defer st.Close()

	sw := New(st, time.Hour, 0, 3, 0) // 只保留 3 条
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// 4 个封存段前 2 个 + 第 3 个共 6 条会先被标记？cap=3：逐段挤出，
	// 8 - 2(seg0) - 2(seg1) - 2(seg2)=2 <=3 => 删 3 段共 6 条。
	if rep.DeletedCount != 6 || len(rep.DeletedSegments) != 3 {
		t.Fatalf("want 6/3, got %+v", rep)
	}
	recs, _ := st.ScanSeqs(context.Background(), 0, 0)
	if len(recs) != 2 || recs[0].ID != "s3-e0" {
		t.Fatalf("newest segment must survive, got %v", recs)
	}
	t.Logf("容量挤出依据: %s", rep.Reason)
}

func TestSweepActiveNeverDeleted(t *testing.T) {
	now := time.Now()
	st := newStoreWithSegs(t, 1, []time.Time{now.Add(-100 * time.Hour), now})
	defer st.Close()
	sw := New(st, time.Hour, time.Hour, 1, 0)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeletedCount != 1 {
		t.Fatalf("only one sealed seg deletable, got %d", rep.DeletedCount)
	}
	if st.Count() != 1 {
		t.Fatalf("active segment must survive, count=%d", st.Count())
	}
}

func TestConcurrentSweepAppend(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	defer st.Close()
	sw := New(st, time.Millisecond*5, 0, 100, 0) // 段很小，靠容量频繁轮转
	// segBytes=0 不轮转；直接手动轮转由测试通过小 segBytes 触发。
	sw2 := New(st, time.Millisecond*5, 0, 100, 1)
	ctx, cancel := context.WithCancel(context.Background())
	sw2.Start(ctx)
	defer cancel()

	const writers, per = 6, 80
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				st.Append(mkRecAt(fmt.Sprintf("w%d-%d", w, i), time.Now()))
			}
		}(w)
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	cancel()
	sw2.Stop()
	_ = sw

	// 清理后扫描必须仍得到一致的记录集（无半写/无重复）。
	recs, err := st.ScanSeqs(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range recs {
		if ids[r.ID] {
			t.Fatalf("duplicate after concurrent sweep: %s", r.ID)
		}
		ids[r.ID] = true
	}
	if st.Count() > 100 {
		t.Fatalf("retention cap exceeded: count=%d", st.Count())
	}
	t.Logf("判定依据: 轮转/清理与并发写入后 count=%d <= 上限100, 无重复", st.Count())
}
