package router

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/retention"
)

func mkEventWithPassword(id string) event.Event {
	return mkEvent(id, map[string]string{"action": "login", "password": "pw"})
}

// 容量被冻结占满时：写入被明确拒绝（capacity_frozen，可区分、可解释），
// 而不是悄悄丢弃；解冻并按原规则清理后，写入恢复。
func TestIngestRejectedWhenCapacityFrozen(t *testing.T) {
	reg, err := freeze.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	f := newFixture(t, Config{MaxCount: 2, IsFrozen: reg.IsFrozen})
	defer f.close(t)
	ctx := context.Background()

	// 1) 填满到上限（2 条，均在活动段）。
	for _, id := range []string{"e1", "e2"} {
		if err := f.router.Ingest(ctx, mkEventWithPassword(id)); err != nil {
			t.Fatalf("ingest %s: %v", id, err)
		}
	}

	// 2) 活动段不可回收：第 3 条必须被明确拒绝，原因可区分。
	assertCapacityRejected(t, f, ctx, "e3")
	if f.st.Count() != 2 {
		t.Fatalf("rejected event must not be stored: count=%d", f.st.Count())
	}

	// 3) 轮转出可清理的封存段后：写入恢复（清理会回收）。
	if err := f.st.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := f.router.Ingest(ctx, mkEventWithPassword("e3")); err != nil {
		t.Fatalf("ingest e3 with reclaimable segment: %v", err)
	}

	// 4) 冻结封存段全部记录：容量被冻结占满，写入再次被明确拒绝。
	if _, err := reg.FreezeIDs(f.st, "e1", "e2"); err != nil {
		t.Fatal(err)
	}
	assertCapacityRejected(t, f, ctx, "e4")
	if !strings.Contains(f.logBuf.String(), "capacity_frozen") {
		t.Fatalf("rejection reason must appear in decision log:\n%s", f.logBuf.String())
	}

	// 5) 解冻后按原规则清理，写入恢复；冻结记录在被清理前一直存活。
	if _, err := reg.UnfreezeIDs("e1", "e2"); err != nil {
		t.Fatal(err)
	}
	sw := retention.New(f.st, time.Hour, 0, 2, 0)
	sw.SetFreezeHook(reg.IsFrozen, nil)
	rep, err := sw.Sweep(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeletedCount != 2 {
		t.Fatalf("unfrozen segment must be reclaimed by original rules: %+v", rep)
	}
	if err := f.router.Ingest(ctx, mkEventWithPassword("e4")); err != nil {
		t.Fatalf("ingest e4 after reclaim: %v", err)
	}
	t.Logf("判定依据: 冻结占满容量时拒绝写入(capacity_frozen), 解冻清理后恢复; sweep reason=%s", rep.Reason)
}

func assertCapacityRejected(t *testing.T, f *fixture, ctx context.Context, id string) {
	t.Helper()
	err := f.router.Ingest(ctx, mkEventWithPassword(id))
	var re *event.RejectError
	if !errors.As(err, &re) {
		t.Fatalf("ingest %s: want RejectError, got %v", id, err)
	}
	if re.Reason != event.RejectCapacityFrozen {
		t.Fatalf("ingest %s: want reason %s, got %s", id, event.RejectCapacityFrozen, re.Reason)
	}
	t.Logf("判定依据: id=%s 被拒绝 reason=%s detail=%q", id, re.Reason, re.Detail)
}

// 未配置容量门控（MaxCount=0）时行为与引入冻结能力前一致：不因冻结拒绝写入。
func TestIngestUnaffectedWithoutCapacityGate(t *testing.T) {
	reg, err := freeze.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	f := newFixture(t, Config{IsFrozen: reg.IsFrozen}) // MaxCount=0：门控关闭
	defer f.close(t)
	ctx := context.Background()

	for _, id := range []string{"a1", "a2", "a3"} {
		if err := f.router.Ingest(ctx, mkEventWithPassword(id)); err != nil {
			t.Fatalf("ingest %s: %v", id, err)
		}
	}
	if _, err := reg.FreezeIDs(f.st, "a1", "a2", "a3"); err != nil {
		t.Fatal(err)
	}
	// 全部冻结、无门控：写入照常接受（清理侧由 sweeper 负责跳过冻结段）。
	if err := f.router.Ingest(ctx, mkEventWithPassword("a4")); err != nil {
		t.Fatalf("ingest without capacity gate must not be rejected: %v", err)
	}
	t.Log("判定依据: MaxCount=0 时门控关闭, 冻结不影响写入路径, 与既有行为一致")
}
