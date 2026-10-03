package freeze

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// memStore 是测试用的只读存储实现。
type memStore struct {
	views []RecordView
}

func (m *memStore) LookupSeq(id string) (int64, bool, error) {
	for _, v := range m.views {
		if v.ID == id {
			return v.Seq, true, nil
		}
	}
	return 0, false, nil
}

func (m *memStore) ScanViews() ([]RecordView, error) {
	out := make([]RecordView, len(m.views))
	copy(out, m.views)
	return out, nil
}

func (m *memStore) HasSeq(seq int64) bool {
	for _, v := range m.views {
		if v.Seq == seq {
			return true
		}
	}
	return false
}

func t0() time.Time { return time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC) }

func fixture() *memStore {
	base := t0()
	return &memStore{views: []RecordView{
		{Seq: 1, ID: "e1", Type: "login", Source: "web", Actor: "alice", Timestamp: base},
		{Seq: 2, ID: "e2", Type: "login", Source: "web", Actor: "bob", Timestamp: base.Add(time.Hour)},
		{Seq: 3, ID: "e3", Type: "logout", Source: "api", Actor: "alice", Timestamp: base.Add(2 * time.Hour)},
		{Seq: 4, ID: "e4", Type: "login", Source: "api", Actor: "carol", Timestamp: base.Add(3 * time.Hour)},
	}}
}

func TestFreezeByIDsIdempotent(t *testing.T) {
	ms := fixture()
	g, err := Open(t.TempDir(), ms)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	rep, err := g.FreezeByIDs([]string{"e1", "e3"}, t0())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Changed != 2 || rep.Skipped != 0 {
		t.Fatalf("first freeze: changed=%d skipped=%d", rep.Changed, rep.Skipped)
	}
	if g.FrozenCount() != 2 {
		t.Fatalf("frozen count=%d want 2", g.FrozenCount())
	}

	// 重复冻结：幂等，不重复计数、不重复落盘。
	rep2, _ := g.FreezeByIDs([]string{"e1", "e1", "eX"}, t0())
	if rep2.Changed != 0 || rep2.Skipped != 2 {
		t.Fatalf("repeat freeze: changed=%d skipped=%d want 0/2", rep2.Changed, rep2.Skipped)
	}
	var notFound, already int
	for _, it := range rep2.Items {
		switch it.Status {
		case StatusNotFound:
			notFound++
		case StatusAlready:
			already++
		}
	}
	if notFound != 1 || already != 1 {
		t.Fatalf("items status wrong: %+v", rep2.Items)
	}
	if g.FrozenCount() != 2 {
		t.Fatalf("count must not change on repeat freeze: %d", g.FrozenCount())
	}
	t.Logf("场景[按ID冻结+重复幂等+未知ID]: %+v", rep2.Items)

	// 解冻一条后可重新冻结；批次内重复 ID 去重，反复解冻不产生重复计数。
	ur, _ := g.UnfreezeByIDs([]string{"e1", "e1"}, t0())
	if ur.Changed != 1 || ur.Skipped != 0 || len(ur.Items) != 1 {
		t.Fatalf("unfreeze changed=%d skipped=%d items=%d want 1/0/1", ur.Changed, ur.Skipped, len(ur.Items))
	}
	if g.FrozenCount() != 1 || g.IsFrozen("e1") || !g.IsFrozen("e3") {
		t.Fatalf("state after unfreeze wrong: count=%d e1=%v e3=%v", g.FrozenCount(), g.IsFrozen("e1"), g.IsFrozen("e3"))
	}
	ur2, _ := g.UnfreezeByIDs([]string{"e1"}, t0())
	if ur2.Changed != 0 {
		t.Fatalf("repeated unfreeze must be idempotent, changed=%d", ur2.Changed)
	}
}

func TestFreezeBySelectorBoundaries(t *testing.T) {
	ms := fixture()
	g, _ := Open(t.TempDir(), ms)
	defer g.Close()
	base := t0()

	// 时间范围边界：[base, base+1h] 闭区间，应恰好命中 e1、e2。
	rep, err := g.FreezeBySelector(Selector{
		From: base, To: base.Add(time.Hour),
	}, base.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Changed != 2 {
		t.Fatalf("time range boundary: changed=%d want 2, items=%+v", rep.Changed, rep.Items)
	}
	g.UnfreezeBySelector(Selector{}, base) // 全量解冻

	// 来源 + 类型 AND：source=web AND type=login -> e1,e2；
	// source=api AND type=login -> 仅 e4。
	rep, _ = g.FreezeBySelector(Selector{Source: "api", Type: "login"}, base)
	if rep.Changed != 1 || rep.Items[0].ID != "e4" {
		t.Fatalf("source+type AND wrong: %+v", rep.Items)
	}
	g.UnfreezeBySelector(Selector{}, base)

	// Actor 条件 + ID 白名单同时生效。
	rep, _ = g.FreezeBySelector(Selector{Actor: "alice", IDs: []string{"e3"}}, base)
	if rep.Changed != 1 || rep.Items[0].ID != "e3" {
		t.Fatalf("actor+ids wrong: %+v", rep.Items)
	}

	// 空条件 = 全量；已是冻结态的记 already，不重复计数。
	rep, _ = g.FreezeBySelector(Selector{}, base)
	if rep.Changed != 3 || rep.Skipped != 1 {
		t.Fatalf("select-all: changed=%d skipped=%d want 3/1", rep.Changed, rep.Skipped)
	}
	if g.FrozenCount() != 4 {
		t.Fatalf("all frozen count=%d want 4", g.FrozenCount())
	}
	t.Logf("场景[条件冻结边界: 时间闭区间/来源类型AND/Actor+ID白名单/全量幂等] 全部通过, frozen=%d", g.FrozenCount())
}

func TestUnfreezeBySelectorThenReCleanable(t *testing.T) {
	ms := fixture()
	g, _ := Open(t.TempDir(), ms)
	defer g.Close()
	base := t0()

	// 冻结 web 来源，再只按时间范围解冻其中 e1（base 时刻）。
	g.FreezeBySelector(Selector{Source: "web"}, base)
	rep, err := g.UnfreezeBySelector(Selector{To: base}, base)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Changed != 1 || rep.Items[0].ID != "e1" {
		t.Fatalf("unfreeze by time boundary wrong: %+v", rep.Items)
	}
	if !g.IsFrozen("e2") || g.IsFrozen("e1") {
		t.Fatalf("selective unfreeze state wrong: e1=%v e2=%v", g.IsFrozen("e1"), g.IsFrozen("e2"))
	}
	t.Logf("场景[条件解冻边界: 上界闭区间只解冻 e1]: %+v", rep.Items)
}

func TestReplayAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	ms := fixture()
	g, _ := Open(dir, ms)
	g.FreezeByIDs([]string{"e1", "e2"}, t0())
	g.UnfreezeByIDs([]string{"e1"}, t0())
	g.FreezeBySelector(Selector{Type: "logout"}, t0())
	if g.FrozenCount() != 2 { // e2 + e3
		t.Fatalf("pre-restart count=%d want 2", g.FrozenCount())
	}
	g.Close()

	// 重新打开：同一 seq 以最后状态为准，结论与重启前一致。
	g2, err := Open(dir, ms)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	if g2.FrozenCount() != 2 {
		t.Fatalf("post-restart count=%d want 2", g2.FrozenCount())
	}
	if g2.IsFrozen("e1") || !g2.IsFrozen("e2") || !g2.IsFrozen("e3") {
		t.Fatalf("post-restart states wrong: e1=%v e2=%v e3=%v", g2.IsFrozen("e1"), g2.IsFrozen("e2"), g2.IsFrozen("e3"))
	}
	if !g2.IsFrozenSeq(2) || g2.IsFrozenSeq(1) {
		t.Fatalf("frozen seqs wrong: %+v", g2.FrozenSeqs())
	}
	entries := g2.Entries()
	if len(entries) != 2 || entries[0].EventID != "e2" || entries[1].EventID != "e3" {
		t.Fatalf("entries not sorted/right: %+v", entries)
	}
	t.Logf("场景[重启恢复]: 冻结条目按序=%v, 与重启前结论一致", []string{entries[0].EventID, entries[1].EventID})
}

func TestReplayTruncatesPartialLine(t *testing.T) {
	dir := t.TempDir()
	ms := fixture()
	g, _ := Open(dir, ms)
	g.FreezeByIDs([]string{"e1"}, t0())
	g.Close()

	p := filepath.Join(dir, logName)
	// 模拟崩溃：追加半写 JSON 行。
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"seq":2,"event_id":"e2","fro`)
	f.Close()

	g2, err := Open(dir, ms)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	if g2.FrozenCount() != 1 || !g2.IsFrozen("e1") {
		t.Fatalf("partial freeze line must be truncated: count=%d", g2.FrozenCount())
	}
	// 截断后仍可正常追加冻结状态。
	rep, _ := g2.FreezeByIDs([]string{"e2"}, t0())
	if rep.Changed != 1 {
		t.Fatalf("freeze after recovery: %+v", rep)
	}
	t.Log("场景[冻结日志半写行截断]: e1 保留、e2 可正常追加冻结")
}
