package freeze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

func mkRecAt(id, actor, typ string, ts time.Time) event.Record {
	return event.Record{Event: event.Event{
		ID: id, Type: typ, Actor: actor, Timestamp: ts,
		Fields: map[string]string{"action": "x"},
	}, PolicyVersion: "v1"}
}

func openStoreWith(t *testing.T, recs []event.Record) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if _, err := st.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestFreezeUnfreezeByID(t *testing.T) {
	st := openStoreWith(t, []event.Record{
		mkRecAt("a", "alice", "login", time.Now()),
		mkRecAt("b", "bob", "login", time.Now()),
	})
	reg, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// 冻结存在的 + 不存在的 ID：不存在的进 Skipped。
	rep, err := reg.FreezeIDs(st, "a", "ghost")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changed) != 1 || rep.Changed[0] != "a" || len(rep.Skipped) != 1 || rep.Skipped[0] != "ghost" {
		t.Fatalf("freeze report wrong: %+v", rep)
	}
	if !reg.IsFrozen("a") || reg.IsFrozen("b") || reg.FrozenCount() != 1 {
		t.Fatalf("frozen state wrong: count=%d", reg.FrozenCount())
	}

	// 幂等：重复冻结是 no-op，不改变计数、不产生 Changed。
	rep, _ = reg.FreezeIDs(st, "a")
	if len(rep.Changed) != 0 || reg.FrozenCount() != 1 {
		t.Fatalf("re-freeze must be no-op: %+v count=%d", rep, reg.FrozenCount())
	}

	// 解冻；重复解冻也是 no-op 且计入 Skipped，不会重复计数。
	rep, _ = reg.UnfreezeIDs("a")
	if len(rep.Changed) != 1 || reg.FrozenCount() != 0 {
		t.Fatalf("unfreeze wrong: %+v count=%d", rep, reg.FrozenCount())
	}
	rep, _ = reg.UnfreezeIDs("a")
	if len(rep.Changed) != 0 || len(rep.Skipped) != 1 || reg.FrozenCount() != 0 {
		t.Fatalf("re-unfreeze must be no-op: %+v count=%d", rep, reg.FrozenCount())
	}
	t.Log("判定依据: 冻结/解冻幂等, 重复操作不改变计数, 未知ID计入Skipped")
}

func TestFreezeByCriteriaBoundaries(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	st := openStoreWith(t, []event.Record{
		mkRecAt("edge-from", "alice", "login", base),                          // From 边界（含）
		mkRecAt("edge-to", "alice", "login", base.Add(2*time.Hour)),           // To 边界（含）
		mkRecAt("inside", "alice", "login", base.Add(time.Hour)),              // 区间内
		mkRecAt("before", "alice", "login", base.Add(-time.Second)),           // 区间外（早1s）
		mkRecAt("after", "alice", "login", base.Add(2*time.Hour+time.Second)), // 区间外（晚1s）
		mkRecAt("wrong-type", "alice", "logout", base.Add(time.Hour)),         // 类型不符
		mkRecAt("wrong-actor", "bob", "login", base.Add(time.Hour)),           // 来源不符
	})
	reg, _ := Open(t.TempDir())
	defer reg.Close()

	c := Criteria{Actor: "alice", Type: "login", From: base, To: base.Add(2 * time.Hour)}
	rep, err := reg.FreezeByCriteria(st, c)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"edge-from", "edge-to", "inside"}
	if fmt.Sprint(rep.Changed) != fmt.Sprint(want) {
		t.Fatalf("boundary match wrong: got %v want %v", rep.Changed, want)
	}
	if reg.FrozenCount() != 3 {
		t.Fatalf("frozen count=%d want 3", reg.FrozenCount())
	}

	// 空条件必须被拒绝（防止误全量冻结）。
	if _, err := reg.FreezeByCriteria(st, Criteria{}); err != ErrEmptyCriteria {
		t.Fatalf("empty criteria must be rejected, got %v", err)
	}
	if _, err := reg.UnfreezeByCriteria(st, Criteria{}); err != ErrEmptyCriteria {
		t.Fatalf("empty criteria must be rejected, got %v", err)
	}

	// 按更窄条件解冻一部分：只解冻 To 边界那一条。
	urep, err := reg.UnfreezeByCriteria(st, Criteria{From: base.Add(2 * time.Hour), To: base.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(urep.Changed) != "[edge-to]" || reg.FrozenCount() != 2 {
		t.Fatalf("partial unfreeze wrong: %+v count=%d", urep, reg.FrozenCount())
	}
	if reg.IsFrozen("edge-to") || !reg.IsFrozen("edge-from") || !reg.IsFrozen("inside") {
		t.Fatalf("frozen set wrong after partial unfreeze: %v", reg.FrozenIDs())
	}
	t.Logf("判定依据: 闭区间边界命中=%v, 空条件拒绝, 窄条件部分解冻=%v", rep.Changed, urep.Changed)
}

func TestFreezePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	st := openStoreWith(t, []event.Record{
		mkRecAt("x", "alice", "login", time.Now()),
		mkRecAt("y", "bob", "logout", time.Now()),
		mkRecAt("z", "carol", "login", time.Now()),
	})

	reg, _ := Open(dir)
	if _, err := reg.FreezeIDs(st, "x", "y"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.UnfreezeIDs("y"); err != nil {
		t.Fatal(err)
	}
	before := reg.FrozenIDs()
	reg.Close()

	// 重启：重放 freeze.log，结论必须一致。
	reg2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	after := reg2.FrozenIDs()
	if fmt.Sprint(before) != fmt.Sprint(after) || fmt.Sprint(after) != "[x]" {
		t.Fatalf("restart mismatch: before=%v after=%v", before, after)
	}
	if !reg2.IsFrozen("x") || reg2.IsFrozen("y") || reg2.FrozenCount() != 1 {
		t.Fatalf("restored state wrong: %v", reg2.FrozenIDs())
	}
	t.Logf("判定依据: 重启前冻结集=%v, 重启后=%v, 一致", before, after)
}

func TestFreezeLogTruncatesPartialLine(t *testing.T) {
	dir := t.TempDir()
	st := openStoreWith(t, []event.Record{mkRecAt("ok", "a", "t", time.Now())})
	reg, _ := Open(dir)
	reg.FreezeIDs(st, "ok")
	reg.Close()

	// 模拟崩溃：追加半写行。
	f, _ := os.OpenFile(filepath.Join(dir, logName), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"op":"freeze","ids":["ha`)
	f.Close()

	reg2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	if !reg2.IsFrozen("ok") || reg2.FrozenCount() != 1 {
		t.Fatalf("partial line must be truncated, state wrong: %v", reg2.FrozenIDs())
	}
	// 半写行截断后仍可正常操作。
	if _, err := reg2.FreezeIDs(st, "ok"); err != nil { // 幂等 no-op
		t.Fatal(err)
	}
	t.Log("判定依据: freeze.log 半写行已在 Open 时截断, 既有冻结状态保留")
}

func TestScanSeqsUnaffectedByFreeze(t *testing.T) {
	// 冻结不改变记录本身：扫描结果与冻结前一致。
	recs := []event.Record{mkRecAt("r1", "a", "t", time.Now()), mkRecAt("r2", "a", "t", time.Now())}
	st := openStoreWith(t, recs)
	reg, _ := Open(t.TempDir())
	defer reg.Close()
	reg.FreezeIDs(st, "r1")
	got, err := st.ScanSeqs(context.Background(), 0, 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("freeze must not alter stored records: n=%d err=%v", len(got), err)
	}
}
