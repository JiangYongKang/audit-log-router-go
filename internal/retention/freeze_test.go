package retention

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

func mkRecView(id, typ, source string, ts time.Time) event.Record {
	return event.Record{Event: event.Event{
		ID: id, Type: typ, Actor: "u", Source: source, Timestamp: ts,
		Fields: map[string]string{"action": "x"},
	}, PolicyVersion: "v1"}
}

func recsAll(t *testing.T, st *store.Store) []event.Record {
	t.Helper()
	recs, err := st.ScanSeqs(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// 场景1：已过保存期的记录被冻结 -> 清理时保留；解冻后再清理 -> 按原规则删除，
// 且不会「一解冻就丢」（解冻本身不触发删除，下次 Sweep 才按规则处理）。
func TestFreezeBlocksAgePurgeThenUnfreezeRejoins(t *testing.T) {
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	st := newStoreWithSegs(t, 2, []time.Time{old, old, now.Add(-time.Hour)})
	hold, err := freeze.Open(st.Dir(), st)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()

	// 冻结最旧段里的一条（s0-e0）。
	rep, err := hold.FreezeByIDs([]string{"s0-e0"}, now)
	if err != nil || rep.Changed != 1 {
		t.Fatalf("freeze: %+v err=%v", rep, err)
	}

	sw := New(st, time.Hour, 24*time.Hour, 0, 0).WithFreeze(hold)
	purge, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	recs := recsAll(t, st)
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	if !ids["s0-e0"] {
		t.Fatalf("frozen record s0-e0 must survive age purge; have %v", ids)
	}
	// 同段另一条未冻结的 s0-e1 应被清走；第二段两条（s1-*）也超期被整段删除。
	if ids["s0-e1"] || ids["s1-e0"] || ids["s1-e1"] {
		t.Fatalf("unfrozen old records must be purged: %v", ids)
	}
	if purge.DeletedCount != 3 {
		t.Fatalf("deleted=%d want 3 (seg1 whole=2 + seg0 compacted=1)", purge.DeletedCount)
	}
	t.Logf("场景[冻结对抗保留期清理] 清理依据: %s; 留存=%v", purge.Reason, ids)

	// 解冻本身不删除记录（不能一解冻就丢）。
	urep, _ := hold.UnfreezeByIDs([]string{"s0-e0"}, now)
	if urep.Changed != 1 {
		t.Fatalf("unfreeze: %+v", urep)
	}
	if hold.FrozenCount() != 0 {
		t.Fatalf("frozen count must be 0")
	}
	recs = recsAll(t, st)
	found := false
	for _, r := range recs {
		if r.ID == "s0-e0" {
			found = true
		}
	}
	if !found {
		t.Fatal("unfreeze must not immediately delete the record")
	}

	// 再次 Sweep：解冻记录重新按保留期规则被清走（也不会怎么都清不掉）。
	purge2, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	recs = recsAll(t, st)
	for _, r := range recs {
		if r.ID == "s0-e0" {
			t.Fatalf("unfrozen record must rejoin age purge on next sweep: %s", purge2.Reason)
		}
	}
	t.Logf("场景[解冻后重新参与清理] 二次清理依据: %s（解冻当下未删除）", purge2.Reason)
}

// 场景2：容量上限清理不能挤掉冻结记录；段内压缩只删未冻结记录，存储不会无限增长。
func TestFreezeHoldsAgainstCountCap(t *testing.T) {
	now := time.Now()
	st := newStoreWithSegs(t, 2, []time.Time{now, now, now, now}) // 4 段 x2 = 8
	hold, _ := freeze.Open(st.Dir(), st)
	defer hold.Close()
	// 冻结最旧段全部 2 条。
	if rep, err := hold.FreezeBySelector(freeze.Selector{IDs: []string{"s0-e0", "s0-e1"}}, now); err != nil || rep.Changed != 2 {
		t.Fatalf("freeze: %+v err=%v", rep, err)
	}

	sw := New(st, time.Hour, 0, 3, 0).WithFreeze(hold) // 容量 3
	purge, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	recs := recsAll(t, st)
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
	}
	for _, id := range []string{"s0-e0", "s0-e1"} {
		if !ids[id] {
			t.Fatalf("frozen %s must survive count cap: %v", id, ids)
		}
	}
	// 冻结占 2 + 最新段 2 = 4 > cap=3，但冻结是硬地板：只能挤到 4，不会删冻结。
	if st.Count() != 4 {
		t.Fatalf("count=%d want 4 (frozen floor=2 + newest seg=2)", st.Count())
	}
	if purge.DeletedCount != 4 { // s1、s2 两个整段
		t.Fatalf("deleted=%d want 4; reason=%s", purge.DeletedCount, purge.Reason)
	}
	t.Logf("场景[容量清理不挤冻结] count=%d(<=冻结2+最新段2), 清理依据: %s", st.Count(), purge.Reason)
}

// 场景3：部分冻结段在容量清理时走段内压缩，冻结记录 seq/内容不变。
func TestPartialFrozenSegmentCompacted(t *testing.T) {
	now := time.Now()
	st := newStoreWithSegs(t, 3, []time.Time{now, now, now}) // 3 段 x3 = 9
	hold, _ := freeze.Open(st.Dir(), st)
	defer hold.Close()
	// 冻结最旧段的中间一条 s0-e1，以及中间段的一条 s1-e0。
	if _, err := hold.FreezeByIDs([]string{"s0-e1", "s1-e0"}, now); err != nil {
		t.Fatal(err)
	}
	sw := New(st, time.Hour, 0, 3, 0).WithFreeze(hold)
	purge, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	recs := recsAll(t, st)
	var seqOfE1 int64
	ids := map[string]bool{}
	for _, r := range recs {
		ids[r.ID] = true
		if r.ID == "s0-e1" {
			// 找 seq：fixture 中 s0-e1 的 seq 恒为 2。
			seqOfE1 = 0
		}
	}
	if !ids["s0-e1"] || !ids["s1-e0"] {
		t.Fatalf("frozen records must survive: %v", ids)
	}
	if ids["s0-e0"] || ids["s0-e2"] || ids["s1-e1"] || ids["s1-e2"] {
		t.Fatalf("unfrozen records in compacted segs must be removed: %v", ids)
	}
	// s0 段压缩后只剩 s0-e1，其内容与 seq 必须保持不变（seq=2）。
	lns, err := st.ScanLines(context.Background(), 2, 3)
	if err != nil || len(lns) != 1 || lns[0].Record.ID != "s0-e1" {
		t.Fatalf("frozen record content/seq must be preserved: lns=%d err=%v", len(lns), err)
	}
	_ = seqOfE1
	// 容量约束：冻结地板 2 + 可挤出后的最新段 3 = 5。
	if st.Count() > 5 {
		t.Fatalf("count=%d must not grow unbounded, want <=5", st.Count())
	}
	t.Logf("场景[部分冻结段压缩] 留存=%v count=%d 依据: %s", ids, st.Count(), purge.Reason)
}

// 场景4：未挂配冻结注册表时，清理行为与旧版完全一致（兼容性）。
func TestNoFreezeBehavesAsBefore(t *testing.T) {
	now := time.Now()
	st := newStoreWithSegs(t, 2, []time.Time{now, now, now, now})
	sw := New(st, time.Hour, 0, 3, 0) // 与既有 TestSweepCountExceededOldestFirst 相同参数
	purge, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if purge.DeletedCount != 6 || len(purge.DeletedSegments) != 3 {
		t.Fatalf("no-freeze behavior changed: %+v", purge)
	}
	recs := recsAll(t, st)
	if len(recs) != 2 || recs[0].ID != "s3-e0" {
		t.Fatalf("newest segment must survive: %v", recs)
	}
	t.Logf("场景[无冻结兼容旧行为]: %s", purge.Reason)
}

// 场景5：重启后冻结状态恢复，对同一批记录的清理结论与重启前一致。
func TestFreezeRestartSameSweepVerdict(t *testing.T) {
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	dir := t.TempDir()

	st, _ := store.Open(dir)
	hold, _ := freeze.Open(dir, st)
	for i := 0; i < 2; i++ {
		st.Append(mkRecAt(fmt.Sprintf("a%d", i), old))
	}
	st.Rotate()
	for i := 0; i < 2; i++ {
		st.Append(mkRecAt(fmt.Sprintf("b%d", i), now))
	}
	hold.FreezeByIDs([]string{"a0"}, now)
	st.Close()
	hold.Close()

	// 重启：store 与 freeze 均从磁盘恢复。
	st2, _ := store.Open(dir)
	defer st2.Close()
	hold2, err := freeze.Open(dir, st2)
	if err != nil {
		t.Fatal(err)
	}
	defer hold2.Close()
	if hold2.FrozenCount() != 1 || !hold2.IsFrozen("a0") {
		t.Fatalf("freeze state not recovered: count=%d a0=%v", hold2.FrozenCount(), hold2.IsFrozen("a0"))
	}
	sw := New(st2, time.Hour, 24*time.Hour, 0, 0).WithFreeze(hold2)
	purge, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	recs := recsAll(t, st2)
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.ID)
	}
	want := map[string]bool{"a0": true, "b0": true, "b1": true}
	if len(ids) != 3 || !want[ids[0]] || !want[ids[1]] || !want[ids[2]] {
		t.Fatalf("post-restart verdict wrong: %v", ids)
	}
	t.Logf("场景[重启后清理结论一致] 留存=%v 依据: %s", ids, purge.Reason)
}

// 场景6：同一段内既有「冻结的超期记录」也有「未冻结但未超期的记录」时，
// 保留期清理只能删除其中真正超期且未冻结的记录，未超期记录必须原样保留。
func TestAgeCompactKeepsFreshUnfrozen(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hold, err := freeze.Open(dir, st)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()

	// 一个封存段：旧、新、旧 交错（段判定按最旧记录，会被整体标记超期）。
	st.Append(mkRecView("old-frozen", "login", "web", now.Add(-72*time.Hour)))
	st.Append(mkRecView("fresh-unfrozen", "login", "web", now.Add(-time.Hour)))
	st.Append(mkRecView("old-unfrozen", "login", "web", now.Add(-72*time.Hour)))
	st.Rotate()
	st.Append(mkRecView("active-fresh", "login", "web", now))

	hold.FreezeByIDs([]string{"old-frozen"}, now)

	sw := New(st, time.Hour, 24*time.Hour, 0, 0).WithFreeze(hold)
	rep, err := sw.Sweep(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range recsAll(t, st) {
		ids[r.ID] = true
	}
	if !ids["old-frozen"] {
		t.Fatal("frozen expired record must survive")
	}
	if !ids["fresh-unfrozen"] {
		t.Fatalf("fresh unfrozen record in the same segment must NOT be purged: %v", ids)
	}
	if ids["old-unfrozen"] {
		t.Fatal("expired unfrozen record must be purged")
	}
	if rep.DeletedCount != 1 {
		t.Fatalf("deleted=%d want exactly 1 (old-unfrozen), reason=%s", rep.DeletedCount, rep.Reason)
	}
	t.Logf("场景[保留期段压缩不误删未超期记录] 留存=%v 依据: %s", ids, rep.Reason)
}
