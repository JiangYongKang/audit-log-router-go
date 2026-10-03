package store

import (
	"context"
	"fmt"
	"testing"
)

func TestPurgeSegmentRecordLevel(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	// 封存段 1：4 条；活动段：1 条。
	for i := 0; i < 4; i++ {
		st.Append(mkRec(fmt.Sprintf("e%d", i)))
	}
	if err := st.Rotate(); err != nil {
		t.Fatal(err)
	}
	st.Append(mkRec("active"))
	segs := st.Segments()
	if len(segs) != 2 {
		t.Fatalf("want 2 segs, got %d", len(segs))
	}
	idx := segs[0].Index
	var keepSeq int64
	if v, ok, _ := st.LookupSeq("e2"); ok {
		keepSeq = v
	} else {
		t.Fatal("lookup e2")
	}

	// 只保留 e2：其余 3 条被记录级删除，e2 的 seq/内容不变。
	deleted, removed, kept, err := st.PurgeSegment(idx, map[int64]bool{keepSeq: true})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 || removed || kept.Count != 1 {
		t.Fatalf("deleted=%d removed=%v kept=%+v", deleted, removed, kept)
	}
	lns, err := st.ScanLines(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(lns) != 2 || lns[0].Seq != keepSeq || lns[0].Record.ID != "e2" || lns[1].Record.ID != "active" {
		t.Fatalf("compaction result wrong: %+v", lns)
	}
	if _, ok, _ := st.LookupSeq("e0"); ok {
		t.Fatal("id index still references deleted e0")
	}
	if _, ok, _ := st.LookupSeq("e2"); !ok {
		t.Fatal("id index lost kept e2")
	}

	// 重启后压缩结果持久、可继续追加。
	st.Close()
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if st2.Count() != 2 {
		t.Fatalf("count after reopen=%d want 2", st2.Count())
	}
	if _, err := st2.Append(mkRec("next")); err != nil {
		t.Fatal(err)
	}
	t.Logf("场景[段内记录级压缩] 删除=%d 保留seq=%d(e2) 活动段不动 重启一致 count=%d", deleted, keepSeq, st2.Count())
}

func TestPurgeSegmentKeepNothingRemovesFile(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	for i := 0; i < 3; i++ {
		st.Append(mkRec(fmt.Sprintf("e%d", i)))
		st.Rotate()
	}
	st.Append(mkRec("active"))
	idx := st.Segments()[0].Index
	deleted, removed, _, err := st.PurgeSegment(idx, map[int64]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || !removed {
		t.Fatalf("deleted=%d removed=%v want 1/true", deleted, removed)
	}
	if len(st.Segments()) != 3 { // 2 封存 + 1 活动
		t.Fatalf("segs after full purge=%d", len(st.Segments()))
	}
	if st.Count() != 3 {
		t.Fatalf("count=%d want 3", st.Count())
	}
	t.Log("场景[段内无保留记录] 整个段文件删除，计数正确")
}
