package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

func mkRec(id string) event.Record {
	return event.Record{Event: event.Event{
		ID: id, Type: "t", Actor: "u", Timestamp: time.Now(),
		Fields: map[string]string{"action": "x"},
	}, PolicyVersion: "v1"}
}

func TestAppendScanAndSeq(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := st.Append(mkRec(fmt.Sprintf("e%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := st.ScanSeqs(context.Background(), 2, 4)
	if err != nil || len(recs) != 2 || recs[0].ID != "e1" || recs[1].ID != "e2" {
		t.Fatalf("scan [2,4): %+v err=%v", recs, err)
	}
	if st.LastSeq() != 5 || st.Count() != 5 {
		t.Fatalf("lastseq=%d count=%d", st.LastSeq(), st.Count())
	}
	st.Close()

	// 重新打开：状态一致。
	st2, err := Open(dir)
	if err != nil || st2.LastSeq() != 5 || st2.Count() != 5 {
		t.Fatalf("reopen mismatch: seq=%d count=%d err=%v", st2.LastSeq(), st2.Count(), err)
	}
	st2.Close()
}

func TestRotateKeepsOrder(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	st.Append(mkRec("e0"))
	st.Append(mkRec("e1"))
	if err := st.Rotate(); err != nil {
		t.Fatal(err)
	}
	st.Append(mkRec("e2"))

	segs := st.Segments()
	if len(segs) != 2 || !segs[0].Sealed || segs[0].StartID != "e0" || segs[0].EndID != "e1" {
		t.Fatalf("segments wrong: %+v", segs)
	}
	recs, _ := st.ScanSeqs(context.Background(), 0, 0)
	if len(recs) != 3 || recs[0].ID != "e0" || recs[2].ID != "e2" {
		t.Fatalf("order across segments wrong: %v", recs)
	}
	t.Logf("判定依据: 封存段索引=%d 范围seq=[%d,%d] 活动段count=%d",
		segs[0].Index, segs[0].StartSeq, segs[0].EndSeq, segs[1].Count)
	st.Close()
}

func TestDeleteSegmentsDeterministic(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	for i := 0; i < 3; i++ {
		st.Append(mkRec(fmt.Sprintf("e%d", i)))
		st.Rotate()
	}
	st.Append(mkRec("e3"))
	segs := st.Segments()
	rep, err := st.DeleteSegments([]int{segs[0].Index, segs[1].Index})
	if err != nil {
		t.Fatal(err)
	}
	if rep.DeletedCount != 2 || len(rep.DeletedSegments) != 2 {
		t.Fatalf("report wrong: %+v", rep)
	}
	for _, s := range rep.DeletedSegments {
		if _, statErr := os.Stat(s.Path); !os.IsNotExist(statErr) {
			t.Fatalf("segment file not removed: %s", s.Path)
		}
	}
	if st.Count() != 2 {
		t.Fatalf("count after delete=%d want 2", st.Count())
	}
	t.Logf("清理结果: %s", rep.Reason)
	st.Close()
}

func TestCrashTruncatesPartialLine(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	seq, _ := st.Append(mkRec("good"))
	_ = seq
	st.Close()

	// 模拟崩溃：向活动段追加一条半写 JSON 行。
	p := filepath.Join(dir, activeName)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"seq":2,"record":{"id":"ha`)
	f.Close()

	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st2.LastSeq() != 1 || st2.Count() != 1 {
		t.Fatalf("partial line must be truncated: seq=%d count=%d", st2.LastSeq(), st2.Count())
	}
	fi, _ := os.Stat(p)
	if fi.Size() > 0 {
		b, _ := os.ReadFile(p)
		if len(b) > 0 && b[len(b)-1] != '\n' {
			t.Fatalf("tail not a complete line: %q", b)
		}
	}
	// 半写行之后仍可正常追加。
	st2.Append(mkRec("next"))
	recs, _ := st2.ScanSeqs(context.Background(), 0, 0)
	if len(recs) != 2 || recs[1].ID != "next" {
		t.Fatalf("append after recovery wrong: %v", recs)
	}
	t.Log("判定依据: 半写行已在 Open 时截断，good 保留、next 正常追加")
	st2.Close()
}

func TestConcurrentAppendRotate(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	const writers, per = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if _, err := st.Append(mkRec(fmt.Sprintf("w%d-e%d", w, i))); err != nil {
					t.Errorf("append: %v", err)
					return
				}
				if i%13 == 0 {
					st.Rotate()
				}
			}
		}(w)
	}
	wg.Wait()
	total := int64(writers * per)
	if st.Count() != total || st.LastSeq() != total {
		t.Fatalf("lost or duplicated: count=%d seq=%d want=%d", st.Count(), st.LastSeq(), total)
	}
	recs, _ := st.ScanSeqs(context.Background(), 0, 0)
	if int64(len(recs)) != total {
		t.Fatalf("scan count=%d want=%d", len(recs), total)
	}
	ids := map[string]bool{}
	for _, r := range recs {
		if ids[r.ID] {
			t.Fatalf("duplicated id %s", r.ID)
		}
		ids[r.ID] = true
	}
	t.Logf("判定依据: 并发写入无丢失无重复, 段数=%d", len(st.Segments()))
	st.Close()
}
