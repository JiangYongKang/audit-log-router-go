package downstream

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

func rec(id string) event.Record {
	return event.Record{Event: event.Event{ID: id, Type: "login", Actor: "u",
		Fields: map[string]string{"action": "login", "token": "X"}},
		PolicyVersion: "v1"}
}

func TestFileTargetDedupAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	t1, err := NewFileTarget("siem", dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t1.Deliver(ctx, rec("a1"))
	t1.Deliver(ctx, rec("a2"))
	t1.Deliver(ctx, rec("a1")) // 同进程内重复
	t1.Close()

	// 模拟重启：重新打开同一文件，去重集合需从落盘内容恢复。
	t2, err := NewFileTarget("siem", dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := t2.Deliver(ctx, rec("a1")); err != nil { // 跨重启重复
		t.Fatal(err)
	}
	t2.Close()

	b, _ := os.ReadFile(filepath.Join(dir, "siem.log"))
	n := len(strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
	if n != 2 {
		t.Fatalf("want 2 unique records across restart, got %d", n)
	}
	t.Log("判定依据: 同进程+跨重启重复投递同 ID 均只落盘一次")
}

func TestFaultTargetToggle(t *testing.T) {
	dir := t.TempDir()
	ft, _ := NewFileTarget("arc", dir)
	flt := NewFaultTarget(ft)
	ctx := context.Background()
	if err := flt.Deliver(ctx, rec("x")); err != nil {
		t.Fatal(err)
	}
	flt.SetDown(true)
	if err := flt.Deliver(ctx, rec("y")); err != ErrUnavailable {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	flt.SetDown(false)
	if err := flt.Deliver(ctx, rec("y")); err != nil {
		t.Fatalf("recovered target should deliver, got %v", err)
	}
}
