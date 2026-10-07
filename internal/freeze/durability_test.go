package freeze

import (
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

// 写盘失败时：apply 返回错误，内存冻结集合保持原样，
// 不允许「内存已变更但 freeze.log 没有」的漂移。
func TestApplyWriteFailureLeavesStateUnchanged(t *testing.T) {
	dir := t.TempDir()
	st := openStoreWith(t, []event.Record{
		mkRecAt("a", "alice", "t", time.Now()),
		mkRecAt("b", "bob", "t", time.Now()),
	})
	reg, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	if _, err := reg.FreezeIDs(st, "a"); err != nil {
		t.Fatal(err)
	}

	// 制造写失败：关闭底层日志 fd，后续 Write 返回 EBADF。
	reg.mu.Lock()
	if err := reg.log.Close(); err != nil {
		reg.mu.Unlock()
		t.Fatal(err)
	}
	reg.mu.Unlock()

	// 新冻结 b：必须返回错误，且 b 不得进入内存集合。
	if _, _, err := reg.apply(logEntry{Op: "freeze", Ts: time.Now()}, []string{"b"}); err == nil {
		t.Fatal("freeze with broken log must return error")
	}
	if reg.IsFrozen("b") {
		t.Fatal("failed freeze must not change in-memory set")
	}
	if !reg.IsFrozen("a") {
		t.Fatal("pre-existing freeze state must remain intact after failed write")
	}

	// 解冻 a 同样必须失败且保持 a 仍冻结。
	if _, _, err := reg.apply(logEntry{Op: "unfreeze", Ts: time.Now()}, []string{"a"}); err == nil {
		t.Fatal("unfreeze with broken log must return error")
	}
	if !reg.IsFrozen("a") {
		t.Fatal("failed unfreeze must not change in-memory set")
	}
	if reg.FrozenCount() != 1 {
		t.Fatalf("frozen count must stay 1, got %d", reg.FrozenCount())
	}
	t.Logf("判定依据: 写盘失败时冻结/解冻返回错误且内存集合不变, count=%d", reg.FrozenCount())
}

// 重启恢复后与失败前的持久化结论一致：只有成功 fsync 的 a 仍是冻结的。
func TestFailedOperationDoesNotSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	st := openStoreWith(t, []event.Record{
		mkRecAt("a", "alice", "t", time.Now()),
		mkRecAt("b", "bob", "t", time.Now()),
	})
	reg, _ := Open(dir)
	if _, err := reg.FreezeIDs(st, "a"); err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	_ = reg.log.Close()
	reg.mu.Unlock()
	_, _, _ = reg.apply(logEntry{Op: "freeze", Ts: time.Now()}, []string{"b"})
	reg.Close()

	reg2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	if !reg2.IsFrozen("a") {
		t.Fatal("durable freeze of a must survive restart")
	}
	if reg2.IsFrozen("b") {
		t.Fatal("non-durable freeze of b must not survive restart")
	}
	t.Log("判定依据: 未成功持久化的冻结在重启后不存在, 已持久化的保持")
}
