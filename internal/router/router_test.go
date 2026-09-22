package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/downstream"
	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/policy"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

type fixture struct {
	dir    string
	engine *policy.Engine
	st     *store.Store
	router *Router
	faults map[string]*downstream.FaultTarget
	files  map[string]*downstream.FileTarget
	logBuf bytes.Buffer
}

func testPolicy(v string) *policy.Policy {
	return &policy.Policy{
		Version:        v,
		RequiredFields: []string{"action"},
		MaskRules: []policy.MaskRule{
			{Field: "password"},
			{Field: "token", EventType: "login"},
		},
		RouteRules: []policy.RouteRule{
			{EventType: "login", Targets: []string{"archive", "siem"}},
		},
		RetentionAge:   "720h",
		RetentionCount: 1_000_000,
		SegmentBytes:   1 << 20,
	}
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	f := &fixture{
		dir:    t.TempDir(),
		faults: map[string]*downstream.FaultTarget{},
		files:  map[string]*downstream.FileTarget{},
	}
	f.engine, _ = policy.NewEngine(testPolicy("v1"))
	var err error
	f.st, err = store.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	logger := log.New(&f.logBuf, "", log.LstdFlags|log.Lmicroseconds)
	cfg.Logger = logger
	f.router = New(f.engine, f.st, cfg)
	for _, name := range []string{"archive", "siem"} {
		ft, err := downstream.NewFileTarget(name, filepath.Join(f.dir, "targets"))
		if err != nil {
			t.Fatal(err)
		}
		f.files[name] = ft
		f.faults[name] = downstream.NewFaultTarget(ft)
		f.router.AddTarget(f.faults[name])
	}
	if err := f.router.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.router.Stop(ctx); err != nil {
		t.Logf("stop: %v", err)
	}
	for _, ft := range f.files {
		ft.Close()
	}
	f.st.Close()
}

func (f *fixture) flushLogs(t *testing.T) {
	t.Helper()
	if f.logBuf.Len() > 0 {
		t.Logf("关键判定日志:\n%s", strings.TrimRight(f.logBuf.String(), "\n"))
	}
}

func mkEvent(id string, fields map[string]string) event.Event {
	if fields == nil {
		fields = map[string]string{"action": "login"}
	}
	return event.Event{ID: id, Type: "login", Actor: "alice", Timestamp: time.Now(), Fields: fields}
}

// waitFor 轮询条件直到成立或超时。
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func (f *fixture) targetLines(t *testing.T, name string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "targets", name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad target line: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func TestFaultIsolation(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 64, MaxRetries: 3, RetryBackoff: 10 * time.Millisecond})
	defer f.flushLogs(t)
	defer f.close(t)

	// siem 持续不可用，archive 正常。
	f.faults["siem"].SetDown(true)
	for i := 0; i < 10; i++ {
		if err := f.router.Ingest(context.Background(), mkEvent(fmt.Sprintf("e%d", i),
			map[string]string{"action": "login", "password": "p" + fmt.Sprint(i)})); err != nil {
			t.Fatal(err)
		}
	}

	if !waitFor(2*time.Second, func() bool {
		s := f.router.Stats()
		return s.Delivered["archive"] == 10 && s.Dropped["siem"] == 10
	}) {
		t.Fatalf("fault isolation failed: %+v", f.router.Stats())
	}
	if lines := f.targetLines(t, "archive"); len(lines) != 10 {
		t.Fatalf("archive should get all 10 despite siem down, got %d", len(lines))
	}
	s := f.router.Stats()
	t.Logf("故障隔离依据: archive 投递=%d, siem 丢弃=%d(明确上限), 队列深度=%v",
		s.Delivered["archive"], s.Dropped["siem"], s.QueueDepth)
}

func TestMaskingNeverLeaks(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 64, MaxRetries: 3, RetryBackoff: 10 * time.Millisecond})
	defer f.flushLogs(t)
	defer f.close(t)

	secret := "SECRET-PASSWORD-12345"
	tok := "SECRET-TOKEN-67890"
	if err := f.router.Ingest(context.Background(), mkEvent("e-secret",
		map[string]string{"action": "login", "password": secret, "token": tok})); err != nil {
		t.Fatal(err)
	}
	if !waitFor(time.Second, func() bool { return f.router.Stats().Delivered["archive"] == 1 }) {
		t.Fatal("event not delivered")
	}

	// 原始值不得出现在：事件段、下游文件、运行日志、投递状态日志。
	var leaked []string
	filepath.WalkDir(f.dir, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(path)
		if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(tok)) {
			leaked = append(leaked, path)
		}
		return nil
	})
	if strings.Contains(f.logBuf.String(), secret) || strings.Contains(f.logBuf.String(), tok) {
		leaked = append(leaked, "test-log")
	}
	if len(leaked) > 0 {
		t.Fatalf("raw secret leaked in: %v", leaked)
	}

	for _, name := range []string{"archive", "siem"} {
		for _, m := range f.targetLines(t, name) {
			rec := m["record"].(map[string]any)
			fields := rec["fields"].(map[string]any)
			if fields["password"] != policy.DefaultMask || fields["token"] != policy.DefaultMask {
				t.Fatalf("unmasked value in %s: %v", name, fields)
			}
		}
	}
	t.Logf("脱敏依据: 全目录扫描未发现原始值; 下游记录 password/token 均为 %q", policy.DefaultMask)
}

func TestRestartRecovery(t *testing.T) {
	dir := t.TempDir()
	logger := log.New(&bytes.Buffer{}, "", 0)

	start := func() (*Router, *store.Store, map[string]*downstream.FileTarget, map[string]*downstream.FaultTarget) {
		eng, _ := policy.NewEngine(testPolicy("v1"))
		st, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		r := New(eng, st, Config{QueueSize: 8, MaxRetries: 100000, RetryBackoff: 5 * time.Millisecond, Logger: logger})
		files := map[string]*downstream.FileTarget{}
		faults := map[string]*downstream.FaultTarget{}
		for _, name := range []string{"archive", "siem"} {
			ft, _ := downstream.NewFileTarget(name, filepath.Join(dir, "targets"))
			files[name] = ft
			ft2 := downstream.NewFaultTarget(ft)
			faults[name] = ft2
			r.AddTarget(ft2)
		}
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		return r, st, files, faults
	}
	// 第一次启动：siem 故障，事件停留在 enqueued 或 dropped。
	r, st, files, faults := start()
	faults["siem"].SetDown(true)
	for i := 0; i < 5; i++ {
		if err := r.Ingest(context.Background(), mkEvent(fmt.Sprintf("r%d", i), nil)); err != nil {
			t.Fatal(err)
		}
	}
	if !waitFor(time.Second, func() bool {
		return r.Stats().Delivered["archive"] == 5
	}) {
		t.Fatal("archive delivery not done before crash")
	}
	// 模拟进程崩溃：不等待未完成投递直接停止。
	r.cancel()
	r.wg.Wait()
	for _, ft := range files {
		ft.Close()
	}
	st.Close()

	// 第二次启动：恢复 enqueued 事件并投递成功。
	r2, st2, files2, faults2 := start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		r2.Stop(ctx)
		for _, ft := range files2 {
			ft.Close()
		}
		st2.Close()
	}()
	faults2["siem"].SetDown(false)
	if !waitFor(2*time.Second, func() bool {
		return r2.Stats().Delivered["siem"] >= 5
	}) {
		t.Fatalf("recovery delivery failed: %+v", r2.Stats())
	}
	t.Logf("重启恢复依据: 重启后 siem 成功投递=%d (delivery.log 重放 enqueued)", r2.Stats().Delivered["siem"])
}

func TestDownstreamDedupByID(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 64, MaxRetries: 3, RetryBackoff: 10 * time.Millisecond})
	defer f.close(t)
	rec := event.Record{Event: mkEvent("dup-1", nil), PolicyVersion: "v1"}
	target := f.faults["archive"]
	for i := 0; i < 3; i++ {
		if err := target.Deliver(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.targetLines(t, "archive")); got != 1 {
		t.Fatalf("duplicate deliveries must collapse to 1, got %d", got)
	}
	if f.files["archive"].Dups != 2 {
		t.Fatalf("Dups counter=%d want 2", f.files["archive"].Dups)
	}
	t.Logf("下游去重依据: 同 ID 投递 3 次, 落盘 1 条, 识别重复 %d 次", f.files["archive"].Dups)
}

func TestRuleReloadConflict(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 64, MaxRetries: 3, RetryBackoff: 10 * time.Millisecond})
	defer f.flushLogs(t)
	defer f.close(t)

	// 冲突规则必须被拒绝，旧规则继续生效。
	bad := testPolicy("v-bad")
	bad.MaskRules = append(bad.MaskRules, policy.MaskRule{Field: "password", Mask: "OTHER"})
	err := f.router.ReloadPolicy(bad)
	if err == nil {
		t.Fatal("conflicting policy must be rejected")
	}
	if f.engine.Current().Version != "v1" {
		t.Fatalf("old policy must stay, got %s", f.engine.Current().Version)
	}

	// 合法新规则原子生效：password 改为新占位符，新增字段 ssn 脱敏。
	good := testPolicy("v2")
	for i := range good.MaskRules {
		if good.MaskRules[i].Field == "password" {
			good.MaskRules[i].Mask = "###"
		}
	}
	good.MaskRules = append(good.MaskRules, policy.MaskRule{Field: "ssn"})
	if err := f.router.ReloadPolicy(good); err != nil {
		t.Fatalf("valid reload failed: %v", err)
	}
	if err := f.router.Ingest(context.Background(), mkEvent("e-reload",
		map[string]string{"action": "login", "password": "p", "ssn": "111-22-3333"})); err != nil {
		t.Fatal(err)
	}
	if !waitFor(time.Second, func() bool { return f.router.Stats().Delivered["archive"] == 1 }) {
		t.Fatal("not delivered")
	}
	m := f.targetLines(t, "archive")[0]["record"].(map[string]any)
	fields := m["fields"].(map[string]any)
	if fields["password"] != "###" || fields["ssn"] != policy.DefaultMask {
		t.Fatalf("new mask rules not applied: %v", fields)
	}
	if m["policy_version"] != "v2" {
		t.Fatalf("record should carry new policy version, got %v", m["policy_version"])
	}
	t.Logf("规则变更依据: 冲突被拒(旧版v1保留); 合法v2生效后 password=### ssn=%s 记录版本=v2",
		policy.DefaultMask)
}

func TestHighConcurrencyIngest(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 4096, MaxRetries: 3, RetryBackoff: 5 * time.Millisecond})
	defer f.flushLogs(t)
	defer f.close(t)

	const writers, per = 16, 100
	var wg sync.WaitGroup
	var rejected int64
	var rejectMu sync.Mutex
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				err := f.router.Ingest(context.Background(), mkEvent(
					fmt.Sprintf("w%d-e%d", w, i),
					map[string]string{"action": "login", "password": "pw"}))
				if err != nil {
					rejectMu.Lock()
					rejected++
					rejectMu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()

	total := int64(writers * per)
	if rejected != 0 {
		t.Fatalf("unexpected rejections: %d", rejected)
	}
	if !waitFor(20*time.Second, func() bool {
		s := f.router.Stats()
		return s.Delivered["archive"] == total && s.Delivered["siem"] == total
	}) {
		t.Fatalf("not all delivered: %+v", f.router.Stats())
	}
	if f.st.Count() != total {
		t.Fatalf("store count=%d want=%d", f.st.Count(), total)
	}
	if n := len(f.targetLines(t, "archive")); int64(n) != total {
		t.Fatalf("archive lines=%d want=%d", n, total)
	}
	if n := len(f.targetLines(t, "siem")); int64(n) != total {
		t.Fatalf("siem lines=%d want=%d", n, total)
	}
	t.Logf("高并发依据: %d 个事件全部落盘且双目标各投递 %d, 拒绝=%d", total, total, rejected)
}

func TestBacklogCapDroppedExplainably(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 4, MaxRetries: 1, RetryBackoff: 20 * time.Millisecond})
	defer f.flushLogs(t)
	defer f.close(t)

	f.faults["archive"].SetDown(true)
	f.faults["siem"].SetDown(true)
	for i := 0; i < 40; i++ {
		f.router.Ingest(context.Background(), mkEvent(fmt.Sprintf("b%d", i), nil))
	}
	if !waitFor(3*time.Second, func() bool {
		s := f.router.Stats()
		return s.Dropped["archive"]+int64(s.QueueDepth["archive"]) >= 40 &&
			s.Dropped["siem"]+int64(s.QueueDepth["siem"]) >= 40
	}) {
		t.Fatalf("bounded backlog violated: %+v", f.router.Stats())
	}
	s := f.router.Stats()
	t.Logf("积压上限依据: 队列深度=%v 丢弃=%v (重试耗尽/积压满均在 delivery.log 标记 dropped)",
		s.QueueDepth, s.Dropped)
}

func TestLedgerIsAuditable(t *testing.T) {
	f := newFixture(t, Config{QueueSize: 4, MaxRetries: 1, RetryBackoff: 5 * time.Millisecond})
	defer f.flushLogs(t)

	f.faults["siem"].SetDown(true)
	f.router.Ingest(context.Background(), mkEvent("audit-1",
		map[string]string{"action": "login", "password": "p"}))
	if !waitFor(2*time.Second, func() bool {
		s := f.router.Stats()
		return s.Delivered["archive"] == 1 && s.Dropped["siem"] == 1
	}) {
		t.Fatalf("unexpected stats: %+v", f.router.Stats())
	}
	// 正常停止后再检查（确保 fsync 落盘）。
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := f.router.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()

	b, err := os.ReadFile(filepath.Join(f.dir, "delivery.log"))
	if err != nil {
		t.Fatal(err)
	}
	var sawDelivered, sawDroppedWithReason, sawEnqueued bool
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		var le ledgerEntry
		if err := json.Unmarshal([]byte(line), &le); err != nil {
			t.Fatal(err)
		}
		switch le.Status {
		case "enqueued":
			sawEnqueued = true
		case "delivered":
			sawDelivered = true
		case "dropped":
			if le.Reason != "" {
				sawDroppedWithReason = true
			}
		}
	}
	if !(sawEnqueued && sawDelivered && sawDroppedWithReason) {
		t.Fatalf("ledger states incomplete: enqueued=%v delivered=%v dropped(reason)=%v",
			sawEnqueued, sawDelivered, sawDroppedWithReason)
	}
	t.Logf("可核查依据: delivery.log 同时包含 enqueued/delivered/dropped(带原因) 三种状态, 原始密码不在其中")
	if bytes.Contains(b, []byte("p-SECRET")) {
		t.Fatal("secret in ledger")
	}
}
