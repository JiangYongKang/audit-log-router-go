// auditrouter 是本地审计日志采集、合规路由与留存组件的示例入口。
//
// 用法：
//
//	go run ./cmd/auditrouter --dir ./data --demo
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/downstream"
	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/policy"
	"github.com/highcumontoa/audit-log-router-go/internal/retention"
	"github.com/highcumontoa/audit-log-router-go/internal/router"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

func main() {
	dir := flag.String("dir", "./data", "数据目录（事件段、投递状态、下游文件）")
	policyFile := flag.String("policy", "", "规则 JSON 文件路径（缺省使用内置示例规则）")
	demo := flag.Bool("demo", false, "写入若干示例事件并打印结论后退出")
	flag.Parse()

	logger := log.New(os.Stdout, "[auditrouter] ", log.LstdFlags|log.Lmicroseconds)

	p, err := loadPolicy(*policyFile)
	if err != nil {
		logger.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(p)
	if err != nil {
		logger.Fatalf("policy conflict: %v", err)
	}

	st, err := store.Open(*dir)
	if err != nil {
		logger.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// 合规冻结注册表：冻结状态独立 append-only 落盘（freeze.log），重启恢复。
	hold, err := freeze.Open(*dir, st)
	if err != nil {
		logger.Fatalf("open freeze registry: %v", err)
	}
	defer hold.Close()

	r := router.New(engine, st, router.Config{
		QueueSize: 128, MaxRetries: 3, RetryBackoff: 20 * time.Millisecond, Logger: logger,
	})
	// 容量硬上限与 retention_count 对齐：冻结把容量占满时，新写入以
	// capacity_locked 显式拒绝，而不是悄悄丢弃或挤掉冻结记录。
	r.WithFreeze(hold, p.RetentionCount)
	for _, name := range []string{"archive", "siem"} {
		t, err := downstream.NewFileTarget(name, *dir+"/targets")
		if err != nil {
			log.Fatal(err)
		}
		r.AddTarget(t)
	}

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		logger.Fatalf("start router: %v", err)
	}

	maxAge, _ := p.ParseAge()
	sw := retention.New(st, time.Second, maxAge, p.RetentionCount, p.SegmentBytes).WithFreeze(hold)
	sw.Start(ctx)
	defer sw.Stop()

	if *demo {
		runDemo(ctx, r, logger)
	}

	stopCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := r.Stop(stopCtx); err != nil {
		logger.Printf("stop: %v", err)
	}
	s := r.Stats()
	fmt.Printf("stats: received=%d accepted=%d rejected=%d capacity_locked=%d delivered=%v dropped=%v queue=%v frozen=%d\n",
		s.Received, s.Accepted, s.Rejected, s.CapacityLocked, s.Delivered, s.Dropped, s.QueueDepth, hold.FrozenCount())
}

func loadPolicy(path string) (*policy.Policy, error) {
	if path != "" {
		return policy.LoadFile(path)
	}
	// 内置示例规则：password 对所有类型脱敏；login 事件的 token 对 login 类型脱敏。
	return &policy.Policy{
		Version:        "demo-v1",
		RequiredFields: []string{"action"},
		MaskRules: []policy.MaskRule{
			{Field: "password"},
			{Field: "token", EventType: "login"},
		},
		RouteRules: []policy.RouteRule{
			{EventType: "login", Targets: []string{"archive", "siem"}},
		},
		RetentionAge:   "720h",
		RetentionCount: 100000,
		SegmentBytes:   1 << 20,
	}, nil
}

func runDemo(ctx context.Context, r *router.Router, logger *log.Logger) {
	now := time.Now()
	events := []event.Event{
		{ID: "evt-1", Type: "login", Actor: "alice", Timestamp: now,
			Fields: map[string]string{"action": "login", "password": "hunter2", "token": "tok-abc"}},
		// 缺少必需字段 action：必须被拒绝。
		{ID: "evt-2", Type: "login", Actor: "bob", Timestamp: now,
			Fields: map[string]string{"password": "secret123"}},
		// 与 evt-1 同 ID：必须被识别为重复。
		{ID: "evt-1", Type: "login", Actor: "alice", Timestamp: now,
			Fields: map[string]string{"action": "login", "password": "hunter2"}},
	}
	for _, ev := range events {
		err := r.Ingest(ctx, ev)
		var re *event.RejectError
		if errors.As(err, &re) {
			logger.Printf("rejected id=%q reason=%s detail=%q", ev.ID, re.Reason, re.Detail)
		}
	}
	time.Sleep(300 * time.Millisecond) // 等待投递循环

	// 演示合规冻结：对已接收的 evt-1 加冻结（freeze.log 可核查，重启后仍在）。
	if rep, err := r.FreezeByIDs([]string{"evt-1"}); err == nil {
		logger.Printf("legal hold: changed=%d skipped=%d items=%+v", rep.Changed, rep.Skipped, rep.Items)
	} else {
		logger.Printf("legal hold: %v", err)
	}
}
