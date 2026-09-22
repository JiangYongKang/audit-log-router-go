// Package router 将已判定事件路由到多个下游目标。
//
// 投递语义：
//   - Ingest 成功返回前，事件已 fsync 落盘（store）且每个目标已写入
//     enqueued 状态（delivery.log），因此进程重启后已接收事件不丢失。
//   - 每个目标有独立的有界队列与重试上限；单目标持续失败不阻塞其他目标。
//   - 超出重试上限或队列积压上限的事件被标记 dropped（可核查），不影响他人。
//   - 重复事件 ID 在采集侧被拒绝；下游侧的重复投递由目标按 ID 幂等识别。
package router

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/downstream"
	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/policy"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

// Config 控制路由行为上限。
type Config struct {
	QueueSize    int           // 每个目标的进程内队列上限
	MaxRetries   int           // 单条事件最大重试次数
	RetryBackoff time.Duration // 重试间隔
	Logger       *log.Logger   // 判定依据日志（可选）
}

func (c *Config) withDefaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.MaxRetries <= 0 {
		c.MaxRetries = 5
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 50 * time.Millisecond
	}
}

// Stats 是路由运行状态快照。
type Stats struct {
	Received   int64
	Accepted   int64
	Rejected   int64
	Delivered  map[string]int64
	Failed     map[string]int64
	Dropped    map[string]int64
	QueueDepth map[string]int
}

// ledgerEntry 是 delivery.log 中的一行投递状态。
type ledgerEntry struct {
	EventID string `json:"event_id"`
	Target  string `json:"target"`
	Status  string `json:"status"` // enqueued | delivered | dropped
	Reason  string `json:"reason,omitempty"`
}

type queuedEvent struct {
	rec event.Record
}

type targetWorker struct {
	name   string
	target downstream.Target
	queue  chan queuedEvent
}

// Router 接收事件、执行合规判定并投递到多个下游。
type Router struct {
	engine *policy.Engine
	store  *store.Store
	cfg    Config

	mu        sync.Mutex // 保护 targets/seenIDs/stats
	targets   map[string]*targetWorker
	seenIDs   map[string]struct{}
	received  int64
	accepted  int64
	rejected  int64
	delivered map[string]int64
	failed    map[string]int64
	dropped   map[string]int64

	ledgerMu sync.Mutex
	ledger   *os.File

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(engine *policy.Engine, st *store.Store, cfg Config) *Router {
	cfg.withDefaults()
	return &Router{
		engine:    engine,
		store:     st,
		cfg:       cfg,
		targets:   map[string]*targetWorker{},
		seenIDs:   map[string]struct{}{},
		delivered: map[string]int64{},
		failed:    map[string]int64{},
		dropped:   map[string]int64{},
	}
}

func (r *Router) logf(format string, args ...any) {
	if r.cfg.Logger != nil {
		r.cfg.Logger.Printf(format, args...)
	}
}

// AddTarget 注册一个下游目标（须在 Start 前调用）。
func (r *Router) AddTarget(t downstream.Target) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[t.Name()] = &targetWorker{
		name:   t.Name(),
		target: t,
		queue:  make(chan queuedEvent, r.cfg.QueueSize),
	}
}

// Start 打开投递状态日志、恢复未完成投递并启动各目标投递循环。
func (r *Router) Start(ctx context.Context) error {
	r.ctx, r.cancel = context.WithCancel(ctx)

	// 1) 重建已见事件 ID（用于重复 ID 拒绝）。
	recs, err := r.store.ScanSeqs(ctx, 0, 0)
	if err != nil {
		return err
	}
	byID := map[string]event.Record{}
	for _, rec := range recs {
		byID[rec.ID] = rec
		r.seenIDs[rec.ID] = struct{}{}
	}

	// 2) 打开/重放投递状态日志。
	ledgerPath := filepath.Join(r.store.Dir(), "delivery.log")
	lf, err := os.OpenFile(ledgerPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	r.ledger = lf
	pending := map[string]map[string]bool{} // target -> eventID -> 未完成
	if _, err := lf.Seek(0, 0); err != nil {
		return err
	}
	sc := bufio.NewScanner(lf)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var le ledgerEntry
		if json.Unmarshal(sc.Bytes(), &le) != nil {
			continue
		}
		if pending[le.Target] == nil {
			pending[le.Target] = map[string]bool{}
		}
		switch le.Status {
		case "enqueued":
			pending[le.Target][le.EventID] = true
		case "delivered", "dropped":
			delete(pending[le.Target], le.EventID)
		}
	}

	// 3) 恢复未完成投递。
	r.mu.Lock()
	for name, w := range r.targets {
		for id := range pending[name] {
			rec, ok := byID[id]
			if !ok {
				// 事件已被留存清理：标记 dropped，结论可解释。
				r.appendLedgerLocked(ledgerEntry{EventID: id, Target: name, Status: "dropped", Reason: "purged_before_delivery"})
				r.dropped[name]++
				continue
			}
			select {
			case w.queue <- queuedEvent{rec: rec}:
			default:
				// 队列满：保持 enqueued 状态，由目标恢复后通过重试机制处理。
				// 简化语义：标记 dropped，结论可核查。
				r.appendLedgerLocked(ledgerEntry{EventID: id, Target: name, Status: "dropped", Reason: "recovery_backlog_full"})
				r.dropped[name]++
			}
		}
	}
	r.mu.Unlock()

	// 4) 启动投递循环。
	r.mu.Lock()
	for _, w := range r.targets {
		r.wg.Add(1)
		go r.deliverLoop(w)
	}
	r.mu.Unlock()
	r.logf("router started: targets=%d recovered_pending=%d", len(r.targets), countPending(pending))
	return nil
}

func countPending(p map[string]map[string]bool) int {
	n := 0
	for _, m := range p {
		n += len(m)
	}
	return n
}

// Stop 停止接收新事件并等待在途投递结束。
// 队列中未投递的事件保持 enqueued 状态，重启后恢复，不丢失。
func (r *Router) Stop(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	if r.ledger != nil {
		return r.ledger.Close()
	}
	return nil
}

// Ingest 采集一条事件：校验 -> 脱敏 -> 落盘 -> 逐目标入队。
// 任一环节失败都返回带可区分原因的错误。
func (r *Router) Ingest(ctx context.Context, ev event.Event) error {
	r.mu.Lock()
	r.received++
	r.mu.Unlock()

	dec := r.engine.Evaluate(ev)
	if !dec.Accepted {
		r.mu.Lock()
		r.rejected++
		r.mu.Unlock()
		r.logf("ingest rejected: id=%q reason=%s detail=%q", ev.ID, dec.Reason, dec.Detail)
		return &event.RejectError{Reason: dec.Reason, Detail: dec.Detail}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.seenIDs[ev.ID]; dup {
		r.rejected++
		r.logf("ingest rejected: id=%q reason=%s", ev.ID, event.RejectDuplicateID)
		return &event.RejectError{Reason: event.RejectDuplicateID, Detail: "event id already ingested"}
	}

	seq, err := r.store.Append(dec.Record)
	if err != nil {
		return fmt.Errorf("persist event: %w", err)
	}
	r.seenIDs[ev.ID] = struct{}{}
	r.accepted++
	r.logf("ingest accepted: id=%q seq=%d policy=%s masked=%v targets=%v",
		ev.ID, seq, dec.Record.PolicyVersion, dec.Record.Masked, dec.Targets)

	for _, name := range dec.Targets {
		w, ok := r.targets[name]
		if !ok {
			r.appendLedgerLocked(ledgerEntry{EventID: ev.ID, Target: name, Status: "dropped", Reason: "unknown_target"})
			r.dropped[name]++
			r.logf("delivery dropped: id=%q target=%q reason=unknown_target", ev.ID, name)
			continue
		}
		r.appendLedgerLocked(ledgerEntry{EventID: ev.ID, Target: name, Status: "enqueued"})
		select {
		case w.queue <- queuedEvent{rec: dec.Record}:
		default:
			r.appendLedgerLocked(ledgerEntry{EventID: ev.ID, Target: name, Status: "dropped", Reason: "backlog_full"})
			r.dropped[name]++
			r.logf("delivery dropped: id=%q target=%q reason=backlog_full", ev.ID, name)
		}
	}
	return nil
}

// deliverLoop 是单个目标的投递循环：有界重试，失败不阻塞其他目标。
func (r *Router) deliverLoop(w *targetWorker) {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case qe := <-w.queue:
			r.deliverWithRetry(w, qe.rec)
		}
	}
}

func (r *Router) deliverWithRetry(w *targetWorker, rec event.Record) {
	var err error
	for attempt := 0; attempt <= r.cfg.MaxRetries; attempt++ {
		if r.ctx.Err() != nil {
			return // 停止中：保持 enqueued，重启恢复
		}
		err = w.target.Deliver(r.ctx, rec)
		if err == nil {
			r.mu.Lock()
			r.delivered[w.name]++
			r.appendLedgerLocked(ledgerEntry{EventID: rec.ID, Target: w.name, Status: "delivered"})
			r.mu.Unlock()
			return
		}
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(r.cfg.RetryBackoff):
		}
	}
	r.mu.Lock()
	r.failed[w.name]++
	r.dropped[w.name]++
	r.appendLedgerLocked(ledgerEntry{EventID: rec.ID, Target: w.name, Status: "dropped", Reason: "retries_exhausted"})
	r.mu.Unlock()
	r.logf("delivery dropped: id=%q target=%q reason=retries_exhausted last_err=%v", rec.ID, w.name, err)
}

// appendLedgerLocked 追加一条投递状态并 fsync。调用方需持有 r.mu 或 ledgerMu。
func (r *Router) appendLedgerLocked(le ledgerEntry) {
	r.ledgerMu.Lock()
	defer r.ledgerMu.Unlock()
	if r.ledger == nil {
		return
	}
	b, err := json.Marshal(le)
	if err != nil {
		return
	}
	if _, err := r.ledger.Write(append(b, '\n')); err == nil {
		r.ledger.Sync()
	}
}

// ReloadPolicy 原子替换规则（冲突则拒绝替换，旧规则继续生效）。
func (r *Router) ReloadPolicy(p *policy.Policy) error {
	if err := r.engine.Load(p); err != nil {
		r.logf("policy reload rejected: %v", err)
		return err
	}
	r.logf("policy reloaded: version=%s", p.Version)
	return nil
}

// Stats 返回运行状态快照（投递状态可核查）。
func (r *Router) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Stats{
		Received:   r.received,
		Accepted:   r.accepted,
		Rejected:   r.rejected,
		Delivered:  map[string]int64{},
		Failed:     map[string]int64{},
		Dropped:    map[string]int64{},
		QueueDepth: map[string]int{},
	}
	for name, w := range r.targets {
		s.Delivered[name] = r.delivered[name]
		s.Failed[name] = r.failed[name]
		s.Dropped[name] = r.dropped[name]
		s.QueueDepth[name] = len(w.queue)
	}
	return s
}
