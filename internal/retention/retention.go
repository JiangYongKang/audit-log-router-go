// Package retention 负责按保留期与容量上限，以确定顺序（最旧段优先）清理事件段。
// 轮转与清理都在 store 的互斥保护内完成，与并发写入互不破坏，不会读到半写状态。
package retention

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

// Sweeper 周期性执行轮转与清理。
type Sweeper struct {
	st       *store.Store
	interval time.Duration
	maxAge   time.Duration
	maxCount int64
	segBytes int64

	// 冻结钩子（可选）：非 nil 时，含冻结记录的段跳过一切清理。
	// 不设置时行为与引入冻结能力前完全一致。
	isFrozen func(id string) bool
	logger   *log.Logger

	cancel func()
	done   chan struct{}
}

func New(st *store.Store, interval, maxAge time.Duration, maxCount, segBytes int64) *Sweeper {
	return &Sweeper{
		st:       st,
		interval: interval,
		maxAge:   maxAge,
		maxCount: maxCount,
		segBytes: segBytes,
	}
}

// SetFreezeHook 注册冻结判定函数与判定日志（均可在引入冻结能力后接入）。
// isFrozen 为 nil 时恢复为无冻结行为。须在 Start/首次 Sweep 前设置。
func (s *Sweeper) SetFreezeHook(isFrozen func(id string) bool, logger *log.Logger) {
	s.isFrozen = isFrozen
	s.logger = logger
}

func (s *Sweeper) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

// Start 启动后台清理循环。
func (s *Sweeper) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = s.Sweep(ctx, time.Now())
			}
		}
	}()
}

func (s *Sweeper) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

// Sweep 执行一次「必要时轮转 + 超期清理 + 容量挤出」，返回解释性报告。
//
// 删除顺序完全确定：
//  1. 段索引最旧（即事件最早）优先；
//  2. 先按保留期标记，再按容量上限补足；
//  3. 活动段从不删除。
func (s *Sweeper) Sweep(ctx context.Context, now time.Time) (*store.PurgeReport, error) {
	if s.segBytes > 0 && s.st.ActiveBytes() >= s.segBytes {
		if err := s.st.Rotate(); err != nil {
			return nil, fmt.Errorf("rotate: %w", err)
		}
	}

	segs := s.st.Segments()
	sealed := segs
	if len(sealed) > 0 && !sealed[len(sealed)-1].Sealed {
		sealed = sealed[:len(sealed)-1] // 排除活动段
	}

	type mark struct {
		seg    store.Segment
		reason string
	}
	var marks []mark
	indexes := map[int]bool{}
	projectedCount := s.st.Count()

	// 冻结判定：含冻结记录的段从两个阶段候选中剔除，理由可核查。
	frozenSeg := map[int]bool{}
	var frozenProtected int64
	if s.isFrozen != nil {
		for _, seg := range sealed {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			has, err := s.segHasFrozen(seg)
			if err != nil {
				return nil, err
			}
			if has {
				frozenSeg[seg.Index] = true
				frozenProtected += seg.Count
				s.logf("retention: segment %06d kept (frozen_hold, count=%d)", seg.Index, seg.Count)
			}
		}
	}

	// 阶段 1：超过保留期的段（从最旧开始）。
	if s.maxAge > 0 {
		for _, seg := range sealed {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if frozenSeg[seg.Index] {
				continue
			}
			oldest, err := s.oldestTimestamp(seg)
			if err != nil {
				return nil, err
			}
			if !oldest.IsZero() && now.Sub(oldest) > s.maxAge {
				marks = append(marks, mark{seg, "age_exceeded"})
				indexes[seg.Index] = true
				projectedCount -= seg.Count
			}
		}
	}

	// 阶段 2：容量上限挤出（继续从最旧段开始补足；冻结段不可挤出）。
	if s.maxCount > 0 {
		for _, seg := range sealed {
			if projectedCount <= s.maxCount {
				break
			}
			if !indexes[seg.Index] && !frozenSeg[seg.Index] {
				marks = append(marks, mark{seg, "count_exceeded"})
				indexes[seg.Index] = true
				projectedCount -= seg.Count
			}
		}
	}

	var reasons []string
	for _, m := range marks {
		reasons = append(reasons, fmt.Sprintf("seg-%06d(%s,count=%d):%s",
			m.seg.Index, m.seg.StartID, m.seg.Count, m.reason))
	}

	// 冻结跳过的段写入报告理由；冻结占用导致无法回收到上限以下时，
	// 给出确定、可解释的结论，而不是静默超量。
	if len(frozenSeg) > 0 {
		var idxs []string
		for _, seg := range sealed {
			if frozenSeg[seg.Index] {
				idxs = append(idxs, fmt.Sprintf("%06d", seg.Index))
			}
		}
		sort.Strings(idxs)
		reasons = append(reasons, fmt.Sprintf("kept_frozen_segments=%s", strings.Join(idxs, ",")))
		if s.maxCount > 0 && projectedCount > s.maxCount {
			s.logf("retention: capacity cannot be fully reclaimed: projected=%d > max=%d, %d record(s) in %d segment(s) protected by freeze",
				projectedCount, s.maxCount, frozenProtected, len(frozenSeg))
			reasons = append(reasons, fmt.Sprintf("capacity_unreclaimable:projected=%d,max=%d,frozen_protected=%d",
				projectedCount, s.maxCount, frozenProtected))
		}
	}

	if len(marks) == 0 {
		return &store.PurgeReport{Reason: strings.Join(reasons, "; ")}, nil
	}

	idxs := make([]int, 0, len(marks))
	for _, m := range marks {
		idxs = append(idxs, m.seg.Index)
	}
	sort.Ints(idxs)
	// 删除前在 store 锁内复核冻结状态：标记之后、删除之前新冻结的记录
	// 所在段会被保留并记入报告，杜绝「检查后被冻结、仍被删除」的交错。
	rep, err := s.st.DeleteSegments(idxs, s.isFrozen)
	if err != nil {
		return nil, err
	}
	for _, seg := range rep.KeptFrozenSegments {
		s.logf("retention: segment %06d kept at delete time (frozen_hold, count=%d)", seg.Index, seg.Count)
		reasons = append(reasons, fmt.Sprintf("seg-%06d kept: frozen_at_delete", seg.Index))
	}
	rep.Reason = strings.Join(reasons, "; ")
	return rep, nil
}

// segHasFrozen 判断段内是否含冻结记录（扫描该段 seq 区间）。
func (s *Sweeper) segHasFrozen(seg store.Segment) (bool, error) {
	recs, err := s.st.ScanSeqs(context.Background(), seg.StartSeq, seg.EndSeq+1)
	if err != nil {
		return false, err
	}
	for _, rec := range recs {
		if s.isFrozen(rec.ID) {
			return true, nil
		}
	}
	return false, nil
}

// oldestTimestamp 读取段内最早事件时间（扫描该段 seq 区间）。
func (s *Sweeper) oldestTimestamp(seg store.Segment) (time.Time, error) {
	recs, err := s.st.ScanSeqs(context.Background(), seg.StartSeq, seg.EndSeq+1)
	if err != nil || len(recs) == 0 {
		return time.Time{}, err
	}
	oldest := recs[0].Timestamp
	for _, r := range recs[1:] {
		if r.Timestamp.Before(oldest) {
			oldest = r.Timestamp
		}
	}
	return oldest, nil
}
