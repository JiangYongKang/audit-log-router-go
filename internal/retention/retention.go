// Package retention 负责按保留期与容量上限，以确定顺序（最旧段优先）清理事件段。
// 轮转与清理都在 store 的互斥保护内完成，与并发写入互不破坏，不会读到半写状态。
package retention

import (
	"context"
	"fmt"
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

	// 阶段 1：超过保留期的段（从最旧开始）。
	if s.maxAge > 0 {
		for _, seg := range sealed {
			if err := ctx.Err(); err != nil {
				return nil, err
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

	// 阶段 2：容量上限挤出（继续从最旧段开始补足）。
	if s.maxCount > 0 {
		for _, seg := range sealed {
			if projectedCount <= s.maxCount {
				break
			}
			if !indexes[seg.Index] {
				marks = append(marks, mark{seg, "count_exceeded"})
				indexes[seg.Index] = true
				projectedCount -= seg.Count
			}
		}
	}

	if len(marks) == 0 {
		return &store.PurgeReport{}, nil
	}

	idxs := make([]int, 0, len(marks))
	var reasons []string
	for _, m := range marks {
		idxs = append(idxs, m.seg.Index)
		reasons = append(reasons, fmt.Sprintf("seg-%06d(%s,count=%d):%s",
			m.seg.Index, m.seg.StartID, m.seg.Count, m.reason))
	}
	sort.Ints(idxs)
	rep, err := s.st.DeleteSegments(idxs)
	if err != nil {
		return nil, err
	}
	rep.Reason = strings.Join(reasons, "; ")
	return rep, nil
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
