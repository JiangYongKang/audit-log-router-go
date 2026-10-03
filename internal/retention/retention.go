// Package retention 负责按保留期与容量上限，以确定顺序（最旧段优先）清理事件段。
// 轮转与清理都在 store 的互斥保护内完成，与并发写入互不破坏，不会读到半写状态。
//
// 挂配合规冻结注册表（WithFreeze）后：被冻结的记录即使超过保留期或撞上
// 容量清理也不会被删除；含冻结记录的段改为「段内压缩」，只清除其中未冻结
// 的记录。未挂配冻结注册表时，清理行为与不支持冻结的旧版本完全一致。
package retention

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
	"github.com/highcumontoa/audit-log-router-go/internal/store"
)

// Sweeper 周期性执行轮转与清理。
type Sweeper struct {
	st       *store.Store
	hold     *freeze.Registry // 合规冻结注册表；nil 表示不启用冻结（行为同旧版）
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

// WithFreeze 为清理器挂配合规冻结注册表（须在 Start/Sweep 前调用）。
// 挂配后，清理过程在冻结注册表互斥保护下进行，与冻结/解冻/写入互不破坏。
func (s *Sweeper) WithFreeze(hold *freeze.Registry) *Sweeper {
	s.hold = hold
	return s
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
//  3. 活动段从不删除；
//  4. 被合规冻结的记录从不删除：含冻结记录的段改为「段内压缩」，
//     只清除其中未冻结的记录，冻结记录原样保留。
//
// 整个过程在冻结注册表互斥保护下执行，与并发的冻结/解冻/写入互不破坏。
func (s *Sweeper) Sweep(ctx context.Context, now time.Time) (*store.PurgeReport, error) {
	var rep *store.PurgeReport
	err := freeze.Guard(s.hold, func() error {
		r, e := s.sweepLocked(ctx, now)
		if e != nil {
			return e
		}
		rep = r
		return nil
	})
	return rep, err
}

// segAction 描述对一个封存段的确定处理方式。
type segAction struct {
	seg     store.Segment
	reason  string // age_exceeded | age_exceeded_partial_frozen | count_exceeded | count_exceeded_partial_frozen
	compact bool   // true=段内压缩（保留冻结记录）；false=整段删除
	frozenN int    // 段内被冻结记录数
}

func (s *Sweeper) sweepLocked(ctx context.Context, now time.Time) (*store.PurgeReport, error) {
	if s.hold != nil {
		// 对账保险：冻结计数必须始终对应仍留存的记录。
		if n := s.hold.Reconcile(s.st); n > 0 {
			return nil, fmt.Errorf("freeze reconcile removed %d entries (state inconsistency)", n)
		}
	}
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

	frozen := map[int64]bool{}
	if s.hold != nil {
		frozen = s.hold.FrozenSeqsLocked()
	}

	// 每个封存段内冻结记录数（段内 seq 连续，按区间统计）。
	segFrozen := make([]int, len(sealed))
	for i, seg := range sealed {
		if seg.Count == 0 {
			continue
		}
		for seq := seg.StartSeq; seq <= seg.EndSeq; seq++ {
			if frozen[seq] {
				segFrozen[i]++
			}
		}
	}

	planned := map[int]bool{}
	var whole []segAction
	var compact []segAction
	projectedCount := s.st.Count()

	plan := func(a segAction) {
		planned[a.seg.Index] = true
		if a.compact {
			compact = append(compact, a)
			projectedCount -= a.seg.Count - int64(a.frozenN)
		} else {
			whole = append(whole, a)
			projectedCount -= a.seg.Count
		}
	}

	// 阶段 1：超过保留期（从最旧开始，逐记录判定）。
	if s.maxAge > 0 {
		for i, seg := range sealed {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fn := segFrozen[i]
			if fn == 0 {
				oldest, err := s.oldestTimestamp(seg)
				if err != nil {
					return nil, err
				}
				if !oldest.IsZero() && now.Sub(oldest) > s.maxAge {
					plan(segAction{seg: seg, reason: "age_exceeded"})
				}
				continue
			}
			// 段内含冻结记录：逐记录判定，是否存在已超期的未冻结记录。
			expiredUnfrozen, err := s.countExpiredUnfrozen(seg, now, frozen)
			if err != nil {
				return nil, err
			}
			if expiredUnfrozen > 0 {
				plan(segAction{seg: seg, reason: "age_exceeded_partial_frozen",
					compact: true, frozenN: fn})
			}
		}
	}

	// 阶段 2：容量上限挤出（继续从最旧段开始补足）。
	if s.maxCount > 0 {
		// 先整段删除不含冻结记录的最旧段（无需重写文件，优先执行）。
		for i, seg := range sealed {
			if projectedCount <= s.maxCount {
				break
			}
			if planned[seg.Index] || segFrozen[i] > 0 {
				continue
			}
			plan(segAction{seg: seg, reason: "count_exceeded"})
		}
		// 仍超限：从最旧段开始压缩含冻结记录的段，挤出其中未冻结记录。
		for i, seg := range sealed {
			if projectedCount <= s.maxCount {
				break
			}
			if planned[seg.Index] {
				continue
			}
			fn := segFrozen[i]
			if fn == 0 || fn == int(seg.Count) {
				continue // 全冻结：挤不出任何空间
			}
			plan(segAction{seg: seg, reason: "count_exceeded_partial_frozen",
				compact: true, frozenN: fn})
		}
	}

	if len(whole)+len(compact) == 0 {
		return &store.PurgeReport{}, nil
	}

	rep := &store.PurgeReport{}
	var reasons []string

	// 执行整段删除（按索引升序）。
	sort.Slice(whole, func(i, j int) bool { return whole[i].seg.Index < whole[j].seg.Index })
	wholeIdx := make([]int, 0, len(whole))
	for _, a := range whole {
		wholeIdx = append(wholeIdx, a.seg.Index)
		reasons = append(reasons, fmt.Sprintf("seg-%06d(%s,count=%d):%s",
			a.seg.Index, a.seg.StartID, a.seg.Count, a.reason))
	}
	if len(wholeIdx) > 0 {
		wrep, err := s.st.DeleteSegments(wholeIdx)
		if err != nil {
			return nil, err
		}
		rep.DeletedSegments = append(rep.DeletedSegments, wrep.DeletedSegments...)
		rep.DeletedCount += wrep.DeletedCount
	}

	// 执行段内压缩（按索引升序）。保留集依清理原因确定：
	// 保留期：冻结记录 + 未超期记录；容量：只保留冻结记录。
	sort.Slice(compact, func(i, j int) bool { return compact[i].seg.Index < compact[j].seg.Index })
	for _, a := range compact {
		keep := map[int64]bool{}
		if strings.HasPrefix(a.reason, "age_exceeded") {
			lns, err := s.st.ScanLines(context.Background(), a.seg.StartSeq, a.seg.EndSeq+1)
			if err != nil {
				return nil, err
			}
			for _, ln := range lns {
				if frozen[ln.Seq] || now.Sub(ln.Record.Timestamp) <= s.maxAge {
					keep[ln.Seq] = true
				}
			}
		} else {
			for seq := a.seg.StartSeq; seq <= a.seg.EndSeq; seq++ {
				if frozen[seq] {
					keep[seq] = true
				}
			}
		}
		deleted, removed, keptSeg, err := s.st.PurgeSegment(a.seg.Index, keep)
		if err != nil {
			return nil, err
		}
		rep.DeletedCount += deleted
		if removed {
			rep.DeletedSegments = append(rep.DeletedSegments, keptSeg)
		}
		reasons = append(reasons, fmt.Sprintf("seg-%06d(%s,count=%d):%s,deleted=%d,kept=%d",
			a.seg.Index, a.seg.StartID, a.seg.Count, a.reason, deleted, keptSeg.Count))
	}

	sort.Slice(rep.DeletedSegments, func(i, j int) bool {
		return rep.DeletedSegments[i].Index < rep.DeletedSegments[j].Index
	})
	rep.Reason = strings.Join(reasons, "; ")
	return rep, nil
}

// oldestTimestamp 读取段内最早事件时间（扫描该段 seq 区间）。
func (s *Sweeper) oldestTimestamp(seg store.Segment) (time.Time, error) {
	lns, err := s.st.ScanLines(context.Background(), seg.StartSeq, seg.EndSeq+1)
	if err != nil || len(lns) == 0 {
		return time.Time{}, err
	}
	oldest := lns[0].Record.Timestamp
	for _, ln := range lns[1:] {
		if ln.Record.Timestamp.Before(oldest) {
			oldest = ln.Record.Timestamp
		}
	}
	return oldest, nil
}

// countExpiredUnfrozen 统计段内「未冻结且超过保留期」的记录数。
func (s *Sweeper) countExpiredUnfrozen(seg store.Segment, now time.Time, frozen map[int64]bool) (int, error) {
	lns, err := s.st.ScanLines(context.Background(), seg.StartSeq, seg.EndSeq+1)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ln := range lns {
		if frozen[ln.Seq] {
			continue
		}
		if now.Sub(ln.Record.Timestamp) > s.maxAge {
			n++
		}
	}
	return n, nil
}
