// Package retention 负责按保留期与容量上限，以确定顺序（最旧段优先）清理事件段。
//
// 并发正确性（与合规冻结并存时）：
//
//	一次 Sweep 的「取冻结集合快照 -> 逐段冻结判定 -> 超期/容量标记 -> 删除段」
//	全程在 store 的同一把互斥临界区内完成；冻结注册表支持 WithSnapshot 时
//	（freeze.Registry 支持），冻结锁在整段时间内持有，冻结集合对本次清理恒定。
//	锁序固定为 store 锁 -> freeze 锁，与冻结/解冻路径完全一致，无死锁。
//
//	因此清理与并发冻结的交错只有两个确定结果：
//	  - 冻结先提交：清理看到它，段被保护，记录保留可查；
//	  - 清理先提交：记录已删除，随后的冻结在 store 临界区扫描时查不到它
//	    （计入 Skipped），不会留下指向空数据的冻结状态。
//
// 未注册冻结钩子时，清理路径不触碰冻结锁，行为与引入冻结能力前完全一致。
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

// FreezeState 是清理侧需要的最小冻结能力：按记录 ID 查询冻结态。
type FreezeState interface {
	IsFrozen(id string) bool
}

// FreezeSnapshotState 在 FreezeState 之上提供「冻结集合快照」：
// 一次清理在 fn 执行期间看到恒定不变的冻结集合（freeze.Registry 实现该接口）。
type FreezeSnapshotState interface {
	FreezeState
	WithSnapshot(fn func(frozen map[string]struct{}) error) error
}

// Sweeper 周期性执行轮转与清理。
type Sweeper struct {
	st       *store.Store
	interval time.Duration
	maxAge   time.Duration
	maxCount int64
	segBytes int64

	// 冻结钩子（可选）：非 nil 时，含冻结记录的段跳过一切清理。
	// 不设置时行为与引入冻结能力前完全一致。
	hook   FreezeState
	logger *log.Logger

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

// SetFreezeHook 注册冻结判定来源与判定日志（均可在引入冻结能力后接入）。
// hook 为 nil 时恢复为无冻结行为。hook 若实现 FreezeSnapshotState
// （*freeze.Registry 即满足），每次清理会在恒定冻结快照下完成。
// 须在 Start/首次 Sweep 前设置。
func (s *Sweeper) SetFreezeHook(hook FreezeState, logger *log.Logger) {
	s.hook = hook
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
//
// 除轮转外，整个判定与删除是 store 临界区（外加可选的冻结快照锁）内的一个
// 原子事务，中途 ctx 取消或删除出错都不会删掉任何冻结记录，也不会让冻结状态
// 与留存数据长期不一致。
func (s *Sweeper) Sweep(ctx context.Context, now time.Time) (*store.PurgeReport, error) {
	rep := &store.PurgeReport{}
	// 轮转 + 判定 + 删除必须在同一个 store 临界区内：
	// Rotate 涉及「关闭活动 fd -> rename -> 开新 fd」，若与并发 Append 交错，
	// Append 可能拿着已关闭的旧 fd 写入而丢失数据（内存计数增加、磁盘没有）。
	err := s.st.RunLocked(func() error {
		if s.segBytes > 0 && s.st.ActiveBytesLocked() >= s.segBytes {
			if err := s.st.RotateLocked(); err != nil {
				return fmt.Errorf("rotate: %w", err)
			}
		}
		return s.sweepLocked(ctx, now, rep)
	})
	if err != nil {
		return rep, err
	}
	return rep, nil
}

// sweepLocked 在持有 store 锁期间执行全部判定与删除。
func (s *Sweeper) sweepLocked(ctx context.Context, now time.Time, rep *store.PurgeReport) error {
	segs := s.st.SegmentsLocked()
	sealed := segs
	if len(sealed) > 0 && !sealed[len(sealed)-1].Sealed {
		sealed = sealed[:len(sealed)-1] // 排除活动段
	}

	// 取恒定冻结视图：优先用快照能力（整段持有冻结锁）；退化时逐条查询。
	// 即便退化，store 临界区也保证并发冻结（需 store 锁）无法插入；
	// 只有不经过 store 的 UnfreezeIDs 可能变化，故生产路径应使用 *freeze.Registry。
	var frozenSet map[string]struct{}
	snapshotHook, canSnapshot := s.hook.(FreezeSnapshotState)
	if s.hook != nil && canSnapshot {
		if err := snapshotHook.WithSnapshot(func(frozen map[string]struct{}) error {
			frozenSet = frozen
			return nil
		}); err != nil {
			return err
		}
	}
	isFrozen := func(id string) bool {
		if frozenSet != nil {
			_, ok := frozenSet[id]
			return ok
		}
		return s.hook != nil && s.hook.IsFrozen(id)
	}

	type segInfo struct {
		seg    store.Segment
		frozen bool
		oldest time.Time
	}
	infos := make([]segInfo, 0, len(sealed))
	frozenSeg := map[int]bool{}
	var frozenProtected int64

	// 每段只扫描一次：同时得到「是否含冻结记录」与「段内最早事件时间」。
	for _, seg := range sealed {
		if err := ctx.Err(); err != nil {
			return err // 尚未删除任何段：状态与调用前完全一致
		}
		recs, err := s.st.ScanSeqsLocked(ctx, seg.StartSeq, seg.EndSeq+1)
		if err != nil {
			return err
		}
		info := segInfo{seg: seg}
		for _, r := range recs {
			if isFrozen(r.ID) {
				info.frozen = true
			}
			if info.oldest.IsZero() || r.Timestamp.Before(info.oldest) {
				info.oldest = r.Timestamp
			}
		}
		if info.frozen {
			frozenSeg[seg.Index] = true
			frozenProtected += seg.Count
			s.logf("retention: segment %06d kept (frozen_hold, count=%d)", seg.Index, seg.Count)
		}
		infos = append(infos, info)
	}

	type mark struct {
		seg    store.Segment
		reason string
	}
	var marks []mark
	indexes := map[int]bool{}
	projectedCount := s.st.CountLocked()

	// 阶段 1：超过保留期的段（从最旧开始）。
	if s.maxAge > 0 {
		for _, info := range infos {
			if err := ctx.Err(); err != nil {
				return err
			}
			if info.frozen {
				continue
			}
			if !info.oldest.IsZero() && now.Sub(info.oldest) > s.maxAge {
				marks = append(marks, mark{info.seg, "age_exceeded"})
				indexes[info.seg.Index] = true
				projectedCount -= info.seg.Count
			}
		}
	}

	// 阶段 2：容量上限挤出（继续从最旧段开始补足；冻结段不可挤出）。
	if s.maxCount > 0 {
		for _, info := range infos {
			if projectedCount <= s.maxCount {
				break
			}
			if !indexes[info.seg.Index] && !info.frozen {
				marks = append(marks, mark{info.seg, "count_exceeded"})
				indexes[info.seg.Index] = true
				projectedCount -= info.seg.Count
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
		for _, info := range infos {
			if info.frozen {
				idxs = append(idxs, fmt.Sprintf("%06d", info.seg.Index))
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
		rep.Reason = strings.Join(reasons, "; ")
		return nil
	}

	idxs := make([]int, 0, len(marks))
	for _, m := range marks {
		idxs = append(idxs, m.seg.Index)
	}
	sort.Ints(idxs)

	// 删除仍在同一临界区 + 同一冻结快照内：自冻结判定以来集合不可能变化，
	// 被删段中保证没有任何冻结记录。
	deleted, err := s.st.DeleteSegmentsLocked(idxs)
	if err != nil {
		// deleteSegmentsLocked 出错时内存状态仍自洽（已删文件的段已摘除），
		// 且被删段都经过上面的冻结判定，不含冻结记录。
		rep.DeletedSegments = deleted.DeletedSegments
		rep.DeletedCount = deleted.DeletedCount
		return err
	}
	rep.DeletedSegments = deleted.DeletedSegments
	rep.DeletedCount = deleted.DeletedCount
	rep.Reason = strings.Join(reasons, "; ")
	return nil
}
