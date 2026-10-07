// Package store 提供基于本地文件的 append-only 事件留存存储。
//
// 布局：
//
//	<dir>/events-active.log   活动段（只允许追加）
//	<dir>/events-000001.log   已封存的轮转段（只读，可被清理删除）
//
// 崩溃恢复：Open 时按行重放所有段，截断末尾的半写行。
// 并发：所有读写共用一把互斥锁，读不到半写状态。
package store

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

const activeName = "events-active.log"

// Segment 表示一个留存段（活动段或已封存的段）。
type Segment struct {
	Path     string
	Index    int
	StartID  string
	EndID    string
	StartSeq int64
	EndSeq   int64
	Count    int64
	Sealed   bool
	Size     int64
}

// PurgeReport 解释一次清理删除了什么（结果可解释、可审计）。
type PurgeReport struct {
	DeletedSegments []Segment
	DeletedCount    int64
	Reason          string
}

// Store 管理事件日志段。
type Store struct {
	dir       string
	mu        sync.Mutex
	active    *os.File
	activeSeg Segment
	sealed    []Segment // 按 Index 升序
	lastSeq   int64
}

// Open 打开（必要时创建）存储目录并重放已有段。
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}

	// 收集已封存段。
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var sealedPaths []string
	for _, e := range entries {
		name := e.Name()
		if name == activeName {
			continue
		}
		var idx int
		if n, err := fmt.Sscanf(name, "events-%d.log", &idx); n == 1 && err == nil {
			sealedPaths = append(sealedPaths, name)
		}
	}
	sort.Strings(sealedPaths)

	for _, name := range sealedPaths {
		var idx int
		fmt.Sscanf(name, "events-%d.log", &idx)
		seg, err := s.replaySegment(filepath.Join(dir, name), idx, true)
		if err != nil {
			return nil, err
		}
		s.sealed = append(s.sealed, seg)
	}

	// 重放活动段（截断半写行）。
	activePath := filepath.Join(dir, activeName)
	activeIdx := 0
	if len(s.sealed) > 0 {
		activeIdx = s.sealed[len(s.sealed)-1].Index + 1
	}
	seg, err := s.replaySegment(activePath, activeIdx, false)
	if err != nil {
		return nil, err
	}
	s.activeSeg = seg

	f, err := os.OpenFile(activePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s.active = f
	return s, nil
}

// replaySegment 逐行读取段文件，统计记录并截断末尾半写行。
func (s *Store) replaySegment(path string, idx int, sealed bool) (Segment, error) {
	seg := Segment{Path: path, Index: idx, Sealed: sealed}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return seg, nil
	}
	if err != nil {
		return seg, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	var goodOffset int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		ln, err := event.DecodeLine(line)
		if err != nil {
			// 半写行：截断到上一个完整行末尾。
			break
		}
		goodOffset += int64(len(line)) + 1
		if seg.Count == 0 {
			seg.StartSeq = ln.Seq
			seg.StartID = ln.Record.ID
		}
		seg.EndSeq = ln.Seq
		seg.EndID = ln.Record.ID
		seg.Count++
		if ln.Seq > s.lastSeq {
			s.lastSeq = ln.Seq
		}
	}
	seg.Size = goodOffset

	fi, err := os.Stat(path)
	if err == nil && fi.Size() > goodOffset {
		if err := os.Truncate(path, goodOffset); err != nil {
			return seg, fmt.Errorf("truncate partial tail of %s: %w", path, err)
		}
	}
	return seg, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil {
		err := s.active.Close()
		s.active = nil
		return err
	}
	return nil
}

// ErrCapacityRejected 表示在原子容量门控下，留存已达上限且当前没有可回收段
// （全部封存段含冻结记录，或只有活动段），写入被明确拒绝。
var ErrCapacityRejected = errors.New("store: retention capacity reached and no reclaimable segment")

// Append 原子追加一条记录并返回分配的单调序号。写后 fsync，重启不丢。
func (s *Store) Append(r event.Record) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(r)
}

// AppendGated 在同一把存储锁内原子完成「容量门控判定 + 追加」：
// 先调用 gate（锁序允许 gate 内取冻结锁），gate 返回 ErrCapacityRejected
// 时拒绝写入；否则立即追加。判定与追加之间不会插入轮转/清理/并发追加，
// 因此不会出现「门控通过但下一刻记录被挤出」或二者结论不一致。
func (s *Store) AppendGated(r event.Record, gate func() error) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gate != nil {
		if err := gate(); err != nil {
			return 0, err
		}
	}
	return s.appendLocked(r)
}

func (s *Store) appendLocked(r event.Record) (int64, error) {
	seq := s.lastSeq + 1
	b, err := event.EncodeLine(seq, r)
	if err != nil {
		return 0, err
	}
	if _, err := s.active.Write(b); err != nil {
		return 0, err
	}
	if err := s.active.Sync(); err != nil {
		return 0, err
	}
	if s.activeSeg.Count == 0 {
		s.activeSeg.StartSeq = seq
		s.activeSeg.StartID = r.ID
	}
	s.activeSeg.EndSeq = seq
	s.activeSeg.EndID = r.ID
	s.activeSeg.Count++
	s.activeSeg.Size += int64(len(b))
	s.lastSeq = seq
	return seq, nil
}

// RunLocked 在持有存储全局互斥锁期间执行 fn。
//
// 用途：把「扫描判定 + 变更（删除段/确认记录存在）」合成一个原子事务，
// 与并发追加、轮转、冻结注册表的存在性检查互斥，杜绝「判定时未冻结、
// 删除时已冻结」之类的交错矛盾。
//
// 锁序约定：允许 store 锁 -> freeze 锁；fn 内可以调用冻结注册表的
// 加锁方法（如 IsFrozen / apply / WithSnapshot），但禁止反向持锁。
func (s *Store) RunLocked(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}

// ScanSeqs 返回 [from,to) 范围内 seq 的记录；to<=0 表示到最新。
func (s *Store) ScanSeqs(ctx context.Context, from int64, to int64) ([]event.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanSeqsLocked(ctx, from, to)
}

// ScanSeqsLocked 同 ScanSeqs，但调用方必须已通过 RunLocked 持有存储锁。
func (s *Store) ScanSeqsLocked(ctx context.Context, from int64, to int64) ([]event.Record, error) {
	return s.scanSeqsLocked(ctx, from, to)
}

func (s *Store) scanSeqsLocked(ctx context.Context, from int64, to int64) ([]event.Record, error) {
	var out []event.Record
	paths := make([]string, 0, len(s.sealed)+1)
	for _, seg := range s.sealed {
		paths = append(paths, seg.Path)
	}
	paths = append(paths, filepath.Join(s.dir, activeName))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		recs, err := scanFile(p, from, to)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

func scanFile(path string, from, to int64) ([]event.Record, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []event.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		ln, err := event.DecodeLine(line)
		if err != nil {
			break // 半写行
		}
		if ln.Seq < from {
			continue
		}
		if to > 0 && ln.Seq >= to {
			return out, nil
		}
		out = append(out, ln.Record)
	}
	return out, sc.Err()
}

// LastSeq 返回最近一次写入的单调序号。
func (s *Store) LastSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// SnapshotRecords 在同一把存储锁内返回现存全部记录与计数，保证二者来自同一
// 一致性视图（并发轮转/删除/写入不会插入其间）。供一致性校验使用。
func (s *Store) SnapshotRecords(ctx context.Context) ([]event.Record, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.scanSeqsLocked(ctx, 0, 0)
	if err != nil {
		return nil, 0, err
	}
	return recs, s.countLocked(), nil
}

// ReclaimableCount 统计「可被清理回收」的记录数：不含冻结记录的封存段之记录总数。
// isFrozen 为 nil 时等价于无冻结（所有封存段均可回收）。
// 活动段不可删除，因此永远不计入可回收。
// 调用方可在持锁回调中查询冻结状态（锁序：store 锁 -> 冻结锁）。
func (s *Store) ReclaimableCount(isFrozen func(id string) bool) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reclaimableCountLocked(isFrozen)
}

// ReclaimableCountLocked 同 ReclaimableCount，调用方必须已持有存储锁。
func (s *Store) ReclaimableCountLocked(isFrozen func(id string) bool) (int64, error) {
	return s.reclaimableCountLocked(isFrozen)
}

func (s *Store) reclaimableCountLocked(isFrozen func(id string) bool) (int64, error) {
	var n int64
	for _, seg := range s.sealed {
		if isFrozen == nil {
			n += seg.Count
			continue
		}
		recs, err := scanFile(seg.Path, seg.StartSeq, seg.EndSeq+1)
		if err != nil {
			return n, err
		}
		frozen := false
		for _, rec := range recs {
			if isFrozen(rec.ID) {
				frozen = true
				break
			}
		}
		if !frozen {
			n += seg.Count
		}
	}
	return n, nil
}

// Count 返回当前留存的事件总数（活动段 + 封存段）。
func (s *Store) Count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.countLocked()
}

// CountLocked 同 Count，调用方必须已持有存储锁。
func (s *Store) CountLocked() int64 { return s.countLocked() }

func (s *Store) countLocked() int64 {
	n := s.activeSeg.Count
	for _, seg := range s.sealed {
		n += seg.Count
	}
	return n
}

// Rotate 封存当前活动段并开启新段。空活动段不产生封存段。
func (s *Store) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateLocked()
}

// RotateLocked 同 Rotate，调用方必须已通过 RunLocked 持有存储锁。
// 这让清理流程可以把「轮转 + 清理判定 + 删除」合成一个原子临界区，
// 避免轮转过程（关 fd / rename / 开新 fd）与并发 Append 交错而丢数据。
func (s *Store) RotateLocked() error { return s.rotateLocked() }

func (s *Store) rotateLocked() error {
	if s.activeSeg.Count == 0 {
		return nil
	}
	if err := s.active.Close(); err != nil {
		return err
	}
	oldPath := filepath.Join(s.dir, activeName)
	newPath := filepath.Join(s.dir, fmt.Sprintf("events-%06d.log", s.activeSeg.Index))
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	seg := s.activeSeg
	seg.Path = newPath
	seg.Sealed = true
	s.sealed = append(s.sealed, seg)

	s.activeSeg = Segment{Path: oldPath, Index: seg.Index + 1}
	f, err := os.OpenFile(oldPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	s.active = f
	return nil
}

// Segments 返回所有段（封存段在前，活动段最后）的快照。
func (s *Store) Segments() []Segment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.segmentsLocked()
}

// SegmentsLocked 同 Segments，调用方必须已持有存储锁。
func (s *Store) SegmentsLocked() []Segment { return s.segmentsLocked() }

func (s *Store) segmentsLocked() []Segment {
	out := make([]Segment, 0, len(s.sealed)+1)
	out = append(out, s.sealed...)
	out = append(out, s.activeSeg)
	return out
}

// ActiveBytes 返回活动段当前字节数。
func (s *Store) ActiveBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeSeg.Size
}

// ActiveBytesLocked 同 ActiveBytes，调用方必须已持有存储锁。
func (s *Store) ActiveBytesLocked() int64 { return s.activeSeg.Size }

// DeleteSegments 按段索引删除封存段（确定顺序：按索引升序）。
// 活动段不可删除。返回解释性报告。
//
// 注意：该方法只执行删除，不与任何冻结判定互斥组合。清理流程应使用
// Store.RunLocked 把「冻结判定 + DeleteSegmentsLocked」放进同一临界区，
// 否则仍可能与并发冻结互相打架。
func (s *Store) DeleteSegments(indexes []int) (*PurgeReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteSegmentsLocked(indexes)
}

// DeleteSegmentsLocked 同 DeleteSegments，调用方必须已通过 RunLocked 持有存储锁。
func (s *Store) DeleteSegmentsLocked(indexes []int) (*PurgeReport, error) {
	return s.deleteSegmentsLocked(indexes)
}

func (s *Store) deleteSegmentsLocked(indexes []int) (*PurgeReport, error) {
	sort.Ints(indexes)
	rep := &PurgeReport{}
	// keep 使用独立底层数组（不能写 s.sealed[:0]）：否则删除后旧数组尾部槽位
	// 仍被新切片引用，之后 Rotate append 新封存段时会覆盖这些槽位，使新段
	// 在下次清理时被误删、Count 与扫描结果漂移。
	keep := make([]Segment, 0, len(s.sealed))
	var firstErr error
	for _, seg := range s.sealed {
		del := false
		for _, idx := range indexes {
			if seg.Index == idx {
				del = true
				break
			}
		}
		if !del {
			keep = append(keep, seg)
			continue
		}
		if err := os.Remove(seg.Path); err != nil && !os.IsNotExist(err) {
			// 出错即停：该段文件未能确认删除，必须继续保留在 s.sealed 中；
			// 同时后续所有段也原样保留。把当前段与剩余段全部追加回 keep，
			// 这样不会出现「文件还在磁盘、内存却不再统计/扫描」的漂移。
			// 已成功删除的段（rep 中记录）则保持删除，结论可核查。
			keep = append(keep, seg)
			s.sealed = append(keep, remainingSegments(s.sealed, seg.Index)...)
			firstErr = err
			break
		}
		rep.DeletedSegments = append(rep.DeletedSegments, seg)
		rep.DeletedCount += seg.Count
	}
	if firstErr == nil {
		s.sealed = keep
	}
	return rep, firstErr
}

// remainingSegments 返回 sealed 中索引严格大于 afterIndex 的段（按原顺序）。
func remainingSegments(sealed []Segment, afterIndex int) []Segment {
	var out []Segment
	past := false
	for _, seg := range sealed {
		if past {
			out = append(out, seg)
			continue
		}
		if seg.Index == afterIndex {
			past = true
		}
	}
	return out
}
