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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
	"github.com/highcumontoa/audit-log-router-go/internal/freeze"
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
	idToSeq   map[string]int64 // 事件 ID -> 序号（重放与追加时维护，供合规冻结解析）
}

// Open 打开（必要时创建）存储目录并重放已有段。
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, idToSeq: map[string]int64{}}

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
		s.idToSeq[ln.Record.ID] = ln.Seq
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

// Append 原子追加一条记录并返回分配的单调序号。写后 fsync，重启不丢。
func (s *Store) Append(r event.Record) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.idToSeq[r.ID] = seq
	return seq, nil
}

// ScanSeqs 返回 [from,to) 范围内 seq 的记录；to<=0 表示到最新。
func (s *Store) ScanSeqs(ctx context.Context, from int64, to int64) ([]event.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		lns, err := scanLinesFile(p, from, to)
		if err != nil {
			return nil, err
		}
		for _, ln := range lns {
			out = append(out, ln.Record)
		}
	}
	return out, nil
}

// scanLines 与 ScanSeqs 相同，但返回带序号的整行（冻结条件解析用）。
func (s *Store) ScanLines(ctx context.Context, from, to int64) ([]event.Line, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []event.Line
	paths := make([]string, 0, len(s.sealed)+1)
	for _, seg := range s.sealed {
		paths = append(paths, seg.Path)
	}
	paths = append(paths, filepath.Join(s.dir, activeName))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lns, err := scanLinesFile(p, from, to)
		if err != nil {
			return nil, err
		}
		out = append(out, lns...)
	}
	return out, nil
}

func scanLinesFile(path string, from, to int64) ([]event.Line, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []event.Line
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
		out = append(out, ln)
	}
	return out, sc.Err()
}

func scanFile(path string, from, to int64) ([]event.Record, error) {
	lns, err := scanLinesFile(path, from, to)
	if err != nil {
		return nil, err
	}
	out := make([]event.Record, 0, len(lns))
	for _, ln := range lns {
		out = append(out, ln.Record)
	}
	return out, nil
}

func (s *Store) LastSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// Count 返回当前留存的事件总数（活动段 + 封存段）。
func (s *Store) Count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64 = s.activeSeg.Count
	for _, seg := range s.sealed {
		n += seg.Count
	}
	return n
}

// Rotate 封存当前活动段并开启新段。空活动段不产生封存段。
func (s *Store) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// DeleteSegments 按段索引删除封存段（确定顺序：按索引升序）。
// 活动段不可删除。返回解释性报告。
func (s *Store) DeleteSegments(indexes []int) (*PurgeReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sort.Ints(indexes)
	rep := &PurgeReport{}
	keep := s.sealed[:0]
	deletedRanges := make([][2]int64, 0, len(indexes))
	for _, seg := range s.sealed {
		del := false
		for _, idx := range indexes {
			if seg.Index == idx {
				del = true
				break
			}
		}
		if del {
			if err := os.Remove(seg.Path); err != nil && !os.IsNotExist(err) {
				return rep, err
			}
			rep.DeletedSegments = append(rep.DeletedSegments, seg)
			rep.DeletedCount += seg.Count
			deletedRanges = append(deletedRanges, [2]int64{seg.StartSeq, seg.EndSeq})
		} else {
			keep = append(keep, seg)
		}
	}
	s.sealed = keep
	// 维护 ID->序号索引：段内序号连续且段间不重叠，按区间精确移除。
	if len(deletedRanges) > 0 {
		for id, seq := range s.idToSeq {
			for _, rng := range deletedRanges {
				if seq >= rng[0] && seq <= rng[1] {
					delete(s.idToSeq, id)
					break
				}
			}
		}
	}
	return rep, nil
}

// LookupSeq 返回事件 ID 对应的单调序号；不存在返回 (0,false,nil)。
// 供合规冻结注册表把事件标识解析为内部序号。
func (s *Store) LookupSeq(id string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, ok := s.idToSeq[id]
	return seq, ok, nil
}

// ScanViews 按 seq 升序返回当前全部留存记录的视图快照（供条件冻结匹配）。
func (s *Store) ScanViews() ([]freeze.RecordView, error) {
	lines, err := s.ScanLines(context.Background(), 0, 0)
	if err != nil {
		return nil, err
	}
	out := make([]freeze.RecordView, 0, len(lines))
	for _, ln := range lines {
		r := ln.Record
		out = append(out, freeze.RecordView{
			Seq:       ln.Seq,
			ID:        r.ID,
			Type:      r.Type,
			Source:    r.Source,
			Actor:     r.Actor,
			Timestamp: r.Timestamp,
		})
	}
	return out, nil
}

// HasSeq 判断某序号当前是否仍被留存（供冻结注册表与存储对账）。
func (s *Store) HasSeq(seq int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 先用段区间快速排除，再扫描确认（清理后 seq 可能存在空洞）。
	possible := false
	for _, seg := range s.sealed {
		if seg.Count > 0 && seq >= seg.StartSeq && seq <= seg.EndSeq {
			possible = true
			break
		}
	}
	seg := s.activeSeg
	if !possible && seg.Count > 0 && seq >= seg.StartSeq && seq <= seg.EndSeq {
		possible = true
	}
	if !possible {
		return false
	}
	lns, err := scanLinesFile(filepath.Join(s.dir, activeName), seq, seq+1)
	if err != nil {
		return false
	}
	for _, l := range lns {
		if l.Seq == seq {
			return true
		}
	}
	for _, sp := range s.sealed {
		if sp.Count == 0 || seq < sp.StartSeq || seq > sp.EndSeq {
			continue
		}
		lns, err := scanLinesFile(sp.Path, seq, seq+1)
		if err != nil {
			return false
		}
		for _, l := range lns {
			if l.Seq == seq {
				return true
			}
		}
	}
	return false
}

// PurgeSegment 对一个封存段做记录级清理：仅保留 keepSeqs 中的记录，
// 其余记录被确定性删除。用于「段内部分记录被合规冻结」的场景：
// 已冻结记录原样保留（序号/内容不变），未冻结记录被清走。
//
// 返回被删除的记录数；若清理后段为空，则删除整个段文件并返回 removed=true。
// 实现为先写临时文件并 fsync、再原子 rename，崩溃不会产生半写段。
func (s *Store) PurgeSegment(index int, keepSeqs map[int64]bool) (deleted int64, removed bool, keptSeg Segment, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pos := -1
	for i := range s.sealed {
		if s.sealed[i].Index == index {
			pos = i
			break
		}
	}
	if pos < 0 {
		return 0, false, Segment{}, fmt.Errorf("segment %d not found or not sealed", index)
	}
	seg := s.sealed[pos]

	lns, err := scanLinesFile(seg.Path, seg.StartSeq, seg.EndSeq+1)
	if err != nil {
		return 0, false, Segment{}, err
	}
	var keep []event.Line
	deletedIDs := map[string]bool{}
	for _, ln := range lns {
		if keepSeqs[ln.Seq] {
			keep = append(keep, ln)
		} else {
			deleted++
			deletedIDs[ln.Record.ID] = true
		}
	}

	if len(keep) == 0 {
		// 没有需要保留的记录：直接删除整个段。
		if rmErr := os.Remove(seg.Path); rmErr != nil && !os.IsNotExist(rmErr) {
			return 0, false, Segment{}, rmErr
		}
		s.sealed = append(s.sealed[:pos], s.sealed[pos+1:]...)
		for id := range deletedIDs {
			delete(s.idToSeq, id)
		}
		emptySeg := seg
		emptySeg.Count = 0
		return deleted, true, emptySeg, nil
	}

	tmpPath := seg.Path + ".compact.tmp"
	tf, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, false, Segment{}, err
	}
	var newSize int64
	for _, ln := range keep {
		b, encErr := event.EncodeLine(ln.Seq, ln.Record)
		if encErr != nil {
			tf.Close()
			os.Remove(tmpPath)
			return 0, false, Segment{}, encErr
		}
		if _, werr := tf.Write(b); werr != nil {
			tf.Close()
			os.Remove(tmpPath)
			return 0, false, Segment{}, werr
		}
		newSize += int64(len(b))
	}
	if err := tf.Sync(); err != nil {
		tf.Close()
		os.Remove(tmpPath)
		return 0, false, Segment{}, err
	}
	if err := tf.Close(); err != nil {
		os.Remove(tmpPath)
		return 0, false, Segment{}, err
	}
	if err := os.Rename(tmpPath, seg.Path); err != nil {
		os.Remove(tmpPath)
		return 0, false, Segment{}, err
	}

	newSeg := Segment{
		Path:     seg.Path,
		Index:    seg.Index,
		StartID:  keep[0].Record.ID,
		EndID:    keep[len(keep)-1].Record.ID,
		StartSeq: keep[0].Seq,
		EndSeq:   keep[len(keep)-1].Seq,
		Count:    int64(len(keep)),
		Sealed:   true,
		Size:     newSize,
	}
	s.sealed[pos] = newSeg
	for id := range deletedIDs {
		delete(s.idToSeq, id)
	}
	return deleted, false, newSeg, nil
}
