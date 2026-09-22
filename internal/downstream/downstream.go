// Package downstream 定义下游投递目标抽象与本地文件模拟实现。
package downstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/highcumontoa/audit-log-router-go/internal/event"
)

// ErrUnavailable 表示目标暂时不可用（可重试）。
var ErrUnavailable = errors.New("downstream unavailable")

// Target 是单个下游投递目标。实现必须保证：对同一事件 ID 的重复投递
// 可被识别（幂等），即重复投递不产生第二条记录。
type Target interface {
	Name() string
	Deliver(ctx context.Context, r event.Record) error
	Close() error
}

// FileTarget 将事件以 JSON 行追加写入本地文件，模拟一个下游系统。
// 内部维护已见事件 ID 集合，重复投递被识别并忽略（幂等去重）。
type FileTarget struct {
	name string
	mu   sync.Mutex
	f    *os.File
	seen map[string]struct{}
	Dups int64 // 被识别为重复的投递次数
}

func NewFileTarget(name, dir string) (*FileTarget, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	t := &FileTarget{name: name, seen: map[string]struct{}{}}
	path := filepath.Join(dir, name+".log")
	// 重放已有文件以恢复去重集合（重启后仍能识别重复）。
	if f, err := os.Open(path); err == nil {
		var ln struct {
			Record event.Record `json:"record"`
		}
		dec := json.NewDecoder(f)
		for dec.Decode(&ln) == nil {
			t.seen[ln.Record.ID] = struct{}{}
		}
		f.Close()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	t.f = f
	return t, nil
}

func (t *FileTarget) Name() string { return t.name }

func (t *FileTarget) Deliver(ctx context.Context, r event.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.seen[r.ID]; ok {
		t.Dups++
		return nil // 重复投递：识别并忽略
	}
	b, err := json.Marshal(map[string]any{"record": r})
	if err != nil {
		return err
	}
	if _, err := t.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := t.f.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	t.seen[r.ID] = struct{}{}
	return nil
}

func (t *FileTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f != nil {
		err := t.f.Close()
		t.f = nil
		return err
	}
	return nil
}

// FaultTarget 包装一个 Target，可注入"目标不可用"故障（测试用）。
type FaultTarget struct {
	inner Target
	down  atomic.Bool
}

func NewFaultTarget(inner Target) *FaultTarget { return &FaultTarget{inner: inner} }

func (t *FaultTarget) Name() string { return t.inner.Name() }

func (t *FaultTarget) Deliver(ctx context.Context, r event.Record) error {
	if t.down.Load() {
		return ErrUnavailable
	}
	return t.inner.Deliver(ctx, r)
}

func (t *FaultTarget) Close() error { return t.inner.Close() }

// SetDown 切换故障状态。
func (t *FaultTarget) SetDown(down bool) { t.down.Store(down) }
