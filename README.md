# audit-log-router-go

本地审计日志的采集、合规路由与留存组件。用本地文件（append-only JSONL）与进程内
有界队列模拟“事件来源”和“多个下游转发目标”，目标是在**高并发写入、下游故障、
进程重启、规则热更**四类扰动下，让每条事件的处理结论都**一致、可解释、可审计**。

不依赖任何外部中间件：持久化就是一个目录里的几个文件，下游就是 JSONL 文件目标和
故障注入目标，开箱即可在本机验证。

---

## 1. 包结构

| 包 | 职责 |
| --- | --- |
| `event` | 事件模型、合规判定状态、每目标投递状态（可审计记录） |
| `rule` | 脱敏 / 必需字段 / 留存 / 路由规则；不可变快照 + 原子热更的合规引擎 |
| `downstream` | 下游目标：`FileTarget`（JSONL 追加、按事件 ID 去重）、`FlakyTarget`（故障注入） |
| `queue` | 每目标有界进程内 FIFO；容量上限显式，溢出返回 `ErrFull` |
| `store` | 双 append-only 日志的持久化层：崩溃重放、epoch 压缩清理、轮转 |
| `router` | 编排：评估 → 落盘 → 每目标有界队列 → 独立 worker 投递 → 状态核查 |

---

## 2. 事件模型

```go
type Event struct {
    ID         string            // 全局唯一标识，去重与状态核查的主键
    Type       string            // 业务事件类型，如 "login"
    OccurredAt time.Time         // 业务发生时间，留存清理的排序依据
    Fields     map[string]string // 负载字段，脱敏规则按字段名命中
    Targets    []string          // 可选：显式指定目标；为空时按路由规则解析
}
```

提交后返回 `IngestResult`：

- `Status`：`accepted` / `rejected:missing-field` / `rejected:rule-conflict`
- `Reason`：**机器可区分**的拒绝原因（字段名可以出现，但绝不包含字段值）
- `Duplicate`：事件 ID 已被持久化时为 `true`（幂等接收，不产生第二次投递）

每一对 `(事件, 目标)` 的投递结论是可核查的 `DeliveryRecord`：
`pending / delivered / failed / dead`，含尝试次数、最后一次错误、更新时间。

---

## 3. 合规规则（`rule.Config`）

```go
Config{
    RequiredFields: []string{"actor", "action"},
    FieldRules: []FieldRule{
        {Field: "password", Action: ActionMask, Replacement: "***"}, // 替换
        {Field: "ssn",      Action: ActionRedact},                   // 删除字段
        {EventType: "login", Field: "actor", Action: ActionKeep},    // 类型级规则优先
    },
    Retention: RetentionRule{MaxAge: 24h, MaxCount: 100000},
    Routes: []RouteRule{
        {EventType: "login", Targets: []string{"audit-file", "siem"}},
        {EventType: "",      Targets: []string{"audit-file"}}, // 通配默认路由
    },
}
```

### 脱敏与不泄漏保证

- 合规引擎**永不修改调用方的事件**：在深拷贝上做替换/删除，避免通过共享 map
  把原始值带到下游。
- 命中 `mask` 的字段值被替换成固定占位符；命中 `redact` 的字段整体从下游副本删除。
- 路由层、worker、运行日志只打印 **事件 ID、目标名、原因**，从不打印任何字段值，
  因此原始敏感值不会出现在下游输出，也不会出现在运行日志中。
- 类型级规则对同名字段优先于通配规则，优先级固定，**结论与规则声明顺序无关**。

### 拒绝：原因可区分

- 缺必需字段 / 字段为空：包装 `ErrMissingField`，Reason 形如
  `missing required field: action`。
- 规则自相矛盾（无法同时满足）：包装 `ErrRuleConflict`，例如：
  - 某字段同时是“必需”和“全局 redact”；
  - 同一作用域把同字段绑定成两种不同动作；
  - 同一事件类型出现两条路由。
- 规则定义本身非法：包装 `ErrInvalidRule`（如 mask 没有 replacement）。

### 规则热更

`ReplaceRules` 先 `Validate` 再用 `atomic.Pointer` 原子替换不可变快照：
- 失败的配置（含冲突）被拒绝，线上仍是旧快照；
- 并发读到的永远是**一份完整快照**，不会读到“半新半旧”；
- 已经落盘的事件沿用旧的投递命运，新提交使用新规则。

---

## 4. 多下游路由与投递语义

- 一个事件按路由可同时进入多个目标；每个目标有**独立的有界队列和独立 worker**，
  单目标持续失败只会积压它自己的队列，不阻塞其他目标。
- **投递确认在持久化之后**：`Submit` 只有在事件已 fsync 落盘后才返回 accepted，
  因此已接收事件在崩溃后不会丢失。
- **重试有明确上限**：每对 `(事件,目标)` 最多投递 `MaxAttempts` 次，指数退避；
  目标不健康时不计入投递次数、短暂等待后重试。超过上限进入终态 `dead`，
  这是**可审计结论**而不是无限重试。
- **积压有明确上限**：每目标队列容量为 `QueueCapacity`。队列满时，Submit 会在
  `EnqueueTimeout` 内随目标排空而重试入队；仍排不进则该对进入终态 `dead`
  （原因 `per-target queue full ... bounded backpressure exhausted`），绝不无限占用内存。
- **去重以事件 ID 为准**，两侧都做：
  - 重启 rehydrate 跳过已 `delivered/dead` 的对；
  - `FileTarget` 启动时重放输出文件重建已接收 ID 集，重复 ID 返回
    `ErrDuplicateDelivery` 且不会第二次写盘。
  - 因此下游出现的重复可被识别，且由构造保证“每事件每目标恰好一次可见落盘”。
- **重启恢复**：`Start` 时从 store 重放所有非终态投递（含从未尝试的），按落盘顺序
  重新填回队列；目标侧文件已有的记录被识别为重复并按 delivered 记账。
- **关停**：`Shutdown(ctx)` 先打断退避等待和清理循环，再让 worker **排空队列**，
  最后关闭队列与存储；超过 `ctx` 宽限仍未投递的事件保持持久化，下次 Start 继续。

### 投递状态可核查

- `DeliveryStatus(eventID, target)` 查单对；`AllDeliveryStatus()` 返回全部记录。
- 底层每次状态迁移都追加进 `state.log`，重启后完整重建。

---

## 5. 留存与轮转

### 磁盘布局

```
<dir>/
  e<E>-s<N>.log   事件分段（epoch E、segment N），每行一条 JSON 记录
  e<E>.ready      epoch E 已完整可见的持久标记
  state.log       每目标投递状态的 append-only 流转日志
```

### 清理顺序确定

`Cleanup(now, maxAge, maxCount)`：
1. 年龄清理：`now - OccurredAt > maxAge` 的事件过期；
2. 容量挤出：在存活事件中保留最新 `MaxCount` 个，其余按
   **OccurredAt 升序、平局按落盘 seq** 的确定顺序挤出；
3. 返回 `CleanupReport{Checked, ExpiredAge, EvictedCap, Remaining, OldEpoch, NewEpoch}`
   解释“查了多少、哪些因年龄删、哪些因容量挤、剩多少”。

### 轮转 / 清理并发安全

- 所有写入、轮转（`Rotate`）、清理（`Cleanup`）都在同一把存储锁下串行化，
  JSON 行以“单次 `write(2)` + fsync”落盘，读端永远看不到半写行；崩溃留下的
  至多是最后一行的截断，重放会明确报错指出行号，而不会读到半截记录。
- 清理采用 **epoch 压缩**：先把存活集完整写进**新一代**并 fsync、落下 ready 标记，
  再把删除记入 `state.log`，最后才删除旧一代文件。任何时刻崩溃都至少留有一代
  完整可读的数据，不会丢存活事件、不会重复计数。
- 自动清理可由 `Config.CleanupInterval` 开启，也可显式调用 `Router.Cleanup`。

---

## 6. 本地验证方法

要求 Go 1.25+（在 Go 1.26 上开发验证）。

```bash
# 编译 + 静态检查
go build ./...
go vet ./...

# 全量单元/集成测试
go test ./... -v

# 高并发与故障注入场景，强烈建议带竞态检测
go test ./... -race -count=1
```

测试覆盖（测试日志中以 `key decision:` 打印关键判定依据）：

| 场景 | 测试 |
| --- | --- |
| 脱敏替换/删除、深拷贝不污染原值、缺字段拒绝、规则冲突拒绝 | `rule/rule_test.go` |
| 有界容量溢出显式、关闭唤醒、并发 FIFO | `queue/queue_test.go` |
| 文件目标同进程/重启去重、半写行检测、并发唯一投递、故障注入重试恰好一次 | `downstream/downstream_test.go` |
| 落盘后重启重放、待投递重建、状态重建、年龄+容量确定顺序清理、轮转×清理并发不丢不重 | `store/store_test.go` |
| 下游故障隔离、有界重试 dead、恢复后恰好一次、重复提交幂等、**崩溃后重启恢复**、规则热更×高并发脱敏零泄漏、背压可审计、留存边界、轮转×写入×清理并发后重启一致 | `router/*_test.go` |

快速验证“脱敏不泄漏”的方式：高并发用例 `TestRuleReloadAndConcurrentNoLeak`
会在两个下游的最终输出里全文扫描所有原始 `SUPERSECRET-*` 与被 redact 的
`token` 字段，出现即失败。

---

## 7. 最小用法

```go
eng, _ := rule.NewEngine(rule.Config{ /* 必需字段 / 脱敏 / 留存 / 路由 */ })

file, _ := downstream.NewFileTarget("audit-file", "./data/audit.jsonl")
flaky := downstream.NewFlakyTarget("siem", 2) // 前 2 次失败，用于演练重试

r, _ := router.New("./data/store", eng,
    []downstream.Target{file, flaky},
    router.Config{
        QueueCapacity: 4096, MaxAttempts: 6,
        RetryBackoff: 50 * time.Millisecond,
        CleanupInterval: time.Minute,
    })
r.Start(context.Background())

res := r.Submit(context.Background(), event.Event{
    ID: "evt-1", Type: "login", OccurredAt: time.Now(),
    Fields: map[string]string{
        "actor": "alice", "action": "login", "password": "hunter2",
    },
})
// res.Status == accepted；下游文件里 password 只会是占位符。

rec, ok := r.DeliveryStatus("evt-1", "audit-file") // 可核查投递结论
_ = r.ReplaceRules(newCfg)                         // 原子热更
_ = r.Shutdown(context.Background())               // 优雅排空 + 落盘
```
