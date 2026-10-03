# audit-log-router-go

本地审计日志的**采集、合规路由、留存与合规冻结**组件。用本地文件与进程内队列模拟事件来源与多个下游转发目标，
保证在高并发写入、下游故障、进程重启与规则变更下，处理结论一致、可解释、可审计。
被法务/合规调查锁定（冻结）的记录即使超过保存期或撞上容量清理也不会被删除，
解冻后则重新按原留存规则参与清理。

## 架构与数据流

```
Ingest(event)
   │
   ▼
policy.Engine ── 必需字段校验 ── 拒绝(missing_*) / 重复ID(duplicate_id)
   │ 通过
   ▼ 脱敏（深拷贝，不改原始事件）
event.Record (只含脱敏后的值 + policy_version + masked 字段清单)
   │
   ├──► store：append-only 事件段（fsync 落盘，重启不丢、半写行截断）
   │
   └──► router：每目标独立有界队列 + 有界重试
            └──► downstream.Target（文件模拟；按事件ID幂等去重）
   │
   delivery.log：enqueued / delivered / dropped(带原因) 状态机（fsync）
   │
retention.Sweeper：按保留期 / 容量上限，从最旧段开始确定性清理
   │            ▲
   └─ freeze.Registry（freeze.log，fsync）：冻结记录受保护，含冻结记录的段做段内压缩
```

## 事件模型

- `event.Event`（原始，内存中）：`id`、`type`、`actor`、`source`（事件来源，可作冻结条件）、`ts`、`fields(map[string]string)`。
- `event.Record`（脱敏后，唯一允许落盘/投递/出现在日志中的形态）：
  - 内嵌 Event，`fields` 中命中规则的字段已被替换；
  - `policy_version`：判定时生效的规则版本；
  - `masked`：被替换字段名的有序清单，便于解释“这条记录做了什么处理”。
- 拒绝原因（`event.RejectReason`，可区分）：
  `missing_id` / `missing_type` / `missing_actor` / `missing_required_field`
  / `rule_conflict` / `duplicate_id` / `capacity_locked`（容量被冻结记录占满）。

## 规则（policy）

示例见 [`example-policy.json`](./example-policy.json)。

- `required_fields`：事件必须携带且非空，否则以 `missing_required_field` 拒绝（detail 指出具体字段）。
- `mask_rules`：命中字段替换为 `mask`（缺省 `***REDACTED***`）；`event_type` 为空表示对全部类型生效。
  - **同一 (field, event_type) 出现不同替换值 = 规则冲突**，整份规则被拒绝，旧规则继续生效。
- `route_rules`：事件类型 → 目标列表；同一事件类型出现目标集合不一致的规则 = 冲突。
- `retention_age`（Go duration）/ `retention_count` / `segment_bytes`：保留期、容量上限、轮转字节阈值。
- 规则加载是「先校验，后原子切换」；`Router.ReloadPolicy` 对冲突规则返回 `rule_conflict` 且不影响在途处理。

### 脱敏不泄漏保证

- 判定时深拷贝 `fields` 后再替换，原始 `Event` 不被修改；
- 只有 `Record` 会写入事件段、投递目标、`delivery.log`；
- 运行日志只打印事件 ID、版本、被脱敏**字段名**与目标，不打印字段值；
- `TestMaskingNeverLeaks` 会对整个数据目录及测试日志做原始秘密扫描断言。

## 投递语义

- **已接收不丢**：`Ingest` 成功返回前，记录已 fsync 到事件段，且每个目标写入 `enqueued` 状态。
  崩溃时仍在队列中的事件保持 `enqueued`，重启时由 `delivery.log` 重放恢复。
- **故障隔离**：每个目标有独立的 goroutine、独立有界队列；一个目标持续失败不阻塞其他目标。
- **有界重试与积压**：`MaxRetries` 用尽 → `dropped(retries_exhausted)`；队列满 → `dropped(backlog_full)`。
  每个 dropped 都带原因并 fsync，结论可核查，不会无限堆积。
- **下游去重**：`FileTarget` 维护已见事件 ID 集合（从落盘文件重放恢复），重复投递按 ID 识别、只落盘一次。
- **状态可核查**：`delivery.log` 每行 `{event_id, target, status, reason}`，可用 `Router.Stats()` 核对计数。

## 留存与轮转

- 活动段 `events-active.log`；达到 `segment_bytes` 后封存为 `events-000001.log` ……
- 清理顺序完全确定：**段索引最旧（事件最早）优先**；先按 `retention_age` 标记，再按
  `retention_count` 从最旧段补足；活动段从不删除。
- 所有读写共用存储互斥锁；崩溃重放时截断末尾半写行；`PurgeReport` 逐段说明删除原因与计数。
- 含部分冻结记录的封存段在需要清理时走**段内压缩**（`Store.PurgeSegment`：写临时文件 +
  fsync + 原子 rename，崩溃不产生半写段），冻结记录的序号与内容保持不变。

## 合规冻结（legal hold）

面向法务/合规调查：某些记录一旦锁定，就不能再被清掉。冻结状态保存在独立的
append-only 日志 `<dir>/freeze.log`（每行 fsync），与事件数据分开，重启时重放恢复。

### 操作与条件

- 按事件标识：`FreezeByIDs` / `UnfreezeByIDs`；
- 按条件批量：`FreezeBySelector` / `UnfreezeBySelector`，`Selector` 支持
  `source`、`type`、`actor`、时间范围 `[from,to]`（**两端均为闭区间**）与可选
  `ids` 白名单；各字段之间是 AND，空字段不参与匹配，空条件表示全量；
- 状态核查：`IsFrozen(id)`、`FrozenCount()`、`Entries()`（按 seq 升序的冻结条目）。
- 所有操作返回逐 ID 的 `Report`：`frozen`/`unfrozen`（本次发生变化）、
  `already`（目标状态本就成立）、`not_found`（记录已不在留存中），并写运行日志。
- 操作幂等：重复冻结/重复解冻不重复计数、不重复落盘；批次内重复 ID 只处理一次。

### 与留存、容量的关系（确定、可解释）

- **冻结对抗清理**：被冻结记录即使超过 `retention_age` 或处于容量挤出范围也不删除；
  清理报告中原因形如 `age_exceeded_partial_frozen` /
  `count_exceeded_partial_frozen`，并给出 `deleted` 与 `kept` 计数。
  - 保留期压缩：只删段内「已超期 **且** 未冻结」的记录；同段未超期的新记录不受影响。
  - 容量压缩：段内未冻结记录让出空间，冻结记录原样保留。
- **冻结占容量，但存储不无限增长**：容量清理先整段删除无冻结的最旧段，仍超时再
  压缩含冻结的段，因此非冻结记录仍被持续回收；清理的硬地板是「冻结记录数」，
  全冻结的段挤不出空间。
- **容量被冻结占满时的写入**：挂配 `Router.WithFreeze(hold, maxRetained)` 后，
  一旦冻结记录数达到 `maxRetained`（示例程序与 `retention_count` 对齐），新写入被
  **显式拒绝**为 `capacity_locked`（带冻结数/上限/当前总量的日志与
  `Stats.CapacityLocked` 计数）——不会悄悄丢，也不会为腾地方删掉冻结记录；
  解冻或提高上限后写入自动恢复。未冻结时超过容量上限不阻塞采集，仍由清理回收。
- **解冻后重新参与清理**：解冻动作本身不删除任何记录（不会「一解冻就丢」）；
  下一次 Sweep 起该记录重新按保留期/容量规则处理（也不会「怎么都清不掉」）。
- **并发自洽**：冻结/解冻、写入的「容量判定+落盘」、Sweep 全程在同一把冻结注册表
  互斥锁 + 存储互斥锁保护下进行；不可能出现同一条记录既被清掉又被当作冻结保留。
  Sweep 前会执行一次注册表与存储的对账（`Reconcile`），保证冻结计数恒等于
  留存中真实存在的冻结记录数。
- **重启一致**：`freeze.log` 重放以同一 seq 的最后状态为准并截断半写行；
  重启前后对同一批记录的冻结/清理结论一致。

### 兼容范围

- 不挂配冻结注册表（`Sweeper.WithFreeze` / `Router.WithFreeze` 不调用）时，
  留存、清理、写入行为与不支持冻结的版本完全一致（`TestNoFreezeBehavesAsBefore` 守护）。
- 旧数据目录没有 `freeze.log` 时按「无冻结」正常打开；事件新增的 `source` 字段
  对旧 JSON 反序列化兼容（缺失即为空，不参与条件匹配）。
- 冻结不改变脱敏边界：冻结日志与运行日志只记录事件 ID / seq，不写字段值。

## 本地验证

```bash
go vet ./...
go test ./... -race -count=1      # 单元 + 故障注入/并发/重启集成测试
go test ./internal/router -race -v
```

关键测试（日志中打印判定依据）：

| 测试 | 覆盖场景 |
| --- | --- |
| `TestHighConcurrencyIngest` | 16×100 并发写入，双目标无丢失/重复 |
| `TestFaultIsolation` | 单目标持续故障，其他目标不受影响，丢弃有上限与原因 |
| `TestRestartRecovery` | 崩溃后重启，`enqueued` 事件重放并投递成功 |
| `TestMaskingNeverLeaks` | 全目录 + 运行日志扫描确认原始秘密不泄漏 |
| `TestRuleReloadConflict` | 冲突规则拒绝且旧规则保留；合法规则原子生效 |
| `TestConcurrentSweepAppend` | 轮转/清理与并发写入同时进行不产生丢失/重复/半写 |
| `TestSweepAgeExceeded` / `TestSweepCountExceededOldestFirst` | 留存边界与确定清理顺序 |
| `TestDownstreamDedupByID` / `TestFileTargetDedupAcrossRestart` | 进程内与跨重启的下游幂等去重 |
| `TestLedgerIsAuditable` | `delivery.log` 三态齐备且 dropped 带原因 |
| `TestFreezeByIDsIdempotent` | 按 ID 冻结/重复幂等/未知 ID/反复解冻不重复计数 |
| `TestFreezeBySelectorBoundaries` / `TestUnfreezeBySelectorThenReCleanable` | 时间闭区间、来源+类型 AND、ID 白名单、条件解冻边界 |
| `TestReplayAcrossRestart` / `TestReplayTruncatesPartialLine` | 冻结状态重启恢复（末态为准）与半写行截断 |
| `TestFreezeBlocksAgePurgeThenUnfreezeRejoins` | 冻结对抗保留期清理；解冻不立即删除、下次 Sweep 重新参与 |
| `TestFreezeHoldsAgainstCountCap` / `TestPartialFrozenSegmentCompacted` | 容量清理不挤冻结；部分冻结段做记录级压缩且 seq/内容不变 |
| `TestAgeCompactKeepsFreshUnfrozen` | 同段「冻结旧记录+未冻结新记录」时不误删未超期记录 |
| `TestFreezeRestartSameSweepVerdict` | 重启后冻结恢复，对同一批记录的清理结论一致 |
| `TestNoFreezeBehavesAsBefore` | 未启用冻结时留存/清理行为与旧版完全一致 |
| `TestIngestRejectedWhenCapacityFrozen` | 容量被冻结占满时写入收到可区分的 `capacity_locked`，解冻后恢复 |
| `TestConcurrentFreezeSweepIngest` | 冻结/解冻 + 清理 + 写入并发：冻结恒存活、计数自洽、无幽灵条目、无重复 |
| `TestPurgeSegmentRecordLevel` / `TestPurgeSegmentKeepNothingRemovesFile` | 段内压缩的持久化、序号保持与整段删除 |

示例程序：

```bash
go run ./cmd/auditrouter --demo --dir ./data \
  # 或指定规则：
  go run ./cmd/auditrouter --demo --dir ./data --policy example-policy.json
```

输出可在 `data/events-active.log`（留存记录）、`data/delivery.log`（投递状态）、
`data/freeze.log`（合规冻结状态）、`data/targets/*.log`（下游收到的记录）中核查。

冻结能力的本地验证建议（用例日志会打印每个场景的判定依据与结果）：

```bash
go test ./internal/freeze ./internal/retention ./internal/router -race -v -count=1
```

在代码中挂配冻结能力的最小用法：

```go
hold, _ := freeze.Open(dir, st)              // 打开/恢复冻结状态（freeze.log）
r := router.New(engine, st, cfg).WithFreeze(hold, p.RetentionCount) // 容量硬上限
sw := retention.New(st, tick, maxAge, p.RetentionCount, segBytes).WithFreeze(hold)

hold.FreezeByIDs([]string{"evt-1"}, time.Now())
hold.FreezeBySelector(freeze.Selector{Source: "web", Type: "login", From: t1, To: t2}, time.Now())
hold.UnfreezeBySelector(freeze.Selector{Source: "web"}, time.Now())
hold.Entries()      // 状态核查
```
