# audit-log-router-go

本地审计日志的**采集、合规路由与留存**组件。用本地文件与进程内队列模拟事件来源与多个下游转发目标，
保证在高并发写入、下游故障、进程重启与规则变更下，处理结论一致、可解释、可审计。

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
```

## 事件模型

- `event.Event`（原始，内存中）：`id`、`type`、`actor`、`ts`、`fields(map[string]string)`。
- `event.Record`（脱敏后，唯一允许落盘/投递/出现在日志中的形态）：
  - 内嵌 Event，`fields` 中命中规则的字段已被替换；
  - `policy_version`：判定时生效的规则版本；
  - `masked`：被替换字段名的有序清单，便于解释“这条记录做了什么处理”。
- 拒绝原因（`event.RejectReason`，可区分）：
  `missing_id` / `missing_type` / `missing_actor` / `missing_required_field`
  / `rule_conflict` / `duplicate_id`。

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

示例程序：

```bash
go run ./cmd/auditrouter --demo --dir ./data \
  # 或指定规则：
  go run ./cmd/auditrouter --demo --dir ./data --policy example-policy.json
```

输出可在 `data/events-active.log`（留存记录）、`data/delivery.log`（投递状态）、
`data/targets/*.log`（下游收到的记录）中核查。
