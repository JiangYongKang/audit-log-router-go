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
   │   （含冻结记录的段一律跳过；冻结占满容量时给出确定结论）
freeze.Registry：合规冻结（legal hold），freeze.log 持久化，重启重放恢复
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

## 合规冻结（legal hold）

给法务/合规排查使用：被冻结的记录**不参与保留期清理与容量挤出**，解冻后按原规则重新参与。

- **冻结方式**（`freeze.Registry`）：
  - `FreezeIDs`：按事件标识冻结；未找到的 ID 计入报告的 `Skipped`；
  - `FreezeByCriteria`：按条件批量冻结，条件字段为 `actor`（来源）、`type`（类型）、
    `from`/`to`（时间闭区间，含边界）；**空条件被拒绝**（`ErrEmptyCriteria`），防止误全量冻结；
  - `UnfreezeIDs` / `UnfreezeByCriteria`：对称的解冻；`IsFrozen` / `FrozenIDs` / `FrozenCount` 核查状态。
- **幂等与计数自洽**：冻结集合是 ID 集合（set 语义）。重复冻结/解冻是 no-op——不重复写日志、
  不改变计数；每次操作返回 `Report{Changed, Skipped}`，只列实际改变状态的记录。
- **持久化**：所有实际改变集合的操作追加到 `<dir>/freeze.log` 并 fsync；重启重放恢复，
  半写行在 Open 时截断。重启前后对同一批记录的清理结论一致。
- **与留存的关系**：清理以段为单位——**段内含任意一条冻结记录，该段整体跳过**
  （保留期与容量两个阶段都跳过），跳过的段写入 `PurgeReport.Reason`
  （`kept_frozen_segments=...`）并打印运行日志。解冻本身不删除任何数据；
  下一次清理按原保留期/容量规则处理已解冻的段。
- **与清理并发的行为约定**（冻结/解冻与留存、容量清理同时发生）：
  - **只要一条记录在任意时刻处于冻结态，它就绝不会被清理**，直到被解冻为止都可查；
  - 冻结生效与段删除互斥：冻结集合的变更在 store 互斥锁内完成
    （`store.ApplyUnderLock`），生效前锁内复核记录仍存在——扫描之后、生效之前
    被清理掉的记录不会进入冻结集合，而是计入报告的 `Skipped`；
  - 段删除前同样在 store 锁内复核冻结状态（`Store.DeleteSegments` 的 `isFrozen`），
    「清理标记完成后、删除执行前」新冻结的记录所在段会被保留，并在
    `PurgeReport.KeptFrozenSegments` 与 `Reason`（`frozen_at_delete`）中说明；
  - 因此同一条记录不会出现「既已清理、又被冻结保留」的自相矛盾；冻结/解冻计数
    不因并发交错而重复或漂移（集合语义 + 幂等 no-op）；
  - 解冻后记录重新按原保留期/容量规则参与清理：解冻操作本身不删数据，
    也不会让记录永远清不掉；
  - 清理中途取消/出错不会波及冻结记录（删除前复核是最后防线），冻结状态与
    实际留存不会长期对不上；进程重启后 `freeze.log` 重放恢复冻结集合，
    对同一批记录的「该保留/该清理」结论与重启前一致。
- **与容量的关系**（确定性行为）：
  - 冻结记录永不因容量压力被挤掉；容量清理只从「不含冻结记录的封存段」中回收；
  - 若冻结占用导致无法回收到上限以下，清理报告给出 `capacity_unreclaimable:...`
    说明（超量是当前确定状态，不是静默失败）；
  - 写入侧门控（`router.Config.MaxCount` + `IsFrozen`，示例程序已接线）：留存总数达上限
    且没有任何可回收段时，`Ingest` 以 `capacity_frozen` **明确拒绝**（`RejectError`，
    可与其他拒绝原因区分），而不是悄悄丢弃或让存储无限增长。
- **兼容范围**：不注册冻结钩子（`Sweeper.SetFreezeHook` 不调用、`Router.Config.MaxCount=0`）时，
  留存、清理与写入行为与引入冻结能力前完全一致；`freeze.log` 缺失时从空集合开始。

## 本地验证

```bash
go vet ./...
go test ./... -race -count=1      # 单元 + 故障注入/并发/重启集成测试
go test ./internal/router -race -v
# 冻结/清理并发用例的稳定性验证（重复多跑 + 竞态检测，日志含每个用例的判定依据）：
go test ./internal/retention ./internal/freeze ./internal/store \
  -race -count=5 -run 'Freeze|Unfreeze|Sweep|DeleteSegments' -v
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
| `TestFreezeUnfreezeByID` / `TestFreezeByCriteriaBoundaries` | 按 ID/条件冻结解冻、闭区间边界、空条件拒绝、幂等计数 |
| `TestFreezePersistsAcrossRestart` / `TestFreezeRestartKeepsSameSweepDecision` | 重启后冻结状态恢复，清理结论一致 |
| `TestSweepSkipsFrozenSegments` / `TestUnfreezeRestoresOriginalPurge` | 冻结段跳过清理；解冻后按原规则参与清理 |
| `TestSweepCapacityUnreclaimableWhenFrozen` | 容量被冻结占满时的确定结论，冻结记录不被挤掉 |
| `TestConcurrentFreezeSweepAppend` | 冻结/解冻/写入/清理并发，冻结记录不丢、计数自洽 |
| `TestConcurrentFreezeUnfreezeSweepStress` | 按 ID + 按条件冻结/解冻与清理高频交错的压力测试；解冻后容量规则恢复生效 |
| `TestSweepDeleteTimeRecheckKeepsNewlyFrozen` | 确定性交错：清理标记后、删除前新冻结的段被锁内复核保留 |
| `TestFreezePurgedRecordIsSkipped` | 冻结生效前记录已被清理 → 计入 Skipped，不进冻结集合 |
| `TestDeleteSegmentsRechecksFrozenAtDeleteTime` | 段删除前锁内复核冻结状态；isFrozen=nil 时行为不变 |
| `TestSweepWithoutFreezeHookUnchanged` | 未注册冻结钩子时清理行为与引入冻结能力前完全一致 |
| `TestIngestRejectedWhenCapacityFrozen` / `TestIngestUnaffectedWithoutCapacityGate` | 容量门控拒绝可区分；无门控时行为不变 |

示例程序：

```bash
go run ./cmd/auditrouter --demo --dir ./data \
  # 或指定规则：
  go run ./cmd/auditrouter --demo --dir ./data --policy example-policy.json
```

输出可在 `data/events-active.log`（留存记录）、`data/delivery.log`（投递状态）、
`data/targets/*.log`（下游收到的记录）、`data/freeze.log`（冻结操作日志）中核查。
demo 模式会额外演示一次按 ID 冻结、按条件冻结、状态核查与解冻。
