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
- **与清理并发时的原子约定（核心）**：冻结/解冻与后台清理可能在任意时刻交错，
  系统用统一锁序与原子临界区保证结论永远自洽：
  - 固定锁序 **store 锁 → freeze 锁**，全代码库无反向获取，杜绝死锁；
  - 一次清理的「取冻结集合快照 → 逐段冻结判定 → 超期/容量标记 → 删除段」（含必要的
    活动段轮转）全程在同一个 store 临界区、同一份冻结快照内完成；
  - 「按 ID/按条件冻结」把**存在性扫描 + 集合变更（含 fsync）**放进同一个 store 临界区。
  - 因此对任意一条记录，「冻结」与「清理」只有两种确定结果，不会再有第三种矛盾结果：
    1. **冻结先提交** → 本次清理判定时它已冻结，其所在段（保留期与容量两个阶段）整体
       跳过，记录在解冻前**一定保留且可查**；
    2. **清理先提交** → 记录已不在留存中，随后的冻结在同一临界区扫描时查不到它，
       计入 `Report.Skipped`，不会留下「冻结状态查得到、留存数据已删除」的悬挂状态。
  - 不会出现同一条记录「既被当成已清理、又被当成冻结保留」的自相矛盾；
    重复冻结/解冻仍是 no-op，`FrozenCount` 与 `FrozenIDs` 不重复、不漂移。
- **写盘失败的原子性**：freeze.log 写入或 fsync 失败时，冻结/解冻操作返回错误且
  **内存集合不变更**——进程绝不带着「未持久化的冻结/解冻」继续运行，重启后结论
  必然与 freeze.log 完全一致。
- **中断/出错安全**：清理在执行前或执行中被 `context` 取消时**零删除**，
  状态与取消前完全一致，不会顺手删掉冻结段；段删除中途若文件系统出错，已确认删除
  的段保持删除（计入报告），未能确认删除的段与后续段原样保留，冻结记录不受影响。
- **解冻后重新参与清理**：解冻本身不删除任何数据（不会一解冻就丢）；下一次清理按
  原来的保留期/容量规则处理已解冻的段（也不会解冻后永远清不掉）。
- **与留存的关系**：清理以段为单位——**段内含任意一条冻结记录，该段整体跳过**
  （保留期与容量两个阶段都跳过），跳过的段写入 `PurgeReport.Reason`
  （`kept_frozen_segments=...`）并打印运行日志。冻结判定、段删除与活动段轮转在
  同一 store 临界区内完成，因此「段刚被判为可删、里面的记录此刻被冻结」这类交错
  不可能产生删除；解冻本身不删除任何数据；下一次清理按原保留期/容量规则处理已解冻的段。
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
# 单元 + 故障注入/并发/重启集成测试；重复多次 + 竞态检测，应稳定全绿：
go test ./... -race -count=1
go test ./internal/retention ./internal/router ./internal/freeze -race -count=10
# 查看每个用例的判定依据与结果（业务覆盖一目了然）：
go test ./internal/retention -race -v
go test ./internal/router -race -v
go test ./internal/freeze -race -v
```

并发用例每个回合都在「冻结集合 ⊆ 现存记录、扫描计数 == 存储计数、无重复 ID、
冻结计数不漂移」的原子联合视图上断言，因此能稳定抓住「刚冻结就被清走」「计数漂移」
等交错问题，而不是时好时坏。

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
| `TestConcurrentFreezeCriteriaSweepAgePressure` | 超期+容量清理 与 按ID/按条件冻结解冻 高并发，冻结集合始终是现存记录子集 |
| `TestSweepCanceledIsAtomicNoDeletion` | 清理被取消时零删除、冻结段与冻结状态不受影响 |
| `TestSweepBehaviorIdenticalWhenHookNotSet` | 未接线冻结钩子时清理结果与无冻结基线完全一致 |
| `TestUnfreezeAfterChurnRejoinsPurge` | 并发结束后解冻的段重新按原保留期规则回收，仍冻结的保留 |
| `TestConcurrentIngestFreezeSweep` | 写入(带容量门控)/投递/冻结解冻/清理端到端并发，不死锁、拒绝原因可区分、解冻回收后写入恢复 |
| `TestApplyWriteFailureLeavesStateUnchanged` / `TestFailedOperationDoesNotSurviveRestart` | freeze.log 写失败时内存集合不变更；未持久化的冻结在重启后不存在 |
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
