# 增加批量注册（并行数 + 需求数）（#8855j）

## 状态

- Status: 已完成
- Created: 2026-03-01
- Last: 2026-03-01

## 背景 / 问题陈述

- 当前 `bun run start` 一次只产出 1 个可用结果（`output/result.json`），需要多账号时只能手动重复运行或依赖外部脚本拼接。
- 需要在项目内提供“批量运行”能力：可设置并行度，并以“成功数达到需求数”作为完成条件。
- 在并行运行下，需要避免端口/输出文件等共享资源冲突导致的非业务失败。

## 目标 / 非目标

### Goals

- 增加批量运行参数：
  - `--parallel <n>`：并行数（默认 `1`）。
  - `--need <n>`：总需求数（默认 `1`）。
- 批量完成条件：`successCount === need` 即视为成功并结束运行。
- 并行模式下，确保每个 run 的代理进程（mihomo）使用独立端口与独立 workDir，避免端口冲突。
- 并行/批量模式下，将诊断产物写入 run 级目录，避免输出文件互相覆盖。
- 保持兼容：
  - `output/result.json` 仍写入“单个成功结果对象”（批量时写入最后一个成功结果）。
  - `output/run_summary.json` 继续包含 `results` 数组；批量时数组长度为成功数（应等于 `need`）。

### Non-goals

- 不新增“最大尝试次数”或“提前取消正在运行的任务”的控制参数（用户可自行中断进程）。
- 不调整注册/风控/验证码/邮箱等业务逻辑与判定规则。

## 范围（Scope）

### In scope

- `src/main.ts`
  - CLI 参数解析（新增 `--parallel`/`--need`）
  - 批量调度器（并发池 + 以 `need` 为完成条件）
  - 运行摘要与终端输出同步
  - run 级输出目录（诊断文件隔离）
  - mihomo 端口与 workDir 的 run 级隔离（批量/并行模式）
- `README.md`、`docs/WORKFLOW.md` 文档同步
- `docs/specs/README.md` 新增本规格索引
- `src/proxy/mihomo.ts`：并行下载 mihomo binary 的去重（避免首次并行时重复下载写文件）

### Out of scope

- 新增新的持久化格式（如 accounts.tsv）或对现有 SQLite 台账 schema 做扩展。
- 对批量运行的“失败策略”做更细粒度分类（如遇到某些错误立即全局失败）。

## 需求（Requirements）

### MUST

- CLI：
  - `--parallel` 与 `--need` 均接受 `--flag value` 与 `--flag=value` 形式。
  - 默认值均为 `1`；小于 `1` 或非整数必须报错。
- 调度：
  - 并发上限为 `parallel`。
  - 同一时刻 in-flight 的任务数不得超过 `need - successCount`（避免多跑）。
  - 任意单次 run 的失败不得导致整个批量提前结束（除非出现致命错误导致主流程无法继续）。
- 成功判定：
  - `successCount === need` 时结束并视为成功。
- 输出：
  - 批量/并行模式下，每个 run 的诊断产物写入 `output/runs/<batchId>/<runId>/`。
  - `output/run_summary.json` 写入批量元信息（`need`/`parallel`/`successCount`/`failureCount`）以及 `results`。
  - `output/result.json` 仍为单结果对象（批量时为最后一个成功结果）。

### SHOULD

- 并行模式下避免共享文件写入导致 JSON 损坏：对 `writeJson` 做“写临时文件 + rename”原子落盘。
- 日志包含批量进度（已成功数/需求数/并行度）。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- `bun run start`：
  - 等价于 `bun run start -- --parallel 1 --need 1`。
- `bun run start -- --need 5 --parallel 2`：
  - 最多同时跑 2 个 run；
  - 当成功数到 5 时结束。

### Edge cases / errors

- `--need 0` / `--parallel 0` / 非数字：启动阶段立即报错。
- 若批量过程中存在失败：
  - 失败 run 的诊断产物保存在对应 `output/runs/<batchId>/<runId>/` 目录；
  - 调度器继续补跑直到成功数达到 `need`（或进程被用户中断 / 遇到致命错误）。

## 接口契约（Interfaces & Contracts）

None

## 验收标准（Acceptance Criteria）

- Given 未传 `--parallel/--need`
  When 执行 `bun run start`
  Then 行为与旧版本一致，并且 `output/result.json` 为单结果对象。
- Given `--need 3 --parallel 2`
  When 执行批量运行
  Then 成功数达到 3 即结束，且 `output/run_summary.json.results.length === 3`。
- Given `--need 0`
  When 启动
  Then 立即失败并输出参数非法错误信息。
- Given 实现完成
  When 执行 `bun run typecheck`
  Then 类型检查通过。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- `bun run typecheck`

### Quality checks

- TypeScript typecheck must pass.

## 文档更新（Docs to Update）

- `README.md`: 新增批量参数与输出说明
- `docs/WORKFLOW.md`: 增加批量调度说明与 run 级产物路径
- `docs/specs/README.md`: 增加索引行并维护状态

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: `src/main.ts` 新增 `--parallel/--need` 参数与批量调度器
- [x] M2: run 级输出目录隔离（含失败诊断产物）
- [x] M3: mihomo 并行运行支持（端口 + workDir 隔离、binary 下载去重）
- [x] M4: 文档同步（README/WORKFLOW/spec index）

## 方案概述（Approach, high-level）

- 在 `run()` 内将“单次执行”抽象为 `runOne()`，批量模式用并发池调度多个 `runOne()` 直到成功数满足 `need`。
- 批量/并行模式下，为每个 `runSingleMode` 分配独立的 mihomo 端口与 workDir，避免端口冲突。
- 将 run 过程中的诊断文件写入 `output/runs/<batchId>/<runId>/`，避免并行覆盖。

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：批量模式可能运行时间较长；缺少最大尝试次数时可能出现长时间补跑（用户可手动中断）。
- 假设：用户希望保留 `output/result.json` 单结果兼容性，因此批量以“最后一个成功结果”写入。

## 变更记录（Change log）

- 2026-03-01: 新建规格，定义批量并行与成功判定、输出与并行隔离约束。
- 2026-03-01: 实现批量运行与并行隔离，完成文档同步。
