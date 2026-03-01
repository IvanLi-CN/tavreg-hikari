# 移除 both 运行模式并收敛为单模式执行（#jfscm）

## 状态

- Status: 已完成
- Created: 2026-03-01
- Last: 2026-03-01

## 背景 / 问题陈述

- 当前 `RUN_MODE` 与 `--mode` 支持 `both`，主流程通过 `resolveModeList + for (mode of modes)` 遍历执行。
- 该能力与当前使用场景不匹配：运行前通常会指定单一模式，`both` 带来的是额外分支复杂度而非业务价值。
- 需要收敛为“单模式执行 + mode 级重试”，并对非法模式显式报错。

## 目标 / 非目标

### Goals

- 删除 `both` 运行模式，仅保留 `headed|headless`。
- 删除多 `modes` 遍历执行模型，改为单模式执行。
- 对 `--mode both` 与 `RUN_MODE=both` 直接报错。
- 保持输出文件兼容：`output/result.json` 为单结果，`output/run_summary.json` 保留 `results` 数组结构（长度固定为 1）。

### Non-goals

- 不调整任务台账 schema（`batchId` 等字段保持不变）。
- 不调整代理、验证码、邮箱、风控策略等业务逻辑。

## 范围（Scope）

### In scope

- `src/main.ts` 的模式类型、参数解析、配置校验与主执行流程重构。
- `README.md` 与 `.env.example` 的模式文档同步。
- `docs/specs/README.md` 新增本规格索引。

### Out of scope

- 新增批量账号注册能力。
- 改动 `docs/WORKFLOW.md`（若无 `both` 文案则不变）。

## 需求（Requirements）

### MUST

- `RunMode` 仅允许 `headed|headless`。
- `parseRunMode` 不再接受 `both`。
- 当环境变量 `RUN_MODE` 被设置但值非法时，启动阶段必须报错，不得静默回退。
- 运行主流程仅执行一个 mode，并保留现有 mode 重试机制（`MODE_RETRY_MAX`）。

### SHOULD

- `run_summary.json` 字段结构尽量稳定，减少下游消费方改动成本。
- 日志从 `start modes=...` 改为 `start mode=...`，语义一致且易读。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- `--mode headed|headless`：正常执行单模式流程。
- `--mode both`：立即抛出 `invalid --mode value: both`。
- `RUN_MODE=both`：配置加载阶段抛出 `Invalid env RUN_MODE: both. Supported values: headed|headless`。
- 单模式执行成功后：
  - `output/result.json` 输出单个结果对象；
  - `output/run_summary.json` 输出 `{ batchId, requestedMode, model, results: [result] }`。

### Edge cases / errors

- mode 重试失败仍沿用既有 `shouldRetryModeFailure` 判定与错误上抛策略。
- 若 mode 最终无结果，错误信息保留 mode 上下文（`[mode] run failed without result`）。

## 验收标准（Acceptance Criteria）

- Given `--mode headed`，When 执行启动，Then 仅执行 headed 模式流程。
- Given `--mode headless`，When 执行启动，Then 仅执行 headless 模式流程。
- Given `--mode both`，When 执行启动，Then 立即失败并报 `invalid --mode value: both`。
- Given `RUN_MODE=both`，When 执行启动，Then 立即失败并报 `Invalid env RUN_MODE: both...`。
- Given 实现完成，When 执行 `bun run typecheck`，Then 类型检查通过。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- `bun run typecheck`
- `bun run start -- --mode both`（负向参数校验）
- `RUN_MODE=both bun run start`（负向环境变量校验）

### Compatibility

- `batchId` 生成与台账写入流程保持不变。
- `run_summary.json` 保持 `results` 数组字段。

## 文档更新（Docs to Update）

- `README.md`
- `.env.example`
- `docs/specs/README.md`

## 变更记录（Change log）

- 2026-03-01: 新建规格，定义删除 `both` 与收敛单模式执行的目标与验收标准。
- 2026-03-01: 完成 `src/main.ts` 重构与文档同步，移除多模式遍历执行路径。
