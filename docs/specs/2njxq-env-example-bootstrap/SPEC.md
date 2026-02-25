# 增加 env 模板并提供本地初始化指引（#2njxq）

## 状态

- Status: 已完成
- Created: 2026-02-25
- Last: 2026-02-25

## 背景 / 问题陈述

- 当前仓库仅约定使用 `.env.local`，但缺少可直接复制的 `.env.example`。
- 新协作者需要手工从 README 摘抄变量，容易漏项或拼写错误。
- 用户已明确要求补充模板并快速生成本地配置文件。

## 目标 / 非目标

### Goals

- 新增 `.env.example`，覆盖当前代码读取到的主要环境变量。
- 在 README 里提供 `cp .env.example .env.local` 的初始化方式。
- 在当前工作区生成 `.env.local` 供用户继续填写。

### Non-goals

- 不调整任何运行时环境变量解析逻辑。
- 不引入新的配置项或改变默认值语义。

## 范围（Scope）

### In scope

- 新增 `.env.example`。
- 更新 README 的环境变量准备说明。
- 生成一份 `.env.local`（来自 `.env.example`）。

### Out of scope

- 变更 `src/main.ts` 或 `src/proxy-cli.ts` 的配置读取行为。
- 修改与本任务无关的脚本或流程文档。

## 需求（Requirements）

### MUST

- `.env.example` 至少包含当前必填项：`OPENAI_KEY`、`OPENAI_BASE_URL`、`MODEL_NAME`、`MIHOMO_SUBSCRIPTION_URL`。
- `.env.example` 中的可选项需附默认值或用途注释。
- README 明确说明模板复制命令。

### SHOULD

- 模板分组清晰，便于快速定位不同配置域。

### COULD

- 对过时示例变量做兼容注释（不影响运行）。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 用户克隆仓库后，执行 `cp .env.example .env.local` 即可得到可编辑本地配置。
- 用户只需补齐必填项，即可继续执行项目命令。

### Edge cases / errors

- 若用户误删 `.env.local`，可再次复制 `.env.example` 重建。

## 接口契约（Interfaces & Contracts）

None

## 验收标准（Acceptance Criteria）

- Given 一个全新仓库副本，When 执行 `cp .env.example .env.local`，Then `.env.local` 成功生成且包含必填配置键。
- Given README 的前置步骤，When 按步骤操作，Then 用户可以在不手抄变量的情况下完成本地配置准备。
- Given 新增模板后运行静态检查，When 执行 `bun run typecheck`，Then 检查通过且无新增类型错误。

## 实现前置条件（Definition of Ready / Preconditions）

- 用户授权本次修改文档与配置模板：已满足。
- 配置读取入口与必填键清单已确认：已满足。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- 执行 `bun run typecheck`，确保本次变更不引入类型问题。

### Quality checks

- README 与 `.env.example` 内容一致且可执行。

## 文档更新（Docs to Update）

- `README.md`：新增模板复制指引。
- `docs/specs/README.md`：新增规格索引项。

## 计划资产（Plan assets）

None

## 资产晋升（Asset promotion）

None

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: 新增 `.env.example` 模板并覆盖主要配置项。
- [x] M2: 更新 README 前置步骤，增加复制命令与指引。
- [x] M3: 生成 `.env.local` 并完成基础验证。

## 方案概述（Approach, high-level）

- 直接以现有代码中的 `process.env` 键名作为模板来源，避免文档与实现脱节。
- 通过 README 引导把“手抄配置”替换为“一键复制再编辑”。

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：后续新增配置项时若未同步模板，仍可能出现偏差。
- 需要决策的问题：None。
- 假设（需主人确认）：当前 README 列出的可选项仍有效。

## 变更记录（Change log）

- 2026-02-25: 初始化规格，冻结本次目标与验收标准。
- 2026-02-25: 完成 `.env.example`、README 指引与 `.env.local` 初始化，`bun run typecheck` 通过。
- 2026-02-25: 创建 PR #1（`th/env-example-local-bootstrap`）进入合并检查。
- 2026-02-25: 根据 review 反馈收敛 README，移除重复模板并明确 `.env.example` 为可选项真源。

## 参考（References）

- `README.md`
- `src/main.ts`
- `src/proxy-cli.ts`
