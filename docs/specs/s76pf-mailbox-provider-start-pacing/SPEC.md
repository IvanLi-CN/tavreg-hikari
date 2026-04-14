# 共享 mailbox provider 启动节流（#s76pf)

## 状态

- Status: 进行中
- Created: 2026-04-14
- Last: 2026-04-14

## 背景 / 问题陈述

- 101 上当前生产镜像已经具备共享 mailbox cooldown，但最新运行事实表明，ChatGPT 新 job 在启动窗口内仍会短时间连续触发 provider mailbox provisioning。
- 2026-04-14 11:53:52Z 启动的 chatgpt job #211 在约 4 秒内触发了 3 次 mailbox provisioning，其中前两次成功进入 attempt，第三次在 draft 阶段直接返回 `mailbox_rate_limited`。
- 这说明现有实现只解决了“429 之后停止重试”，还没有主动压平“429 之前的启动波峰”；只要 provider 对瞬时 burst 更敏感，当前项目仍会在合理并发设置下过早命中 429。

## 目标 / 非目标

### Goals

- 为共享 mailbox provider guard 增加启动阶段请求节流，在 cooldown 触发前就主动压平同一 provider identity 的 mailbox provisioning 峰值。
- 保持 Grok / ChatGPT 共用同一节流与 cooldown 真相源，不新增新的数据库字段或 HTTP API。
- 保留现有 429 / 5xx 归一化和 cooldown 行为，只补“429 前限速”这一层。

### Non-goals

- 不修改 CFMAIL provider、本机外部服务、数据库 schema 或 Web UI 契约。
- 不改变 attempt 成败判定、现有 cooldown 文案和跨站点共享 cooldown 语义。

## 范围（Scope）

### In scope

- `src/server/mailbox-provider-guard.ts`
- 与 provider guard 直接相关的单元测试
- ChatGPT / Grok 调度器对共享 guard 的现有接入验证

### Out of scope

- ChatGPT / Grok worker 内部的页面自动化流程
- provider 配额、部署 secrets 或远端容器编排

## 需求（Requirements）

### MUST

- 同一 mailbox provider identity 下的 provisioning 仍必须串行执行。
- 在 production 环境下，共享 guard 必须为同一 provider identity 强制最小启动间隔，避免 fresh job 在数秒内连续打出多个 `POST /api/mailboxes`。
- 当 provider 已进入 `mailbox_rate_limited` 或 `mailbox_provider_unavailable` cooldown 时，现有 cooldown 行为必须保持不变。
- 节流逻辑必须同时作用于 ChatGPT draft 与 Grok mailbox 创建路径，因为两者共用同一 guard。

### SHOULD

- 节流窗口应允许测试环境保持快速执行，避免把单元测试整体拖慢。
- 回归测试应覆盖“同一 provider identity 下第二次 provisioning 会被延后启动”的事实。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 当 ChatGPT 或 Grok 需要创建新的 CFMAIL mailbox 时，shared guard 先等待上一个同 identity provisioning 完成，再检查 cooldown，最后按最小启动间隔决定是否继续等待。
- 若最小启动间隔尚未到达，则新的 provisioning 不应立即发起 HTTP 请求，而应等待到允许时间再继续。
- 一旦底层请求返回 429 / 5xx，仍按现有逻辑切换到对应 cooldown。

### Edge cases / errors

- 测试环境默认不得引入 5 秒级全局等待；若需要验证节流，应允许通过测试配置把最小间隔调小。
- 若最小间隔配置为 `0`，guard 行为应退化回纯串行 + cooldown，而不是报错。

## 验收标准（Acceptance Criteria）

- Given 同一 provider identity 连续收到两个 mailbox provisioning 请求
  When 第一个请求已经开始且第二个请求排队进入 guard
  Then 第二个请求的实际启动时间至少晚于配置的最小间隔。

- Given production 环境启动新的 ChatGPT / Grok job
  When 同一个 provider identity 需要连续 provision mailbox
  Then guard 会主动压平启动波峰，而不是让多个 mailbox create 在 1~2 秒内连续打到 provider。

- Given provider 已进入 `mailbox_rate_limited` cooldown
  When ChatGPT 或 Grok 再次尝试启动
  Then 当前 cooldown 快照与失败语义保持不变。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- Unit tests: `test/mailbox-provider-guard.test.ts`
- Regression tests: `test/chatgpt-scheduler.test.ts`、`test/shared-mailbox-cooldown.test.ts`、`test/grok-scheduler.test.ts`

### Quality checks

- `bun test test/mailbox-provider-guard.test.ts test/chatgpt-scheduler.test.ts test/shared-mailbox-cooldown.test.ts test/grok-scheduler.test.ts`
- `bun run typecheck`

## 文档更新（Docs to Update）

- `docs/specs/README.md`

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: 补充 shared mailbox provider 启动节流实现
- [x] M2: 覆盖节流回归测试并通过 targeted validation
- [ ] M3: 完成 PR 收口

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：provider 的真实限额窗口并未公开，本次只能基于当前运行事实压平启动波峰，不能保证彻底消除所有 429。
- 假设：当前 101 仍是单实例部署，因此进程内 guard 状态足以覆盖 Grok / ChatGPT 的共享 provider。

## 参考（References）

- `docs/specs/55uxa-provider-first-default-mailboxes/SPEC.md`
- `src/server/mailbox-provider-guard.ts`

## 变更记录（Change log）

- 2026-04-14: 创建 spec，冻结共享 mailbox provider 启动节流范围。
- 2026-04-14: shared guard 增加 production 默认最小启动间隔，并补齐节流回归测试与 targeted validation。
