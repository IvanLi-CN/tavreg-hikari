# Release 失败 Telegram 告警接入（#vyg62）

## 状态

- Status: 已完成
- Created: 2026-04-11
- Last: 2026-04-19

## 背景 / 问题陈述

- `Release` 工作流已经具备 candidate build、发布与 PR release comment 闭环，但失败时缺少 repo-local 的 Telegram 告警入口，发布链路失效后不能及时告知 owner。
- Release 失败上下文里真正需要告警的目标 SHA 可能不是 `workflow_run.head_sha`，若只依赖 workflow payload，手动 backfill 或 pending release 场景会把告警指向错误提交。
- 当前仓库已经存在可复用的共享 Telegram workflow，因此本次收口目标是补齐 repo-local wrapper、SHA 解析与 smoke 证据，而不是重写整套告警系统。

## 目标 / 非目标

### Goals

- 为 `Release` 失败路径新增 repo-local notifier wrapper，统一复用共享 Telegram 告警 workflow。
- 在 `release.yml` 中显式输出 `RELEASE_REQUESTED_SHA` 与 `RELEASE_TARGET_SHA`，让失败告警优先解析真实 release target。
- 保留 `workflow_dispatch` smoke 入口，用于独立验证通知链路与模板渲染。

### Non-goals

- 不修改既有 Release artifact、candidate image、GitHub Release 或 PR release comment 的发布语义。
- 不把 Telegram 告警扩展到 `CI PR`、`CI Main` 或其他 workflow。
- 不引入新的外部通知提供商或 repo 外状态存储。

## 范围（Scope）

- `.github/workflows/notify-release-failure.yml`
- `.github/workflows/release.yml`
- `docs/specs/README.md`

## 行为规格

### Release 目标 SHA 解析

- `release.yml` 在解析手动 backfill 或 workflow-run 触发的目标提交后，必须显式打印 `RELEASE_REQUESTED_SHA=<sha>`。
- 当 pending release target 被最终确定后，必须再打印 `RELEASE_TARGET_SHA=<sha>`，供 notifier 从 Release run logs 中优先提取真实 target。
- 手动 backfill 场景下，若 workflow payload 的 `head_sha` 不是最终 release target，告警仍必须以日志解析得到的目标 SHA 为准。

### 失败告警 workflow

- `notify-release-failure.yml` 只在 `Release` workflow `completed + failure` 时自动触发通知。
- resolver job 必须从 workflow run jobs / logs 中按优先级提取 `RELEASE_TARGET_SHA`、回退 `RELEASE_REQUESTED_SHA`，最后才回退到 `workflow_run.head_sha`。
- 告警内容必须包含：仓库、workflow 名称、失败状态、run URL、ref label、目标 SHA、run attempt、actor 与额外上下文。

### Smoke 验证

- `workflow_dispatch` 运行 notifier workflow 时，不依赖真实失败的 Release run，也能发送一条标记为 `release-alert-smoke` 的测试通知。
- smoke 通知正文必须复用正式模板，确保 Telegram 入口、共享 reusable workflow 和 secrets wiring 都可验证。

## 验收标准（Acceptance Criteria）

- Given `Release` workflow 在 `main` 上失败，When `notify-release-failure.yml` 被 `workflow_run` 触发，Then Telegram 告警会自动发送。
- Given `Release` run logs 中包含 `RELEASE_TARGET_SHA=<sha>`，When notifier 解析失败上下文，Then 告警优先使用该 SHA，而不是仅回退到 workflow 头 SHA。
- Given 手动执行 notifier 的 `workflow_dispatch`，When smoke job 完成，Then 会发送一条可审计的测试通知。
- Given 告警首行渲染完成，When owner 查看 Telegram 消息，Then 首行包含 Emoji + 状态 + 项目名。

## 验证证据（Validation Evidence）

- `.github/workflows/release.yml` 已输出 `RELEASE_REQUESTED_SHA` / `RELEASE_TARGET_SHA`，并在 release-meta 阶段记录解析结果。
- `.github/workflows/notify-release-failure.yml` 已实现 `workflow_run` 失败触发、日志解析、shared reusable workflow 调用与 `workflow_dispatch` smoke。
- `docs/specs/README.md` 已同步为 `已完成`，说明该 spec 不再停留在草稿骨架态。

## 文档更新（Docs to Update）

- `docs/specs/README.md`
- `docs/specs/vyg62-release-failure-telegram-alerts/SPEC.md`
