# Microsoft proof 补邮箱分支修复与多语言诊断加固（#zxuvb）

## 状态

- Status: 已完成
- Created: 2026-04-17
- Last: 2026-04-18

## 背景 / 问题陈述

- 线上 Microsoft Bootstrap 在 `account.live.com/proofs/Add` 的繁体中文变体下，会误落入通用 proof email handler，直接报 `microsoft_proof_mailbox_missing`。
- 实际上 proof mailbox 应由 Bootstrap 在 add-surface 上自动 provision，并把 `proof_mailbox_provider/address/id` 回写到账号数据库。
- 当前识别过度依赖英文/简体中文文案，未来新增语言或布局变体时，容易再次漏判，且失败会被误分类成“没有配置 proof mailbox”，不利于排查。

## 目标 / 非目标

### Goals

- 修复 `/proofs/Add` 在繁体中文等变体下未触发 auto-provision 的问题。
- 将 Microsoft proof surface 识别改成 URL / DOM 信号优先、文案兜底。
- 为未知 proof surface 增加显式诊断与稳定错误码，避免静默落入错误 handler。
- 保持 verify / confirm / code 等既有分支行为不回退。

### Non-goals

- 不重写整个 Microsoft 登录状态机。
- 不扩展 Google / GitHub / LinkedIn 等其他 provider。
- 不将网络型 `ERR_CONNECTION_CLOSED` 作为本次必须根治的问题。

## 范围（Scope）

### In scope

- 提炼 Microsoft proof surface classifier，并让 add / method / email / confirmation 复用同一分类结果。
- 修正 add-surface 的 proof mailbox auto-provision 触发条件。
- 新增 `microsoft_proof_surface_unclassified` 诊断与失败留痕。
- 更新错误分类、重试策略与自动化测试。
- 按既有 `home-lab-tavreg-hikari` 发布路径上线并回归验证。

### Out of scope

- 重构整个 OAuth 状态机。
- 变更对外 HTTP API / Web UI。
- 修改 proof mailbox provider 能力边界（仍只支持 `cfmail`）。

## 需求（Requirements）

### MUST

- `/account.live.com/proofs/Add` 上的 add-surface 必须在识别到需要新增备用邮箱时允许 `allowProvision: true`。
- proof surface classifier 必须优先使用 URL / DOM 信号（如 `#iProofOptions`、`#EmailAddress`、`#iProofEmail`、OTP 输入），文案只作兜底。
- 未能归类的 proof surface 必须抛出稳定错误码，并附带 URL、surface kind、命中 selector、标题 / body 摘要等诊断信息。
- `microsoft_proof_surface_unclassified` 必须快速失败并完整落库，不能继续伪装成 `microsoft_proof_mailbox_missing`。
- 现有 verify / confirmation / code 分支必须保持既有边界，避免在非 add-surface 上误建邮箱。

### SHOULD

- classifier 对 zh-CN、zh-TW、英文页面均能稳定识别 add-surface。
- 诊断信息应尽量稳定、可 grep、适合 worker log 与 result.json 排障。

### COULD

- 为 future locale/layout 追加 selector 命中摘要，减少后续人工复现成本。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 当页面位于 Microsoft proof route 时，先收集 surface snapshot（URL、标题、正文摘要、关键 selector 命中）。
- classifier 根据 route + DOM 信号判断 surface kind：`add_method`、`add_email`、`confirm_email`、`verify_choice`、`code_entry` 或 `unclassified`。
- `handleMicrosoftProofAddPrompt` 与 `handleMicrosoftProofMethodPrompt` 只在 classifier 判定为 add-surface 时触发，并允许自动 provision proof mailbox。
- `handleMicrosoftProofEmailPrompt` / `handleMicrosoftProofConfirmationEmailPrompt` 仅在 classifier 判定为对应 surface 时继续；若是 proof route 但 classifier 无法归类，则直接抛显式诊断错误。
- 进入 code surface 后仍沿用现有 proof code 拉取与提交逻辑。

### Edge cases / errors

- 若 proof route 页面既不满足 add / verify / confirm / code 的 DOM/文本特征，程序抛 `microsoft_proof_surface_unclassified`，并附带 snapshot 摘要。
- 若页面已明确是 verify / confirmation surface，但账号配置的 proof mailbox 与 challenge 不匹配，仍沿用 `microsoft_unknown_recovery_email` / `microsoft_account_locked` 等既有错误。
- 若 add-surface 的邮箱输入缺失或提交按钮缺失，继续沿用 `microsoft_proof_add_email_input_missing` / `microsoft_proof_add_submit_missing`。

## 接口契约（Interfaces & Contracts）

### 接口清单（Inventory）

| 接口（Name） | 类型（Kind） | 范围（Scope） | 变更（Change） | 契约文档（Contract Doc） | 负责人（Owner） | 使用方（Consumers） | 备注（Notes） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Microsoft proof surface classifier | internal | internal | Modify | None | tavreg-hikari | login state machine | 仅内部状态机与错误分类调整 |

### 契约文档（按 Kind 拆分）

None

## 验收标准（Acceptance Criteria）

- Given Microsoft 登录进入 `/account.live.com/proofs/Add` 的繁体中文页面，When Bootstrap 继续执行，Then 程序自动 provision proof mailbox，而不是报 `microsoft_proof_mailbox_missing`。
- Given zh-CN、zh-TW、英文 add-surface，When classifier 运行，Then 都会被归类为允许 auto-provision 的 add-flow。
- Given verify / confirmation / code surface，When classifier 运行，Then 继续走既有 handler，不会因为放宽 add 判定而误建邮箱。
- Given proof route 出现新的未知语言 / 布局，When classifier 无法归类，Then worker log / result.json 落下 `microsoft_proof_surface_unclassified`，且包含 URL、selector 命中与标题 / 正文摘要。
- Given 本次实现完成，When 执行 `bun run typecheck` 与 `bun test`，Then 检查通过。
- Given 101 上 `home-lab-tavreg-hikari` 更新到包含本修复的镜像，When 重新触发 `raidendaniella9161@hotmail.com` 的 mailbox bootstrap，Then worker log 出现 `provisioned Microsoft proof mailbox ...`，数据库 `proof_mailbox_provider/address/id` 不再为空。

## 实现前置条件（Definition of Ready / Preconditions）

- 范围、非目标与验收标准已冻结。
- 本次实现不新增对外接口，内部状态机修改以本 spec 为准。
- 线上 stack 与回归账号已确认：`home-lab-tavreg-hikari` / `raidendaniella9161@hotmail.com`。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- Unit tests: proof surface classifier 纯函数测试，覆盖 zh-TW add-surface、现有英文 / zh-CN 分支、未知 surface 诊断。
- Integration tests: 针对 `src/main.ts` 的最小必要保护测试，确保 add-route 仍允许 provision，未知 proof surface 被显式诊断。
- E2E tests (if applicable): 101 线上单账号 bootstrap 回归。

### UI / Storybook (if applicable)

- None

### Quality checks

- `bun run typecheck`
- `bun test`

## 文档更新（Docs to Update）

- `docs/specs/README.md`: 新增本规格索引并在完成后回写状态。
- `docs/specs/zxuvb-microsoft-proof-surface-locale-hardening/SPEC.md`: 维护实现状态、里程碑与最终结论。

## 计划资产（Plan assets）

- Directory: `docs/specs/zxuvb-microsoft-proof-surface-locale-hardening/assets/`
- In-plan references: `![...](./assets/<file>.png)`
- Visual evidence source: maintain `## Visual Evidence` in this spec when owner-facing or PR-facing screenshots are needed.
- If an asset must be used in impl (runtime/test/official docs), list it in `资产晋升（Asset promotion）` and promote it to a stable project path during implementation.

## Visual Evidence

## 资产晋升（Asset promotion）

None

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: 建立 proof surface classifier 与未知 surface 显式诊断
- [x] M2: 修正 add-surface auto-provision 分支与错误分类 / 重试策略
- [x] M3: 补齐回归测试并完成 `bun run typecheck` / `bun test`
- [x] M4: 完成 fast-track 收口、101 滚动上线与目标账号回归验证

## 方案概述（Approach, high-level）

- 把 proof surface 识别抽成纯函数，输入为 route、标题 / body 摘要与关键 selector 命中，减少 handler 对单语言文案的耦合。
- 把 add-surface 与 email/confirmation/code surface 的路由判定统一收口，避免 generic email prompt 抢先接管 `/proofs/Add` 页面。
- 用显式诊断错误替代误导性的 mailbox missing 错误，让未来 locale/layout 漂移至少第一时间可观测。

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：Microsoft proof 页面存在 A/B layout，某些布局可能只有部分 selector 可见，需要 selector + 文案双重兜底。
- 需要决策的问题：None。
- 假设（需主人确认）：`home-lab-tavreg-hikari` 仍沿用既有 release 到 GHCR latest 再由 101 pull 的发布链路。

## 变更记录（Change log）

- 2026-04-17: 创建规格，冻结 proof surface locale hardening + diagnostics 的实现范围与验收口径。
- 2026-04-17: 完成 classifier / handler / 诊断改动，并通过 `bun run typecheck`、`bun test` 与两轮本地 review 收敛。
- 2026-04-18: 完成 101 热修上线与目标账号 `raidendaniella9161@hotmail.com` 的 proof mailbox 回归，worker log 确认 `provisioned Microsoft proof mailbox ...`，数据库 proof mailbox 与 session 状态回到可用态。

## 参考（References）

- `docs/specs/m1sso-microsoft-login/SPEC.md`
- `/home/ivan/srv/home-lab/tavreg-hikari-data/mailbox-oauth/mailbox-431-1776417415816/worker.log`
- `/home/ivan/srv/home-lab/tavreg-hikari-data/mailbox-oauth/mailbox-430-1776417286407/worker.log`
