# 默认邮箱生成收敛：provider-first + 真人风格兜底（#55uxa）

## 状态

- Status: 已完成
- Created: 2026-04-12
- Last: 2026-04-12

## 背景 / 问题陈述

- ChatGPT 默认 draft 目前会把邮箱直接拼成 `mail-<hex>@box-<hex>.<rootDomain>`，主人已经明确指出这种格式非常不合理。
- DuckMail 默认 local-part 也仍然是仓库内自拼策略，虽然比 hex 样式更好一些，但没有和 ChatGPT 的默认邮箱策略统一。
- 如果继续保留现状，运行态 Attempt、Storybook 演示与后续凭据视图会持续暴露不自然的邮箱地址，影响主人验收与后续使用判断。

## 目标 / 非目标

### Goals

- 将 ChatGPT 默认草稿改为优先使用 CF Mail provider 自动生成的随机邮箱。
- 为 ChatGPT fallback 与 DuckMail 共用一套更自然的 local-part 生成器。
- 保持现有 draft / job payload / DB 字段、DuckMail domain 选择与冲突重试链路不变。
- 更新 Storybook 示例与演示 fixture，确保当前 Attempt 卡片不再展示 `mail-<hex>@box-<hex>` 风格邮箱。

### Non-goals

- 不调整 GPTMail / VMail / Microsoft proof mailbox 的现有 provider 侧邮箱生成逻辑。
- 不新增新的环境变量、HTTP API、数据库字段或前端配置项，并移除 `CHATGPT_CFMAIL_ROOT_DOMAIN` 在 ChatGPT draft 路径中的使用。
- 不迁移历史已落库的邮箱记录。

## 范围（Scope）

### In scope

- `/src/server/main.ts` 的 ChatGPT draft 生成入口。
- `/src/main.ts` 的 DuckMail local-part 生成入口。
- 与邮箱生成相关的共享工具、单元测试与 ChatGPT Storybook 示例。

### Out of scope

- 账号导入格式、运行面板布局、凭据表结构或 CF Mail provider 自身的 domain 池管理策略。
- 与本次邮箱格式收敛无关的文案、交互和调度逻辑。

## 需求（Requirements）

### MUST

- ChatGPT 默认 draft 必须先尝试 provider-managed CF Mail mailbox 创建，请求中不得再主动传 `localPart/subdomain/rootDomain`。
- 当 provider-managed 创建因不支持自动生成或返回不可用记录而失败时，系统必须自动回退到共享的真人风格 local-part 方案；若当前 CF Mail 部署额外要求 caller-supplied `subdomain`，则 fallback 还必须补一个人类可读的 subdomain。
- DuckMail 创建地址时必须复用同一套真人风格 local-part 规则，且保留现有 domain 选择、地址冲突重试和 token 获取流程。
- 新的 local-part 必须保持小写 ASCII，并遵守当前 CF Mail provider 的 caller-supplied local-part 约束：整体风格固定为“名字 + 姓氏/别名 + 2~4 位数字”，必要时仅允许单个 `-` 作为连接，不得再出现 `mail-`、`box-` 或长 hex slug。
- ChatGPT 相关 Storybook 示例与演示 fixture 必须体现新的邮箱风格。

### SHOULD

- ChatGPT fallback 遇到地址冲突时继续自动重试，而不是把冲突直接上抛给主人。
- 与邮箱生成相关的新增测试应覆盖 provider-first 请求形状、fallback 条件与真人风格 local-part 约束。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- Web server 生成 ChatGPT attempt draft 时，先调用 CF Mail provision 接口且不主动传邮箱地址组成部分，由 provider 自己决定 canonical 邮箱地址、domain 与 mailbox id。
- 若该 provider-first 请求触发“需要 local-part / 自动生成不支持 / 返回记录不可用”一类错误，服务端改用共享真人风格 local-part 再发起 provision 请求；若 fallback 过程中返回 `subdomain required` 一类错误，则继续补充人类可读 subdomain 后重试。
- DuckMail 创建地址时继续先解析可用域名，再用新的真人风格 local-part 拼接邮箱地址并沿用现有冲突重试与 token 获取链路。
- ChatGPT 页 Storybook 运行态与最近 attempt 示例同步改成更自然的邮箱地址，作为主人验收入口。

### Edge cases / errors

- `cfmail_api_key_missing`、鉴权失败、rate-limit、provider domain 池异常等非“自动生成不支持”错误不得被 fallback 静默吞掉，必须继续按原错误上抛。
- Fallback provisioning 若再次命中地址冲突，可在当前 draft 生成链路内有限次重试；若重试耗尽，则返回最后一次真实错误。
- 生成出的 fallback local-part 若不满足规则约束，必须继续重试而不是落地异常格式。

## 接口契约（Interfaces & Contracts）

None

## 验收标准（Acceptance Criteria）

- Given ChatGPT 需要生成新的 attempt draft
  When 服务端首次调用 CF Mail provision
  Then 请求中不再主动传 `localPart/subdomain/rootDomain`。

- Given provider-managed CF Mail mailbox 创建成功
  When draft 返回给前端或调度器
  Then `email` 与 `mailboxId` 直接使用 provider 返回值，且 payload / DB 字段不发生变化。

- Given provider-managed 创建返回“需要 local-part”或不可用记录错误
  When 系统执行 fallback
  Then 会自动改用共享真人风格 local-part 重新 provision，并返回新的可用邮箱。

- Given 当前 CF Mail 部署在 fallback 时要求 `subdomain`
  When 系统收到 `subdomain required` 一类错误
  Then 会自动补充人类可读 subdomain 并继续 provision，而不是让 ChatGPT draft 直接失败。

- Given DuckMail 创建新邮箱地址
  When 需要组装 `address`
  Then local-part 使用共享真人风格规则，且现有 domain 选择、409 冲突重试与 token 请求行为保持不变。

- Given 主人查看 ChatGPT 运行态 Storybook
  When 页面展示 running / recent attempts
  Then 不再出现 `mail-<hex>@box-<hex>...` 风格邮箱，而是展示更自然的邮箱地址。

## 实现前置条件（Definition of Ready / Preconditions）

- 默认邮箱收敛范围已锁定为 ChatGPT draft + DuckMail 自拼入口。
- 无需新增 API / DB / env 配置的约束已锁定，且 `CHATGPT_CFMAIL_ROOT_DOMAIN` 必须从 ChatGPT draft 路径彻底移除。
- Storybook 已存在，可用于稳定展示 ChatGPT 运行态示例。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- Unit tests: 邮箱生成工具、ChatGPT provider-first / fallback draft 逻辑。
- Integration tests: 复用现有 Bun 测试覆盖，确保未破坏调度器与 CF Mail 封装。
- E2E tests (if applicable): 无新增 live E2E 要求。

### UI / Storybook (if applicable)

- Stories to add/update: `web/src/components/chatgpt-view.stories.tsx`
- Docs pages / state galleries to add/update: 复用现有 ChatGPT autodocs 页面。
- `play` / interaction coverage to add/update: 复用现有交互 story，确认更新后的示例数据仍可通过。

### Quality checks

- Lint / typecheck / formatting: `bun run typecheck`、`bun test`、`bun run build-storybook`

## 文档更新（Docs to Update）

- `docs/specs/README.md`: 新增本 spec，并在实现完成后回写状态与备注。

## 资产晋升（Asset promotion）

None

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: ChatGPT draft 生成改为 provider-first，并具备 fallback
- [x] M2: DuckMail 接入共享真人风格 local-part 生成器
- [x] M3: 补齐邮箱生成相关单元测试与 Storybook 示例数据
- [x] M4: 完成本地验证 / review proof / spec 收口

## 方案概述（Approach, high-level）

- 抽出一个共享邮箱生成工具模块，统一承载真人风格 local-part 规则与 CF Mail fallback 判定。
- ChatGPT draft 保持“provider canonical address 优先”，只在自动生成不受支持或记录不可用时回退到共享 local-part。
- DuckMail 只替换 local-part 生成器，不碰现有 domain / retry / token 链路。

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：CF Mail 线上错误消息格式若与当前预判不一致，fallback 判定可能需要再补充模式。
- 风险：不同 provider domain 池下返回的地址风格可能不完全一致，可能出现 provider-first 成功但地址仍偏随机，或 fallback 需要额外 caller-supplied `subdomain` 的情况。
- 假设：provider-managed 与 fallback provisioning 在不传 `rootDomain` 时都可由 CF Mail provider 自行选择可用 domain；若 provider 行为收紧，本次 fallback 仍需以真实错误上抛而不是重新引入 env。

## 变更记录（Change log）

- 2026-04-12: 创建 spec，冻结 provider-first + 真人风格兜底的默认邮箱生成改造范围。
- 2026-04-12: ChatGPT draft 改为 provider-first，DuckMail 切换到共享真人风格 local-part，并同步更新 Storybook 示例。
- 2026-04-12: ChatGPT fallback 补充兼容“subdomain required”类型部署，必要时自动生成人类可读 subdomain。
- 2026-04-12: 根据 live CF Mail 验证结果移除 `CHATGPT_CFMAIL_ROOT_DOMAIN` 依赖，provider-first 与 fallback 均改为让 provider 自行选择可用 domain。
- 2026-04-12: 根据 live CF Mail 的 local-part 校验规则收紧 fallback 生成器，改为 provider-compatible 的真人风格地址。
- 2026-04-12: 主人确认本任务不要求视觉证据，移除 spec 证据资产，仅保留 Storybook 示例与验证记录。
- 2026-04-12: 本地 typecheck / test / Storybook / review proof 已通过，任务完成。

## 参考（References）

- `docs/specs/pakwp-chatgpt-web-site/SPEC.md`
