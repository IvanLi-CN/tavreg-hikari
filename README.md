# Tavreg Hikari

本项目用于通过 Microsoft 账号完成 Tavily 第三方登录流程，并提取 API key。现在同时提供 CLI 和本机 Web 管理台两种入口。

## 入口

- `bun run start`
  - 保留原有 CLI 流程，适合单次调试或兼容旧脚本；该入口仍直接使用 Mihomo，需要配置 `MIHOMO_SUBSCRIPTION_URL`。
- `bun run web:build && bun run web:start`
  - 启动 Web 管理台服务；当前默认面向反向代理 / Forward Auth 场景，提供账号导入、主流程控制、API key 查询、`/settings` → `API Access` 与代理节点面板。

## Web 管理台

- 主流程页：启动任务、暂停、恢复、动态调整 `parallel / need / maxAttempts`，并支持在缺号时按站点开关自动提取微软账号；当前支持 `账号鸭 / 闪邮箱 / 闪客云 / Hotmail666` 四个渠道，按单源 `500ms/次` 轮转、最多 `4` 个并发请求。
- 微软账号页：支持 `email,password`、`email:password`、`email|password` 或 `email password` 的批量导入，按邮箱去重，查看是否已有 API key、最近状态、导入时间、跳过原因与收信状态，并提供四个提取器 KEY 设置与最近 7 天的本地提取历史查询。
- 微软账号页可在本地实例手动“从线上同步”，通过 production integration API 拉取线上账号、proof mailbox、分组、Tavily key 与服务快照，用本地 SQLite 重建可运行账号数据。
- 微软账号页现在会在导入/自动提取后立即为账号创建持久浏览器会话 bootstrap：自动选取代理池 IP、记住登录态、保存 `output/browser-profiles/accounts/<accountId>/chrome`，并在账号列表展示 session 状态、代理/IP 与 profile 路径摘要。
- 账号 session bootstrap 使用有界并发池，默认同时处理 3 个账号；可通过 `.env.local` 的 `MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY`、`MICROSOFT_ACCOUNT_BOOTSTRAP_WORKER_TIMEOUT_MS`、`MICROSOFT_ACCOUNT_BOOTSTRAP_KILL_GRACE_MS`，或 Microsoft Graph 设置页调整并发、worker 超时和强杀宽限。
- 后续 Tavily attempt 会优先复用账号上次成功的代理 IP；若原 IP 不在池中，则按同 region、再按全池健康节点的 LRU 选择代理，并继续复用同一持久 profile。
- 微软邮箱页：通过 Microsoft Graph OAuth 接入 Inbox，只读显示导入账号对应的收信状态、邮件列表与正文；主工作台固定为三栏收件箱视图，Graph 凭据改到独立设置页维护。
- Microsoft mailbox Bootstrap 以 Graph callback 写入的 token 状态为最终事实源：如果浏览器最终停在 SSO 中继页，但 DB 已写入 `refresh_token` / `oauth_connected_at`，服务端会按成功收敛，避免把已授权账号误标失败。
- API Keys 页：查询已提取的完整 KEY、状态、账号归属与提取时间，并支持行内复制。
- 设置页（API Access）：管理 `/api/integration/v1/*` 的外部接入 API key，支持多 key 创建、一次性明文展示、轮换、禁用与 last-used 审计。
- 代理节点页：查看 Proxy Broker profile catalog、活动 listener sessions、出口 IP / 地理信息诊断快照和 24 小时成功提取数量。

## 访问控制与外部接入

- Web 管理台现在统一按三类边界收口；生产部署可继续通过 Authelia ForwardAuth 生成 `Remote-User` / `Remote-Email`，但应用服务端仍会校验共享密钥并执行最终 gate：
  - `public`：仅保留 `/api/health`、`/api/microsoft-mail/oauth/callback` 与 `/api/integration/v1/*` namespace。
  - `internal`：其余 SPA / HTTP API / SSE / WebSocket upgrade 全部要求 Forward Auth 身份头。
  - `integration`：`/api/integration/v1/*` 只接受 API key，不回落到 Forward Auth。
- `internal` 默认读取以下头：
  - `X-Forwarded-User`
  - `X-Forwarded-Email`
- `internal` 还要求一个受信任代理共享密钥头，默认读取：
  - `X-Forwarded-Auth-Secret`
- 头名可通过 `.env.local` 覆盖：
  - `FORWARD_AUTH_USER_HEADER`
  - `FORWARD_AUTH_EMAIL_HEADER`
  - `FORWARD_AUTH_SECRET_HEADER`
- 共享密钥通过 `.env.local` 提供：
  - `FORWARD_AUTH_SECRET`
- 若 integration 流量经过本机/内网受信任反向代理，但该代理不会额外附带 `X-Forwarded-Auth-Secret` 到 integration 请求，可通过 `.env.local` 声明受信任代理网段：
  - `TRUSTED_PROXY_CIDRS`（默认空；只有显式声明的代理网段才会参与 forwarded client IP attribution）
- 若未配置 `FORWARD_AUTH_SECRET`，内部入口会 fail closed 并返回 `503`，避免直连请求伪造 Forward Auth 头绕过鉴权。
- `WEB_HOST` 只控制监听地址，不再等价于“localhost 免鉴权”；即使监听在 `127.0.0.1`，内部入口仍要求 Forward Auth。
- 外部实例接入 `/api/integration/v1/*` 时，可使用：
  - `Authorization: Bearer <plainTextKey>`
  - `X-API-Key: <plainTextKey>`
- v1 目前只开放 Microsoft 账号、Tavily 服务接入快照、Microsoft Mail Inbox 与 `cfmail` proof mailbox 验证码能力。

## 本地同步线上账号池

- 先在本地 `/settings` 的“线上数据同步”卡片开启同步，并保存线上地址、production integration API key 与回写模式。
- 本地 `/accounts` 的“从线上同步”按钮会调用 `POST /api/upstream-sync/accounts`，并按本地设置请求线上 `/api/integration/v1/microsoft-accounts`。
- 回写模式设为 `success_only` 后，本地 Tavily 单账号或批量 attempt 成功时只回写成功结果；失败、禁用、分组编辑、密码编辑不会回写线上。
- 同步不会复制线上 SQLite 或 Chrome profile。本地会保留自己的 `account_browser_sessions.profile_path` 与 session 状态，新同步账号仍需要在本机 bootstrap 或复用本机已有 profile。

## 运行前准备

- 主工作区首次初始化先执行 `bun install`，它会安装共享 `post-checkout` hook，供后续 linked worktree 自动补齐缺失的本地运行态。
- 复制 `.env.example` 为 `.env.local` 并填写必要配置。
- 至少需要：
  - OCR/OpenAI 兼容接口配置
  - `PROXY_BROKER_API_KEY`
  - 浏览器与邮箱相关配置（按当前运行模式选择）
  - 如需自动补号，请配置一个或多个提取器 KEY：`EXTRACTOR_ZHANGHAOYA_KEY`、`EXTRACTOR_SHANYOUXIANG_KEY`、`EXTRACTOR_SHANKEYUN_KEY`、`EXTRACTOR_HOTMAIL666_KEY`

## 显式指纹浏览器契约

- 运行时现在**只接受显式 `CHROME_EXECUTABLE_PATH`**，不会再扫描系统 Chrome、仓库工具目录、Playwright 缓存或其它候选浏览器。
- `CHROME_EXECUTABLE_PATH` 必须指向主人提供的指纹浏览器；路径缺失或不是允许的指纹浏览器时，worker 会在启动前直接失败。
- 浏览器来源现在固定为仓库内的 release manifest + 安装脚本：
  - Linux 默认固定 `144.0.7559.132`
  - macOS 默认固定 `142.0.7444.175`
- 本地安装统一使用：
  - `bash ./scripts/install-fingerprint-browser.sh --platform macos --force`
  - `bash ./scripts/install-fingerprint-browser.sh --platform linux --force`
- 默认安装路径：
  - macOS: `.tools/Chromium.app/Contents/MacOS/Chromium`
  - Linux: `.tools/fingerprint-browser/linux/chrome`
- Docker / Linux 运行镜像现在直接内置 Linux 指纹浏览器：
  - image path: `/opt/fingerprint-browser/chrome`
  - env: `CHROME_EXECUTABLE_PATH=/opt/fingerprint-browser/chrome`
- 当前 Linux 发布资产与 Docker 运行镜像都**仅支持 amd64 / x86_64**；arm64 Linux 会在安装阶段直接失败，避免装入错误架构的浏览器。

## Proxy Broker 代理运行时

- Web 调度路径不再启动本地 Mihomo 或读取订阅代理池；任务、账号 bootstrap、ChatGPT / Grok / Tavily worker 会通过 Proxy Broker 创建 mixed listener session。
- 默认 Broker 地址为 `https://proxy-broker.ivanli.cc`，默认 Broker project/profile 为 `Tavily`；可通过 `.env.local` 设置 `PROXY_BROKER_BASE_URL` 与 `PROXY_BROKER_PROFILE_ID` 覆盖。
- `PROXY_BROKER_API_KEY` 只从运行环境读取，不写入 SQLite，也不会返回给前端；未配置时 Web 任务启动会直接失败。
- 代理页只读展示 Broker base URL；保存配置时只接受 `proxyBrokerProfileId`、`checkUrl`、`timeoutMs`、`maxLatencyMs`，旧 Mihomo subscription / group / port 字段不再作为 Web 配置入口。
- 旧 Mihomo CLI 与兼容源码暂时保留，供历史调试路径使用；只运行 Web 管理台时不需要 `MIHOMO_SUBSCRIPTION_URL`。

## 发布治理

- 仓库已补齐 release-intent labels 与质量门禁：`type:*` + `channel:*`、`Review Policy Gate`、`CI PR`、`CI Main`、`Release`、release snapshot、PR release comment。
- 对外发布到 GHCR 的稳定 tag（例如 `v*` 与 `latest`）现在必须解析为**公开可读**的 single-platform image index / manifest list，而不是单 manifest 镜像对象。
- 上述公开 tag 必须至少暴露一个 `linux/amd64` 平台描述符，供外部检测链直接读取架构；镜像本体仍保持 amd64-only，不因此承诺 arm64。
- `candidate-*` 仍只作为 release pipeline 内部中间产物使用，不属于对外稳定契约的一部分。
- 未合并 PR 可通过 `PR Preview` workflow 发布临时 GHCR 镜像：`pr-<pr_number>-<short_sha>` 与 `pr-<pr_number>-latest`；该流程只从 PR head 构建，必须通过 Docker smoke 后才推送并在 PR 上评论 tag 与 digest。

## Linked Worktree Bootstrap

- 当主工作区已经准备好 `.env.local` 与 `output/registry/tavreg-hikari.sqlite` 后，新建 linked worktree 会在首次 checkout 时自动补齐缺失项；其中 `.env.local` 默认会以软链接方式共享主工作区配置。
- 若主工作区仍保留历史文件名 `output/registry/signup-tasks.sqlite`，首次启动或 bootstrap 会自动兼容到新的默认库名。
- 如果 worktree 里还没有 `node_modules`，bootstrap 还会自动执行依赖安装；存在 `bun.lock` 时固定走 `bun install --frozen-lockfile`，没有锁文件时改用 Bun 官方 `bun install --no-save`，避免历史 revision 被自动写出新锁文件。手工 `WORKTREE_SYNC_FORCE=1` 重跑时只有“之前已成功 bootstrap 的依赖状态”才会跳过，半失败残留会继续重试；安装失败也只记日志，不会让 checkout 直接失败。
- 同步清单固定来自 `scripts/worktree-sync.paths`；`.env.local` 默认以软链接共享，ledger 主文件仍生成独立快照；不会复制浏览器 profile、Mihomo 工作目录、运行日志或截图；但如果 `.env.local` 的 `CHROME_EXECUTABLE_PATH` 指向仓库内的指纹浏览器路径，bootstrap 仍会自动补齐当前 worktree 对应的浏览器运行时。仅当需要把共享 env 中的浏览器路径改写成当前 worktree 专属值时，脚本才会把 `.env.local` 落地为本地文件后再改写。
- 需要把 linked worktree 的 `.env.local` 发往其它目录或远端环境时（例如 shared testbox runner），上传流程会先解析共享软链接并传输实际文件内容，避免把指回本地主工作区的失效符号链接带出去。
- SQLite ledger 会通过 SQLite 原生 `VACUUM INTO` 生成一致性快照，不直接复制活跃数据库的 `-wal/-shm` 文件，也不会把整库一次性读进 JS 内存；若本机 `sqlite3` 不支持该语法，脚本会自动回退到 Bun 内置 SQLite 实现。
- 自动与手工重跑都遵循“只补缺，不覆盖”：目标文件已存在时会保留现状，不会覆盖 worktree 内的本地修改。
- 手工预演可用 `WORKTREE_SYNC_FORCE=1 WORKTREE_SYNC_DRY_RUN=1 ./scripts/sync-worktree-resources.sh`。
- 手工补齐缺失项可用 `WORKTREE_SYNC_FORCE=1 ./scripts/sync-worktree-resources.sh`。

## 常用脚本

- `bash ./scripts/install-fingerprint-browser.sh --platform macos --force`
- `bash ./scripts/install-fingerprint-browser.sh --platform linux --force`
- `node ./scripts/smoke-fingerprint-browser.mjs "$CHROME_EXECUTABLE_PATH"`
- `bun run typecheck`
- `bun test`
- `bun run hooks:install`
- `bun run test:worktree-bootstrap`
- `bun run web:build`
- `bun run web:start`
- `bun run ledger:query`
- `bun run proxy:check-all`

## 关联项目

- [Tavily Hikari](https://github.com/IvanLi-CN/tavily-hikari)：号池相关项目
