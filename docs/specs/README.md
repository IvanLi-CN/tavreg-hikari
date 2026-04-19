# 规格（Spec）总览

本目录用于管理工作项的规格与追踪，作为实现与验收的统一口径来源。

## Index（固定表格）

| ID | Title | Status | Spec | Last | Notes |
| ---: | --- | --- | --- | --- | --- |
| 8tmtv | 微软账号列表双字段分组与图标化操作 | 已实现 | `8tmtv-microsoft-account-list-two-field-layout/SPEC.md` | 2026-04-17 | 双字段布局、辅助邮箱命名、图标 tooltip 与默认导入时间倒序已落地 |
| kq7rv | 跨站点任务控制区对齐：ChatGPT 补齐更新限制，Tavily / ChatGPT 对齐 Grok | 已完成 | `kq7rv-cross-site-job-control-alignment/SPEC.md` | 2026-04-17 | PR #48；ChatGPT 补 pause/resume/update_limits，Tavily 控制区文案与按钮顺序对齐 Grok |
| s76pf | 共享 mailbox provider 启动节流 | 已完成 | `s76pf-mailbox-provider-start-pacing/SPEC.md` | 2026-04-14 | PR #41；共享 guard 增加最小启动间隔，压平 ChatGPT / Grok 的 mailbox provisioning 启动波峰 |
| vyg62 | Release 失败 Telegram 告警接入 | 进行中 | `vyg62-release-failure-telegram-alerts/SPEC.md` | 2026-04-11 | release notifier wrapper、SHA 标记、Telegram smoke test |
| k9tfr | 显式指纹浏览器契约 + GitHub 质量门禁收口 | 进行中 | `k9tfr-explicit-fingerprint-browser-quality-gates/SPEC.md` | 2026-04-08 | 显式 `CHROME_EXECUTABLE_PATH`、跨平台安装脚本、Docker 内置指纹浏览器、CI/Release/branch rules |
| r6h9s | 主流程停止控制重构 | 进行中 | `r6h9s-job-stop-controls/SPEC.md` | 2026-03-28 | stop / force-stop、统一主按钮、Storybook 视觉证据 |
| m1sso | 固定 Microsoft Account 登录接入 Tavily 主流程 | 已完成 | `m1sso-microsoft-login/SPEC.md` | 2026-03-18 | 已落地 |
| 8855j | 增加批量注册（并行数 + 需求数） | 已完成 | `8855j-batch-parallel-need/SPEC.md` | 2026-03-01 | 已落地 |
| jfscm | 移除 both 运行模式并收敛为单模式执行 | 已完成 | `jfscm-remove-both-mode/SPEC.md` | 2026-03-01 | 已落地 |
| 6sfgt | 隐私数据与项目定位内容联合清理（含 main 历史重写） | 已完成 | `6sfgt-privacy-scrub/SPEC.md` | 2026-02-26 | 已落地 |
| 8v2kp | 注册任务 SQLite 台账与风控可筛选记录 | 已完成 | `8v2kp-signup-task-sqlite-ledger/SPEC.md` | 2026-02-25 | 已落地 |
| 2njxq | 增加 env 模板并提供本地初始化指引 | 已完成 | `2njxq-env-example-bootstrap/SPEC.md` | 2026-02-25 | PR #1 |
| 5nkhw | Tavreg Hikari Web 管理台 | 已完成 | `5nkhw-tavreg-hikari-web-control/SPEC.md` | 2026-04-16 | Web 控制台、调度器、预解析导入与账号分组已落地；微软多段 `----` 导入仅取前两段 |
| 2dkks | API Keys 批量选择与导出（`key | ip`） | 已完成 | `2dkks-api-key-batch-export/SPEC.md` | 2026-04-15 | PR #6；Tavily Keys 列表补充明文 KEY 单列与行内复制 |
| svjx5 | 微软账号自动提取与本地历史接入 | 已完成 | `svjx5-microsoft-account-auto-extractor/SPEC.md` | 2026-03-27 | 四源适配、自动补号、本地历史 |
| gw9zj | 主工作区运行态同步到新 Worktree 的自动 Bootstrap | 已完成 | `gw9zj-worktree-runtime-bootstrap/SPEC.md` | 2026-04-10 | `.env.local` 默认改为共享软链接；仅在浏览器路径需要 worktree 专属改写时落地为本地文件，shared testbox 上传链路会自动传输解析后的 env 内容，并补齐 source-only helper 的 SQLite staging / temp cleanup 覆盖 |
| 9h2xd | 收敛 macOS 下 fingerprint Chromium + CDP 登录恢复链路 | 已完成 | `9h2xd-macos-headless-chrome-launch/SPEC.md` | 2026-03-27 | 保持 fingerprint-chromium + CDP，worker 优先走 Node，并修正 Tavily home / passkey 恢复链路 |
| jg53e | 微软邮箱 Graph/OAuth 收信模块 | 已实现 | `jg53e-microsoft-mail-inbox/SPEC.md` | 2026-03-31 | `/mailboxes` 三栏页、独立 Graph 设置页、账号页收信状态，补齐桌面操作列防挤压证据 |
| rxae7 | 默认 SQLite 数据库文件名规范化 | 已完成 | `rxae7-registry-db-filename/SPEC.md` | 2026-03-31 | 默认库名收敛为 tavreg-hikari.sqlite，并兼容历史 signup-tasks.sqlite |
| wht6n | 微软账号持久会话、代理复用与 Profile 落库改造 | 已实现 | `wht6n-persistent-account-browser-sessions/SPEC.md` | 2026-03-31 | 账号级 session bootstrap、proxy reuse、profile path 落库与账号页视觉证据 |
| 3jg3v | 提号器 Outlook/Hotmail/不限 类型全链路支持 | 已完成 | `3jg3v-extractor-account-type-switch/SPEC.md` | 2026-04-04 | 提号器、自动补号与号源请求参数统一支持 `outlook \| hotmail \| unlimited`，含 Storybook 证据 |
| pakwp | ChatGPT 站点接入现有 Web 管理台 | 已实现 | `pakwp-chatgpt-web-site/SPEC.md` | 2026-04-05 | 多站点 current job、ChatGPT 页面、完整凭据入库 |
| 3hrx4 | Grok 第三站点接入现有 Web 管理台 | 已实现 | `3hrx4-grok-web-site/SPEC.md` | 2026-04-10 | 第三站点路由、Grok scheduler/worker、独立 keys tab 与导出 |
| m9jnq | Keys 页双数据源收敛：Tavily / ChatGPT 双 Tabs | 已完成 | `m9jnq-keys-dual-source-page/SPEC.md` | 2026-04-09 | 统一 Keys 导航与双 tabs，接管 pakwp / 2dkks 的旧 UI 口径 |
| 55uxa | 默认邮箱生成收敛：provider-first + 真人风格兜底 | 已完成 | `55uxa-provider-first-default-mailboxes/SPEC.md` | 2026-04-12 | ChatGPT draft provider-first、DuckMail 共用真人风格 local-part，移除 `CHATGPT_CFMAIL_ROOT_DOMAIN` 依赖 |
| 9p1fh | 微软账号页 Session Proxy 行内更换代理节点 | 已完成 | `9p1fh-account-session-proxy-switch/SPEC.md` | 2026-04-17 | 账号级代理切换弹窗、单节点测速复用、立即 rebootstrap；切换后列表/弹窗即时回显新节点并清空旧 IP |
| bqa97 | 代理节点检查并发化与 SSE 进度流 | 已完成 | `bqa97-proxy-check-progress-stream/SPEC.md` | 2026-04-15 | `/api/proxies` 快照化、独立 proxy check coordinator、SSE 进度推送 |
| zxuvb | Microsoft proof 补邮箱分支修复与多语言诊断加固 | 已完成 | `zxuvb-microsoft-proof-surface-locale-hardening/SPEC.md` | 2026-04-18 | 101 热修上线并完成 `raidendaniella9161@hotmail.com` 的 proof mailbox 回归；zh-TW `/proofs/Add` auto-provision 已恢复 |
| vhvds | ChatGPT 补号到 codex-vibe-monitor 分组 | 已完成 | `vhvds-chatgpt-upstream-account-supplement/SPEC.md` | 2026-04-18 | 自动补号 + Keys 批量补号 + 设置入口收敛到 Keys > ChatGPT |
| 8qyzh | Web 管理台导航收敛与 Microsoft 信箱抽屉整合 | 已完成 | `8qyzh-nav-keys-mailbox-consolidation/SPEC.md` | 2026-04-19 | PR #54 merge-ready；顶栏五项、站内 Keys 子视图、Microsoft drawer、工具列记忆与视觉证据已收口 |
