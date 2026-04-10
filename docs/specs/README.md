# 规格（Spec）总览

本目录用于管理工作项的规格与追踪，作为实现与验收的统一口径来源。

## Index（固定表格）

| ID | Title | Status | Spec | Last | Notes |
| ---: | --- | --- | --- | --- | --- |
| k9tfr | 显式指纹浏览器契约 + GitHub 质量门禁收口 | 进行中 | `k9tfr-explicit-fingerprint-browser-quality-gates/SPEC.md` | 2026-04-08 | 显式 `CHROME_EXECUTABLE_PATH`、跨平台安装脚本、Docker 内置指纹浏览器、CI/Release/branch rules |
| r6h9s | 主流程停止控制重构 | 进行中 | `r6h9s-job-stop-controls/SPEC.md` | 2026-03-28 | stop / force-stop、统一主按钮、Storybook 视觉证据 |
| m1sso | 固定 Microsoft Account 登录接入 Tavily 主流程 | 已完成 | `m1sso-microsoft-login/SPEC.md` | 2026-03-18 | 已落地 |
| 8855j | 增加批量注册（并行数 + 需求数） | 已完成 | `8855j-batch-parallel-need/SPEC.md` | 2026-03-01 | 已落地 |
| jfscm | 移除 both 运行模式并收敛为单模式执行 | 已完成 | `jfscm-remove-both-mode/SPEC.md` | 2026-03-01 | 已落地 |
| 6sfgt | 隐私数据与项目定位内容联合清理（含 main 历史重写） | 已完成 | `6sfgt-privacy-scrub/SPEC.md` | 2026-02-26 | 已落地 |
| 8v2kp | 注册任务 SQLite 台账与风控可筛选记录 | 已完成 | `8v2kp-signup-task-sqlite-ledger/SPEC.md` | 2026-02-25 | 已落地 |
| 2njxq | 增加 env 模板并提供本地初始化指引 | 已完成 | `2njxq-env-example-bootstrap/SPEC.md` | 2026-02-25 | PR #1 |
| 5nkhw | Tavreg Hikari Web 管理台 | 已完成 | `5nkhw-tavreg-hikari-web-control/SPEC.md` | 2026-03-19 | Web 控制台、调度器、预解析导入与账号分组已落地 |
| 2dkks | API Keys 批量选择与导出（`key | ip`） | 已完成 | `2dkks-api-key-batch-export/SPEC.md` | 2026-03-20 | PR #6 |
| svjx5 | 微软账号自动提取与本地历史接入 | 已完成 | `svjx5-microsoft-account-auto-extractor/SPEC.md` | 2026-03-27 | 四源适配、自动补号、本地历史 |
| gw9zj | 主工作区运行态同步到新 Worktree 的自动 Bootstrap | 已完成 | `gw9zj-worktree-runtime-bootstrap/SPEC.md` | 2026-04-10 | `.env.local` 默认改为共享软链接；仅在浏览器路径需要 worktree 专属改写时落地为本地文件，SQLite ledger 仍保持独立快照 |
| 9h2xd | 收敛 macOS 下 fingerprint Chromium + CDP 登录恢复链路 | 已完成 | `9h2xd-macos-headless-chrome-launch/SPEC.md` | 2026-03-27 | 保持 fingerprint-chromium + CDP，worker 优先走 Node，并修正 Tavily home / passkey 恢复链路 |
| jg53e | 微软邮箱 Graph/OAuth 收信模块 | 已实现 | `jg53e-microsoft-mail-inbox/SPEC.md` | 2026-03-31 | `/mailboxes` 三栏页、独立 Graph 设置页、账号页收信状态，补齐桌面操作列防挤压证据 |
| rxae7 | 默认 SQLite 数据库文件名规范化 | 已完成 | `rxae7-registry-db-filename/SPEC.md` | 2026-03-31 | 默认库名收敛为 tavreg-hikari.sqlite，并兼容历史 signup-tasks.sqlite |
| wht6n | 微软账号持久会话、代理复用与 Profile 落库改造 | 已实现 | `wht6n-persistent-account-browser-sessions/SPEC.md` | 2026-03-31 | 账号级 session bootstrap、proxy reuse、profile path 落库与账号页视觉证据 |
| 3jg3v | 提号器 Outlook/Hotmail/不限 类型全链路支持 | 已完成 | `3jg3v-extractor-account-type-switch/SPEC.md` | 2026-04-04 | 提号器、自动补号与号源请求参数统一支持 `outlook \| hotmail \| unlimited`，含 Storybook 证据 |
| pakwp | ChatGPT 站点接入现有 Web 管理台 | 已实现 | `pakwp-chatgpt-web-site/SPEC.md` | 2026-04-05 | 多站点 current job、ChatGPT 页面、完整凭据入库 |
| m9jnq | Keys 页双数据源收敛：Tavily / ChatGPT 双 Tabs | 已完成 | `m9jnq-keys-dual-source-page/SPEC.md` | 2026-04-09 | 统一 Keys 导航与双 tabs，接管 pakwp / 2dkks 的旧 UI 口径 |
