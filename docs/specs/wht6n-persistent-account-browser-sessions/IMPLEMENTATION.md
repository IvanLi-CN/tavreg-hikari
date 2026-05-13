# 实现状态

## Bootstrap 并发池

- `AccountSessionBootstrapDispatcher` 负责账号级有界并发、pending/active 去重与完成后继续泵队列。
- `src/server/main.ts` 保留原有 queue/force defer 语义；同账号重复 force 请求会等当前账号结束后重新排队，不会并发使用同一 profile。
- `microsoftAccountBootstrapConcurrency` 默认 `3`，通过 `MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY` 或 Graph 设置页调整，并规范化到 `1..10`。
- `AccountBootstrapProxyTracker` 在并发池内维护活跃 bootstrap 出口 IP，并在打开 Proxy Broker session 时传入 `excludedIps`；显式选择节点时不排除其他活跃 IP，避免违背用户选择。
- 只有 `ready` browser session 的历史 IP 可作为 preferred IP。失败 session 的 IP 会继续保留在失败快照中做诊断，但不会参与后续非 ready session 的优先复用。
- 显式选择代理节点且已解析出 preferred IP 时，Broker session 直接按该 IP 打开，不再先依赖全量 catalog 健康筛选；若该 IP 当前不可开，直接返回 Broker 的精确失败。
- Broker catalog refresh 后会短轮询最新探测结果，避免刚刷新后读到暂时为空的健康池而误报无可用节点。
- 本地外部验证可通过 `PROXY_BROKER_DISPLAY_HOST_OVERRIDE` 将 Broker 返回的内部 `display_address` host 映射成当前机器可访问 host；生产默认不启用。

## Bootstrap 登录方案

- `microsoftAccountBootstrapLoginMode` 默认 `microsoft_graph`，可通过 `MICROSOFT_ACCOUNT_BOOTSTRAP_LOGIN_MODE` 或 Microsoft Graph 设置页切换。
- `microsoft_graph` 方案复用现有 `microsoft-oauth-worker`，以本地 OAuth callback/Graph token 写入与 profile 登录态保留作为成功事实源，不再要求访问或回到 `app.tavily.com/home`。
- `tavily_home` 方案保留旧兼容语义：Microsoft social login 必须回到 Tavily Home；未到达时继续归类为 `microsoft_oauth_did_not_reach_home`。
- Microsoft keep-signed-in prompt 覆盖英文、中文与日语文案，避免 Graph/Tavily 登录链路停在日语 `サインインの状態を維持しますか?` 页面。

## Worker 超时与回收

- Microsoft mailbox OAuth worker 使用独立进程组启动，超时先发 `SIGTERM`，`microsoftAccountBootstrapKillGraceMs` 后发 `SIGKILL` 兜底。
- `runMailboxOauthWorker` 的 `finally` 仍统一释放 mihomo 端口 lease；worker 失败、结果缺失或 timeout 都由 `authorizeMailboxWithBrowserAutomation` 写入 session/mailbox 失败态。
- `microsoftAccountBootstrapWorkerTimeoutMs` 默认 `300000`，`microsoftAccountBootstrapKillGraceMs` 默认 `10000`，两者最小值均为 `1000`。
- 服务启动和 `/api/accounts` 读取路径都会收敛超过 `workerTimeoutMs + killGraceMs + 30000` 的 stale `bootstrapping` session，将 session、mailbox 与 account 同步标记为 `failed/session_bootstrap_stale`。
- Microsoft OAuth 失败、worker timeout 与 Proxy Broker abort 会归一到稳定错误码，并在落库前脱敏诊断 URL 的 query/hash。

## 设置与 UI

- `/api/microsoft-mail/settings` GET/POST 返回并保存 Graph OAuth 设置、bootstrap 登录方案和性能参数。
- `MailboxSettingsView` 在 Graph 设置页展示并发、worker timeout 与 kill grace 输入项，时间类输入以秒展示和编辑，保存时转换为 API 兼容的毫秒字段。
- 账号页 `Session` 与 `收信` badge 复用 `StatusBadge` 和 Radix Tooltip；失败、阻断、锁定和失效状态可通过 hover/focus 查看阶段、错误码与失败原因。
- 账号池列表刷新使用 latest-only request gate；SSE/WebSocket 触发的自动刷新如果晚于用户翻页请求返回，不会覆盖当前页数据或触发旧页的空页回退。
