# 实现状态

## Bootstrap 并发池

- `AccountSessionBootstrapDispatcher` 负责账号级有界并发、pending/active 去重与完成后继续泵队列。
- `src/server/main.ts` 保留原有 queue/force defer 语义；同账号重复 force 请求会等当前账号结束后重新排队，不会并发使用同一 profile。
- `microsoftAccountBootstrapConcurrency` 默认 `3`，通过 `MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY` 或 Graph 设置页调整，并规范化到 `1..10`。

## Worker 超时与回收

- Microsoft mailbox OAuth worker 使用独立进程组启动，超时先发 `SIGTERM`，`microsoftAccountBootstrapKillGraceMs` 后发 `SIGKILL` 兜底。
- `runMailboxOauthWorker` 的 `finally` 仍统一释放 mihomo 端口 lease；worker 失败、结果缺失或 timeout 都由 `authorizeMailboxWithBrowserAutomation` 写入 session/mailbox 失败态。
- `microsoftAccountBootstrapWorkerTimeoutMs` 默认 `300000`，`microsoftAccountBootstrapKillGraceMs` 默认 `10000`，两者最小值均为 `1000`。

## 设置与 UI

- `/api/microsoft-mail/settings` GET/POST 返回并保存 Graph OAuth 设置和 bootstrap 性能参数。
- `MailboxSettingsView` 在 Graph 设置页展示并发、worker timeout 与 kill grace 输入项，时间类输入以秒展示和编辑，保存时转换为 API 兼容的毫秒字段。
