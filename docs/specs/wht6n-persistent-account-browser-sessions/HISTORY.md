# 历史记录

## 2026-05-11

- 修复账号池分页与实时刷新竞态：`/api/accounts` 旧请求晚返回时不再覆盖用户已切换到的新页。
- 补充 stale `bootstrapping` session 自动失败收敛，避免 worker 已结束但账号页仍显示运行中的残留状态。
- 将 Microsoft OAuth 未回到 Tavily Home、worker timeout 与代理 session abort 统一落成可诊断错误码，并在账号页 `Session` / `收信` badge 上暴露失败 tooltip。

## 2026-05-09

- 将 Microsoft account session bootstrap 从串行 exclusive runner 改为账号级有界并发池，默认并发 `3`，上限 `10`。
- 为 mailbox OAuth worker 增加配置化 timeout 与 `SIGTERM` -> `SIGKILL` 兜底，沿用端口 lease `finally` 释放路径。
- Graph 设置页与 `/api/microsoft-mail/settings` 增加 bootstrap 性能参数，方便运行时调优。

## 2026-04-26

- 补充 Graph OAuth/收信 integration detail API 的 token 过期测试边界，避免日期推进导致验证误判。

## 2026-04-07

- 补充账号页桌面态工具列收起、`Session / 收信状态` 服务端筛选，以及批量 Bootstrap preview / 强制模式的收口说明与视觉证据。

## 2026-03-31

- 初版 spec 冻结账号持久会话、代理复用与 profile 落库改造范围。
