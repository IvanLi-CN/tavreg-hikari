# 线上账号数据同步到本地实例实现状态（#hn72q）

## Current Status

- Implementation: 已实现，待最终验证与 PR 收敛
- Lifecycle: active
- Catalog note: 本地 `/accounts` 需要从线上 integration API 拉取账号数据与三站点成功 keys，并仅回写本地成功结果。

## Coverage / rollout summary

- 新增本地 upstream sync API、`/settings` 持久化配置入口与 `/accounts` 手动同步入口。
- `/settings` 使用显式同步开关控制本地是否访问线上实例；API key 输入为空时保留已保存 key，不提供清除 key 功能。
- 扩展 integration v1 账号读契约、统一 keys 读契约与三站点 success writeback。
- 新增 SQLite 上游映射字段、同步 repository 方法、ChatGPT/Grok synthetic sync attempt 与 Tavily service access snapshot 导入。
- Storybook 覆盖 `/settings` 同步配置状态与 `/accounts` 同步 idle/loading/success/error 状态。

## References

- `./SPEC.md`
- `../3aqn8-http-integration-auth-v1/SPEC.md`
- `../wht6n-persistent-account-browser-sessions/SPEC.md`
