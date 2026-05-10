# Proxy Broker 代理运行时迁移历史（#pbk7x）

## 背景

本项目原先直接启动 Mihomo 并从订阅中维护本地代理池。Proxy Broker 已经成为统一代理能力入口，提供 profile catalog、listener session 与机器认证。

## 决策

- Web 生产路径以 Proxy Broker session 为代理运行时边界。
- 旧 Mihomo 源码暂时保留，降低 CLI 与历史调试路径迁移风险。
- 前端只展示 Broker profile、catalog、active sessions 与历史诊断快照，不展示或编辑 Broker API key。
- 既有 `proxy_nodes` / `proxy_checks` 作为历史诊断表继续存在，不再作为生产调度池的真相源。
