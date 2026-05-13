# Proxy Broker 代理运行时迁移历史（#pbk7x）

## 背景

本项目原先直接启动 Mihomo 并从订阅中维护本地代理池。Proxy Broker 已经成为统一代理能力入口，提供 profile catalog、listener session 与机器认证。

## 决策

- Web 生产路径以 Proxy Broker session 为代理运行时边界。
- 业务任务启动不再只依赖 Broker session 创建成功；必须先通过同一个 listener session 探测业务域名，失败时关闭并轮换，避免浏览器第一跳才暴露代理不可达。
- 业务启动前的 Broker refresh 是恢复手段而不是常规门槛；当 catalog 已经有健康候选时，混合存在的少量 stale metadata 不应触发同步 refresh，否则会把 Tavily、ChatGPT 与 Grok 启动共同拖入 Broker API timeout。
- 显式指定代理出口的启动路径保持精确出口语义；该出口业务域名不可达时直接失败并要求轮换，不会静默换用其它出口。
- 旧 Mihomo 源码暂时保留，降低 CLI 与历史调试路径迁移风险。
- 前端只展示 Broker profile、catalog、active sessions 与历史诊断快照，不展示或编辑 Broker API key。
- 既有 `proxy_nodes` / `proxy_checks` 作为历史诊断表继续存在，不再作为生产调度池的真相源。
