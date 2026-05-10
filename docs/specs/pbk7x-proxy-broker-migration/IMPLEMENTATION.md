# Proxy Broker 代理运行时迁移实现（#pbk7x）

## 实现口径

- `src/proxy/broker.ts` 封装 Broker API client，统一 base URL、Bearer API key、超时、JSON 读取与 HTTP 错误映射。
- `src/server/proxy-broker-runtime.ts` 负责把 app settings 与环境变量归一化为 Broker 配置，并把 opened session 转为 worker 可消费的 `PROXY_BROKER_*` env。
- `src/server/proxy-broker-runtime.ts` 在 open session 前读取 catalog，必要时触发 project refresh，并只把近期探测成功且延迟达标的 IP 作为 Broker session 候选。
- Web 调度器在 attempt 启动前 open Broker session，记录 session id、display address、node id、node name 与出口 IP，并在 attempt 完成、失败、停止或 spawn 失败时 best-effort close。
- Worker 进程检测 `PROXY_BROKER_PROXY_URL` 后直接使用注入代理控制器，不再启动 Mihomo。
- 代理页 API 从本地 Mihomo sync/check 改为读取 Broker catalog 与 active sessions；手动检查触发 Broker project refresh，并把 catalog 探测结果写入现有 proxy diagnostics 表供历史查询。

## 数据

- `job_attempts` 增加 `broker_session_id`、`proxy_display_address`、`proxy_node_id`。
- `proxy_nodes` 与 `proxy_checks` 继续保留，用于展示历史节点/IP/探测诊断，不作为生产代理池调度真相源。
- catalog 快照状态以 `last_probe_ok` 为准；`can_open_session` 不写成健康状态。
- `PROXY_BROKER_API_KEY` 不进入 SQLite 与前端 payload。

## 验证

- `ProxyBrokerClient` 单元测试覆盖认证头、URL 拼接、open/list/close 与错误映射。
- `ProxyBrokerClient.refreshProject()` 单元测试覆盖 project refresh 请求与响应。
- Runtime 单元测试覆盖健康低延迟筛选、过期探测自动 refresh、无健康候选失败、catalog 不可读失败。
- 调度与 worker runtime 测试覆盖 Broker env 注入、attempt session 字段记录与 worker 跳过 Mihomo。
- 代理页 Storybook 覆盖 catalog loaded、probe states、empty、auth error 与设置保存交互。
