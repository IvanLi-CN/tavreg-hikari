# Proxy Broker 代理运行时迁移实现（#pbk7x）

## 实现口径

- `src/proxy/broker.ts` 封装 Broker API client，统一 base URL、Bearer API key、超时、JSON 读取与 HTTP 错误映射。
- `src/server/proxy-broker-runtime.ts` 负责把 app settings 与环境变量归一化为 Broker 配置，并把 opened session 转为 worker 可消费的 `PROXY_BROKER_*` env。
- `src/server/proxy-broker-runtime.ts` 默认使用 30 秒 Broker API 超时，环境变量 `PROXY_BROKER_TIMEOUT_MS` 可覆盖；AbortError 被保留为 `proxy_broker_request_timeout`。
- `src/server/proxy-broker-runtime.ts` 提供 ready-session-only 的 proxy IP 复用 helper，调度器和单账号业务流不会从 failed / blocked / pending / bootstrapping 账号 session 继承旧 IP。
- `src/server/proxy-broker-runtime.ts` 在 open session 前读取 catalog，并只把近期探测成功且延迟达标的 IP 作为 Broker session 候选；仅当没有健康候选且 catalog 需要刷新时才同步触发 project refresh，避免少量 stale metadata 把业务启动卡在重探测接口。
- `src/server/proxy-broker-runtime.ts` 提供 `openDomainProbedProxyBrokerRuntimeSession`，先打开 Broker session，再用 `Impit({ proxyUrl: session.proxyUrl })` 经由同一个 listener 探测业务域名。
- 域名探测按业务站点绑定目标 URL，且不跟随重定向以便直接判定首个响应；HTTP 2xx、3xx、401、403、404 视为可达，其余 HTTP 状态、网络错误、超时与代理连接错误统一视为不可达。
- 域名不可达时 runtime best-effort 关闭失败 session，把 `selected_ip` 加入本次排除列表并重开 session；默认最多轮换 3 次，耗尽或健康候选提前耗尽后抛出上一轮 `proxy_domain_unreachable`，错误信息携带 site、URL、node、session id、出口 IP 与底层摘要。显式要求固定 preferred IP 且禁止 fallback 的调用方不会轮换到其它出口，固定出口探测失败后直接返回该 session 的 `proxy_domain_unreachable`。
- Web 调度器在 attempt 启动前 open Broker session，记录 session id、display address、node id、node name 与出口 IP，并在 attempt 完成、失败、停止或 spawn 失败时 best-effort close。
- Tavily、ChatGPT、Grok scheduler，单账号 Tavily / Microsoft / ChatGPT / Grok flow，以及 Microsoft mailbox OAuth bootstrap 均通过业务域名探测 helper 启动 Broker session。
- Worker 进程检测 `PROXY_BROKER_PROXY_URL` 后直接使用注入代理控制器，不再启动 Mihomo。
- 代理页 API 从本地 Mihomo sync/check 改为读取 Broker catalog 与 active sessions；手动检查触发 Broker project refresh，并把 catalog 探测结果写入现有 proxy diagnostics 表供历史查询。
- 代理页 API 在 catalog 或 active sessions 读取失败时返回已有快照和 `syncError`，不让前端收到空 catalog 导致二次 TypeError。

## 数据

- `job_attempts` 增加 `broker_session_id`、`proxy_display_address`、`proxy_node_id`。
- `proxy_nodes` 与 `proxy_checks` 继续保留，用于展示历史节点/IP/探测诊断，不作为生产代理池调度真相源。
- `proxy_nodes.node_id` 保存 Broker catalog 的稳定节点标识；显式代理节点选择必须使用 `node_id` 打开 session，并校验 Broker 返回的 `node_id` 与用户选择一致。
- catalog 快照状态以 `last_probe_ok` 为准；`can_open_session` 不写成健康状态。
- `PROXY_BROKER_API_KEY` 不进入 SQLite 与前端 payload。

## 验证

- `ProxyBrokerClient` 单元测试覆盖认证头、URL 拼接、open/list/close 与错误映射。
- `ProxyBrokerClient.refreshProject()` 单元测试覆盖 project refresh 请求与响应。
- Runtime 单元测试覆盖健康低延迟筛选、全量过期探测自动 refresh、混合 fresh/stale catalog 直接使用健康候选、无健康候选失败、catalog 不可读失败。
- Runtime 单元测试覆盖业务域名探测成功、失败后关闭并轮换、固定 preferred IP 禁止 fallback、排除 IP 合并、轮换耗尽与健康候选提前耗尽后的 `proxy_domain_unreachable`。
- 调度与 worker runtime 测试覆盖 Broker env 注入、attempt session 字段记录与 worker 跳过 Mihomo。
- 源码约束测试覆盖 Tavily、Microsoft、ChatGPT、Grok 启动入口传入正确业务站点 probe 配置。
- 代理页 Storybook 覆盖 catalog loaded、probe states、empty、auth error 与设置保存交互。
