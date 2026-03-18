# Tavreg Hikari Web 管理台（#5nkhw）

## 状态

- Status: 已实现
- Created: 2026-03-18
- Last: 2026-03-18

## 背景 / 问题陈述

- 当前项目以 CLI 为唯一控制入口，虽然已经具备 Microsoft 登录、Tavily Home 落地、API key 提取、SQLite ledger 与代理节点检查能力，但账号导入、批量控制、代理状态和历史查询都只能通过命令行与散落的 JSON/SQLite 工具完成。
- 号池和主流程已经出现“账号池管理”“跳过已有 key”“动态调整并行”“代理状态面板”“运行中实时观察”的明确产品需求，现有 CLI 结构无法支撑。
- 现有自动化主逻辑高度集中在 `src/main.ts`，需要在不破坏既有流程的前提下，补一层 Web 控制台与可复用服务边界。

## 目标 / 非目标

### Goals

- 提供 `localhost` Web 管理台作为主入口，支持微软账号导入、主流程控制、账号查询、API key 查询和代理节点管理。
- 保留现有 Bun/TypeScript + SQLite + Playwright + Mihomo 技术方向，避免引入额外重型运行时。
- 将主流程改造成单活任务编排器，支持软暂停、动态调整 `parallel` / `need` / `maxAttempts`，并实时回传运行状态。
- 复用现有自动化逻辑完成 Microsoft 第三方登录与 Tavily API key 提取，不做人工接管流程。
- 将“已有 API key 的账号跳过”“账号去重导入”“代理节点 24h 成功统计”等业务规则做成结构化数据与可查询界面。

### Non-goals

- 不支持公网部署与多用户权限控制。
- 不支持 Google/GitHub/LinkedIn 等其他第三方登录提供商。
- 不实现代理节点的手工增删改，只处理 Mihomo 订阅配置与节点同步/选择/检查。
- 不抓取 Tavily 配额、套餐、usage 等更深层账号信息。

## 技术选型

- 服务端：`Bun.serve`
- 持久化：`bun:sqlite`（与现有 `TASK_LEDGER_DB_PATH` 共用同一 SQLite 文件）
- 前端：`Vite + React + TypeScript`
- 样式：`Tailwind CSS`
- 实时通道：`WebSocket`
- 自动化执行：保留现有 `src/main.ts` 单账号运行能力，通过服务端调度器按账号子进程复用，并补必要的环境变量与 ledger 关联字段

### 选型理由

- 与现有项目快照保持一致：`Tavreg Hikari` 已是 `Bun/TypeScript + SQLite + browser automation` 单体。
- `Vite + React` 适合高频交互控制台，不需要引入 SSR。
- `Tailwind CSS` 能快速实现响应式管理台，并与后续组件抽象兼容。
- `WebSocket` 比 SSE 更适合多类型事件与后续控制命令扩展。

## 范围（Scope）

### In scope

- 新增业务数据表：`microsoft_accounts`、`api_keys`、`jobs`、`job_attempts`、`proxy_nodes`、`proxy_checks`、`app_settings`
- 扩展 `signup_tasks` 以关联 `job_id` / `account_id`
- 新增 Web API 与前端管理台
- 新增导入规则、调度规则、代理检查与同步逻辑
- 保持现有 CLI 脚本与输出产物兼容

### Out of scope

- 改写现有所有自动化细节为插件式架构
- 重写 Playwright/Mihomo 核心实现
- 更换数据库或拆分为多服务部署

## 数据模型

### microsoft_accounts

- `id`
- `microsoft_email`（唯一）
- `password_plaintext`
- `has_api_key`
- `api_key_id`
- `imported_at`
- `updated_at`
- `last_used_at`
- `last_result_status`
- `last_result_at`
- `last_error_code`
- `skip_reason`
- `disabled_at`

### api_keys

- `id`
- `account_id`
- `api_key`
- `api_key_prefix`
- `status`
- `extracted_at`
- `last_verified_at`

### jobs

- `id`
- `status`
- `run_mode`
- `need`
- `parallel`
- `max_attempts`
- `success_count`
- `failure_count`
- `skip_count`
- `launched_count`
- `started_at`
- `paused_at`
- `completed_at`

### job_attempts

- `id`
- `job_id`
- `account_id`
- `run_id`
- `status`
- `stage`
- `proxy_node`
- `proxy_ip`
- `error_code`
- `error_message`
- `started_at`
- `completed_at`
- `duration_ms`

### proxy_nodes

- `id`
- `node_name`（唯一）
- `is_selected`
- `last_status`
- `last_latency_ms`
- `last_egress_ip`
- `last_country`
- `last_city`
- `last_org`
- `last_checked_at`
- `last_selected_at`

### proxy_checks

- `id`
- `node_name`
- `status`
- `latency_ms`
- `egress_ip`
- `country`
- `city`
- `org`
- `error`
- `checked_at`

### app_settings

- `key`
- `value_json`
- 用于保存 Mihomo 订阅参数、默认任务参数、Web 监听配置

## API 合约

- `POST /api/accounts/import`
- `GET /api/accounts`
- `GET /api/api-keys`
- `GET /api/proxies`
- `POST /api/proxies/settings`
- `POST /api/proxies/check`
- `POST /api/proxies/select`
- `GET /api/jobs/current`
- `POST /api/jobs/current/control`
- `GET /api/events/ws`

## 行为规格

### 账号导入

- 前端导入格式固定为 `email,password`
- 空行忽略
- 同一批次重复邮箱以最后一条为准
- 落库时按邮箱唯一 upsert
- 若账号已有有效 API key，则保留 `has_api_key=true` 与 `skip_reason=has_api_key`

### 主流程调度

- 仅允许一个 active job
- 只派发“未禁用、未 lease、无 API key、无跳过标记、本 job 未跑过”的账号
- 排序规则：`last_used_at nulls first, imported_at asc`
- 完成条件：成功提取到 API key 的账号数达到 `need`
- 软暂停：停止新派发，已启动账号继续完成
- 动态调参：仅影响未派发部分

### 代理页

- 支持更新 Mihomo 订阅参数并立即同步节点列表
- 支持检查当前节点、全部节点或单个节点
- 节点状态展示需要包含：当前状态、延迟、出口 IP、地理信息、24h 成功数

## 验收标准（Acceptance Criteria）

- Given 导入同一微软邮箱多次，When 导入完成，Then 数据库中仅保留一条账号记录并更新密码、导入时间和最近来源。
- Given 某账号已有有效 API key，When 创建主流程任务，Then 调度器不会派发该账号，并在账号页标记为跳过。
- Given 主流程正在运行，When 用户点击暂停，Then 不再派发新账号，已运行账号继续完成。
- Given 主流程正在运行，When 用户修改 `parallel` / `need` / `maxAttempts`，Then 修改立即作用于后续派发，不中断当前账号。
- Given 任务成功完成 Microsoft 登录与 Tavily Home 流程，When 成功提取 API key，Then 账号状态、API key 记录、job attempt 与 `signup_tasks` 都正确关联更新。
- Given 用户打开代理页并执行节点检查，When 检查完成，Then 界面显示节点延迟、出口 IP、地理信息和检查结果。
- Given 当前实现完成，When 执行 `bun run typecheck`、`bun test` 与前端构建，Then 全部通过。

## 里程碑

- [x] M1: 建立 spec、前端工具链与 Web/Bun 入口
- [x] M2: 完成业务数据表与 repository
- [x] M3: 完成单活 job scheduler 与子进程复用现有 CLI 自动化
- [x] M4: 完成账户/API key/代理 REST API 与 WebSocket
- [x] M5: 完成 React 管理台三大页面
- [x] M6: 完成验证、spec sync 与 merge-ready 收敛

## 文档更新（Docs to Update）

- `docs/specs/README.md`
- `.env.example`
- `README.md`

## Change log

- 2026-03-18: 初始化 Web 管理台规格，锁定 Bun 单体 + React/Vite + SQLite + WebSocket 方案。
- 2026-03-18: 完成 Web 管理台实现，补齐业务表、调度器、REST/WebSocket、React 控制台、测试入口与文档同步。
