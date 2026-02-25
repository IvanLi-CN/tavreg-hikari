# 注册任务 SQLite 台账与风控可筛选记录（#8v2kp）

## 状态

- Status: 已完成
- Created: 2026-02-25
- Last: 2026-02-25

## 背景 / 问题陈述

- 当前仅有 `output/*.json` 文件型产物，缺少结构化历史台账，不便跨任务筛选“高风险 IP / 失败模式 / 成功率”。
- 注册失败存在 `Too many signups from the same IP` 与 `Suspicious activity` 等风险信号，需要可查询、可统计的数据沉淀。
- 运行环境可能并发（多个程序/实例），必须考虑 SQLite 并发读写稳定性。

## 目标 / 非目标

### Goals

- 引入 SQLite 任务台账，记录每次注册任务的关键字段（可筛选列）与详细 JSON（富上下文）。
- 在主流程中写入“开始/进行中/成功/失败”全生命周期记录。
- 提供并发安全方案（WAL + busy_timeout + 索引 + 轻量事务）支持多读单写场景。
- 将“近期触发 IP 限流”的历史信息接入代理选点避让。

### Non-goals

- 不替代现有 `output/*.json` 文件产物（仍保留）。
- 不引入外部数据库服务（仅 SQLite）。

## 范围（Scope）

### In scope

- 新增 SQLite 模块与表结构初始化（schema version、主表、必要索引）。
- 主流程写库：任务开始、阶段更新、结束结果（成功/失败）、风险信号摘要。
- 关键字段列化（如 status/proxy_ip/error_code/suspicious flags），其余明细写 JSON 字段。
- 代理选点时读取近期限流 IP，并进行候选避让。
- 更新 `.env.example`/README 文档说明数据库配置与用途。

### Out of scope

- 构建 Web UI 或报表页面。
- 历史 JSON 回填迁移脚本（后续可补）。

## 需求（Requirements）

### MUST

- SQLite 默认路径可配置，默认落在项目可写目录（`output/` 下）。
- 必须启用 `PRAGMA journal_mode=WAL` 与 `PRAGMA busy_timeout`，避免并发写入冲突导致频繁失败。
- 每条任务记录至少包含：时间、模式、状态、代理节点/IP、失败阶段、失败代码、核心风险标记、结果摘要。
- 风险相关字段可直接 SQL 过滤（例如 `has_ip_rate_limit`, `has_suspicious_activity`, `proxy_ip`, `status`）。
- 详细上下文（notes、request/network 摘要、错误原文）以 JSON 保存。

### SHOULD

- 对常用过滤条件建立索引（时间、状态、IP、失败代码）。
- 对敏感字段做最小暴露（列中避免存储完整密钥）。

### COULD

- 增加轻量聚合视图，便于后续快速分析。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 运行启动时初始化 SQLite schema。
- 进入单模式执行前插入一条 `running` 记录。
- 阶段推进时更新关键列（proxy_ip、failure_stage、precheck 结果等）。
- 成功结束：写入 `succeeded`、完成时间、耗时、验证与 API key 摘要。
- 失败结束：写入 `failed`、失败代码、风险标记、错误摘要与诊断 JSON。

### Edge cases / errors

- 写库失败不阻塞主任务执行（降级为日志告警），但应尽量重试或保留错误信息。
- 并发写库出现 `SQLITE_BUSY` 时依赖 busy_timeout + 短事务降低冲突。

## 接口契约（Interfaces & Contracts）

- Internal module: `src/storage/task-db.ts`
  - `createRunRecord(...)`
  - `patchRunRecord(...)`
  - `finishRunRecord(...)`
  - `listRecentRateLimitedIps(...)`

## 验收标准（Acceptance Criteria）

- Given 连续执行注册任务，When 查询 SQLite，Then 能看到每次任务的开始/结束状态与关键风险字段。
- Given 同时运行多个实例，When 并发写入，Then 不出现高频写库失败（busy_timeout 生效）。
- Given 出现 `Too many signups from the same IP`，When 后续选点，Then 程序优先避开近期限流 IP。
- Given 本次实现完成，When 执行 `bun run typecheck`，Then 类型检查通过。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- `bun run typecheck`
- 至少一次真实运行，验证 `output/` 下 SQLite 文件生成且有记录落库

### Quality checks

- 关键筛选字段存在索引
- JSON 字段结构可读且含时间戳

## 文档更新（Docs to Update）

- `.env.example`
- `README.md`
- `docs/specs/README.md`

## 变更记录（Change log）

- 2026-02-25: 初始化规格，定义 SQLite 台账与并发策略边界。
- 2026-02-25: 完成 SQLite 台账模块与主流程接入，新增关键筛选列 + JSON 明细。
- 2026-02-25: 完成并发配置（WAL + busy_timeout）与近期限流 IP 避让策略；实跑验证记录入库。
