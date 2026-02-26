# 隐私数据与项目定位内容联合清理（含 main 历史重写）（#6sfgt）

## 状态

- Status: 已完成
- Created: 2026-02-26
- Last: 2026-02-26

## 背景 / 问题陈述

- 仓库存在基础设施标识（邮箱服务域名）暴露风险。
- 终端默认输出中包含 `password` / `api_key` 明文。
- 项目文档与默认命名中仍有历史活动语义，不符合当前定位。

## 目标 / 非目标

### Goals

- 隐藏默认终端敏感输出，仅在显式开关开启时输出。
- 清理代码与文档中的基础设施域名默认值与历史活动文案。
- 仅对 `main` 历史执行净化并强推覆盖，保留本地回滚锚点。

### Non-goals

- 不重写标签与其他分支。
- 不改变 SQLite 台账当前密文字段策略。

## 范围（Scope）

### In scope

- `src/main.ts`：
  - 新增 `--print-secrets`。
  - 默认隐藏 `PASSWORD`/`DEFAULT_API_KEY` 终端输出。
  - `keyName` 默认前缀改为 `reg-key-`。
  - 移除邮箱服务域名硬编码默认值，改为显式配置。
- `.env.example`：改为中性占位符，不包含真实基础设施域名。
- `.gitignore`：采用 `.env.*` + `!.env.example` 规则。
- `README.md` 与 `docs/WORKFLOW.md`：清理历史活动文案与失效引用。
- `main` 分支历史重写：替换邮箱服务域名与历史活动相关字样。

### Out of scope

- 改造数据库 schema 或历史数据脱敏迁移。
- 调整业务流程本身（注册/验证/选点核心逻辑不变）。

## 验收标准（Acceptance Criteria）

- HEAD 中不再包含历史活动关键词、旧 key 前缀和邮箱服务域名标识。
- `git check-ignore -v .env.local .env.staging .env.example`：前两者被忽略，`.env.example` 不被忽略。
- 默认运行终端摘要不输出密钥明文；`--print-secrets` 开启后才输出。
- `main` 历史重写后，敏感域名与历史活动关键词在 `main` 历史无命中。

## 实施摘要（Implementation Notes）

- CLI 输出由“默认明文”改为“默认隐藏 + 显式开关”。
- 邮箱服务 URL/域名由“硬编码默认”改为“按 provider 显式注入”。
- 历史重写前创建本地回滚分支：`backup/pre-scrub-main-<timestamp>`。
- 使用 `git-filter-repo --refs refs/heads/main --replace-text <rules>` 执行仅 main 的净化。

## 变更记录（Change log）

- 2026-02-26: 初始化并完成隐私与项目定位清理规格，落地代码/文档修复与 main 历史净化策略。
