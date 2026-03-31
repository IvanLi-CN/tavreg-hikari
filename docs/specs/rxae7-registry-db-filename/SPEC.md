# 统一默认 SQLite 数据库文件名为 registry.sqlite（#rxae7）

## 状态

- Status: 已完成
- Created: 2026-03-31
- Last: 2026-03-31

## 背景 / 问题陈述

- 当前默认数据库文件名为 `output/registry/signup-tasks.sqlite`，名称只描述早期注册任务台账，已经不能准确表达当前 SQLite 文件同时承载应用设置、账号、作业、邮箱与台账等整套运行态的事实。
- 文件名语义过窄，容易让维护者误判“这个文件只存 signup task”，也会让 worktree bootstrap、共享测试机与手工排障时的运行态判断变得含糊。
- 仓库已经存在历史运行态与脚本依赖旧文件名，直接切名会导致现有数据或 bootstrap 流程断裂。

## 目标 / 非目标

### Goals

- 把默认数据库文件名统一收敛为 `output/registry/registry.sqlite`。
- 保留 `TASK_LEDGER_DB_PATH` 显式覆盖能力，不破坏自定义路径。
- 对历史默认文件名 `signup-tasks.sqlite` 提供兼容迁移，避免现有运行态首次升级后被误判为空库。
- 同步 worktree bootstrap、shared testbox 脚本、示例 env、README 与相关 spec 引用。

### Non-goals

- 不拆分现有 SQLite schema，也不把单库改成多库。
- 不调整已有表结构、业务字段或数据模型。
- 不移除显式配置的自定义数据库路径。

## 范围（Scope）

### In scope

- 新增统一数据库路径 helper，供 CLI、主流程与 Web 服务复用。
- 默认路径改为 `output/registry/registry.sqlite`。
- 当默认新路径不存在但旧默认文件存在时，自动把旧库一致性快照到新文件名后继续使用。
- 更新 bootstrap/testbox 脚本，让它们优先使用新文件名，同时兼容旧源文件。
- 新增针对默认路径与兼容迁移的测试。

### Out of scope

- 对已有自定义 `TASK_LEDGER_DB_PATH` 做自动重写或搬迁。
- 清理用户磁盘上的历史 `signup-tasks.sqlite` 旧文件。

## 需求（Requirements）

### MUST

- 默认运行态数据库路径必须是 `output/registry/registry.sqlite`。
- `TASK_LEDGER_DB_PATH` 已显式配置时，必须直接尊重该路径。
- 兼容迁移只能在“未显式配置路径 + 新默认文件不存在 + 旧默认文件存在”时触发。
- 兼容迁移必须采用 SQLite 原生一致性快照方式，不能简单复制活跃库的 `-wal/-shm` 伴生文件。
- `AppDatabase`、`TaskLedger`、CLI 默认路径、Web 服务默认路径、worktree bootstrap 与 shared testbox 脚本必须对新默认文件名保持一致。

### SHOULD

- 兼容迁移逻辑应集中在单一 helper，避免多处重复硬编码。
- 相关文档与 spec 索引应明确说明新旧默认文件名的关系。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 正常启动时，若未显式配置 `TASK_LEDGER_DB_PATH`，系统默认使用 `output/registry/registry.sqlite`。
- 若默认新文件不存在，但同目录下存在历史默认文件 `signup-tasks.sqlite`，系统会先把旧库一致性快照到 `registry.sqlite`，随后继续使用新文件名。
- worktree bootstrap 只向目标 worktree 写入 `output/registry/registry.sqlite`；若源主工作区仍只有旧文件名，脚本会从旧源文件生成新目标文件。
- shared testbox 远端运行准备阶段会优先传输 `registry.sqlite`；若本地仍只有旧文件名，则自动把旧文件作为源并上传成新目标名。

## 验收标准（Acceptance Criteria）

- Given 仓库未设置 `TASK_LEDGER_DB_PATH`，When CLI 或 Web 服务解析默认数据库路径，Then 默认值为 `output/registry/registry.sqlite`。
- Given 本地只有历史默认文件 `output/registry/signup-tasks.sqlite`，When 系统首次按新默认路径启动，Then 新文件 `output/registry/registry.sqlite` 会被自动生成，且保留旧库已提交数据。
- Given 主工作区仍使用历史默认文件名，When 新 linked worktree 首次 bootstrap，Then 目标 worktree 获得的是 `output/registry/registry.sqlite`，且数据与源库一致。
- Given 显式设置了 `TASK_LEDGER_DB_PATH`，When 系统启动，Then 不触发默认路径迁移逻辑，而是直接使用显式路径。
- Given 本次实现完成，When 执行 `bun run typecheck`、`bun test test/app-db.test.js test/db-paths.test.ts test/main-config.test.ts` 与 `bash scripts/test-worktree-bootstrap.sh`，Then 相关验证通过。

## 文档更新（Docs to Update）

- `README.md`
- `.env.example`
- `docs/specs/README.md`
- `docs/specs/gw9zj-worktree-runtime-bootstrap/SPEC.md`

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: 收敛默认数据库文件名与统一路径 helper。
- [x] M2: 增加旧默认文件名到新默认文件名的一致性快照兼容迁移。
- [x] M3: 同步 bootstrap/testbox/README/env/spec 索引。
- [x] M4: 补齐路径兼容测试并完成验证。

## 风险 / 假设（Risks, Assumptions）

- 风险：若外部脚本仍硬编码旧默认文件名，需要手工跟进更新或继续依赖兼容源路径。
- 风险：兼容迁移会在首次升级时额外生成一个新文件，但不会自动删除旧文件。
- 假设：默认数据库文件名的语义应描述“整套 registry 运行态”，而不是某一张历史子表。

## 变更记录（Change log）

- 2026-03-31: 将默认数据库文件名从 `signup-tasks.sqlite` 收敛为 `registry.sqlite`，并补齐旧文件名兼容迁移、脚本与测试同步。
