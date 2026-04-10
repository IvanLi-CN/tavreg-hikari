# 主工作区运行态同步到新 Worktree 的自动 Bootstrap（#gw9zj）

## 状态

- Status: 已完成
- Created: 2026-03-27
- Last: 2026-04-10

## 背景 / 问题陈述

- 当前 linked worktree 默认只带 Git tracked 内容，`.env.local` 与本地 SQLite ledger 需要手工复制，初始化步骤容易漏掉。
- 本仓库运行态明显依赖 `.env.local` 与 `output/registry/tavreg-hikari.sqlite`；缺少这些文件时，Web 控制台与 CLI 都会退化到不完整或空状态。
- 主工作区 `output/` 里同时堆积大量浏览器 profile、诊断截图、批量运行产物与 Mihomo 工作目录，不能用粗暴整目录镜像来同步。

## 目标 / 非目标

### Goals

- 为仓库补一套 repo-local worktree bootstrap：主工作区执行一次 `bun install` 后，新 linked worktree 在首次 checkout 时自动补齐缺失的本地运行态。
- worktree bootstrap 需要把基本开发环境一并准备好，包括在新 linked worktree 缺少依赖时自动执行包安装。
- 把同步范围锁定为白名单 manifest，仅覆盖 `.env.local` 与 SQLite ledger 主文件。
- 保证同步策略固定为“源存在才复制，目标已存在绝不覆盖”。
- 用真实 `git worktree add` smoke test 兜住首次 bootstrap、main worktree no-op、missing source 跳过与历史 revision 安全降级。

### Non-goals

- 不引入 `lefthook`、husky 或其它新 hook 框架。
- 不复制 `output/chrome-profile`、`output/chrome-inspect-profile`、`output/mihomo`、`output/runs`、截图、日志或旧 `output/app.sqlite`/`output/app.db`。
- 不做已有 linked worktree 的持续双向同步；v1 只负责首次 bootstrap，后续只支持人工 forced rerun。

## 范围（Scope）

### In scope

- 新增 `scripts/install-hooks.sh`、`scripts/sync-worktree-resources.sh`、`scripts/worktree-sync.paths`、`scripts/test-worktree-bootstrap.sh`。
- 更新 `package.json`，新增 `hooks:install`、`prepare`、`test:worktree-bootstrap`。
- 更新 `README.md` 的 linked worktree 初始化说明。
- 新增 worktree bootstrap 规格与 CLI 契约文档。

### Out of scope

- 变更运行时对 `.env.local` 或 SQLite 路径的读取逻辑。
- 为其它本地产物增加自动同步策略。
- 替换仓库现有 `output/` 结构或清理历史产物。

## 需求（Requirements）

### MUST

- `post-checkout` hook 通过 repo-local 安装脚本落到共享 hooks 目录，并记录 `codex.worktree-sync.main-root`。
- 自动同步仅在 linked worktree 首次 checkout 时触发；main worktree 必须稳定 no-op。
- manifest 只允许 `.env.local` 与 `output/registry/tavreg-hikari.sqlite`。
- 目标文件已存在时必须保留现状并输出 `keep target exists`。
- linked worktree 缺少 `node_modules` 时必须自动执行依赖安装；存在 `bun.lock` 时必须使用 `bun install --frozen-lockfile`。
- linked worktree 若不存在 `bun.lock`，自动依赖安装必须使用 `bun install --no-save`，避免 checkout 自动写出新锁文件。
- `WORKTREE_SYNC_FORCE=1` 只能重新补齐缺失依赖，不能对已存在的 `node_modules` 触发重装。
- 依赖安装必须是 best-effort：若 `bun install` 失败，只能记录日志并继续 checkout，不能让 worktree 创建失败。
- 是否跳过依赖 bootstrap 必须基于“本 revision 的成功安装标记”，不能仅凭 `node_modules/` 目录存在与否判断。
- 源文件缺失时必须输出 `skip source missing` 并以 `0` 退出，不能阻断 checkout。
- 历史 commit 缺少同步脚本时，共享 hook 必须安全降级为 no-op。
- SQLite ledger 必须通过 SQLite 一致性快照生成，不得直接逐文件复制活跃数据库的 `-wal/-shm` 伴生文件。
- SQLite ledger 快照实现不得把整库一次性读进 JS 堆内存；应使用 SQLite 原生 `VACUUM INTO` 或等价原生命令生成目标文件。
- 若本机 `sqlite3` 不支持 `VACUUM INTO`，脚本必须自动回退到 Bun 内置 SQLite 实现，而不是中断 bootstrap。

### SHOULD

- 安装脚本应保留并串联任何既有 `post-checkout` hook，而不是覆盖掉它。
- smoke test 应使用真实 SQLite fixture，而不是空壳文件。

### COULD

- 手工重跑支持 dry-run，方便在 worktree 内预演同步清单。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 主工作区执行 `bun install` 时，`prepare` 调用 `scripts/install-hooks.sh`，在共享 hooks 目录安装 managed `post-checkout` wrapper。
- 用户执行 `git worktree add` 创建新 linked worktree 时，`post-checkout` 调用 `scripts/sync-worktree-resources.sh`。
- 同步脚本发现当前目录是 linked worktree 且处于首次 checkout，就从主工作区读取 `scripts/worktree-sync.paths`，对 `.env.local` 默认创建共享软链接、对 ledger 主文件做基于 SQLite 原生 `VACUUM INTO` 的一致性快照，并在缺少 `node_modules` 时自动安装依赖。
- 用户在 worktree 内执行 `WORKTREE_SYNC_FORCE=1 ./scripts/sync-worktree-resources.sh` 时，脚本重新遍历 manifest，但仍只补缺、不覆盖。

### Edge cases / errors

- 若当前目录是主工作区，脚本输出 `skip main worktree` 并退出。
- 若 manifest 缺失、主工作区根无法解析，脚本输出 `skip ...` 并退出，不报错中断。
- 若 checkout 到旧 revision，当前 worktree 没有 `scripts/sync-worktree-resources.sh`，managed hook 直接退出 `0`。
- 若目标 worktree 已经手工修改过 `.env.local` 或 ledger 文件，forced rerun 也只能保留现有内容。

## 接口契约（Interfaces & Contracts）

### 接口清单（Inventory）

| 接口（Name） | 类型（Kind） | 范围（Scope） | 变更（Change） | 契约文档（Contract Doc） | 负责人（Owner） | 使用方（Consumers） | 备注（Notes） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bun run hooks:install` | CLI | internal | New | ./contracts/cli.md | repo maintainers | local developers | 安装共享 `post-checkout` hook |
| `bun run test:worktree-bootstrap` | CLI | internal | New | ./contracts/cli.md | repo maintainers | local developers / CI | 真实 `git worktree add` smoke test |
| `./scripts/sync-worktree-resources.sh` | CLI | internal | New | ./contracts/cli.md | repo maintainers | managed hook / local developers | 支持 `WORKTREE_SYNC_FORCE` 与 `WORKTREE_SYNC_DRY_RUN` |

### 契约文档（按 Kind 拆分）

- [contracts/README.md](./contracts/README.md)
- [contracts/cli.md](./contracts/cli.md)

## 验收标准（Acceptance Criteria）

- Given 主工作区已经存在 `.env.local` 与活跃的 `output/registry/tavreg-hikari.sqlite`，When 执行 `git worktree add` 创建新 linked worktree，Then 新 worktree 无需手工复制即可拿到共享 `.env.local` 软链接与一致性 ledger 快照。
- Given 新 linked worktree 的 `.env.local` 需要改写 `CHROME_EXECUTABLE_PATH` 才能适配当前 worktree，When bootstrap 执行浏览器运行时补齐，Then 脚本会先把共享 `.env.local` 落地为本地文件，再写入 worktree 专属路径。
- Given 新 linked worktree 初次 bootstrap 时尚无 `node_modules`，When `post-checkout` hook 触发脚本，Then worktree 会自动完成依赖安装，且带 `bun.lock` 的 revision 使用 `bun install --frozen-lockfile`。
- Given worktree 已有 `node_modules`，When 执行 `WORKTREE_SYNC_FORCE=1 ./scripts/sync-worktree-resources.sh`，Then 脚本只会输出 `keep dependency install: node_modules exists`，不会再次执行依赖安装。
- Given linked worktree 缺少 `node_modules` 但当前环境下 `bun install` 失败，When hook 或 forced sync 触发依赖 bootstrap，Then 脚本会输出 `skip dependency install failed` 并继续完成非依赖资源同步，不会让 checkout 失败。
- Given linked worktree 来源 revision 不带 `bun.lock`，When hook 自动执行依赖安装，Then 脚本使用 `bun install --no-save`，不会把 worktree 自动写脏为新增 `bun.lock`。
- Given 上一次依赖 bootstrap 失败后 worktree 里残留了 `node_modules/`，When 再次执行 forced sync，Then 脚本仍会重试安装，而不是仅因目录存在就跳过。
- Given 新 worktree 中任一目标文件已存在，When 自动 hook 或 `WORKTREE_SYNC_FORCE=1` 重跑同步，Then 现有文件保留不变，且日志包含 `keep target exists`。
- Given 在主工作区运行 `WORKTREE_SYNC_FORCE=1 ./scripts/sync-worktree-resources.sh`，When 脚本执行，Then 输出 `skip main worktree` 且不发生自覆盖。
- Given 主工作区缺少某个 manifest 资源，When 新 worktree 首次 checkout 或手工重跑同步，Then 脚本输出 `skip source missing` 且以 `0` 退出。
- Given 共享 hook 已安装，When checkout 到缺少同步脚本的历史 revision，Then Git 不会报 `No such file or directory` 或 `exit status 127`。
- Given 主工作区 ledger 仍处于打开的 WAL 连接中，When linked worktree 手工 forced sync 或首次 bootstrap 生成快照，Then 已提交的数据会出现在目标 ledger 中，且脚本不会因为 JS 堆内存快照而失败。
- Given 本机存在较老的 `sqlite3` 且不支持 `VACUUM INTO`，When bootstrap 需要生成 ledger 快照，Then 脚本会自动回退到 Bun 内置 SQLite 实现并继续完成同步。
- Given 本次实现完成，When 执行 `bun run test:worktree-bootstrap` 与 `bun test`，Then 相关验证通过且无新增回归。

## 实现前置条件（Definition of Ready / Preconditions）

- 主工作区运行态依赖已确认：`.env.local` 与 `output/registry/tavreg-hikari.sqlite`。
- 不同步的高噪声目录已确认：浏览器 profile、Mihomo 工作目录、批量运行产物、截图与日志。
- 自动触发点已确认：共享 `post-checkout` hook。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- `bun run test:worktree-bootstrap`
- `bun test`

### Quality checks

- `bun install --frozen-lockfile` 能成功执行并安装 shared hook
- README 与 `scripts/worktree-sync.paths` 的同步范围说明一致
- SQLite ledger 通过 SQLite 原生 `VACUUM INTO` 一致性快照复制，不直接搬运 `-wal/-shm`
- smoke test 能证明 linked worktree 首次 bootstrap 后已具备 `node_modules`

## 文档更新（Docs to Update）

- `README.md`: 补充主工作区初始化与 linked worktree bootstrap 说明
- `docs/specs/README.md`: 记录本规格索引项

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: 新增共享 `post-checkout` hook 安装脚本，记录主工作区根并保留既有 hook 链。
- [x] M2: 新增资源同步脚本与 manifest，只补齐 `.env.local` 与 SQLite ledger 主文件。
- [x] M3: 新增真实 `git worktree add` smoke test，覆盖首次 bootstrap、missing source、forced rerun 不覆盖与历史 revision 安全降级。
- [x] M4: 更新 package scripts / README，并完成验证。

## 方案概述（Approach, high-level）

- 复用 `style-playbook` 里的 worktree bootstrap 口味：共享 hook + 白名单 manifest + “copy missing, never overwrite”。
- 用 `git rev-parse --git-path hooks` 解析当前仓库真实生效的 hooks 目录，避免 linked worktree 下误落到 per-worktree 假路径。
- 把 hook 设计成“缺脚本即 no-op”的 wrapper，让历史 revision checkout 不因为 bootstrap 漏文件而中断。

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：若用户已有复杂的自定义 `post-checkout` 逻辑，串联顺序不当可能影响其副作用。
- 风险：一致性快照只复制 ledger 主文件，新 worktree 需要在首次写入时再按 SQLite 行为生成自己的 `-wal/-shm`。
- 需要决策的问题：None。
- 假设（需主人确认）：主工作区会作为 linked worktree 的运行态真源。

## 变更记录（Change log）

- 2026-03-27: 初始化规格，冻结 worktree bootstrap 范围、白名单与验收口径。
- 2026-03-27: 完成共享 `post-checkout` hook、manifest 白名单同步脚本与 smoke test。
- 2026-03-27: 验证通过：`bun install --frozen-lockfile`、`bun run test:worktree-bootstrap`、`bun test`。
- 2026-03-27: 根据 review 反馈改为对 ledger 主文件做 SQLite 一致性快照，不再复制活跃数据库的 `-wal/-shm` 文件。
- 2026-03-27: 将 ledger 快照实现收敛为 SQLite 原生 `VACUUM INTO`，避免大库在 bootstrap 时因 JS 堆内存快照而失败。
- 2026-03-27: bootstrap 范围扩展为“资源补齐 + 依赖安装”，linked worktree 首次 checkout 会自动准备 `node_modules`。
- 2026-03-27: 根据 PR review 修正 forced rerun 与旧版 `sqlite3` 兼容性，确保依赖只补缺且 `VACUUM INTO` 失败时自动回退到 Bun。
- 2026-03-27: 将依赖安装收敛为 best-effort，避免网络/凭证类 `bun install` 失败阻断 worktree checkout。
- 2026-03-27: 将无锁文件 revision 的依赖 bootstrap 切到 `bun install --no-save`，并用成功标记避免半失败 `node_modules` 阻断后续重试。
- 2026-03-27: 最终实现对齐规格：无锁文件 revision 真实执行 `bun install --no-save`，并修正 smoke test 中的 Bun 包装脚本以避免递归调用。
- 2026-03-31: 跟随默认运行态数据库文件名规范化，将 bootstrap manifest 与文档口径统一到 `output/registry/tavreg-hikari.sqlite`，并兼容旧源文件名。
- 2026-04-10: 将 `.env.local` 默认同步策略改为共享软链接；仅在需要改写 `CHROME_EXECUTABLE_PATH` 适配当前 worktree 时，才落地为本地文件后继续改写。

## 参考（References）

- `README.md`
- `src/server/main.ts`
- `src/ledger-cli.ts`
- `docs/WORKFLOW.md`
