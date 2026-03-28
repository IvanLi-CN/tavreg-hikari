# Tavreg Hikari

本项目用于通过 Microsoft 账号完成 Tavily 第三方登录流程，并提取 API key。现在同时提供 CLI 和本机 Web 管理台两种入口。

## 入口

- `bun run start`
  - 保留原有 CLI 流程，适合单次调试或兼容旧脚本。
- `bun run web:build && bun run web:start`
  - 启动 `localhost` Web 管理台，提供账号导入、主流程控制、API key 查询和代理节点面板。

## Web 管理台

- 主流程页：启动任务、暂停、恢复、动态调整 `parallel / need / maxAttempts`，并支持在缺号时按站点开关自动提取微软账号；当前支持 `账号鸭 / 闪邮箱 / 闪客云 / Hotmail666` 四个渠道，按单源 `500ms/次` 轮转、最多 `4` 个并发请求。
- 微软账号页：支持 `email,password`、`email:password`、`email|password` 或 `email password` 的批量导入，按邮箱去重，查看是否已有 API key、最近状态、导入时间与跳过原因，并提供四个提取器 KEY 设置与本地提取历史查询。
- API Keys 页：查询已提取的 key 前缀、状态、账号归属与时间信息。
- 代理节点页：修改 Mihomo 订阅设置、同步节点、检查当前节点/全部节点/单节点，并查看出口 IP、地理信息和 24 小时成功提取数量。

## 运行前准备

- 主工作区首次初始化先执行 `bun install`，它会安装共享 `post-checkout` hook，供后续 linked worktree 自动补齐缺失的本地运行态。
- 复制 `.env.example` 为 `.env.local` 并填写必要配置。
- 至少需要：
  - OCR/OpenAI 兼容接口配置
  - `MIHOMO_SUBSCRIPTION_URL`
  - 浏览器与邮箱相关配置（按当前运行模式选择）
  - 如需自动补号，请配置一个或多个提取器 KEY：`EXTRACTOR_ZHANGHAOYA_KEY`、`EXTRACTOR_SHANYOUXIANG_KEY`、`EXTRACTOR_SHANKEYUN_KEY`、`EXTRACTOR_HOTMAIL666_KEY`

## Linked Worktree Bootstrap

- 当主工作区已经准备好 `.env.local` 与 `output/registry/signup-tasks.sqlite` 后，新建 linked worktree 会在首次 checkout 时自动补齐缺失项。
- 如果 worktree 里还没有 `node_modules`，bootstrap 还会自动执行依赖安装；存在 `bun.lock` 时固定走 `bun install --frozen-lockfile`，没有锁文件时改用 Bun 官方 `bun install --no-save`，避免历史 revision 被自动写出新锁文件。手工 `WORKTREE_SYNC_FORCE=1` 重跑时只有“之前已成功 bootstrap 的依赖状态”才会跳过，半失败残留会继续重试；安装失败也只记日志，不会让 checkout 直接失败。
- 同步清单固定来自 `scripts/worktree-sync.paths`；v1 只覆盖 `.env.local` 与 ledger 主文件，不复制浏览器 profile、Mihomo 工作目录、运行日志或截图。
- SQLite ledger 会通过 SQLite 原生 `VACUUM INTO` 生成一致性快照，不直接复制活跃数据库的 `-wal/-shm` 文件，也不会把整库一次性读进 JS 内存；若本机 `sqlite3` 不支持该语法，脚本会自动回退到 Bun 内置 SQLite 实现。
- 自动与手工重跑都遵循“只补缺，不覆盖”：目标文件已存在时会保留现状，不会覆盖 worktree 内的本地修改。
- 手工预演可用 `WORKTREE_SYNC_FORCE=1 WORKTREE_SYNC_DRY_RUN=1 ./scripts/sync-worktree-resources.sh`。
- 手工补齐缺失项可用 `WORKTREE_SYNC_FORCE=1 ./scripts/sync-worktree-resources.sh`。

## 常用脚本

- `bun run typecheck`
- `bun test`
- `bun run hooks:install`
- `bun run test:worktree-bootstrap`
- `bun run web:build`
- `bun run web:start`
- `bun run ledger:query`
- `bun run proxy:check-all`

## 关联项目

- [Tavily Hikari](https://github.com/IvanLi-CN/tavily-hikari)：号池相关项目
