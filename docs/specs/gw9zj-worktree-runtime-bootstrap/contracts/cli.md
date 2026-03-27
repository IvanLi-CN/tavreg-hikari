# 命令行（CLI）

## `bun run hooks:install`

- 范围（Scope）: internal
- 变更（Change）: New

### 用法（Usage）

```text
bun run hooks:install
```

### 参数（Args / options）

- None

### 输出（Output）

- Format: human
- 成功时打印 `hooks-install: ...` 日志，说明主工作区记录与共享 `post-checkout` wrapper 安装结果。

### 退出码（Exit codes）

- `0`: hook 安装或刷新成功
- 非 `0`: Git 根目录不可解析、hooks 目录不可写或 wrapper 写入失败

### 兼容性与迁移（Compatibility / migration）

- 允许重复执行；重复运行只会刷新 managed wrapper，不覆盖非 managed 旧 hook，而是先快照为 `post-checkout.codex-worktree-sync-prev` 后再串联。

## `bun run test:worktree-bootstrap`

- 范围（Scope）: internal
- 变更（Change）: New

### 用法（Usage）

```text
bun run test:worktree-bootstrap
```

### 参数（Args / options）

- None

### 输出（Output）

- Format: human
- 成功时输出 `worktree bootstrap smoke test passed`

### 退出码（Exit codes）

- `0`: smoke test 通过
- 非 `0`: 任一 bootstrap 断言失败

### 兼容性与迁移（Compatibility / migration）

- 测试在临时 fixture repo 中运行，不依赖当前仓库工作区已有 `.env.local` 或 SQLite 文件。

## `./scripts/sync-worktree-resources.sh`

- 范围（Scope）: internal
- 变更（Change）: New

### 用法（Usage）

```text
./scripts/sync-worktree-resources.sh [old-head] [new-head] [is-branch-checkout]
```

### 参数（Args / options）

- `<old-head>`: Git `post-checkout` 提供的旧提交 SHA；手工重跑可省略
- `<new-head>`: Git `post-checkout` 提供的新提交 SHA；手工重跑可省略
- `<is-branch-checkout>`: Git `post-checkout` 提供的分支切换标记；首次 worktree checkout 预期为 `1`
- `WORKTREE_SYNC_FORCE=1`: 忽略首次 checkout 限制，手工重跑同步逻辑
- `WORKTREE_SYNC_DRY_RUN=1`: 只输出 `would copy`，不实际复制文件

### 输出（Output）

- Format: human
- 日志前缀固定为 `worktree-sync:`
- 关键状态文案：
  - `skip main worktree`
  - `skip non-initial checkout`
  - `skip source missing: <path>`
  - `keep target exists: <path>`
  - `keep dependency install: node_modules exists`
  - `would snapshot: <path>`
  - `would install dependencies: bun install ...`
  - `copied: <path>`
  - `snapshotted sqlite: <path>`
  - `installing dependencies: bun install ...`
  - `installed dependencies`
  - `dry-run complete`
  - `sync complete`

### 退出码（Exit codes）

- `0`: 成功执行、跳过或 dry-run 完成
- 非 `0`: 仅在脚本本身运行环境异常时出现，例如 Git 根解析失败或复制系统调用失败

### 兼容性与迁移（Compatibility / migration）

- 同步范围固定来自 `scripts/worktree-sync.paths`
- `.sqlite` 路径通过 SQLite 原生 `VACUUM INTO` 生成一致性快照，不复制 `-wal/-shm`
- 依赖安装会在 linked worktree 缺少 `node_modules` 时自动执行；存在 `bun.lock` 时使用 `bun install --frozen-lockfile`
- 目标文件已存在时绝不覆盖
- 当前 revision 缺少脚本或 manifest 时，shared hook 必须降级为 no-op
