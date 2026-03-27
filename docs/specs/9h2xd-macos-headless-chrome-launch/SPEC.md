# 收敛 macOS 下 headless Chrome 启动卡住问题（#9h2xd）

## 状态

- Status: 已完成
- Created: 2026-03-27
- Last: 2026-03-27

## 背景 / 问题陈述

- 当前 macOS 环境下，headless 任务默认走 native Chrome CDP 附着。
- 项目必须继续使用 CDP，且浏览器必须保持为 `adryfish/fingerprint-chromium`，不能回退到 Playwright 直启路径。
- 当 `connectOverCDP` 或 debugger endpoint 轮询卡住时，单个 worker 会在 `browser_launch` 阶段停留过久；外层 task timeout 即使触发，也不能及时打断这条 native CDP 启动链。
- Web 管理台本身仍可响应，但 job 会给出“仍在运行”的错觉，影响补号与主流程调度判断。

## 目标 / 非目标

### Goals

- 保持 macOS 继续使用 native Chrome CDP 与 `adryfish/fingerprint-chromium`。
- 让 task timeout 能够中断仍在进行中的 native CDP 启动链，而不是继续把 worker 挂在 `browser_launch`。
- 让运行中的 attempt 能把当前 stage 持续写入台账，避免 UI 长时间只显示 `spawned` 假状态。
- 为该行为补上回归约束，防止后续再次把 CDP 路径改掉或失去超时中断能力。

### Non-goals

- 不修改 Windows / Linux 的 Chrome 自动化策略。
- 不改写调度器补号逻辑。
- 不在本次修复里引入新的 UI 改动。

## 行为规格

- 当浏览器引擎是 `chrome` 且开启 `CHROME_NATIVE_AUTOMATION` 时，macOS 仍必须保留 native Chrome CDP 路径。
- 当 Web 管理台本身运行在 Bun 下时，worker 仍应优先切到 Node 运行 `src/main.ts`，因为 `fingerprint-chromium + playwright-core.connectOverCDP` 在 Bun 下会稳定超时，但在 Node 下可正常附着；这一调整不改变 CDP 协议与浏览器选择。
- native CDP 启动链必须能响应外层 task timeout，在 timeout 触发后尽快终止 debugger endpoint 轮询与 CDP attach。
- 运行中的 task ledger 快照必须带上当前 `failureStage`，并回写到 `job_attempts`，这样活动 attempt 在 API 与 SQLite 中都能显示 `browser_launch`、`login_home` 等实时阶段，而不是长期停在 `spawned`。

## 验收标准（Acceptance Criteria）

- Given 任务运行在 macOS，When 浏览器引擎是 `chrome` 且开启 `CHROME_NATIVE_AUTOMATION`，Then 运行时仍会选择 native Chrome CDP。
- Given Web 管理台运行在 Bun，When 调度器为微软账号任务拉起 worker，Then worker 仍会优先使用 Node 执行 `src/main.ts`，同时浏览器仍保持为 `fingerprint-chromium` 并通过 CDP 连接。
- Given native CDP 启动链还在等待 debugger endpoint 或 CDP attach，When task timeout 触发，Then worker 会中断当前启动链并尽快以 timeout 失败退出。
- Given 活动 attempt 正在运行，When Web 管理台读取 attempt 详情或直接查看 `job_attempts`，Then 都能看到当前阶段而不是一直停在 `spawned`。
- Given 本次修复完成，When 执行 `bun test test/main-config.test.ts test/app-db.test.js` 与 `bun run typecheck`，Then 全部通过。

## Visual Evidence

- 不适用：本次改动只涉及运行时平台分支与 worker 启动路径，没有新增或修改主人可见 UI。
