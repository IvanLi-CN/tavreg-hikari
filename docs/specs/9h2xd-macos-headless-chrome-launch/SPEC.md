# 收敛 macOS 下 fingerprint Chromium + CDP 登录恢复链路（#9h2xd）

## 状态

- Status: 已完成
- Created: 2026-03-27
- Last: 2026-03-27

## 背景 / 问题陈述

- 当前 macOS 环境下，headless 任务默认走 native Chrome CDP 附着。
- 项目必须继续使用 CDP，且浏览器必须保持为 `adryfish/fingerprint-chromium`，不能回退到 Playwright 直启路径。
- 当 `connectOverCDP` 或 debugger endpoint 轮询卡住时，单个 worker 会在 `browser_launch` 阶段停留过久；外层 task timeout 即使触发，也不能及时打断这条 native CDP 启动链。
- Web 管理台本身仍可响应，但 job 会给出“仍在运行”的错觉，影响补号与主流程调度判断。
- 在修好 worker 运行时后，微软登录链路还暴露出两个恢复缺口：
  - 已经回到 Tavily `/home` 且会话有效时，旧的 home 判定仍可能误判为“未登录”，从而错误地重新发起第二轮微软登录。
  - Microsoft passkey 中断恢复后重新回到 Tavily 登录页时，provider 提交逻辑可能被被动 challenge 的假阻塞卡住，无法继续点击 Microsoft 入口。

## 目标 / 非目标

### Goals

- 保持 macOS 继续使用 native Chrome CDP 与 `adryfish/fingerprint-chromium`。
- 让 task timeout 能够中断仍在进行中的 native CDP 启动链，而不是继续把 worker 挂在 `browser_launch`。
- 让运行中的 attempt 能把当前 stage 持续写入台账，避免 UI 长时间只显示 `spawned` 假状态。
- 让 headed / headless 登录链路在 Microsoft passkey 中断恢复后，能正确识别 Tavily 已登录 home，并继续提取默认 API key。
- 让 passkey 恢复后的 Tavily 登录页在没有真实 captcha/token 阻塞时，允许受控降级到直接 provider click，而不是无限等待被动 challenge。
- 为该行为补上回归约束，防止后续再次把 CDP 路径改掉或失去超时中断能力。

### Non-goals

- 不修改 Windows / Linux 的 Chrome 自动化策略。
- 不改写调度器补号逻辑。
- 不在本次修复里引入新的 UI 改动。

## 行为规格

- 当浏览器引擎是 `chrome` 且开启 `CHROME_NATIVE_AUTOMATION` 时，macOS 仍必须保留 native Chrome CDP 路径。
- 当 Web 管理台本身运行在 Bun 下时，worker 仅在 `node` 与 `tsx` 都可用时才优先切到 Node 运行 `src/main.ts`；若当前部署缺少 `tsx`，必须回退到 Bun worker，避免在生产环境因为 devDependencies 缺失而直接起不来。这一调整不改变 CDP 协议与浏览器选择。
- native CDP 启动链必须能响应外层 task timeout，在 timeout 触发后尽快终止 debugger endpoint 轮询与 CDP attach。
- 运行中的 task ledger 快照必须带上当前 `failureStage`，并回写到 `job_attempts`，这样活动 attempt 在 API 与 SQLite 中都能显示 `browser_launch`、`login_home` 等实时阶段，而不是长期停在 `spawned`。
- Tavily `/home` 的已登录判定不能只依赖首屏文案；当 `/api/auth/me`、`/api/account` 或 `/api/keys` 已经确认会话有效时，即使页面还在落地阶段，也必须把它视为已登录 home。
- `waitHomeStable` 必须给 Microsoft 回跳后的 Tavily home 一个额外的鉴权落地窗口，避免刚回到 `/home` 就因为首轮 DOM 过薄而误判失败。
- Microsoft passkey 恢复后若重新回到 Tavily 登录页，且 challenge 侧没有真实 captcha input、token、错误提示或明确成功信号，则 login 页允许在被动 challenge 超时后继续直接点击 Microsoft provider；signup 页不允许走这条降级。

## 验收标准（Acceptance Criteria）

- Given 任务运行在 macOS，When 浏览器引擎是 `chrome` 且开启 `CHROME_NATIVE_AUTOMATION`，Then 运行时仍会选择 native Chrome CDP。
- Given Web 管理台运行在 Bun 且 `node + tsx` 都可用，When 调度器为微软账号任务拉起 worker，Then worker 会优先使用 Node 执行 `src/main.ts`，同时浏览器仍保持为 `fingerprint-chromium` 并通过 CDP 连接。
- Given Web 管理台运行在 Bun 但当前部署缺少 `tsx`，When 调度器为微软账号任务拉起 worker，Then worker 会回退到 Bun 运行时，而不是生成一个启动即失败的 Node worker。
- Given native CDP 启动链还在等待 debugger endpoint 或 CDP attach，When task timeout 触发，Then worker 会中断当前启动链并尽快以 timeout 失败退出。
- Given 活动 attempt 正在运行，When Web 管理台读取 attempt 详情或直接查看 `job_attempts`，Then 都能看到当前阶段而不是一直停在 `spawned`。
- Given Microsoft 登录在 passkey 中断后已经回到 Tavily `/home`，When Tavily 的鉴权接口已经返回有效会话，Then 登录流程会把当前页识别为成功 home，而不是再次发起微软登录。
- Given Microsoft passkey 恢复后重新落到 Tavily login identifier，When 页面只残留无 token 的被动 challenge 外壳，Then login provider 提交流程会在超时后降级成直接 provider click，并继续后续登录。
- Given 一个可用的微软账号与代理节点，When 分别执行 headed 与 headless 直跑登录，Then 两个模式都能走完整条 `fingerprint-chromium + CDP` 链路并提取默认 Tavily API key。
- Given 本次修复完成，When 执行 `bun test test/main-config.test.ts test/app-db.test.js`、`bun run typecheck`，并做一次真实 headed 与 headless 端到端复测，Then 全部通过。

## Visual Evidence

- 不适用：本次改动只涉及运行时平台分支与 worker 启动路径，没有新增或修改主人可见 UI。
