# 收敛 macOS 下 headless Chrome 启动卡住问题（#9h2xd）

## 状态

- Status: 已完成
- Created: 2026-03-27
- Last: 2026-03-27

## 背景 / 问题陈述

- 当前 macOS 环境下，headless 任务默认走 native Chrome CDP 附着。
- 当 `connectOverCDP` 反复超时时，单个 worker 会在 `browser_launch` 阶段停留过久，主流程表现为 attempt 长时间卡在 `spawned`。
- Web 管理台本身仍可响应，但 job 会给出“仍在运行”的错觉，影响补号与主流程调度判断。

## 目标 / 非目标

### Goals

- 在 macOS 上禁用 headless / headed Chrome 的 native CDP 自动化分支。
- 让 macOS Chrome 统一回退到 Playwright 直启路径，避免 native CDP 附着超时把单个 worker 拖成超长启动。
- 为该平台分支补上回归约束，防止后续重新引入 native CDP。

### Non-goals

- 不修改 Windows / Linux 的 Chrome 自动化策略。
- 不改写调度器补号逻辑。
- 不在本次修复里引入新的 UI 改动。

## 行为规格

- 当 `process.platform === "darwin"` 时，`shouldUseNativeChromeAutomation(...)` 必须返回 `false`。
- headless 与 headed 两种模式都必须避开 native Chrome CDP 路径。
- 现有的 macOS 平台回归测试必须覆盖这个判断。

## 验收标准（Acceptance Criteria）

- Given 任务运行在 macOS，When 浏览器引擎是 `chrome` 且开启 `CHROME_NATIVE_AUTOMATION`，Then 运行时仍不会选择 native Chrome CDP。
- Given 代码回归测试运行，When 检查 `src/main.ts` 的平台判断，Then 能验证 macOS 下统一跳过 native CDP 自动化。
- Given 本次修复完成，When 执行 `bun test test/main-config.test.ts` 与 `bun run typecheck`，Then 全部通过。

## Visual Evidence

- 不适用：本次改动只涉及运行时平台分支与 worker 启动路径，没有新增或修改主人可见 UI。
