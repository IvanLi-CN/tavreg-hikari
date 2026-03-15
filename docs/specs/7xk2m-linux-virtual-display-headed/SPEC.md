# Linux 无 DE headed 指纹浏览器支持（#7xk2m）

## 状态

- Status: 已完成
- Created: 2026-03-15
- Last: 2026-03-15

## 背景 / 问题陈述

- 项目已支持 Chrome 原生自动化与 fingerprint-chromium，但 Linux 无桌面环境时仍依赖外部显示环境。
- 当前 `CHROME_NATIVE_AUTOMATION=true` 的 README 声称 CDP 失败后会回退到持久化 Chrome，上线实现却会直接失败。
- fingerprint-chromium 参数此前未按实际平台生成，Linux 环境下无法稳定注入正确的 `--fingerprint-platform`。

## 目标 / 非目标

### Goals

- 在 Linux x64、无 `DISPLAY/WAYLAND_DISPLAY` 的 `headed + chrome` 场景下，自动托管 `Xvfb` 并继续以有头模式运行浏览器。
- 为 Chrome 启动链路补齐 fingerprint-chromium 参数与 native CDP -> persistent context 回退。
- 让诊断产物显式记录本次运行使用的是系统显示还是 `Xvfb`。

### Non-goals

- 不把 `headless` 伪装成真正 headed。
- 不扩展到 Windows、Linux arm64 或跨平台统一显示抽象。
- 不负责安装 `Xvfb` 或下载 fingerprint-chromium 可执行文件。

## 范围（Scope）

### In scope

- `src/main.ts` 的 Chrome 启动链路与 inspect 模式。
- 新增浏览器运行时辅助模块与单元测试。
- 更新 `README.md`、`.env.example`、`docs/WORKFLOW.md`。

### Out of scope

- Camoufox 的无显示环境适配。
- 新增 CLI 参数。

## 需求（Requirements）

### MUST

- Linux + `headed` + `chrome` + 无 `DISPLAY/WAYLAND_DISPLAY` + `VIRTUAL_DISPLAY_ENABLED=true` 时自动启动 `Xvfb`。
- 缺少 `Xvfb` 或启动超时时抛出 `virtual_display_unavailable:*`，不得偷偷降级为 `headless`。
- `launchNativeChromeCdp(...)` 失败后自动回退到 `launchChromePersistent(...)`。
- fingerprint-chromium 在 Linux 注入 `--fingerprint-platform=linux`，在 macOS 注入 `--fingerprint-platform=macos`。
- `output/result.json`、`output/browser_precheck_*.json`、`output/inspect_sites.json` 记录 `displayBackend`。

### SHOULD

- 优先复用现有 Chrome 启动逻辑，不引入额外命令入口。
- 为关键纯逻辑补齐 Bun 单元测试。

## 功能与行为规格（Functional/Behavior Spec）

### Core flows

- 运行 `RUN_MODE=headed BROWSER_ENGINE=chrome` 时，先决定显示后端：
  - 有系统显示 => `displayBackend=system`
  - 无系统显示且满足 Linux Chrome headed 条件 => 启动 `Xvfb` 并记为 `displayBackend=xvfb`
- Chrome 原生 CDP 链路失败时，沿用同一代理、同一 locale、同一显示环境回退到 Playwright persistent context。
- 预检报告写入 `browser_precheck_<mode>.json`，并在失败时中止流程。

### Edge cases / errors

- `VIRTUAL_DISPLAY_ENABLED=false` 或浏览器并非 Chrome 时，不启动 `Xvfb`。
- fingerprint-chromium 可执行文件之外的普通 Chrome 不注入 `--fingerprint*` 参数。

## 接口契约（Interfaces & Contracts）

### New env vars

- `VIRTUAL_DISPLAY_ENABLED`
- `VIRTUAL_DISPLAY_EXECUTABLE_PATH`
- `VIRTUAL_DISPLAY_DISPLAY_NUM`
- `VIRTUAL_DISPLAY_SCREEN`
- `VIRTUAL_DISPLAY_STARTUP_TIMEOUT_MS`

### Runtime payload additions

- `ResultPayload.displayBackend`
- `BrowserPrecheckReport.displayBackend`

## 验收标准（Acceptance Criteria）

- Given Linux x64 无显示环境且 `RUN_MODE=headed`，When 启动 Chrome/fingerprint-chromium，Then 程序自动托管 `Xvfb` 并记录 `displayBackend=xvfb`。
- Given Linux x64 已有显示环境，When 启动同样命令，Then 程序不启动 `Xvfb` 且记录 `displayBackend=system`。
- Given native Chrome CDP 握手失败，When 浏览器启动重试，Then 自动回退到 persistent context 而不是直接报 `native_cdp_unavailable`。
- Given fingerprint-chromium 可执行文件，When 在 Linux 生成启动参数，Then 包含 `--fingerprint-platform=linux`。

## 非功能性验收 / 质量门槛（Quality Gates）

### Testing

- `bun run typecheck`
- `bun test src/browser/runtime.test.ts`

### Quality checks

- 文档中的 Linux 无 DE 使用说明与环境变量说明保持一致。

## 文档更新（Docs to Update）

- `README.md`
- `.env.example`
- `docs/WORKFLOW.md`
- `docs/specs/README.md`

## 实现里程碑（Milestones / Delivery checklist）

- [x] M1: 新增虚拟显示辅助模块并接入 headed Chrome 启动链路。
- [x] M2: 修复 native CDP -> persistent context fallback，并补齐 fingerprint 平台参数。
- [x] M3: 更新文档与环境变量说明。
- [x] M4: 完成类型检查与运行时辅助单元测试。

## 方案概述（Approach, high-level）

- 通过独立 `browser/runtime` 模块封装“是否需要 Xvfb”“如何生成 fingerprint-chromium 参数”“是否允许 persistent fallback”等纯逻辑。
- 在 `runSingleMode` 与 `runInspectSites` 入口处统一分配显示会话，并把显示环境注入到 native Chrome 与 Playwright 启动选项。
- 保留现有 `headed|headless` 模式语义，仅为 headed Linux Chrome 补充显示托管能力。

## 风险 / 开放问题 / 假设（Risks, Open Questions, Assumptions）

- 风险：Linux 真实 `Xvfb` 启动验证需要目标环境预装系统包，当前工作区只能完成类型与纯逻辑测试。
- 假设：调用方会自行提供 fingerprint-chromium 路径，不需要程序自动下载。

## 变更记录（Change log）

- 2026-03-15: 初始化规格并冻结 Linux 无 DE headed 方案、fallback 行为与验收标准。
- 2026-03-15: 完成虚拟显示接入、fingerprint 平台映射、native CDP fallback、文档更新与单元测试。

## 参考（References）

- `src/main.ts`
- `src/browser/runtime.ts`
- `README.md`
