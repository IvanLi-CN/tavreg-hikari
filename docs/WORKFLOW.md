# 注册工作流程

## 目标

完成一次完整 Tavily 注册，并产出 `output/result.json`，至少满足：

- `email`
- `verificationLink`
- `apiKey`
- `precheckPassed=true`
- `verifyPassed=true`

## 入口命令

- 完整注册（推荐）：
  - `BROWSER_ENGINE=chrome CHROME_NATIVE_AUTOMATION=true RUN_MODE=headed bun run start -- --mode headed --browser-engine chrome`
- 站点人工检查：
  - `bun run start -- --inspect-sites --browser-engine chrome`

## 运行流水线

1. 从 `.env.local` 加载配置。
2. 选择代理节点（出口 IP 去重 + 本机出口保护）。
3. 启动浏览器。
4. 浏览器预检：
   - 3 个国内 IP 站点 + 2 个国际 IP 站点（同一浏览器上下文并行多标签页）。
   - `fingerprint.goldenowl.ai` + WebRTC 探测。
   - 校验跨站 IP 一致性以及与预期代理出口一致。
5. 注册：
   - 创建邮箱会话（由 `MAIL_PROVIDER` 决定具体服务）。
   - 识别验证码。
   - 提交注册表单。
6. 邮箱验证：
   - 轮询邮箱服务获取验证链接。
   - 打开链接并确认验证成功信号。
7. 登录并提取 API Key。
8. 持久化输出：
   - `output/result.json`
   - `output/run_summary.json`
   - `output/browser_precheck*.json`

## 重试策略

- `mode` 重试（`MODE_RETRY_MAX`）：重跑完整 `runSingleMode`（会新建邮箱和浏览器会话）。
- 浏览器启动重试（`BROWSER_LAUNCH_RETRY_MAX`）：在单次 mode 内重试启动/上下文创建。
- 页面可恢复错误：在单次 mode 内重建 `context/page` 继续。

## 失败排查

1. 预检因 WebRTC 或 IP 不一致失败：
   - 查看 `output/browser_precheck_headed.json`。
   - 对比“选中代理出口 IP”和“浏览器实际观测 IP”。
2. 验证码反复失败：
   - 提高 `MAX_CAPTCHA_ROUNDS`。
   - 检查 OCR 模型是否可用（`/models`）。
3. 验证邮件超时：
   - 提高 `EMAIL_WAIT_MS`。
   - 检查当前邮箱服务 API 可用性。
4. API Key 未提取到：
   - 查看 `output/network_headed.json` 与 `output/home_headed.html`。

## 执行约束

- Cloudflare 挑战页默认不作为失败条件；仅在显式开启 CF Probe 门禁时才参与筛选。
- 调试阶段优先有头模式。
- 结果判定只基于项目内命令和项目产物，不混用外部手工浏览器结果。
