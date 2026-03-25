# Tavreg Hikari

本项目用于通过 Microsoft 账号完成目标站点登录流程，并提取可复用产物。当前 provider-aware MVP 支持 `Tavily API key` 与 `ChatGPT Web access_token`，同时提供 CLI 和本机 Web 管理台两种入口。

## 入口

- `bun run start`
  - 保留 CLI 流程，适合单次调试或兼容旧脚本；可通过 `--targets tavily,chatgpt` 选择目标集。
- `bun run web:build && bun run web:start`
  - 启动 `localhost` Web 管理台，提供账号导入、主流程控制、Artifacts 查询和代理节点面板。

## Web 管理台

- 主流程页：启动任务、暂停、恢复、动态调整 `parallel / need / maxAttempts / targets`，并查看实时 attempts、目标步骤进度与事件流。
- 微软账号页：支持 `email,password`、`email:password`、`email|password` 或 `email password` 的批量导入，按邮箱去重，查看 Tavily / ChatGPT 的目标状态、导入时间与跳过原因。
- Artifacts 页：查询已提取的 Tavily API key 与 ChatGPT access_token 的脱敏预览、状态、账号归属与时间信息。
- 代理节点页：修改 Mihomo 订阅设置、同步节点、检查当前节点/全部节点/单节点，并查看出口 IP、地理信息和 24 小时成功提取数量。

## 目标选择

- 默认目标仍是 `tavily`，以兼容现有脚本和旧行为。
- CLI 可用：
  - `bun run start --targets tavily`
  - `bun run start --targets chatgpt`
  - `bun run start --targets tavily,chatgpt`
- Web job 启动时也支持选择目标集。
- 同一账号在同一个 browser context 内按固定顺序串行执行所选目标，默认顺序 `tavily -> chatgpt`。

## 运行前准备

- 复制 `.env.example` 为 `.env.local` 并填写必要配置。
- 至少需要：
  - OCR/OpenAI 兼容接口配置
  - `MIHOMO_SUBSCRIPTION_URL`
  - 浏览器与邮箱相关配置（按当前运行模式选择）
  - 若启用 ChatGPT 目标，确认默认 allowlist 已覆盖 `chatgpt.com`、`auth.openai.com`、`openai.com`

## 常用脚本

- `bun run typecheck`
- `bun test`
- `bun run web:build`
- `bun run web:start`
- `bun run ledger:query`
- `bun run proxy:check-all`

## 关联项目

- [Tavily Hikari](https://github.com/IvanLi-CN/tavily-hikari)：号池相关项目
