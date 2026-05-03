# 线上账号数据同步到本地实例历史（#hn72q）

## 2026-04-30

- 新增 topic spec，明确第一阶段采用 integration API 拉取重建，而不是复制线上 SQLite 或浏览器 profile。
- 锁定回写边界为 Tavily success-only，避免本地失败、调试状态或人工编辑污染线上账号池。
- upstream 连接信息改为本地 `/settings` 持久化设置；不得使用环境变量配置。
- 上线前按设置页反馈去掉“清除 API Key”入口，并新增同步启用开关；关闭时同步与成功回写都不会访问线上。
