# HTTP 外部接入与鉴权收口（v1）演进历史（#3aqn8）

> 这里记录会影响 Agent 理解“为什么一步步变成现在这样”的关键演进；规范正文仍以 `./SPEC.md` 为准。

## Decision Trace

- 2026-04-24：创建新 topic spec，明确这不是对既有 `localhost only` contract 的小修，而是一次新的长期 auth boundary 与 external integration API 收口主题。
- 2026-04-24：实现改为“先收口鉴权、再开放 integration v1”，避免 external API 与内部控制面共享历史无鉴权入口。
- 2026-04-24：API key 管理定为“多 key + hash-at-rest + 一次性明文展示”，不引入 v1 scope/RBAC。
- 2026-04-24：Tavily service access 采用显式快照表持久化 cookies / fingerprint / extracted IP，而不是从零散运行态现算。

## Key Reasons / Replacements

- 既有 `Auth: none（localhost only）` 口径在 `WEB_HOST` 可改写监听地址后不再成立，需要用新的规范替代该隐式假设。
- 现有 Microsoft / Tavily / Mailbox 能力已足够支撑 v1 external API，因此使用新 spec 聚合 auth、snapshot、验证码解析与 settings UI，而不是继续把这些改动分散到旧 spec。
- `API Access` 选择放在新的 `/settings` 专区，而不是挪动现有 Microsoft Graph / ChatGPT 设置入口，以避免 v1 同时引入过多导航重排。

## References

- `./SPEC.md`
- `./IMPLEMENTATION.md`
