# HTTP 外部接入与鉴权收口（v1）实现状态（#3aqn8）

> 当前有效规范仍以 `./SPEC.md` 为准；这里记录实现覆盖、交付进度与 rollout 相关事实。

## Current Status

- Implementation: 进行中
- Lifecycle: active
- Catalog note: auth gate、integration v1、API Access UI 与服务接入快照已落地；剩余 Storybook 视觉证据、全量 checks 与 PR 收敛。

## Coverage / rollout summary

- 已新增 `public / internal / integration` 鉴权分类器，并在服务端入口按 Forward Auth / API key / allowlist 收口请求。
- 已落地 `integration_api_keys` 与 `account_service_access` 模型，支持 create / rotate / revoke / authenticate / last-used 回写。
- 已落地 `/api/integration/v1/*` 只读接口，覆盖 Microsoft 账号、Microsoft Mail、cfmail proof mailbox 与验证码解析结果。
- 已新增 `/settings` → `API Access` UI，以及对应 Storybook stories / play 覆盖。
- README 与 `.env.example` 已同步 Forward Auth 头映射、integration v1 范围与 `WEB_HOST` 语义。

## Remaining Gaps

- 生成并回传稳定的 Storybook 视觉证据，并写回 spec 的 `## Visual Evidence`。
- 跑完 `bun test`、`bunx tsc --noEmit`、`bun run web:build`、`bun run build-storybook`。
- 进行 review-loop 与 PR merge-ready 收敛。

## Related Changes

- `/Users/ivan/.codex/worktrees/d361/tavreg-hikari/src/server/auth-gate.ts`
- `/Users/ivan/.codex/worktrees/d361/tavreg-hikari/src/server/integration-api.ts`
- `/Users/ivan/.codex/worktrees/d361/tavreg-hikari/src/server/verification-codes.ts`
- `/Users/ivan/.codex/worktrees/d361/tavreg-hikari/src/storage/app-db.ts`
- `/Users/ivan/.codex/worktrees/d361/tavreg-hikari/web/src/components/api-access-settings-view.tsx`

## References

- `./SPEC.md`
- `./HISTORY.md`
