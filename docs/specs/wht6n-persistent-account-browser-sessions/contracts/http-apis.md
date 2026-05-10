# HTTP API contracts

## `GET /api/accounts`

- each account row includes `browserSession`
- summary fields include session status, proxy snapshot, profile path, timestamps, error snapshot
- supports `sessionStatus` and `mailboxStatus` query params as server-side filters

## `POST /api/accounts/:accountId/session/rebootstrap`

- enqueues or starts account bootstrap
- accepts optional `{ force?: boolean }`; omitted/`true` means force Bootstrap, `false` revalidates `pending_only` eligibility atomically at execution time
- returns latest account row plus browser session snapshot

## `POST /api/accounts/session-bootstrap/preview`

- accepts `{ ids: number[]; mode: "pending_only" | "force" }`
- returns normalized `queueIds`, per-account `decision/reason`, and summary counts for cross-page batch Bootstrap preview

## `GET /api/microsoft-mail/settings`

- returns Microsoft Graph OAuth settings summary plus `microsoftAccountBootstrapConcurrency`, `microsoftAccountBootstrapWorkerTimeoutMs`, and `microsoftAccountBootstrapKillGraceMs`
- `microsoftGraphClientSecret` remains masked and is never returned in plaintext

## `POST /api/microsoft-mail/settings`

- accepts Graph OAuth fields plus optional bootstrap tuning fields:
  - `microsoftAccountBootstrapConcurrency`: clamped to `1..10`
  - `microsoftAccountBootstrapWorkerTimeoutMs`: minimum `1000`
  - `microsoftAccountBootstrapKillGraceMs`: minimum `1000`
- returns the same serialized settings shape as `GET`
