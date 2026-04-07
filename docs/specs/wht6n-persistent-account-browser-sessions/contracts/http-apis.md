# HTTP API contracts

## `GET /api/accounts`

- each account row includes `browserSession`
- summary fields include session status, proxy snapshot, profile path, timestamps, error snapshot
- supports `sessionStatus` and `mailboxStatus` query params as server-side filters

## `POST /api/accounts/:accountId/session/rebootstrap`

- enqueues or starts account bootstrap
- returns latest account row plus browser session snapshot

## `POST /api/accounts/session-bootstrap/preview`

- accepts `{ ids: number[]; mode: "pending_only" | "force" }`
- returns normalized `queueIds`, per-account `decision/reason`, and summary counts for cross-page batch Bootstrap preview
