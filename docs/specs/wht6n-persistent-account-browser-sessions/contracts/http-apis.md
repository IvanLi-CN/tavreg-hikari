# HTTP API contracts

## `GET /api/accounts`

- each account row includes `browserSession`
- summary fields include session status, proxy snapshot, profile path, timestamps, error snapshot

## `POST /api/accounts/:accountId/session/rebootstrap`

- enqueues or starts account bootstrap
- returns latest account row plus browser session snapshot
