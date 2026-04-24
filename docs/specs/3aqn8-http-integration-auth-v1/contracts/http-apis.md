# HTTP API contracts

## Auth boundary / gate classifier

### `public`

- `GET /api/health`
- `GET /api/microsoft-mail/oauth/callback`

### `integration`

- `/api/integration/v1/*`
- Auth:
  - `Authorization: Bearer <integration-api-key>` **or**
  - `X-API-Key: <integration-api-key>`

### `internal`

- 除 `public` / `integration` 外的全部 HTTP、SSE、WebSocket upgrade、SPA 静态资源请求
- Auth:
  - default forwarded user header: `X-Forwarded-User`
  - default forwarded email header: `X-Forwarded-Email`
  - default trusted proxy secret header: `X-Forwarded-Auth-Secret`
  - header names can be overridden by env
  - shared secret env: `FORWARD_AUTH_SECRET`
  - if `FORWARD_AUTH_SECRET` is missing, internal requests fail closed with `503 { error: "forward auth secret not configured" }`

## Internal settings APIs

### `GET /api/settings/api-access/keys`

- Scope: `internal`
- Response:
  - `ok: true`
  - `rows: IntegrationApiKeyRecord[]`

### `POST /api/settings/api-access/keys`

- Scope: `internal`
- Request:
  - `label: string`
  - `notes?: string | null`
- Response:
  - `ok: true`
  - `record: IntegrationApiKeyRecord`
  - `plainTextKey: string` (one-time only)

### `POST /api/settings/api-access/keys/:id/rotate`

- Scope: `internal`
- Request:
  - `label?: string`
  - `notes?: string | null`
- Response:
  - `ok: true`
  - `record: IntegrationApiKeyRecord`
  - `plainTextKey: string` (one-time only)

### `POST /api/settings/api-access/keys/:id/revoke`

- Scope: `internal`
- Response:
  - `ok: true`
  - `record: IntegrationApiKeyRecord`

## Integration v1 read APIs

### `GET /api/integration/v1/microsoft-accounts`

- Scope: `integration`
- Query:
  - `page?: number`
  - `pageSize?: number`
  - `q?: string`
- Response:
  - `ok: true`
  - `rows: IntegrationMicrosoftAccountRecord[]`
  - `page`
  - `pageSize`
  - `total`
- Notes:
  - summary rows omit `passwordPlaintext`
  - summary/session data omit host-local browser `profilePath`

### `GET /api/integration/v1/microsoft-accounts/:id`

- Scope: `integration`
- Response:
  - `ok: true`
  - `account: IntegrationMicrosoftAccountRecord`
- Notes:
  - detail keeps `passwordPlaintext`
  - session summary omits host-local browser `profilePath`

### `GET /api/integration/v1/microsoft-accounts/:id/proof-mailbox/codes`

- Scope: `integration`
- Provider support: `cfmail` only
- Response:
  - `ok: true`
  - `accountId`
  - `provider: "cfmail"`
  - `mailboxAddress`
  - `rows: ProofMailboxMessageRecord[]`

### `GET /api/integration/v1/mailboxes`

- Scope: `integration`
- Query:
  - `page?: number`
  - `pageSize?: number`
  - `accountId?: number`
- Response:
  - `ok: true`
  - `rows`
  - `page`
  - `pageSize`
  - `total`

### `GET /api/integration/v1/mailboxes/:mailboxId/messages`

- Scope: `integration`
- Query:
  - `limit?: number`
  - `offset?: number`
- Response:
  - `ok: true`
  - `mailbox`
  - `rows` (each row includes `parsedVerificationCodes`)
  - `limit`
  - `offset`
  - `total`
  - `hasMore`

### `GET /api/integration/v1/messages/:messageId`

- Scope: `integration`
- Response:
  - `ok: true`
  - `message` (includes `parsedVerificationCodes`)

## Error contract

- `401 { error }`
  - missing / invalid auth for the current gate
- `403 { error }`
  - valid principal exists but key is revoked / blocked
- `404 { error }`
  - requested resource not found
- `409 { error }`
  - unsupported state transition or unavailable mailbox/provider state
- `422 { error }`
  - syntactically valid but semantically unsupported request
