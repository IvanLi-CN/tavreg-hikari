# DB contracts

## `integration_api_keys`

- one row per externally managed integration API key
- must not store plaintext key
- required fields:
  - `id`
  - `label`
  - `notes`
  - `key_hash`
  - `key_prefix`
  - `status` (`active | revoked`)
  - `created_at`
  - `updated_at`
  - `rotated_at`
  - `revoked_at`
  - `last_used_at`
  - `last_used_ip`

## `account_service_access`

- one row per `(account_id, service)` snapshot
- v1 service set:
  - `tavily`
- required fields:
  - `id`
  - `account_id`
  - `service`
  - `status`
  - `api_key_id` (nullable link to current Tavily key row)
  - `snapshot_json` (cookies / fingerprint / derived summary)
  - `extracted_ip`
  - `last_success_at`
  - `created_at`
  - `updated_at`
- unique key:
  - `(account_id, service)`

## Existing table interactions

- `microsoft_accounts`
  - remains the source of truth for account identity、密码、proof mailbox 与当前 `api_key_id`
- `api_keys`
  - continues to store extracted Tavily API keys in plaintext for operator/internal consumption
- `microsoft_mailboxes`
  - remains the source of truth for Microsoft Mail OAuth/token/sync status
- `microsoft_mail_messages`
  - remains the source of truth for Inbox message content; parser results can be derived at read time in v1
