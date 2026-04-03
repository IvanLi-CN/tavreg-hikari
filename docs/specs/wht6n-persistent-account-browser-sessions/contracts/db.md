# DB contracts

## `account_browser_sessions`

- one row per `microsoft_accounts.id`
- stores session status, canonical profile path, browser engine, proxy geo snapshot, timestamps, last error
- `status` values: `pending | bootstrapping | ready | failed | blocked`

## `proxy_nodes`

- add `last_region TEXT`
- add `last_leased_at TEXT`
- health/selection continue to rely on inventory presence + last status

## `proxy_checks`

- add `region TEXT`
