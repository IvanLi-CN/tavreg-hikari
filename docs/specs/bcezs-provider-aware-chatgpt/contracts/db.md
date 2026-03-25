# DB

## New tables

### `account_target_states`

- 唯一键：`(account_id, target)`
- 记录每个账号在 Tavily / ChatGPT 上的目标级状态、错误和产物关联。

### `artifacts`

- 通用产物表。
- 关键字段：
  - `account_id`
  - `target`
  - `artifact_type`
  - `secret_value`
  - `preview`
  - `metadata_json`
  - `status`
  - `extracted_at`
  - `last_verified_at`

## Altered tables

### `jobs`

- 新增 `targets_json`

### `job_attempts`

- 新增：
  - `target`
  - `sequence_index`

## Compatibility

- `api_keys` 与 `microsoft_accounts.has_api_key/api_key_id` 保留为 Tavily 投影。
- 新实现以 `artifacts` + `account_target_states` 为主读源。
