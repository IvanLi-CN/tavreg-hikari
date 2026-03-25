# HTTP APIs

## `GET /api/accounts`

- 返回账号基础字段，并新增 `targetStates`：
  - `tavily`
  - `chatgpt`
- 每个 target state 至少包含：
  - `target`
  - `status`
  - `hasArtifact`
  - `artifactType`
  - `artifactPreview`
  - `lastResultAt`
  - `lastErrorCode`

## `POST /api/jobs/current/control`

- `action=start` 时新增 `targets` 数组。
- `targets` 允许值：
  - `["tavily"]`
  - `["chatgpt"]`
  - `["tavily","chatgpt"]`
- 未传时默认 `["tavily"]`。

## `GET /api/artifacts`

- 通用产物查询接口。
- 支持按 `target`、`artifactType`、`status`、`q` 过滤。
- 返回脱敏后的 `preview`，不直接返回 `secretValue`。

## `GET /api/api-keys`

- 保持兼容。
- 仅返回 `target=tavily` 且 `artifactType=api_key` 的结果。

## `GET /api/jobs/current`

- `job` 新增 `targets`。
- `activeAttempts` / `recentAttempts` 新增：
  - `target`
  - `sequenceIndex`
