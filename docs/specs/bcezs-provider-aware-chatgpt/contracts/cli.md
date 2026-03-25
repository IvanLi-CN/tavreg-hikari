# CLI

## `bun run start`

- 新增 `--targets <csv>`
- 支持：
  - `--targets tavily`
  - `--targets chatgpt`
  - `--targets tavily,chatgpt`
- 未传时默认 `tavily`

## Worker result

- 每次执行输出：
  - `output/result.json`
  - `output/attempt-result.json`
- `attempt-result.json` 作为 scheduler 真相源，至少包含：
  - `targets`
  - `targetResults[]`
  - `ok`
  - `email`
  - `mode`

## Environment

- 新增 `TARGETS` 环境变量，与 `--targets` 语义一致。
