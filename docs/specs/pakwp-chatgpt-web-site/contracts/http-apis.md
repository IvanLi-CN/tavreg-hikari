# HTTP API

## 站点化 Current Job（GET `/api/jobs/current`）

- 范围（Scope）: internal
- 变更（Change）: Modify
- 鉴权（Auth）: none（localhost only）

### 请求（Request）

- Query:
  - `site?: tavily|chatgpt`
  - 未传时默认 `tavily`，作为旧接口兼容 alias。

### 响应（Response）

- Success:
  - `site`
  - `job`
  - `activeAttempts`
  - `recentAttempts`
  - `eligibleCount`
  - `autoExtractState`
- Error:
  - `400 { error }` 当 `site` 非法

### 兼容性与迁移（Compatibility / migration）

- 老前端继续访问 `/api/jobs/current` 时得到 Tavily current job。
- 新前端必须显式传 `site`。

## 站点化 Current Job Control（POST `/api/jobs/current/control`）

- 范围（Scope）: internal
- 变更（Change）: Modify
- 鉴权（Auth）: none（localhost only）

### 请求（Request）

- Body:
  - `site?: tavily|chatgpt`
  - `action: start|pause|resume|stop|force_stop|update_limits`
  - Tavily: 继续接受现有 `runMode/need/parallel/maxAttempts/autoExtract*`
  - ChatGPT:
    - `need`
    - `parallel`
    - `maxAttempts`
    - 服务端固定忽略外部 `runMode`，统一按 headed 执行
    - 服务端会在启动时为每个 attempt 自动生成独立的 cf-mail 邮箱、密码、昵称与生日资料

### 响应（Response）

- Success:
  - `ok: true`
  - `job`
- Error:
  - `409 { error }` 当前 `site` 已有活跃 job
  - `400 { error }` 参数非法或 cf-mail provision/ensure 失败

## ChatGPT 最近凭据（GET `/api/chatgpt/credentials`）

- 范围（Scope）: internal
- 变更（Change）: New
- 鉴权（Auth）: none（localhost only）

### 请求（Request）

- Query:
  - `limit?: number`
  - `includeSecrets?: boolean`

### 响应（Response）

- Success:
  - `ok: true`
  - `rows: [{ id, jobId, attemptId, email, accountId, accessTokenMasked, refreshTokenMasked, idTokenMasked, expiresAt, createdAt, hasSecrets }]`
- Error:
  - `400 { error }` 参数非法

### 兼容性与迁移（Compatibility / migration）

- 默认不返回完整 secret；只有 `includeSecrets=true` 时才返回完整凭据字段。
