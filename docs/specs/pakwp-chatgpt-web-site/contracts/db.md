# 数据库（DB）

## jobs 站点化扩展

- 范围（Scope）: internal
- 变更（Change）: Modify
- 影响表（Affected tables）: `jobs`

### Schema delta（结构变更）

- DDL / migration snippet（尽量精简）:
  - `ALTER TABLE jobs ADD COLUMN site TEXT NOT NULL DEFAULT 'tavily';`
  - `ALTER TABLE jobs ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}';`
- Constraints / indexes:
  - 增加 `INDEX jobs_site_id_idx ON jobs(site, id DESC)`

### Migration notes（迁移说明）

- 向后兼容窗口（Backward compatibility window）: 旧 job 记录自动视为 `site='tavily'`
- 发布/上线步骤（Rollout steps）: 先迁移 DB，再切前后端到站点化接口
- 回滚策略（Rollback strategy）: 代码可忽略新列并继续按 Tavily 读取
- 回填/数据迁移（Backfill / data migration, 如适用）: 历史行无需额外回填

## ChatGPT 凭据表

- 范围（Scope）: internal
- 变更（Change）: New
- 影响表（Affected tables）: `chatgpt_credentials`

### Schema delta（结构变更）

- DDL / migration snippet（尽量精简）:
  - `CREATE TABLE chatgpt_credentials (...)`
  - 关键字段：
    - `job_id`
    - `attempt_id`
    - `email`
    - `account_id`
    - `access_token`
    - `refresh_token`
    - `id_token`
    - `expires_at`
    - `credential_json`
    - `created_at`
- Constraints / indexes:
  - `UNIQUE(attempt_id)`
  - `INDEX chatgpt_credentials_created_idx ON chatgpt_credentials(created_at DESC)`

### Migration notes（迁移说明）

- 向后兼容窗口（Backward compatibility window）: 新表不影响 Tavily 既有数据读取
- 发布/上线步骤（Rollout steps）: 与 `jobs.site` 同次迁移
- 回滚策略（Rollback strategy）: 可保留空表，不影响旧逻辑
- 回填/数据迁移（Backfill / data migration, 如适用）: 无
