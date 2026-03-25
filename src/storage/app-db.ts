import { Database } from "bun:sqlite";
import { access, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  DEFAULT_TARGETS,
  defaultArtifactTypeForTarget,
  hasArtifactCompatibleStatus,
  normalizeProviderTargets,
  type ProviderTarget,
  type TargetArtifactType,
  type TargetRunStatus,
} from "../provider-targets.js";

export type AccountStatus =
  | "ready"
  | "leased"
  | "running"
  | "succeeded"
  | "failed"
  | "skipped_has_key"
  | "skipped_has_artifact"
  | "disabled";
export type JobStatus = "idle" | "running" | "paused" | "completing" | "completed" | "failed";
export type AttemptStatus = "running" | "succeeded" | "failed" | "skipped";
export type ApiKeyStatus = "active" | "revoked" | "unknown";
export type ArtifactStatus = "active" | "revoked" | "unknown";

export interface AppSettings extends Record<string, unknown> {
  subscriptionUrl: string;
  groupName: string;
  routeGroupName: string;
  checkUrl: string;
  timeoutMs: number;
  maxLatencyMs: number;
  apiPort: number;
  mixedPort: number;
  serverHost: string;
  serverPort: number;
  defaultRunMode: "headed" | "headless";
  defaultNeed: number;
  defaultParallel: number;
  defaultMaxAttempts: number;
}

export interface MicrosoftAccountRecord {
  id: number;
  microsoftEmail: string;
  passwordPlaintext: string;
  hasApiKey: boolean;
  apiKeyId: number | null;
  importedAt: string;
  updatedAt: string;
  importSource: string;
  lastUsedAt: string | null;
  lastResultStatus: AccountStatus;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: string | null;
  groupName: string | null;
  disabledAt: string | null;
  leaseJobId: number | null;
  leaseStartedAt: string | null;
}

export interface AccountTargetStateRecord {
  id: number;
  accountId: number;
  target: ProviderTarget;
  hasArtifact: boolean;
  artifactId: number | null;
  lastResultStatus: AccountStatus;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: string | null;
  lastUsedAt: string | null;
  leaseJobId: number | null;
  leaseStartedAt: string | null;
  updatedAt: string;
}

export interface ImportAccountsResult {
  created: number;
  updated: number;
  total: number;
  affectedIds: number[];
}

export interface ApiKeyRecord {
  id: number;
  accountId: number;
  microsoftEmail: string;
  apiKey: string;
  apiKeyPrefix: string;
  status: ApiKeyStatus;
  extractedAt: string;
  lastVerifiedAt: string | null;
}

export interface ArtifactRecord {
  id: number;
  accountId: number;
  microsoftEmail: string;
  target: ProviderTarget;
  artifactType: TargetArtifactType;
  secretValue: string;
  preview: string;
  metadataJson: string | null;
  status: ArtifactStatus;
  extractedAt: string;
  lastVerifiedAt: string | null;
}

export interface JobRecord {
  id: number;
  status: JobStatus;
  runMode: "headed" | "headless";
  need: number;
  parallel: number;
  maxAttempts: number;
  successCount: number;
  failureCount: number;
  skipCount: number;
  launchedCount: number;
  startedAt: string;
  pausedAt: string | null;
  completedAt: string | null;
  lastError: string | null;
  updatedAt: string;
  targets: ProviderTarget[];
}

export interface JobAttemptRecord {
  id: number;
  jobId: number;
  accountId: number;
  runId: string | null;
  status: AttemptStatus;
  stage: string;
  proxyNode: string | null;
  proxyIp: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  outputDir: string | null;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  target: ProviderTarget | null;
  sequenceIndex: number;
}

export interface WorkerArtifactInput {
  target: ProviderTarget;
  artifactType?: TargetArtifactType;
  secretValue: string;
  preview?: string | null;
  metadataJson?: string | null;
  status?: ArtifactStatus;
}

export interface WorkerTargetResultInput {
  target: ProviderTarget;
  status: TargetRunStatus;
  stage: string;
  errorCode?: string | null;
  errorMessage?: string | null;
  runId?: string | null;
  proxyNode?: string | null;
  proxyIp?: string | null;
  durationMs?: number | null;
  artifact?: WorkerArtifactInput | null;
}

export interface WorkerAttemptResultInput {
  ok: boolean;
  targetResults: WorkerTargetResultInput[];
  errorMessage?: string | null;
}

export interface ProxyNodeRecord {
  id: number;
  nodeName: string;
  isSelected: boolean;
  lastStatus: string | null;
  lastLatencyMs: number | null;
  lastEgressIp: string | null;
  lastCountry: string | null;
  lastCity: string | null;
  lastOrg: string | null;
  lastCheckedAt: string | null;
  lastSelectedAt: string | null;
  success24h: number;
}

interface SettingsRow {
  key: string;
  value_json: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function asBoolean(value: unknown): boolean {
  return value === 1 || value === true;
}

function parseJson<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function fileExists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}

function mapAccountRow(row: Record<string, unknown>): MicrosoftAccountRecord {
  return {
    id: Number(row.id),
    microsoftEmail: String(row.microsoft_email),
    passwordPlaintext: String(row.password_plaintext || ""),
    hasApiKey: asBoolean(row.has_api_key),
    apiKeyId: row.api_key_id == null ? null : Number(row.api_key_id),
    importedAt: String(row.imported_at),
    updatedAt: String(row.updated_at),
    importSource: String(row.import_source || "manual"),
    lastUsedAt: row.last_used_at == null ? null : String(row.last_used_at),
    lastResultStatus: String(row.last_result_status || "ready") as AccountStatus,
    lastResultAt: row.last_result_at == null ? null : String(row.last_result_at),
    lastErrorCode: row.last_error_code == null ? null : String(row.last_error_code),
    skipReason: row.skip_reason == null ? null : String(row.skip_reason),
    groupName: row.group_name == null ? null : String(row.group_name),
    disabledAt: row.disabled_at == null ? null : String(row.disabled_at),
    leaseJobId: row.lease_job_id == null ? null : Number(row.lease_job_id),
    leaseStartedAt: row.lease_started_at == null ? null : String(row.lease_started_at),
  };
}

function mapApiKeyRow(row: Record<string, unknown>): ApiKeyRecord {
  return {
    id: Number(row.id),
    accountId: Number(row.account_id),
    microsoftEmail: String(row.microsoft_email),
    apiKey: String(row.api_key),
    apiKeyPrefix: String(row.api_key_prefix),
    status: String(row.status || "unknown") as ApiKeyStatus,
    extractedAt: String(row.extracted_at),
    lastVerifiedAt: row.last_verified_at == null ? null : String(row.last_verified_at),
  };
}

function mapArtifactRow(row: Record<string, unknown>): ArtifactRecord {
  return {
    id: Number(row.id),
    accountId: Number(row.account_id),
    microsoftEmail: String(row.microsoft_email || ""),
    target: String(row.target) as ProviderTarget,
    artifactType: String(row.artifact_type) as TargetArtifactType,
    secretValue: String(row.secret_value || ""),
    preview: String(row.preview || ""),
    metadataJson: row.metadata_json == null ? null : String(row.metadata_json),
    status: String(row.status || "unknown") as ArtifactStatus,
    extractedAt: String(row.extracted_at),
    lastVerifiedAt: row.last_verified_at == null ? null : String(row.last_verified_at),
  };
}

function mapAccountTargetStateRow(row: Record<string, unknown>): AccountTargetStateRecord {
  return {
    id: Number(row.id),
    accountId: Number(row.account_id),
    target: String(row.target) as ProviderTarget,
    hasArtifact: asBoolean(row.has_artifact),
    artifactId: row.artifact_id == null ? null : Number(row.artifact_id),
    lastResultStatus: String(row.last_result_status || "ready") as AccountStatus,
    lastResultAt: row.last_result_at == null ? null : String(row.last_result_at),
    lastErrorCode: row.last_error_code == null ? null : String(row.last_error_code),
    skipReason: row.skip_reason == null ? null : String(row.skip_reason),
    lastUsedAt: row.last_used_at == null ? null : String(row.last_used_at),
    leaseJobId: row.lease_job_id == null ? null : Number(row.lease_job_id),
    leaseStartedAt: row.lease_started_at == null ? null : String(row.lease_started_at),
    updatedAt: String(row.updated_at),
  };
}

function mapJobRow(row: Record<string, unknown>): JobRecord {
  return {
    id: Number(row.id),
    status: String(row.status) as JobStatus,
    runMode: String(row.run_mode || "headed") as "headed" | "headless",
    need: Number(row.need || 0),
    parallel: Number(row.parallel || 0),
    maxAttempts: Number(row.max_attempts || 0),
    successCount: Number(row.success_count || 0),
    failureCount: Number(row.failure_count || 0),
    skipCount: Number(row.skip_count || 0),
    launchedCount: Number(row.launched_count || 0),
    startedAt: String(row.started_at),
    pausedAt: row.paused_at == null ? null : String(row.paused_at),
    completedAt: row.completed_at == null ? null : String(row.completed_at),
    lastError: row.last_error == null ? null : String(row.last_error),
    updatedAt: String(row.updated_at),
    targets: normalizeProviderTargets(parseJson(row.targets_json == null ? "[]" : String(row.targets_json), DEFAULT_TARGETS)),
  };
}

function mapAttemptRow(row: Record<string, unknown>): JobAttemptRecord {
  return {
    id: Number(row.id),
    jobId: Number(row.job_id),
    accountId: Number(row.account_id),
    runId: row.run_id == null ? null : String(row.run_id),
    status: String(row.status) as AttemptStatus,
    stage: String(row.stage || ""),
    proxyNode: row.proxy_node == null ? null : String(row.proxy_node),
    proxyIp: row.proxy_ip == null ? null : String(row.proxy_ip),
    errorCode: row.error_code == null ? null : String(row.error_code),
    errorMessage: row.error_message == null ? null : String(row.error_message),
    outputDir: row.output_dir == null ? null : String(row.output_dir),
    startedAt: String(row.started_at),
    completedAt: row.completed_at == null ? null : String(row.completed_at),
    durationMs: row.duration_ms == null ? null : Number(row.duration_ms),
    target: row.target == null ? null : (String(row.target) as ProviderTarget),
    sequenceIndex: Number(row.sequence_index || 1),
  };
}

export function computeLaunchCapacity(
  job: Pick<JobRecord, "status" | "parallel" | "need" | "successCount" | "maxAttempts" | "launchedCount">,
  activeCount: number,
): number {
  if (job.status !== "running") return 0;
  const availableSlots = Math.max(0, job.parallel - activeCount);
  const needLeft = Math.max(0, job.need - job.successCount);
  const attemptBudget = Math.max(0, job.maxAttempts - job.launchedCount);
  return Math.max(0, Math.min(availableSlots, needLeft, attemptBudget));
}

export function shouldEnterCompleting(job: Pick<JobRecord, "need" | "successCount" | "maxAttempts" | "launchedCount">): boolean {
  return job.successCount >= job.need || job.launchedCount >= job.maxAttempts;
}

export class AppDatabase {
  readonly dbPath: string;
  private readonly db: Database;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.db = new Database(dbPath, { create: true, strict: true });
    this.db.exec("PRAGMA journal_mode=WAL;");
    this.db.exec("PRAGMA synchronous=NORMAL;");
    this.db.exec("PRAGMA temp_store=MEMORY;");
    this.db.exec("PRAGMA busy_timeout=5000;");
    this.db.exec("PRAGMA foreign_keys=ON;");
    this.migrate();
  }

  static async open(dbPath: string, legacyProxyUsagePath?: string): Promise<AppDatabase> {
    await mkdir(path.dirname(dbPath), { recursive: true });
    const appDb = new AppDatabase(dbPath);
    appDb.recoverStaleState();
    if (legacyProxyUsagePath) {
      await appDb.importLegacyProxyUsage(legacyProxyUsagePath);
    }
    return appDb;
  }

  close(): void {
    this.db.close(false);
  }

  private hasSignupTasksTable(): boolean {
    return Boolean(
      (
        this.db
          .query("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'signup_tasks' LIMIT 1")
          .get() as { ok?: number } | null
      )?.ok,
    );
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE IF NOT EXISTS microsoft_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        microsoft_email TEXT NOT NULL UNIQUE,
        password_plaintext TEXT NOT NULL,
        has_api_key INTEGER NOT NULL DEFAULT 0,
        api_key_id INTEGER,
        imported_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        import_source TEXT NOT NULL DEFAULT 'manual',
        last_used_at TEXT,
        last_result_status TEXT NOT NULL DEFAULT 'ready',
        last_result_at TEXT,
        last_error_code TEXT,
        skip_reason TEXT,
        group_name TEXT,
        disabled_at TEXT,
        lease_job_id INTEGER,
        lease_started_at TEXT
      );

      CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL REFERENCES microsoft_accounts(id) ON DELETE CASCADE,
        api_key TEXT NOT NULL UNIQUE,
        api_key_prefix TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        extracted_at TEXT NOT NULL,
        last_verified_at TEXT
      );

      CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL REFERENCES microsoft_accounts(id) ON DELETE CASCADE,
        target TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        secret_value TEXT NOT NULL,
        preview TEXT NOT NULL,
        metadata_json TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        extracted_at TEXT NOT NULL,
        last_verified_at TEXT,
        UNIQUE(account_id, target, artifact_type)
      );

      CREATE TABLE IF NOT EXISTS account_target_states (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL REFERENCES microsoft_accounts(id) ON DELETE CASCADE,
        target TEXT NOT NULL,
        has_artifact INTEGER NOT NULL DEFAULT 0,
        artifact_id INTEGER REFERENCES artifacts(id) ON DELETE SET NULL,
        last_result_status TEXT NOT NULL DEFAULT 'ready',
        last_result_at TEXT,
        last_error_code TEXT,
        skip_reason TEXT,
        last_used_at TEXT,
        lease_job_id INTEGER,
        lease_started_at TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE(account_id, target)
      );

      CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        status TEXT NOT NULL,
        run_mode TEXT NOT NULL,
        targets_json TEXT NOT NULL DEFAULT '["tavily"]',
        need INTEGER NOT NULL,
        parallel INTEGER NOT NULL,
        max_attempts INTEGER NOT NULL,
        success_count INTEGER NOT NULL DEFAULT 0,
        failure_count INTEGER NOT NULL DEFAULT 0,
        skip_count INTEGER NOT NULL DEFAULT 0,
        launched_count INTEGER NOT NULL DEFAULT 0,
        started_at TEXT NOT NULL,
        paused_at TEXT,
        completed_at TEXT,
        last_error TEXT,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS job_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        account_id INTEGER NOT NULL REFERENCES microsoft_accounts(id) ON DELETE CASCADE,
        run_id TEXT,
        target TEXT,
        sequence_index INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL,
        stage TEXT NOT NULL,
        proxy_node TEXT,
        proxy_ip TEXT,
        error_code TEXT,
        error_message TEXT,
        output_dir TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        duration_ms INTEGER
      );

      CREATE TABLE IF NOT EXISTS proxy_nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_name TEXT NOT NULL UNIQUE,
        is_selected INTEGER NOT NULL DEFAULT 0,
        last_status TEXT,
        last_latency_ms INTEGER,
        last_egress_ip TEXT,
        last_country TEXT,
        last_city TEXT,
        last_org TEXT,
        last_checked_at TEXT,
        last_selected_at TEXT
      );

      CREATE TABLE IF NOT EXISTS proxy_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_name TEXT NOT NULL,
        status TEXT NOT NULL,
        latency_ms INTEGER,
        egress_ip TEXT,
        country TEXT,
        city TEXT,
        org TEXT,
        error TEXT,
        checked_at TEXT NOT NULL
      );
    `);

    const signupTaskTableExists = this.hasSignupTasksTable();
    if (signupTaskTableExists) {
      const tableInfo = this.db.query("PRAGMA table_info(signup_tasks);").all() as Array<Record<string, unknown>>;
      const existingColumns = new Set(tableInfo.map((item) => String(item.name || "").toLowerCase()));
      if (!existingColumns.has("job_id")) {
        this.db.exec("ALTER TABLE signup_tasks ADD COLUMN job_id INTEGER;");
      }
      if (!existingColumns.has("account_id")) {
        this.db.exec("ALTER TABLE signup_tasks ADD COLUMN account_id INTEGER;");
      }
    }

    const accountTableInfo = this.db.query("PRAGMA table_info(microsoft_accounts);").all() as Array<Record<string, unknown>>;
    const accountColumns = new Set(accountTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!accountColumns.has("group_name")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN group_name TEXT;");
    }

    const jobsTableInfo = this.db.query("PRAGMA table_info(jobs);").all() as Array<Record<string, unknown>>;
    const jobColumns = new Set(jobsTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!jobColumns.has("targets_json")) {
      this.db.exec(`ALTER TABLE jobs ADD COLUMN targets_json TEXT NOT NULL DEFAULT '["tavily"]';`);
    }

    const attemptsTableInfo = this.db.query("PRAGMA table_info(job_attempts);").all() as Array<Record<string, unknown>>;
    const attemptColumns = new Set(attemptsTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!attemptColumns.has("target")) {
      this.db.exec("ALTER TABLE job_attempts ADD COLUMN target TEXT;");
    }
    if (!attemptColumns.has("sequence_index")) {
      this.db.exec("ALTER TABLE job_attempts ADD COLUMN sequence_index INTEGER NOT NULL DEFAULT 1;");
    }

    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_result ON microsoft_accounts(last_result_status, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_skip_reason ON microsoft_accounts(skip_reason, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_group_name ON microsoft_accounts(group_name, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(account_id);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_artifacts_account_target ON artifacts(account_id, target, artifact_type);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_artifacts_target_status ON artifacts(target, status, extracted_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_account_target_states_target_status ON account_target_states(target, last_result_status, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_account_target_states_account_target ON account_target_states(account_id, target);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_jobs_status_started ON jobs(status, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_job_attempts_job_status ON job_attempts(job_id, status, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_job_attempts_job_target ON job_attempts(job_id, target, sequence_index, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_proxy_checks_node_checked ON proxy_checks(node_name, checked_at DESC);");
    if (signupTaskTableExists) {
      this.db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_job_account ON signup_tasks(job_id, account_id, started_at DESC);");
    }

    const legacyApiKeyRows = this.db
      .query("SELECT * FROM api_keys")
      .all() as Array<Record<string, unknown>>;
    for (const row of legacyApiKeyRows) {
      const accountId = Number(row.account_id || 0);
      const apiKey = String(row.api_key || "");
      if (!accountId || !apiKey) continue;
      this.db
        .query(`
          INSERT INTO artifacts (
            account_id, target, artifact_type, secret_value, preview, metadata_json, status, extracted_at, last_verified_at
          ) VALUES (?, 'tavily', 'api_key', ?, ?, NULL, ?, ?, ?)
          ON CONFLICT(account_id, target, artifact_type) DO UPDATE SET
            secret_value = excluded.secret_value,
            preview = excluded.preview,
            status = excluded.status,
            extracted_at = excluded.extracted_at,
            last_verified_at = excluded.last_verified_at
        `)
        .run(
          accountId,
          apiKey,
          String(row.api_key_prefix || apiKey.slice(0, Math.min(apiKey.length, 12))),
          String(row.status || "active"),
          String(row.extracted_at || nowIso()),
          row.last_verified_at == null ? null : String(row.last_verified_at),
        );
      const artifact = this.getArtifact(accountId, "tavily", "api_key");
      this.upsertAccountTargetState({
        accountId,
        target: "tavily",
        hasArtifact: true,
        artifactId: artifact?.id ?? null,
        lastResultStatus: "skipped_has_artifact",
        lastResultAt: row.last_verified_at == null ? String(row.extracted_at || nowIso()) : String(row.last_verified_at),
        lastErrorCode: null,
        skipReason: "has_artifact",
      });
    }
  }

  recoverStaleState(): void {
    const now = nowIso();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .query("UPDATE jobs SET status = 'failed', completed_at = ?, updated_at = ?, last_error = COALESCE(last_error, 'server_restart') WHERE status IN ('running', 'completing', 'paused')")
        .run(now, now);
      this.db
        .query("UPDATE job_attempts SET status = 'failed', stage = 'server_restart', completed_at = ?, duration_ms = 0 WHERE status = 'running'")
        .run(now);
      this.db
        .query("UPDATE microsoft_accounts SET lease_job_id = NULL, lease_started_at = NULL, last_result_status = CASE WHEN disabled_at IS NOT NULL THEN 'disabled' WHEN has_api_key = 1 THEN 'skipped_has_key' ELSE 'ready' END WHERE lease_job_id IS NOT NULL")
        .run();
      this.db
        .query(
          "UPDATE account_target_states SET lease_job_id = NULL, lease_started_at = NULL, last_result_status = CASE WHEN has_artifact = 1 THEN 'skipped_has_artifact' ELSE 'ready' END, updated_at = ? WHERE lease_job_id IS NOT NULL",
        )
        .run(now);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  async importLegacyProxyUsage(legacyPath: string): Promise<number> {
    const existingCount = Number((this.db.query("SELECT COUNT(*) AS count FROM proxy_nodes").get() as { count?: number })?.count || 0);
    if (existingCount > 0) return 0;
    if (!(await fileExists(legacyPath))) return 0;

    const raw = await readFile(legacyPath, "utf8");
    const parsed = parseJson<{ nodes?: Record<string, Record<string, unknown>>; recentSelected?: string[] }>(raw, {});
    const nodes = parsed.nodes || {};
    const selected = Array.isArray(parsed.recentSelected) ? String(parsed.recentSelected[0] || "") : "";
    let imported = 0;

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const stmt = this.db.query(`
        INSERT INTO proxy_nodes (
          node_name, is_selected, last_status, last_latency_ms, last_egress_ip,
          last_country, last_city, last_org, last_checked_at, last_selected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_name) DO UPDATE SET
          is_selected = excluded.is_selected,
          last_status = excluded.last_status,
          last_latency_ms = excluded.last_latency_ms,
          last_egress_ip = excluded.last_egress_ip,
          last_country = excluded.last_country,
          last_city = excluded.last_city,
          last_org = excluded.last_org,
          last_checked_at = excluded.last_checked_at,
          last_selected_at = excluded.last_selected_at
      `);
      for (const [name, payload] of Object.entries(nodes)) {
        const geo = payload.lastGeo as Record<string, unknown> | undefined;
        stmt.run(
          name,
          name === selected ? 1 : 0,
          payload.lastOutcome ? String(payload.lastOutcome) : null,
          payload.lastLatencyMs == null ? null : Number(payload.lastLatencyMs),
          payload.lastIp ? String(payload.lastIp) : geo?.ip ? String(geo.ip) : null,
          geo?.country ? String(geo.country) : null,
          geo?.city ? String(geo.city) : null,
          geo?.org ? String(geo.org) : null,
          payload.lastCheckedAt ? String(payload.lastCheckedAt) : null,
          payload.lastUsedAt ? String(payload.lastUsedAt) : null,
        );
        imported += 1;
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }

    return imported;
  }

  ensureSettings(defaults: AppSettings): AppSettings {
    const merged = {
      ...defaults,
      ...this.getSettings(defaults),
    };
    this.setSettings(merged);
    return merged;
  }

  getSettings<T extends Record<string, unknown>>(defaults: T): T {
    const rows = this.db.query("SELECT key, value_json FROM app_settings").all() as SettingsRow[];
    const current = { ...defaults };
    for (const row of rows) {
      if (!(row.key in current)) continue;
      (current as Record<string, unknown>)[row.key] = parseJson(row.value_json, (defaults as Record<string, unknown>)[row.key]);
    }
    return current;
  }

  setSettings(settings: Record<string, unknown>): void {
    const now = nowIso();
    const stmt = this.db.query(`
      INSERT INTO app_settings (key, value_json, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        updated_at = excluded.updated_at
    `);
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      for (const [key, value] of Object.entries(settings)) {
        stmt.run(key, JSON.stringify(value), now);
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  private synthesizeTargetState(account: MicrosoftAccountRecord, target: ProviderTarget): AccountTargetStateRecord {
    const hasArtifact = target === "tavily" ? account.hasApiKey : false;
    const lastResultStatus: AccountStatus =
      account.disabledAt != null
        ? "disabled"
        : hasArtifact
          ? "skipped_has_artifact"
          : target === "tavily"
            ? account.lastResultStatus
            : "ready";
    return {
      id: 0,
      accountId: account.id,
      target,
      hasArtifact,
      artifactId: target === "tavily" ? account.apiKeyId : null,
      lastResultStatus,
      lastResultAt: target === "tavily" ? account.lastResultAt : null,
      lastErrorCode: target === "tavily" ? account.lastErrorCode : null,
      skipReason: hasArtifact ? "has_artifact" : null,
      lastUsedAt: target === "tavily" ? account.lastUsedAt : null,
      leaseJobId: null,
      leaseStartedAt: null,
      updatedAt: account.updatedAt,
    };
  }

  getAccountTargetState(accountId: number, target: ProviderTarget): AccountTargetStateRecord {
    const row = this.db
      .query("SELECT * FROM account_target_states WHERE account_id = ? AND target = ? LIMIT 1")
      .get(accountId, target) as Record<string, unknown> | null;
    if (row) return mapAccountTargetStateRow(row);
    const account = this.getAccount(accountId);
    if (!account) throw new Error(`account not found: ${accountId}`);
    return this.synthesizeTargetState(account, target);
  }

  listAccountTargetStatesForAccounts(accountIds: number[]): Map<number, Partial<Record<ProviderTarget, AccountTargetStateRecord>>> {
    const uniqueIds = Array.from(new Set(accountIds.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)));
    const grouped = new Map<number, Partial<Record<ProviderTarget, AccountTargetStateRecord>>>();
    if (uniqueIds.length === 0) return grouped;
    const placeholders = uniqueIds.map(() => "?").join(", ");
    const rows = this.db
      .query(`SELECT * FROM account_target_states WHERE account_id IN (${placeholders})`)
      .all(...uniqueIds) as Array<Record<string, unknown>>;
    for (const raw of rows) {
      const state = mapAccountTargetStateRow(raw);
      const entry = grouped.get(state.accountId) || {};
      entry[state.target] = state;
      grouped.set(state.accountId, entry);
    }
    for (const accountId of uniqueIds) {
      const account = this.getAccount(accountId);
      if (!account) continue;
      const entry = grouped.get(accountId) || {};
      for (const target of ["tavily", "chatgpt"] as ProviderTarget[]) {
        if (!entry[target]) {
          entry[target] = this.synthesizeTargetState(account, target);
        }
      }
      grouped.set(accountId, entry);
    }
    return grouped;
  }

  private upsertAccountTargetState(input: {
    accountId: number;
    target: ProviderTarget;
    hasArtifact?: boolean;
    artifactId?: number | null;
    lastResultStatus?: AccountStatus;
    lastResultAt?: string | null;
    lastErrorCode?: string | null;
    skipReason?: string | null;
    lastUsedAt?: string | null;
    leaseJobId?: number | null;
    leaseStartedAt?: string | null;
  }): AccountTargetStateRecord {
    const current = this.getAccountTargetState(input.accountId, input.target);
    const next: AccountTargetStateRecord = {
      ...current,
      hasArtifact: input.hasArtifact ?? current.hasArtifact,
      artifactId: input.artifactId === undefined ? current.artifactId : input.artifactId,
      lastResultStatus: input.lastResultStatus ?? current.lastResultStatus,
      lastResultAt: input.lastResultAt === undefined ? current.lastResultAt : input.lastResultAt,
      lastErrorCode: input.lastErrorCode === undefined ? current.lastErrorCode : input.lastErrorCode,
      skipReason: input.skipReason === undefined ? current.skipReason : input.skipReason,
      lastUsedAt: input.lastUsedAt === undefined ? current.lastUsedAt : input.lastUsedAt,
      leaseJobId: input.leaseJobId === undefined ? current.leaseJobId : input.leaseJobId,
      leaseStartedAt: input.leaseStartedAt === undefined ? current.leaseStartedAt : input.leaseStartedAt,
      updatedAt: nowIso(),
    };
    this.db
      .query(`
        INSERT INTO account_target_states (
          account_id, target, has_artifact, artifact_id, last_result_status, last_result_at, last_error_code,
          skip_reason, last_used_at, lease_job_id, lease_started_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(account_id, target) DO UPDATE SET
          has_artifact = excluded.has_artifact,
          artifact_id = excluded.artifact_id,
          last_result_status = excluded.last_result_status,
          last_result_at = excluded.last_result_at,
          last_error_code = excluded.last_error_code,
          skip_reason = excluded.skip_reason,
          last_used_at = excluded.last_used_at,
          lease_job_id = excluded.lease_job_id,
          lease_started_at = excluded.lease_started_at,
          updated_at = excluded.updated_at
      `)
      .run(
        input.accountId,
        input.target,
        next.hasArtifact ? 1 : 0,
        next.artifactId,
        next.lastResultStatus,
        next.lastResultAt,
        next.lastErrorCode,
        next.skipReason,
        next.lastUsedAt,
        next.leaseJobId,
        next.leaseStartedAt,
        next.updatedAt,
      );
    return this.getAccountTargetState(input.accountId, input.target);
  }

  importAccounts(
    entries: Array<{ email: string; password: string }>,
    options?: { source?: string; groupName?: string | null },
  ): ImportAccountsResult {
    const deduped = new Map<string, string>();
    for (const entry of entries) {
      const email = entry.email.trim().toLowerCase();
      const password = entry.password.trim();
      if (!email || !password) continue;
      deduped.set(email, password);
    }

    const now = nowIso();
    const source = options?.source || "manual";
    const normalizedGroupName = options?.groupName?.trim() ? options.groupName.trim() : null;
    let created = 0;
    let updated = 0;
    const affectedIds: number[] = [];
    const selectStmt = this.db.query("SELECT * FROM microsoft_accounts WHERE microsoft_email = ?");
    const insertStmt = this.db.query(`
      INSERT INTO microsoft_accounts (
        microsoft_email, password_plaintext, has_api_key, api_key_id, imported_at, updated_at, import_source, group_name,
        last_result_status, skip_reason
      ) VALUES (?, ?, 0, NULL, ?, ?, ?, ?, 'ready', NULL)
    `);
    const updateStmt = this.db.query(`
      UPDATE microsoft_accounts
      SET password_plaintext = ?,
          updated_at = ?,
          import_source = ?,
          group_name = COALESCE(?, group_name),
          skip_reason = CASE WHEN has_api_key = 1 THEN 'has_api_key' ELSE NULL END,
          last_result_status = CASE
            WHEN disabled_at IS NOT NULL THEN 'disabled'
            WHEN has_api_key = 1 THEN 'skipped_has_key'
            WHEN lease_job_id IS NOT NULL THEN 'leased'
            ELSE 'ready'
          END
      WHERE id = ?
    `);

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      for (const [email, password] of deduped.entries()) {
        const existing = selectStmt.get(email) as Record<string, unknown> | null;
        if (!existing) {
          insertStmt.run(email, password, now, now, source, normalizedGroupName);
          const inserted = selectStmt.get(email) as Record<string, unknown> | null;
          if (inserted?.id != null) {
            affectedIds.push(Number(inserted.id));
          }
          created += 1;
          continue;
        }
        updateStmt.run(password, now, source, normalizedGroupName, Number(existing.id));
        affectedIds.push(Number(existing.id));
        updated += 1;
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }

    return { created, updated, total: deduped.size, affectedIds };
  }

  listAccounts(filters: {
    q?: string;
    status?: string;
    hasApiKey?: boolean;
    skipReason?: string;
    groupName?: string;
    page?: number;
    pageSize?: number;
  }): { rows: MicrosoftAccountRecord[]; total: number; summary: { ready: number; linked: number; failed: number } } {
    const page = Math.max(1, filters.page || 1);
    const pageSize = Math.max(1, Math.min(100, filters.pageSize || 20));
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.q?.trim()) {
      const normalizedQuery = filters.q.trim().toLowerCase();
      const rawQuery = filters.q.trim();
      where.push("(microsoft_email LIKE ? OR password_plaintext LIKE ? OR LOWER(COALESCE(group_name, '')) LIKE ?)");
      params.push(`%${normalizedQuery}%`, `%${rawQuery}%`, `%${normalizedQuery}%`);
    }
    if (filters.status?.trim()) {
      where.push("last_result_status = ?");
      params.push(filters.status.trim());
    }
    if (typeof filters.hasApiKey === "boolean") {
      where.push("has_api_key = ?");
      params.push(filters.hasApiKey ? 1 : 0);
    }
    if (filters.skipReason?.trim()) {
      where.push("skip_reason = ?");
      params.push(filters.skipReason.trim());
    }
    if (filters.groupName?.trim()) {
      where.push("group_name = ?");
      params.push(filters.groupName.trim());
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const summaryRow = this.db
      .query(`
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN last_result_status = 'ready' THEN 1 ELSE 0 END) AS ready_count,
          SUM(CASE WHEN has_api_key = 1 THEN 1 ELSE 0 END) AS linked_count,
          SUM(CASE WHEN last_result_status = 'failed' THEN 1 ELSE 0 END) AS failed_count
        FROM microsoft_accounts
        ${whereSql}
      `)
      .get(...(params as any[])) as { total?: number; ready_count?: number; linked_count?: number; failed_count?: number } | null;
    const total = Number(summaryRow?.total || 0);
    const rows = this.db
      .query(`SELECT * FROM microsoft_accounts ${whereSql} ORDER BY updated_at DESC LIMIT ? OFFSET ?`)
      .all(...([...(params as any[]), pageSize, (page - 1) * pageSize] as any[])) as Record<string, unknown>[];
    return {
      rows: rows.map(mapAccountRow),
      total,
      summary: {
        ready: Number(summaryRow?.ready_count || 0),
        linked: Number(summaryRow?.linked_count || 0),
        failed: Number(summaryRow?.failed_count || 0),
      },
    };
  }

  listAccountGroups(): string[] {
    const rows = this.db
      .query(`
        SELECT DISTINCT group_name
        FROM microsoft_accounts
        WHERE group_name IS NOT NULL AND TRIM(group_name) <> ''
        ORDER BY group_name COLLATE NOCASE ASC
      `)
      .all() as Array<Record<string, unknown>>;
    return rows
      .map((row) => String(row.group_name || "").trim())
      .filter(Boolean);
  }

  getAccountsByEmails(emails: string[]): MicrosoftAccountRecord[] {
    const normalizedEmails = Array.from(new Set(emails.map((email) => email.trim().toLowerCase()).filter(Boolean)));
    if (normalizedEmails.length === 0) return [];
    const placeholders = normalizedEmails.map(() => "?").join(", ");
    const rows = this.db
      .query(`SELECT * FROM microsoft_accounts WHERE microsoft_email IN (${placeholders})`)
      .all(...normalizedEmails) as Array<Record<string, unknown>>;
    return rows.map(mapAccountRow);
  }

  updateAccountsGroup(ids: number[], groupName: string | null): { updated: number; groupName: string | null } {
    const uniqueIds = Array.from(new Set(ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)));
    if (uniqueIds.length === 0) {
      return { updated: 0, groupName: groupName?.trim() || null };
    }
    const normalizedGroupName = groupName?.trim() ? groupName.trim() : null;
    const placeholders = uniqueIds.map(() => "?").join(", ");
    this.db
      .query(
        `UPDATE microsoft_accounts SET group_name = ?, updated_at = ? WHERE id IN (${placeholders})`,
      )
      .run(normalizedGroupName, nowIso(), ...uniqueIds);
    const changesRow = this.db.query("SELECT changes() AS count").get() as { count?: number } | null;
    return {
      updated: Number(changesRow?.count || 0),
      groupName: normalizedGroupName,
    };
  }

  deleteAccounts(ids: number[]): { deleted: number; blockedIds: number[] } {
    const uniqueIds = Array.from(new Set(ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)));
    if (uniqueIds.length === 0) {
      return { deleted: 0, blockedIds: [] };
    }

    const placeholders = uniqueIds.map(() => "?").join(", ");
    const blockedRows = this.db
      .query(`
        SELECT DISTINCT a.id
        FROM microsoft_accounts a
        LEFT JOIN account_target_states ats ON ats.account_id = a.id AND ats.has_artifact = 1
        WHERE a.id IN (${placeholders})
          AND (a.lease_job_id IS NOT NULL OR a.has_api_key = 1 OR ats.id IS NOT NULL)
      `)
      .all(...uniqueIds) as Array<Record<string, unknown>>;
    const blockedIds = blockedRows.map((row) => Number(row.id));
    const deletableIds = uniqueIds.filter((id) => !blockedIds.includes(id));

    if (deletableIds.length === 0) {
      return { deleted: 0, blockedIds };
    }

    const deletePlaceholders = deletableIds.map(() => "?").join(", ");
    this.db.query(`DELETE FROM microsoft_accounts WHERE id IN (${deletePlaceholders})`).run(...deletableIds);
    const deleted = Number((this.db.query("SELECT changes() AS count").get() as { count?: number } | null)?.count || 0);
    return { deleted, blockedIds };
  }

  getArtifact(accountId: number, target: ProviderTarget, artifactType?: TargetArtifactType): ArtifactRecord | null {
    const resolvedType = artifactType || defaultArtifactTypeForTarget(target);
    const row = this.db
      .query(
        `
          SELECT art.*, acc.microsoft_email
          FROM artifacts art
          JOIN microsoft_accounts acc ON acc.id = art.account_id
          WHERE art.account_id = ? AND art.target = ? AND art.artifact_type = ?
          LIMIT 1
        `,
      )
      .get(accountId, target, resolvedType) as Record<string, unknown> | null;
    return row ? mapArtifactRow(row) : null;
  }

  private maskArtifactSecret(secret: string, visible = 6): string {
    if (!secret) return "";
    if (secret.length <= visible) return "*".repeat(secret.length);
    return `${secret.slice(0, Math.min(visible, secret.length))}${"*".repeat(Math.max(4, secret.length - visible * 2))}${secret.slice(-visible)}`;
  }

  recordArtifact(input: WorkerArtifactInput & { accountId: number }): ArtifactRecord {
    const now = nowIso();
    const artifactType = input.artifactType || defaultArtifactTypeForTarget(input.target);
    const preview = input.preview?.trim() || this.maskArtifactSecret(input.secretValue);
    this.db.exec("BEGIN IMMEDIATE;");
    let row: Record<string, unknown>;
    try {
      const previousArtifactOwner = this.db
        .query(
          "SELECT id, account_id FROM artifacts WHERE target = ? AND artifact_type = ? AND secret_value = ? LIMIT 1",
        )
        .get(input.target, artifactType, input.secretValue) as { id?: number; account_id?: number | null } | null;
      row = this.db
        .query(`
          INSERT INTO artifacts (
            account_id, target, artifact_type, secret_value, preview, metadata_json, status, extracted_at, last_verified_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(account_id, target, artifact_type) DO UPDATE SET
            secret_value = excluded.secret_value,
            preview = excluded.preview,
            metadata_json = excluded.metadata_json,
            status = excluded.status,
            extracted_at = excluded.extracted_at,
            last_verified_at = excluded.last_verified_at
          RETURNING *
        `)
        .get(
          input.accountId,
          input.target,
          artifactType,
          input.secretValue,
          preview,
          input.metadataJson || null,
          input.status || "active",
          now,
          now,
        ) as Record<string, unknown>;
      const artifactId = Number(row.id);
      const previousArtifactAccountId =
        previousArtifactOwner?.account_id == null ? null : Number(previousArtifactOwner.account_id);
      if (previousArtifactAccountId && previousArtifactAccountId !== input.accountId) {
        this.db
          .query("DELETE FROM artifacts WHERE id = ?")
          .run(previousArtifactOwner?.id == null ? 0 : Number(previousArtifactOwner.id));
        this.upsertAccountTargetState({
          accountId: previousArtifactAccountId,
          target: input.target,
          hasArtifact: false,
          artifactId: null,
          lastResultStatus: "ready",
          lastResultAt: now,
          lastErrorCode: null,
          skipReason: null,
          leaseJobId: null,
          leaseStartedAt: null,
        });
      }
      this.upsertAccountTargetState({
        accountId: input.accountId,
        target: input.target,
        hasArtifact: true,
        artifactId,
        lastResultStatus: "succeeded",
        lastResultAt: now,
        lastErrorCode: null,
        skipReason: "has_artifact",
        lastUsedAt: now,
        leaseJobId: null,
        leaseStartedAt: null,
      });
      if (input.target === "tavily" && artifactType === "api_key") {
        const prefix = input.secretValue.slice(0, Math.min(input.secretValue.length, 12));
        const previous = this.db.query("SELECT account_id FROM api_keys WHERE api_key = ? LIMIT 1").get(input.secretValue) as { account_id?: number | null } | null;
        const apiKeyRow = this.db
          .query(`
            INSERT INTO api_keys (account_id, api_key, api_key_prefix, status, extracted_at, last_verified_at)
            VALUES (?, ?, ?, 'active', ?, ?)
            ON CONFLICT(api_key) DO UPDATE SET
              account_id = excluded.account_id,
              api_key_prefix = excluded.api_key_prefix,
              status = excluded.status,
              extracted_at = CASE
                WHEN api_keys.account_id IS excluded.account_id THEN api_keys.extracted_at
                ELSE excluded.extracted_at
              END,
              last_verified_at = excluded.last_verified_at
            RETURNING id
          `)
          .get(input.accountId, input.secretValue, prefix, now, now) as { id?: number } | null;
        const previousAccountId = previous?.account_id == null ? null : Number(previous.account_id);
        if (previousAccountId && previousAccountId !== input.accountId) {
          this.db
            .query(`
              UPDATE microsoft_accounts
              SET has_api_key = 0,
                  api_key_id = NULL,
                  skip_reason = NULL,
                  last_result_status = CASE WHEN disabled_at IS NOT NULL THEN 'disabled' ELSE 'ready' END,
                  updated_at = ?,
                  lease_job_id = NULL,
                  lease_started_at = NULL
              WHERE id = ?
            `)
            .run(now, previousAccountId);
          this.upsertAccountTargetState({
            accountId: previousAccountId,
            target: "tavily",
            hasArtifact: false,
            artifactId: null,
            lastResultStatus: "ready",
            lastResultAt: now,
            lastErrorCode: null,
            skipReason: null,
            leaseJobId: null,
            leaseStartedAt: null,
          });
        }
        this.db
          .query(`
            UPDATE microsoft_accounts
            SET has_api_key = 1,
                api_key_id = ?,
                skip_reason = 'has_api_key',
                last_result_status = 'skipped_has_key',
                last_result_at = ?,
                updated_at = ?,
                lease_job_id = NULL,
                lease_started_at = NULL
            WHERE id = ?
          `)
          .run(apiKeyRow?.id == null ? null : Number(apiKeyRow.id), now, now, input.accountId);
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
    return mapArtifactRow({
      ...row,
      microsoft_email: this.getAccount(input.accountId)?.microsoftEmail || "",
    });
  }

  listArtifacts(filters: {
    q?: string;
    status?: string;
    target?: ProviderTarget | "";
    artifactType?: TargetArtifactType | "";
    page?: number;
    pageSize?: number;
  }): { rows: ArtifactRecord[]; total: number; summary: { active: number; revoked: number } } {
    const page = Math.max(1, filters.page || 1);
    const pageSize = Math.max(1, Math.min(100, filters.pageSize || 20));
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.q?.trim()) {
      where.push("(LOWER(a.microsoft_email) LIKE ? OR art.preview LIKE ?)");
      params.push(`%${filters.q.trim().toLowerCase()}%`, `%${filters.q.trim()}%`);
    }
    if (filters.status?.trim()) {
      where.push("art.status = ?");
      params.push(filters.status.trim());
    }
    if (filters.target?.trim()) {
      where.push("art.target = ?");
      params.push(filters.target.trim());
    }
    if (filters.artifactType?.trim()) {
      where.push("art.artifact_type = ?");
      params.push(filters.artifactType.trim());
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const summaryRow = this.db
      .query(`
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN art.status = 'active' THEN 1 ELSE 0 END) AS active_count,
          SUM(CASE WHEN art.status = 'revoked' THEN 1 ELSE 0 END) AS revoked_count
        FROM artifacts art
        JOIN microsoft_accounts a ON a.id = art.account_id
        ${whereSql}
      `)
      .get(...(params as any[])) as { total?: number; active_count?: number; revoked_count?: number } | null;
    const rows = this.db
      .query(`
        SELECT art.*, a.microsoft_email
        FROM artifacts art
        JOIN microsoft_accounts a ON a.id = art.account_id
        ${whereSql}
        ORDER BY art.extracted_at DESC
        LIMIT ? OFFSET ?
      `)
      .all(...([...(params as any[]), pageSize, (page - 1) * pageSize] as any[])) as Array<Record<string, unknown>>;
    return {
      rows: rows.map(mapArtifactRow),
      total: Number(summaryRow?.total || 0),
      summary: {
        active: Number(summaryRow?.active_count || 0),
        revoked: Number(summaryRow?.revoked_count || 0),
      },
    };
  }

  listApiKeys(filters: { q?: string; status?: string; page?: number; pageSize?: number }): { rows: ApiKeyRecord[]; total: number; summary: { active: number; revoked: number } } {
    const page = Math.max(1, filters.page || 1);
    const pageSize = Math.max(1, Math.min(100, filters.pageSize || 20));
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.q?.trim()) {
      where.push("(a.microsoft_email LIKE ? OR k.api_key_prefix LIKE ?)");
      params.push(`%${filters.q.trim().toLowerCase()}%`, `%${filters.q.trim()}%`);
    }
    if (filters.status?.trim()) {
      where.push("k.status = ?");
      params.push(filters.status.trim());
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const summaryRow = this.db
      .query(`
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN k.status = 'active' THEN 1 ELSE 0 END) AS active_count,
          SUM(CASE WHEN k.status = 'revoked' THEN 1 ELSE 0 END) AS revoked_count
        FROM api_keys k
        JOIN microsoft_accounts a ON a.id = k.account_id
        ${whereSql}
      `)
      .get(...(params as any[])) as { total?: number; active_count?: number; revoked_count?: number } | null;
    const total = Number(summaryRow?.total || 0);
    const rows = this.db
      .query(`
        SELECT k.*, a.microsoft_email
        FROM api_keys k
        JOIN microsoft_accounts a ON a.id = k.account_id
        ${whereSql}
        ORDER BY k.extracted_at DESC
        LIMIT ? OFFSET ?
      `)
      .all(...([...(params as any[]), pageSize, (page - 1) * pageSize] as any[])) as Record<string, unknown>[];
    return {
      rows: rows.map(mapApiKeyRow),
      total,
      summary: {
        active: Number(summaryRow?.active_count || 0),
        revoked: Number(summaryRow?.revoked_count || 0),
      },
    };
  }

  createJob(input: { runMode: "headed" | "headless"; need: number; parallel: number; maxAttempts: number; targets?: ProviderTarget[] }): JobRecord {
    const active = this.getCurrentJob();
    if (active && ["running", "paused", "completing"].includes(active.status)) {
      throw new Error(`active job exists: ${active.id}`);
    }
    const now = nowIso();
    const targets = normalizeProviderTargets(input.targets);
    const result = this.db
      .query(`
        INSERT INTO jobs (
          status, run_mode, targets_json, need, parallel, max_attempts, success_count, failure_count, skip_count, launched_count,
          started_at, paused_at, completed_at, last_error, updated_at
        ) VALUES ('running', ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, NULL, NULL, NULL, ?)
        RETURNING *
      `)
      .get(input.runMode, JSON.stringify(targets), input.need, input.parallel, input.maxAttempts, now, now) as Record<string, unknown>;
    return mapJobRow(result);
  }

  getCurrentJob(): JobRecord | null {
    const row = this.db
      .query("SELECT * FROM jobs ORDER BY id DESC LIMIT 1")
      .get() as Record<string, unknown> | null;
    return row ? mapJobRow(row) : null;
  }

  getJob(jobId: number): JobRecord | null {
    const row = this.db.query("SELECT * FROM jobs WHERE id = ?").get(jobId) as Record<string, unknown> | null;
    return row ? mapJobRow(row) : null;
  }

  private accountHasTargetArtifact(account: MicrosoftAccountRecord, target: ProviderTarget): boolean {
    if (target === "tavily" && account.hasApiKey) return true;
    return this.getAccountTargetState(account.id, target).hasArtifact;
  }

  private isAccountEligibleForTargets(account: MicrosoftAccountRecord, targets: ProviderTarget[]): boolean {
    if (account.disabledAt != null) return false;
    return targets.some((target) => !this.accountHasTargetArtifact(account, target));
  }

  updateJobState(jobId: number, patch: Partial<Pick<JobRecord, "status" | "parallel" | "need" | "maxAttempts" | "pausedAt" | "completedAt" | "lastError" | "successCount" | "failureCount" | "skipCount" | "launchedCount" | "targets">>): JobRecord {
    const current = this.getJob(jobId);
    if (!current) throw new Error(`job not found: ${jobId}`);
    const next: JobRecord = {
      ...current,
      ...patch,
      updatedAt: nowIso(),
    };
    this.db
      .query(`
        UPDATE jobs
        SET status = ?, parallel = ?, need = ?, max_attempts = ?, success_count = ?, failure_count = ?,
            skip_count = ?, launched_count = ?, paused_at = ?, completed_at = ?, last_error = ?, targets_json = ?, updated_at = ?
        WHERE id = ?
      `)
      .run(
        next.status,
        next.parallel,
        next.need,
        next.maxAttempts,
        next.successCount,
        next.failureCount,
        next.skipCount,
        next.launchedCount,
        next.pausedAt,
        next.completedAt,
        next.lastError,
        JSON.stringify(normalizeProviderTargets(next.targets)),
        next.updatedAt,
        jobId,
      );
    return next;
  }

  leaseNextAccount(jobId: number): MicrosoftAccountRecord | null {
    const now = nowIso();
    const job = this.getJob(jobId);
    if (!job) return null;
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const rows = this.db
        .query(`
          SELECT *
          FROM microsoft_accounts
          WHERE lease_job_id IS NULL
            AND id NOT IN (SELECT account_id FROM job_attempts WHERE job_id = ?)
          ORDER BY CASE WHEN last_used_at IS NULL THEN 0 ELSE 1 END, last_used_at ASC, imported_at ASC
        `)
        .all(jobId) as Record<string, unknown>[];
      const picked = rows.map(mapAccountRow).find((account) => this.isAccountEligibleForTargets(account, job.targets));
      if (!picked) {
        this.db.exec("COMMIT;");
        return null;
      }
      this.db
        .query(`
          UPDATE microsoft_accounts
          SET lease_job_id = ?, lease_started_at = ?, last_result_status = 'leased', updated_at = ?
          WHERE id = ?
        `)
        .run(jobId, now, now, picked.id);
      for (const target of job.targets) {
        if (this.accountHasTargetArtifact(picked, target)) {
          continue;
        }
        this.upsertAccountTargetState({
          accountId: picked.id,
          target,
          lastResultStatus: "leased",
          lastUsedAt: now,
          leaseJobId: jobId,
          leaseStartedAt: now,
        });
      }
      this.db.exec("COMMIT;");
      return this.getAccount(picked.id);
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  countEligibleAccounts(jobId: number): number {
    const job = this.getJob(jobId);
    if (!job) return 0;
    const rows = this.db
      .query(`
        SELECT *
        FROM microsoft_accounts
        WHERE lease_job_id IS NULL
          AND id NOT IN (SELECT account_id FROM job_attempts WHERE job_id = ?)
      `)
      .all(jobId) as Record<string, unknown>[];
    return rows.map(mapAccountRow).filter((account) => this.isAccountEligibleForTargets(account, job.targets)).length;
  }

  getAccount(accountId: number): MicrosoftAccountRecord | null {
    const row = this.db.query("SELECT * FROM microsoft_accounts WHERE id = ?").get(accountId) as Record<string, unknown> | null;
    return row ? mapAccountRow(row) : null;
  }

  createAttempt(jobId: number, accountId: number, outputDir: string, target?: ProviderTarget | null, sequenceIndex = 1): JobAttemptRecord {
    const now = nowIso();
    const row = this.db
      .query(`
        INSERT INTO job_attempts (
          job_id, account_id, run_id, target, sequence_index, status, stage, proxy_node, proxy_ip, error_code, error_message, output_dir,
          started_at, completed_at, duration_ms
        ) VALUES (?, ?, NULL, ?, ?, 'running', 'spawned', NULL, NULL, NULL, NULL, ?, ?, NULL, NULL)
        RETURNING *
      `)
      .get(jobId, accountId, target || null, sequenceIndex, outputDir, now) as Record<string, unknown>;
    const job = this.getJob(jobId);
    if (job) {
      this.updateJobState(jobId, { launchedCount: job.launchedCount + 1 });
    }
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = 'running', last_used_at = ?, updated_at = ?
        WHERE id = ?
      `)
      .run(now, now, accountId);
    if (target) {
      this.upsertAccountTargetState({
        accountId,
        target,
        lastResultStatus: "running",
        lastUsedAt: now,
      });
    }
    return mapAttemptRow(row);
  }

  updateAttempt(
    attemptId: number,
    patch: Partial<
      Pick<
        JobAttemptRecord,
        "runId" | "target" | "sequenceIndex" | "stage" | "proxyNode" | "proxyIp" | "errorCode" | "errorMessage" | "status" | "completedAt" | "durationMs"
      >
    >,
  ): JobAttemptRecord {
    const current = this.getAttempt(attemptId);
    if (!current) throw new Error(`attempt not found: ${attemptId}`);
    const next = { ...current, ...patch };
    this.db
      .query(`
        UPDATE job_attempts
        SET run_id = ?, target = ?, sequence_index = ?, stage = ?, proxy_node = ?, proxy_ip = ?, error_code = ?, error_message = ?, status = ?, completed_at = ?, duration_ms = ?
        WHERE id = ?
      `)
      .run(
        next.runId,
        next.target,
        next.sequenceIndex,
        next.stage,
        next.proxyNode,
        next.proxyIp,
        next.errorCode,
        next.errorMessage,
        next.status,
        next.completedAt,
        next.durationMs,
        attemptId,
      );
    return this.getAttempt(attemptId)!;
  }

  getAttempt(attemptId: number): JobAttemptRecord | null {
    const row = this.db.query("SELECT * FROM job_attempts WHERE id = ?").get(attemptId) as Record<string, unknown> | null;
    return row ? mapAttemptRow(row) : null;
  }

  listAttempts(jobId: number, onlyActive = false): JobAttemptRecord[] {
    const where = onlyActive ? "AND status = 'running'" : "";
    const rows = this.db
      .query(`SELECT * FROM job_attempts WHERE job_id = ? ${where} ORDER BY started_at DESC`)
      .all(jobId) as Record<string, unknown>[];
    return rows.map(mapAttemptRow);
  }

  insertAttemptRecord(input: {
    jobId: number;
    accountId: number;
    outputDir: string | null;
    runId?: string | null;
    target?: ProviderTarget | null;
    sequenceIndex?: number;
    status: AttemptStatus;
    stage: string;
    proxyNode?: string | null;
    proxyIp?: string | null;
    errorCode?: string | null;
    errorMessage?: string | null;
    startedAt?: string;
    completedAt?: string | null;
    durationMs?: number | null;
  }): JobAttemptRecord {
    const row = this.db
      .query(`
        INSERT INTO job_attempts (
          job_id, account_id, run_id, target, sequence_index, status, stage, proxy_node, proxy_ip,
          error_code, error_message, output_dir, started_at, completed_at, duration_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *
      `)
      .get(
        input.jobId,
        input.accountId,
        input.runId || null,
        input.target || null,
        input.sequenceIndex || 1,
        input.status,
        input.stage,
        input.proxyNode || null,
        input.proxyIp || null,
        input.errorCode || null,
        input.errorMessage || null,
        input.outputDir || null,
        input.startedAt || nowIso(),
        input.completedAt || null,
        input.durationMs || null,
      ) as Record<string, unknown>;
    return mapAttemptRow(row);
  }

  processWorkerAttemptResult(
    jobId: number,
    baseAttemptId: number,
    accountId: number,
    outcome: WorkerAttemptResultInput,
    outputDir: string | null,
  ): { job: JobRecord; attempts: JobAttemptRecord[] } {
    const currentJob = this.getJob(jobId);
    if (!currentJob) throw new Error(`job not found: ${jobId}`);
    const now = nowIso();
    const attempts: JobAttemptRecord[] = [];
    const targetResults = outcome.targetResults.slice();

    let firstFailureCode: string | null = null;
    for (let index = 0; index < targetResults.length; index += 1) {
      const result = targetResults[index]!;
      const completedAt = now;
      const status: AttemptStatus = result.status === "failed" ? "failed" : result.status === "skipped_has_artifact" ? "skipped" : "succeeded";
      const startedAt = this.getAttempt(baseAttemptId)?.startedAt || now;
      const durationMs = result.durationMs == null ? Math.max(0, Date.parse(completedAt) - Date.parse(startedAt)) : result.durationMs;
      let attempt: JobAttemptRecord;
      if (index === 0) {
        attempt = this.updateAttempt(baseAttemptId, {
          runId: result.runId || null,
          target: result.target,
          sequenceIndex: index + 1,
          status,
          stage: result.stage,
          proxyNode: result.proxyNode || null,
          proxyIp: result.proxyIp || null,
          errorCode: result.errorCode || null,
          errorMessage: result.errorMessage || null,
          completedAt,
          durationMs,
        } as Partial<JobAttemptRecord>);
      } else {
        attempt = this.insertAttemptRecord({
          jobId,
          accountId,
          outputDir,
          runId: result.runId || null,
          target: result.target,
          sequenceIndex: index + 1,
          status,
          stage: result.stage,
          proxyNode: result.proxyNode || null,
          proxyIp: result.proxyIp || null,
          errorCode: result.errorCode || null,
          errorMessage: result.errorMessage || null,
          startedAt,
          completedAt,
          durationMs,
        });
      }
      attempts.push(attempt);

      if (result.status === "failed") {
        if (!firstFailureCode) firstFailureCode = result.errorCode || "target_failed";
        this.upsertAccountTargetState({
          accountId,
          target: result.target,
          lastResultStatus: "failed",
          lastResultAt: completedAt,
          lastErrorCode: result.errorCode || "target_failed",
          lastUsedAt: completedAt,
          leaseJobId: null,
          leaseStartedAt: null,
        });
        continue;
      }

      if (result.status === "skipped_has_artifact") {
        const existingArtifact = this.getArtifact(accountId, result.target);
        this.upsertAccountTargetState({
          accountId,
          target: result.target,
          hasArtifact: true,
          artifactId: existingArtifact?.id ?? this.getAccountTargetState(accountId, result.target).artifactId,
          lastResultStatus: "skipped_has_artifact",
          lastResultAt: completedAt,
          lastErrorCode: null,
          skipReason: "has_artifact",
          lastUsedAt: completedAt,
          leaseJobId: null,
          leaseStartedAt: null,
        });
        continue;
      }

      if (result.artifact) {
        this.recordArtifact({
          accountId,
          target: result.target,
          artifactType: result.artifact.artifactType,
          secretValue: result.artifact.secretValue,
          preview: result.artifact.preview,
          metadataJson: result.artifact.metadataJson,
          status: result.artifact.status || "active",
        });
      } else {
        this.upsertAccountTargetState({
          accountId,
          target: result.target,
          hasArtifact: false,
          artifactId: null,
          lastResultStatus: "succeeded",
          lastResultAt: completedAt,
          lastErrorCode: null,
          lastUsedAt: completedAt,
          leaseJobId: null,
          leaseStartedAt: null,
        });
      }
    }

    const overallSuccess = targetResults.length > 0 && targetResults.every((result) => result.status !== "failed");
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = ?,
            last_result_at = ?,
            last_error_code = ?,
            last_used_at = ?,
            updated_at = ?,
            lease_job_id = NULL,
            lease_started_at = NULL
        WHERE id = ?
      `)
      .run(overallSuccess ? "succeeded" : "failed", now, firstFailureCode, now, now, accountId);
    const nextJob = this.updateJobState(jobId, {
      successCount: currentJob.successCount + (overallSuccess ? 1 : 0),
      failureCount: currentJob.failureCount + (overallSuccess ? 0 : 1),
      status: shouldEnterCompleting({
        need: currentJob.need,
        successCount: currentJob.successCount + (overallSuccess ? 1 : 0),
        maxAttempts: currentJob.maxAttempts,
        launchedCount: currentJob.launchedCount,
      })
        ? "completing"
        : currentJob.status,
      lastError: overallSuccess ? null : outcome.errorMessage || firstFailureCode,
    });
    return { job: nextJob, attempts };
  }

  getLatestSignupTask(jobId: number, accountId: number): Record<string, unknown> | null {
    if (!this.hasSignupTasksTable()) return null;
    const row = this.db
      .query(`
        SELECT *
        FROM signup_tasks
        WHERE job_id = ? AND account_id = ?
        ORDER BY id DESC
        LIMIT 1
      `)
      .get(jobId, accountId) as Record<string, unknown> | null;
    return row || null;
  }

  recordApiKey(accountId: number, apiKey: string): ApiKeyRecord {
    this.recordArtifact({
      accountId,
      target: "tavily",
      artifactType: "api_key",
      secretValue: apiKey,
      status: "active",
    });
    const row = this.db
      .query(
        `
          SELECT k.*, a.microsoft_email
          FROM api_keys k
          JOIN microsoft_accounts a ON a.id = k.account_id
          WHERE k.api_key = ?
          LIMIT 1
        `,
      )
      .get(apiKey) as Record<string, unknown> | null;
    if (!row) {
      throw new Error(`api key record missing after insert for account=${accountId}`);
    }
    return mapApiKeyRow(row);
  }

  completeAttemptSuccess(jobId: number, attemptId: number, accountId: number, apiKey: string, signupTask?: Record<string, unknown> | null): { job: JobRecord; attempt: JobAttemptRecord } {
    const now = nowIso();
    const currentJob = this.getJob(jobId);
    if (!currentJob) throw new Error(`job not found: ${jobId}`);
    this.recordApiKey(accountId, apiKey);
    const startedAt = this.getAttempt(attemptId)?.startedAt || now;
    const durationMs = Math.max(0, Date.parse(now) - Date.parse(startedAt));
    const attempt = this.updateAttempt(attemptId, {
      status: "succeeded",
      stage: "completed",
      completedAt: now,
      durationMs,
      runId: signupTask?.run_id ? String(signupTask.run_id) : null,
      proxyNode: signupTask?.proxy_node ? String(signupTask.proxy_node) : null,
      proxyIp: signupTask?.proxy_ip ? String(signupTask.proxy_ip) : null,
    });
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = 'succeeded',
            last_result_at = ?,
            last_error_code = NULL,
            updated_at = ?,
            lease_job_id = NULL,
            lease_started_at = NULL
        WHERE id = ?
      `)
      .run(now, now, accountId);
    const job = this.updateJobState(jobId, {
      successCount: currentJob.successCount + 1,
      status: shouldEnterCompleting({
        need: currentJob.need,
        successCount: currentJob.successCount + 1,
        maxAttempts: currentJob.maxAttempts,
        launchedCount: currentJob.launchedCount,
      })
        ? "completing"
        : currentJob.status,
    });
    return { job, attempt };
  }

  completeAttemptFailure(
    jobId: number,
    attemptId: number,
    accountId: number,
    failure: { errorCode?: string | null; errorMessage?: string | null },
    signupTask?: Record<string, unknown> | null,
  ): { job: JobRecord; attempt: JobAttemptRecord } {
    const now = nowIso();
    const currentJob = this.getJob(jobId);
    if (!currentJob) throw new Error(`job not found: ${jobId}`);
    const startedAt = this.getAttempt(attemptId)?.startedAt || now;
    const durationMs = Math.max(0, Date.parse(now) - Date.parse(startedAt));
    const errorCode = failure.errorCode || (signupTask?.error_code ? String(signupTask.error_code) : null);
    const errorMessage = failure.errorMessage || (signupTask?.error_message ? String(signupTask.error_message) : null);
    const attempt = this.updateAttempt(attemptId, {
      status: "failed",
      stage: "failed",
      completedAt: now,
      durationMs,
      errorCode,
      errorMessage,
      runId: signupTask?.run_id ? String(signupTask.run_id) : null,
      proxyNode: signupTask?.proxy_node ? String(signupTask.proxy_node) : null,
      proxyIp: signupTask?.proxy_ip ? String(signupTask.proxy_ip) : null,
    });
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = 'failed',
            last_result_at = ?,
            last_error_code = ?,
            updated_at = ?,
            lease_job_id = NULL,
            lease_started_at = NULL
        WHERE id = ?
      `)
      .run(now, errorCode, now, accountId);
    const job = this.updateJobState(jobId, {
      failureCount: currentJob.failureCount + 1,
      status: shouldEnterCompleting(currentJob) ? "completing" : currentJob.status,
    });
    return { job, attempt };
  }

  completeJob(jobId: number, success: boolean, errorMessage?: string): JobRecord {
    return this.updateJobState(jobId, {
      status: success ? "completed" : "failed",
      completedAt: nowIso(),
      lastError: errorMessage || null,
    });
  }

  listProxyNodes(): ProxyNodeRecord[] {
    const rows = this.hasSignupTasksTable()
      ? (this.db
          .query(`
            SELECT
              p.*,
              COALESCE((
                SELECT COUNT(*)
                FROM signup_tasks s
                WHERE s.proxy_node = p.node_name
                  AND s.status = 'succeeded'
                  AND COALESCE(s.completed_at, s.started_at) >= ?
              ), 0) AS success24h
            FROM proxy_nodes p
            ORDER BY p.is_selected DESC, p.node_name ASC
          `)
          .all(new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()) as Record<string, unknown>[])
      : (this.db
          .query(`
            SELECT
              p.*,
              0 AS success24h
            FROM proxy_nodes p
            ORDER BY p.is_selected DESC, p.node_name ASC
          `)
          .all() as Record<string, unknown>[]);
    return rows.map((row) => ({
      id: Number(row.id),
      nodeName: String(row.node_name),
      isSelected: asBoolean(row.is_selected),
      lastStatus: row.last_status == null ? null : String(row.last_status),
      lastLatencyMs: row.last_latency_ms == null ? null : Number(row.last_latency_ms),
      lastEgressIp: row.last_egress_ip == null ? null : String(row.last_egress_ip),
      lastCountry: row.last_country == null ? null : String(row.last_country),
      lastCity: row.last_city == null ? null : String(row.last_city),
      lastOrg: row.last_org == null ? null : String(row.last_org),
      lastCheckedAt: row.last_checked_at == null ? null : String(row.last_checked_at),
      lastSelectedAt: row.last_selected_at == null ? null : String(row.last_selected_at),
      success24h: Number(row.success24h || 0),
    }));
  }

  upsertProxyInventory(nodes: string[], selectedName?: string | null): void {
    const now = nowIso();
    const normalizedNodes = [...new Set(nodes.map((name) => name.trim()).filter(Boolean))];
    const normalizedSelectedName =
      typeof selectedName === "string" && normalizedNodes.includes(selectedName.trim()) ? selectedName.trim() : null;
    const stmt = this.db.query(`
      INSERT INTO proxy_nodes (node_name, is_selected, last_selected_at)
      VALUES (?, ?, ?)
      ON CONFLICT(node_name) DO UPDATE SET
        is_selected = excluded.is_selected,
        last_selected_at = CASE WHEN excluded.is_selected = 1 THEN excluded.last_selected_at ELSE proxy_nodes.last_selected_at END
    `);
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      if (normalizedNodes.length > 0) {
        const placeholders = normalizedNodes.map(() => "?").join(", ");
        this.db.query(`DELETE FROM proxy_nodes WHERE node_name NOT IN (${placeholders})`).run(...normalizedNodes);
      } else {
        this.db.query("DELETE FROM proxy_nodes").run();
      }
      this.db.query("UPDATE proxy_nodes SET is_selected = 0").run();
      for (const name of normalizedNodes) {
        stmt.run(name, name === normalizedSelectedName ? 1 : 0, name === normalizedSelectedName ? now : null);
      }
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  setSelectedProxy(nodeName: string): void {
    const now = nowIso();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db.query("UPDATE proxy_nodes SET is_selected = 0").run();
      this.db.query("UPDATE proxy_nodes SET is_selected = 1, last_selected_at = ? WHERE node_name = ?").run(now, nodeName);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  recordProxyCheck(input: {
    nodeName: string;
    status: string;
    latencyMs?: number | null;
    egressIp?: string | null;
    country?: string | null;
    city?: string | null;
    org?: string | null;
    error?: string | null;
  }): void {
    const now = nowIso();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .query(`
          INSERT INTO proxy_checks (node_name, status, latency_ms, egress_ip, country, city, org, error, checked_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(input.nodeName, input.status, input.latencyMs ?? null, input.egressIp ?? null, input.country ?? null, input.city ?? null, input.org ?? null, input.error ?? null, now);
      this.db
        .query(`
          INSERT INTO proxy_nodes (
            node_name, is_selected, last_status, last_latency_ms, last_egress_ip, last_country, last_city, last_org, last_checked_at, last_selected_at
          ) VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, NULL)
          ON CONFLICT(node_name) DO UPDATE SET
            last_status = excluded.last_status,
            last_latency_ms = excluded.last_latency_ms,
            last_egress_ip = excluded.last_egress_ip,
            last_country = excluded.last_country,
            last_city = excluded.last_city,
            last_org = excluded.last_org,
            last_checked_at = excluded.last_checked_at
        `)
        .run(input.nodeName, input.status, input.latencyMs ?? null, input.egressIp ?? null, input.country ?? null, input.city ?? null, input.org ?? null, now);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  getSelectedProxyName(): string | null {
    const row = this.db
      .query("SELECT node_name FROM proxy_nodes WHERE is_selected = 1 ORDER BY last_selected_at DESC LIMIT 1")
      .get() as { node_name?: string } | null;
    return row?.node_name || null;
  }
}
