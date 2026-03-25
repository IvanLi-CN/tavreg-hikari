import { access, mkdir, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

type SqliteBindValue = string | number | boolean | null | undefined;
type SqliteNamedParams = Record<string, SqliteBindValue>;
type SqliteStmtParams = [] | [SqliteNamedParams] | SqliteBindValue[];

interface SqliteStatement {
  run: (...args: SqliteStmtParams) => unknown;
  get: (...args: SqliteStmtParams) => unknown;
  all: (...args: SqliteStmtParams) => unknown[];
}

interface SqliteDatabase {
  exec: (sql: string) => void;
  query: (sql: string) => SqliteStatement;
  close: () => void;
}

function openSqliteDatabase(dbPath: string): SqliteDatabase {
  if (typeof Bun !== "undefined") {
    const { Database } = require("bun:sqlite") as typeof import("bun:sqlite");
    const db = new Database(dbPath, { create: true, strict: true });
    return {
      exec: (sql: string) => db.exec(sql),
      query: (sql: string) => {
        const stmt = db.query(sql) as any;
        return {
          run: (...args: any[]) => stmt.run(...args),
          get: (...args: any[]) => stmt.get(...args),
          all: (...args: any[]) => stmt.all(...args),
        };
      },
      close: () => db.close(false),
    };
  }

  const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");
  const db = new DatabaseSync(dbPath);
  return {
    exec: (sql: string) => db.exec(sql),
    query: (sql: string) => {
      const stmt = db.prepare(sql) as any;
      return {
        run: (...args: any[]) => stmt.run(...args),
        get: (...args: any[]) => stmt.get(...args),
        all: (...args: any[]) => stmt.all(...args),
      };
    },
    close: () => db.close(),
  };
}

export type AccountStatus =
  | "ready"
  | "leased"
  | "running"
  | "succeeded"
  | "failed"
  | "skipped_has_key"
  | "disabled";
export type JobStatus = "idle" | "running" | "paused" | "completing" | "completed" | "failed";
export type AttemptStatus = "running" | "succeeded" | "failed";
export type ApiKeyStatus = "active" | "revoked" | "unknown";
export type ProofMailboxProvider = "moemail";

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
  proofMailboxProvider: ProofMailboxProvider | null;
  proofMailboxAddress: string | null;
  proofMailboxId: string | null;
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
  disabledReason: string | null;
  leaseJobId: number | null;
  leaseStartedAt: string | null;
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
  groupName: string | null;
  apiKey: string;
  apiKeyPrefix: string;
  status: ApiKeyStatus;
  extractedAt: string;
  extractedIp: string | null;
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

const PINNED_PROXY_NODE_SETTING_KEY = "pinnedProxyNodeName";

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
    proofMailboxProvider: row.proof_mailbox_provider == null ? null : (String(row.proof_mailbox_provider) as ProofMailboxProvider),
    proofMailboxAddress: row.proof_mailbox_address == null ? null : String(row.proof_mailbox_address),
    proofMailboxId: row.proof_mailbox_id == null ? null : String(row.proof_mailbox_id),
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
    disabledReason: row.disabled_reason == null ? null : String(row.disabled_reason),
    leaseJobId: row.lease_job_id == null ? null : Number(row.lease_job_id),
    leaseStartedAt: row.lease_started_at == null ? null : String(row.lease_started_at),
  };
}

function mapApiKeyRow(row: Record<string, unknown>): ApiKeyRecord {
  return {
    id: Number(row.id),
    accountId: Number(row.account_id),
    microsoftEmail: String(row.microsoft_email),
    groupName: row.group_name == null ? null : String(row.group_name),
    apiKey: String(row.api_key),
    apiKeyPrefix: String(row.api_key_prefix),
    status: String(row.status || "unknown") as ApiKeyStatus,
    extractedAt: String(row.extracted_at),
    extractedIp: row.extracted_ip == null ? null : String(row.extracted_ip),
    lastVerifiedAt: row.last_verified_at == null ? null : String(row.last_verified_at),
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
  private readonly db: SqliteDatabase;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.db = openSqliteDatabase(dbPath);
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
    this.db.close();
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
        proof_mailbox_provider TEXT,
        proof_mailbox_address TEXT,
        proof_mailbox_id TEXT,
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
        disabled_reason TEXT,
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
        extracted_ip TEXT,
        last_verified_at TEXT
      );

      CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        status TEXT NOT NULL,
        run_mode TEXT NOT NULL,
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
    if (!accountColumns.has("proof_mailbox_provider")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN proof_mailbox_provider TEXT;");
    }
    if (!accountColumns.has("proof_mailbox_address")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN proof_mailbox_address TEXT;");
    }
    if (!accountColumns.has("proof_mailbox_id")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN proof_mailbox_id TEXT;");
    }
    if (!accountColumns.has("disabled_reason")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN disabled_reason TEXT;");
    }
    const apiKeyTableInfo = this.db.query("PRAGMA table_info(api_keys);").all() as Array<Record<string, unknown>>;
    const apiKeyColumns = new Set(apiKeyTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!apiKeyColumns.has("extracted_ip")) {
      this.db.exec("ALTER TABLE api_keys ADD COLUMN extracted_ip TEXT;");
    }

    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_result ON microsoft_accounts(last_result_status, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_skip_reason ON microsoft_accounts(skip_reason, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_group_name ON microsoft_accounts(group_name, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_proof_mailbox ON microsoft_accounts(proof_mailbox_address, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(account_id);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_jobs_status_started ON jobs(status, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_job_attempts_job_status ON job_attempts(job_id, status, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_proxy_checks_node_checked ON proxy_checks(node_name, checked_at DESC);");
    if (signupTaskTableExists) {
      this.db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_job_account ON signup_tasks(job_id, account_id, started_at DESC);");
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
      where.push("(microsoft_email LIKE ? OR password_plaintext LIKE ? OR LOWER(COALESCE(group_name, '')) LIKE ? OR LOWER(COALESCE(proof_mailbox_address, '')) LIKE ?)");
      params.push(`%${normalizedQuery}%`, `%${rawQuery}%`, `%${normalizedQuery}%`, `%${normalizedQuery}%`);
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

  updateAccountProofMailbox(
    accountId: number,
    input: {
      provider?: ProofMailboxProvider | null;
      address?: string | null;
      mailboxId?: string | null;
    },
  ): MicrosoftAccountRecord {
    const current = this.getAccount(accountId);
    if (!current) {
      throw new Error(`account not found: ${accountId}`);
    }

    const addressChanged = input.address !== undefined;
    const normalizedAddress = input.address === undefined ? current.proofMailboxAddress : input.address?.trim() || null;
    let normalizedProvider = input.provider === undefined ? current.proofMailboxProvider : input.provider;
    let normalizedMailboxId = input.mailboxId === undefined ? current.proofMailboxId : input.mailboxId?.trim() || null;

    if (!normalizedAddress) {
      normalizedProvider = null;
      normalizedMailboxId = null;
    } else {
      if (!normalizedProvider) {
        normalizedProvider = "moemail";
      }
      if (normalizedProvider !== "moemail") {
        throw new Error("only moemail proof mailbox provider is supported");
      }
      if (addressChanged && normalizedAddress !== current.proofMailboxAddress && input.mailboxId === undefined) {
        normalizedMailboxId = null;
      }
    }

    this.db
      .query(`
        UPDATE microsoft_accounts
        SET proof_mailbox_provider = ?,
            proof_mailbox_address = ?,
            proof_mailbox_id = ?,
            updated_at = ?
        WHERE id = ?
      `)
      .run(normalizedProvider, normalizedAddress, normalizedMailboxId, nowIso(), accountId);

    return this.getAccount(accountId)!;
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

  updateAccountAvailability(
    accountId: number,
    input: {
      disabled?: boolean;
      reason?: string | null;
    },
  ): MicrosoftAccountRecord {
    const current = this.getAccount(accountId);
    if (!current) {
      throw new Error(`account not found: ${accountId}`);
    }

    const now = nowIso();
    const disabled = input.disabled === undefined ? current.disabledAt != null : Boolean(input.disabled);
    const normalizedReason = disabled ? input.reason?.trim() || current.disabledReason || null : null;
    const disabledAt = disabled ? current.disabledAt || now : null;
    const nextStatus: AccountStatus = disabled
      ? "disabled"
      : current.hasApiKey
        ? "skipped_has_key"
        : current.leaseJobId != null
          ? "leased"
          : "ready";

    this.db
      .query(`
        UPDATE microsoft_accounts
        SET disabled_at = ?,
            disabled_reason = ?,
            last_result_status = ?,
            last_result_at = ?,
            updated_at = ?
        WHERE id = ?
      `)
      .run(disabledAt, normalizedReason, nextStatus, now, now, accountId);

    return this.getAccount(accountId)!;
  }

  markAccountUnavailable(
    accountId: number,
    reason: string,
    errorCode?: string | null,
    options?: { releaseLease?: boolean },
  ): void {
    const now = nowIso();
    const releaseLease = options?.releaseLease !== false;
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET disabled_at = COALESCE(disabled_at, ?),
            disabled_reason = ?,
            last_result_status = 'disabled',
            last_result_at = ?,
            last_error_code = COALESCE(?, last_error_code),
            updated_at = ?${
              releaseLease
                ? `,
            lease_job_id = NULL,
            lease_started_at = NULL`
                : ""
            }
        WHERE id = ?
      `)
      .run(now, reason.trim(), now, errorCode ?? null, now, accountId);
  }

  deleteAccounts(ids: number[]): { deleted: number; blockedIds: number[] } {
    const uniqueIds = Array.from(new Set(ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)));
    if (uniqueIds.length === 0) {
      return { deleted: 0, blockedIds: [] };
    }

    const placeholders = uniqueIds.map(() => "?").join(", ");
    const blockedRows = this.db
      .query(`SELECT id FROM microsoft_accounts WHERE id IN (${placeholders}) AND (lease_job_id IS NOT NULL OR has_api_key = 1)`)
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

  listApiKeys(filters: { q?: string; status?: string; groupName?: string; page?: number; pageSize?: number }): { rows: ApiKeyRecord[]; total: number; summary: { active: number; revoked: number } } {
    const page = Math.max(1, filters.page || 1);
    const pageSize = Math.max(1, Math.min(100, filters.pageSize || 20));
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.q?.trim()) {
      const pattern = `%${filters.q.trim().toLowerCase()}%`;
      where.push("(LOWER(a.microsoft_email) LIKE ? OR LOWER(k.api_key_prefix) LIKE ? OR LOWER(COALESCE(a.group_name, '')) LIKE ?)");
      params.push(pattern, pattern, pattern);
    }
    if (filters.status?.trim()) {
      where.push("k.status = ?");
      params.push(filters.status.trim());
    }
    if (filters.groupName?.trim()) {
      where.push("a.group_name = ?");
      params.push(filters.groupName.trim());
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
        SELECT k.*, a.microsoft_email, a.group_name
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

  listApiKeysForExport(ids: number[]): ApiKeyRecord[] {
    const uniqueIds = Array.from(new Set(ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)));
    if (uniqueIds.length === 0) return [];
    const rows: Record<string, unknown>[] = [];
    const chunkSize = 500;
    for (let index = 0; index < uniqueIds.length; index += chunkSize) {
      const chunk = uniqueIds.slice(index, index + chunkSize);
      const placeholders = chunk.map(() => "?").join(", ");
      const chunkRows = this.db
        .query(`
          SELECT k.*, a.microsoft_email, a.group_name
          FROM api_keys k
          JOIN microsoft_accounts a ON a.id = k.account_id
          WHERE k.id IN (${placeholders})
        `)
        .all(...chunk) as Record<string, unknown>[];
      rows.push(...chunkRows);
    }
    const byId = new Map(rows.map((row) => [Number(row.id), mapApiKeyRow(row)]));
    return uniqueIds.map((id) => byId.get(id)).filter((row): row is ApiKeyRecord => Boolean(row));
  }

  createJob(input: { runMode: "headed" | "headless"; need: number; parallel: number; maxAttempts: number }): JobRecord {
    const active = this.getCurrentJob();
    if (active && ["running", "paused", "completing"].includes(active.status)) {
      throw new Error(`active job exists: ${active.id}`);
    }
    const now = nowIso();
    const result = this.db
      .query(`
        INSERT INTO jobs (
          status, run_mode, need, parallel, max_attempts, success_count, failure_count, skip_count, launched_count,
          started_at, paused_at, completed_at, last_error, updated_at
        ) VALUES ('running', ?, ?, ?, ?, 0, 0, 0, 0, ?, NULL, NULL, NULL, ?)
        RETURNING *
      `)
      .get(input.runMode, input.need, input.parallel, input.maxAttempts, now, now) as Record<string, unknown>;
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

  updateJobState(jobId: number, patch: Partial<Pick<JobRecord, "status" | "parallel" | "need" | "maxAttempts" | "pausedAt" | "completedAt" | "lastError" | "successCount" | "failureCount" | "skipCount" | "launchedCount">>): JobRecord {
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
            skip_count = ?, launched_count = ?, paused_at = ?, completed_at = ?, last_error = ?, updated_at = ?
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
        next.updatedAt,
        jobId,
      );
    return next;
  }

  leaseNextAccount(jobId: number): MicrosoftAccountRecord | null {
    const now = nowIso();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const row = this.db
        .query(`
          SELECT *
          FROM microsoft_accounts
          WHERE disabled_at IS NULL
            AND has_api_key = 0
            AND COALESCE(skip_reason, '') <> 'has_api_key'
            AND lease_job_id IS NULL
            AND id NOT IN (SELECT account_id FROM job_attempts WHERE job_id = ?)
          ORDER BY
            CASE WHEN last_used_at IS NULL THEN 0 ELSE 1 END,
            last_used_at ASC,
            imported_at ASC
          LIMIT 1
        `)
        .get(jobId) as Record<string, unknown> | null;
      if (!row) {
        this.db.exec("COMMIT;");
        return null;
      }
      const id = Number(row.id);
      this.db
        .query(`
          UPDATE microsoft_accounts
          SET lease_job_id = ?, lease_started_at = ?, last_result_status = 'leased', updated_at = ?
          WHERE id = ?
        `)
        .run(jobId, now, now, id);
      this.db.exec("COMMIT;");
      return this.getAccount(id);
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }

  countEligibleAccounts(jobId: number): number {
    const row = this.db
      .query(`
        SELECT COUNT(*) AS count
        FROM microsoft_accounts
        WHERE disabled_at IS NULL
          AND has_api_key = 0
          AND COALESCE(skip_reason, '') <> 'has_api_key'
          AND lease_job_id IS NULL
          AND id NOT IN (SELECT account_id FROM job_attempts WHERE job_id = ?)
      `)
      .get(jobId) as { count?: number } | null;
    return Number(row?.count || 0);
  }

  getAccount(accountId: number): MicrosoftAccountRecord | null {
    const row = this.db.query("SELECT * FROM microsoft_accounts WHERE id = ?").get(accountId) as Record<string, unknown> | null;
    return row ? mapAccountRow(row) : null;
  }

  createAttempt(jobId: number, accountId: number, outputDir: string): JobAttemptRecord {
    const now = nowIso();
    const row = this.db
      .query(`
        INSERT INTO job_attempts (
          job_id, account_id, run_id, status, stage, proxy_node, proxy_ip, error_code, error_message, output_dir,
          started_at, completed_at, duration_ms
        ) VALUES (?, ?, NULL, 'running', 'spawned', NULL, NULL, NULL, NULL, ?, ?, NULL, NULL)
        RETURNING *
      `)
      .get(jobId, accountId, outputDir, now) as Record<string, unknown>;
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
    return mapAttemptRow(row);
  }

  updateAttempt(attemptId: number, patch: Partial<Pick<JobAttemptRecord, "runId" | "stage" | "proxyNode" | "proxyIp" | "errorCode" | "errorMessage" | "status" | "completedAt" | "durationMs">>): JobAttemptRecord {
    const current = this.getAttempt(attemptId);
    if (!current) throw new Error(`attempt not found: ${attemptId}`);
    const next = { ...current, ...patch };
    this.db
      .query(`
        UPDATE job_attempts
        SET run_id = ?, stage = ?, proxy_node = ?, proxy_ip = ?, error_code = ?, error_message = ?, status = ?, completed_at = ?, duration_ms = ?
        WHERE id = ?
      `)
      .run(
        next.runId,
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

  recordApiKey(accountId: number, apiKey: string, extractedIp?: string | null): ApiKeyRecord {
    const now = nowIso();
    const prefix = apiKey.slice(0, Math.min(apiKey.length, 12));
    const normalizedExtractedIp = extractedIp == null ? null : String(extractedIp).trim() || null;
    const previous = this.db.query("SELECT account_id FROM api_keys WHERE api_key = ? LIMIT 1").get(apiKey) as { account_id?: number | null } | null;
    this.db.exec("BEGIN IMMEDIATE;");
    let row: Record<string, unknown>;
    try {
      row = this.db
        .query(`
          INSERT INTO api_keys (account_id, api_key, api_key_prefix, status, extracted_at, extracted_ip, last_verified_at)
          VALUES (?, ?, ?, 'active', ?, ?, ?)
          ON CONFLICT(api_key) DO UPDATE SET
            account_id = excluded.account_id,
            api_key_prefix = excluded.api_key_prefix,
            status = excluded.status,
            extracted_at = CASE
              WHEN api_keys.account_id IS excluded.account_id THEN api_keys.extracted_at
              ELSE excluded.extracted_at
            END,
            extracted_ip = CASE
              WHEN api_keys.account_id IS excluded.account_id AND api_keys.extracted_ip IS NOT NULL THEN api_keys.extracted_ip
              ELSE excluded.extracted_ip
            END,
            last_verified_at = excluded.last_verified_at
          RETURNING *
        `)
        .get(accountId, apiKey, prefix, now, normalizedExtractedIp, now) as Record<string, unknown>;
      const keyId = Number(row.id);
      const previousAccountId = previous?.account_id == null ? null : Number(previous.account_id);
      if (previousAccountId && previousAccountId !== accountId) {
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
        .run(keyId, now, now, accountId);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
    const account = this.getAccount(accountId);
    return mapApiKeyRow({
      ...row,
      microsoft_email: account?.microsoftEmail || "",
      group_name: account?.groupName ?? null,
    });
  }

  completeAttemptSuccess(jobId: number, attemptId: number, accountId: number, apiKey: string, signupTask?: Record<string, unknown> | null): { job: JobRecord; attempt: JobAttemptRecord } {
    const now = nowIso();
    const currentJob = this.getJob(jobId);
    if (!currentJob) throw new Error(`job not found: ${jobId}`);
    const currentAttempt = this.getAttempt(attemptId);
    const extractedIp = signupTask?.proxy_ip ? String(signupTask.proxy_ip) : currentAttempt?.proxyIp || null;
    this.recordApiKey(accountId, apiKey, extractedIp);
    const startedAt = currentAttempt?.startedAt || now;
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

  markAccountDirectSuccess(accountId: number): void {
    const now = nowIso();
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
  }

  markAccountDirectFailure(accountId: number, errorCode?: string | null, options?: { releaseLease?: boolean }): void {
    const now = nowIso();
    const releaseLease = options?.releaseLease !== false;
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = CASE WHEN disabled_at IS NOT NULL THEN 'disabled' ELSE 'failed' END,
            last_result_at = ?,
            last_error_code = ?,
            updated_at = ?${
              releaseLease
                ? `,
            lease_job_id = NULL,
            lease_started_at = NULL`
                : ""
            }
        WHERE id = ?
      `)
      .run(now, errorCode ?? null, now, accountId);
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
        SET last_result_status = CASE WHEN disabled_at IS NOT NULL THEN 'disabled' ELSE 'failed' END,
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
    const pinnedProxyName = this.getPinnedProxyName();
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
      if (pinnedProxyName && !normalizedNodes.includes(pinnedProxyName)) {
        this.db.query("DELETE FROM app_settings WHERE key = ?").run(PINNED_PROXY_NODE_SETTING_KEY);
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

  clearSelectedProxy(): void {
    this.db.exec("UPDATE proxy_nodes SET is_selected = 0");
  }

  getPinnedProxyName(): string | null {
    const row = this.db.query("SELECT value_json FROM app_settings WHERE key = ?").get(PINNED_PROXY_NODE_SETTING_KEY) as
      | { value_json?: string }
      | null;
    const value = parseJson<string | null>(row?.value_json ?? "null", null);
    return typeof value === "string" && value.trim() ? value.trim() : null;
  }

  setPinnedProxyName(nodeName: string | null): void {
    const normalized = typeof nodeName === "string" ? nodeName.trim() : "";
    if (!normalized) {
      this.db.query("DELETE FROM app_settings WHERE key = ?").run(PINNED_PROXY_NODE_SETTING_KEY);
      return;
    }
    const now = nowIso();
    this.db
      .query(`
        INSERT INTO app_settings (key, value_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
          value_json = excluded.value_json,
          updated_at = excluded.updated_at
      `)
      .run(PINNED_PROXY_NODE_SETTING_KEY, JSON.stringify(normalized), now);
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

  hasProxyNode(nodeName: string): boolean {
    const normalized = nodeName.trim();
    if (!normalized) return false;
    const row = this.db.query("SELECT 1 AS present FROM proxy_nodes WHERE node_name = ? LIMIT 1").get(normalized) as { present?: number } | null;
    return row?.present === 1;
  }
}
