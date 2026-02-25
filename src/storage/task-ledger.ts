import { Database } from "bun:sqlite";
import { mkdir } from "node:fs/promises";
import path from "node:path";

export interface TaskLedgerConfig {
  enabled: boolean;
  dbPath: string;
  busyTimeoutMs: number;
  ipRateLimitCooldownMs: number;
  ipRateLimitMax: number;
  suspiciousCooldownMs: number;
  suspiciousMax: number;
  allowRateLimitedIpFallback: boolean;
}

export interface SignupTaskRecord {
  runId: string;
  batchId: string;
  mode: "headed" | "headless";
  attemptIndex: number;
  modeRetryMax: number;
  status: "running" | "succeeded" | "failed";
  startedAt: string;
  completedAt?: string;
  durationMs?: number;
  failureStage?: string;
  errorCode?: string;
  errorMessage?: string;
  proxyNode?: string;
  proxyIp?: string;
  proxyCountry?: string;
  proxyCity?: string;
  proxyTimezone?: string;
  browserEngine?: string;
  browserMode?: string;
  browserUserAgent?: string;
  browserLocale?: string;
  browserTimezone?: string;
  modelName?: string;
  precheckPassed?: boolean;
  verifyPassed?: boolean;
  signupSubmitted?: boolean;
  requestCount?: number;
  suspiciousHitCount?: number;
  captchaSubmitCount?: number;
  maxCaptchaLength?: number;
  hasIpRateLimit?: boolean;
  hasSuspiciousActivity?: boolean;
  hasExtensibilityError?: boolean;
  hasInvalidCaptcha?: boolean;
  emailAddress?: string;
  emailDomain?: string;
  emailLocalLen?: number;
  apiKeyPrefix?: string;
  notesJson?: string;
  detailsJson?: string;
}

interface SignupTaskRecordRow {
  runId: string;
  batchId: string;
  mode: string;
  attemptIndex: number;
  modeRetryMax: number;
  status: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  failureStage: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  proxyNode: string | null;
  proxyIp: string | null;
  proxyCountry: string | null;
  proxyCity: string | null;
  proxyTimezone: string | null;
  browserEngine: string | null;
  browserMode: string | null;
  browserUserAgent: string | null;
  browserLocale: string | null;
  browserTimezone: string | null;
  modelName: string | null;
  precheckPassed: number | null;
  verifyPassed: number | null;
  signupSubmitted: number | null;
  requestCount: number;
  suspiciousHitCount: number;
  captchaSubmitCount: number;
  maxCaptchaLength: number | null;
  hasIpRateLimit: number;
  hasSuspiciousActivity: number;
  hasExtensibilityError: number;
  hasInvalidCaptcha: number;
  emailAddress: string | null;
  emailDomain: string | null;
  emailLocalLen: number | null;
  apiKeyPrefix: string | null;
  notesJson: string | null;
  detailsJson: string | null;
  updatedAt: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function boolToDb(value: boolean | undefined): number | null {
  if (value == null) return null;
  return value ? 1 : 0;
}

function toNullableString(value: string | undefined): string | null {
  const trimmed = (value || "").trim();
  return trimmed.length > 0 ? trimmed : null;
}

function toNullableNumber(value: number | undefined): number | null {
  if (value == null) return null;
  return Number.isFinite(value) ? value : null;
}

function toRecordRow(input: SignupTaskRecord): SignupTaskRecordRow {
  return {
    runId: input.runId,
    batchId: input.batchId,
    mode: input.mode,
    attemptIndex: input.attemptIndex,
    modeRetryMax: input.modeRetryMax,
    status: input.status,
    startedAt: input.startedAt,
    completedAt: toNullableString(input.completedAt),
    durationMs: toNullableNumber(input.durationMs),
    failureStage: toNullableString(input.failureStage),
    errorCode: toNullableString(input.errorCode),
    errorMessage: toNullableString(input.errorMessage),
    proxyNode: toNullableString(input.proxyNode),
    proxyIp: toNullableString(input.proxyIp),
    proxyCountry: toNullableString(input.proxyCountry),
    proxyCity: toNullableString(input.proxyCity),
    proxyTimezone: toNullableString(input.proxyTimezone),
    browserEngine: toNullableString(input.browserEngine),
    browserMode: toNullableString(input.browserMode),
    browserUserAgent: toNullableString(input.browserUserAgent),
    browserLocale: toNullableString(input.browserLocale),
    browserTimezone: toNullableString(input.browserTimezone),
    modelName: toNullableString(input.modelName),
    precheckPassed: boolToDb(input.precheckPassed),
    verifyPassed: boolToDb(input.verifyPassed),
    signupSubmitted: boolToDb(input.signupSubmitted),
    requestCount: Number.isFinite(input.requestCount || 0) ? Math.max(0, input.requestCount || 0) : 0,
    suspiciousHitCount: Number.isFinite(input.suspiciousHitCount || 0) ? Math.max(0, input.suspiciousHitCount || 0) : 0,
    captchaSubmitCount: Number.isFinite(input.captchaSubmitCount || 0) ? Math.max(0, input.captchaSubmitCount || 0) : 0,
    maxCaptchaLength: toNullableNumber(input.maxCaptchaLength),
    hasIpRateLimit: input.hasIpRateLimit ? 1 : 0,
    hasSuspiciousActivity: input.hasSuspiciousActivity ? 1 : 0,
    hasExtensibilityError: input.hasExtensibilityError ? 1 : 0,
    hasInvalidCaptcha: input.hasInvalidCaptcha ? 1 : 0,
    emailAddress: toNullableString(input.emailAddress),
    emailDomain: toNullableString(input.emailDomain),
    emailLocalLen: toNullableNumber(input.emailLocalLen),
    apiKeyPrefix: toNullableString(input.apiKeyPrefix),
    notesJson: toNullableString(input.notesJson),
    detailsJson: toNullableString(input.detailsJson),
    updatedAt: nowIso(),
  };
}

export class TaskLedger {
  private readonly db: Database;

  private readonly cfg: TaskLedgerConfig;

  constructor(db: Database, cfg: TaskLedgerConfig) {
    this.db = db;
    this.cfg = cfg;
  }

  static async open(cfg: TaskLedgerConfig): Promise<TaskLedger | null> {
    if (!cfg.enabled) return null;
    await mkdir(path.dirname(cfg.dbPath), { recursive: true });

    const db = new Database(cfg.dbPath, { create: true, strict: true });
    db.exec("PRAGMA journal_mode=WAL;");
    db.exec("PRAGMA synchronous=NORMAL;");
    db.exec("PRAGMA temp_store=MEMORY;");
    db.exec(`PRAGMA busy_timeout=${Math.max(500, cfg.busyTimeoutMs)};`);
    db.exec("PRAGMA foreign_keys=ON;");
    db.exec("PRAGMA wal_autocheckpoint=1000;");

    db.exec(`
      CREATE TABLE IF NOT EXISTS signup_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL UNIQUE,
        batch_id TEXT NOT NULL,
        mode TEXT NOT NULL,
        attempt_index INTEGER NOT NULL,
        mode_retry_max INTEGER NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        duration_ms INTEGER,
        failure_stage TEXT,
        error_code TEXT,
        error_message TEXT,
        proxy_node TEXT,
        proxy_ip TEXT,
        proxy_country TEXT,
        proxy_city TEXT,
        proxy_timezone TEXT,
        browser_engine TEXT,
        browser_mode TEXT,
        browser_user_agent TEXT,
        browser_locale TEXT,
        browser_timezone TEXT,
        model_name TEXT,
        precheck_passed INTEGER,
        verify_passed INTEGER,
        signup_submitted INTEGER,
        request_count INTEGER NOT NULL DEFAULT 0,
        suspicious_hit_count INTEGER NOT NULL DEFAULT 0,
        captcha_submit_count INTEGER NOT NULL DEFAULT 0,
        max_captcha_length INTEGER,
        has_ip_rate_limit INTEGER NOT NULL DEFAULT 0,
        has_suspicious_activity INTEGER NOT NULL DEFAULT 0,
        has_extensibility_error INTEGER NOT NULL DEFAULT 0,
        has_invalid_captcha INTEGER NOT NULL DEFAULT 0,
        email_address TEXT,
        email_domain TEXT,
        email_local_len INTEGER,
        api_key_prefix TEXT,
        notes_json TEXT,
        details_json TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );
    `);

    db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_started_at ON signup_tasks(started_at DESC);");
    db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_status_started ON signup_tasks(status, started_at DESC);");
    db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_proxy_ip_started ON signup_tasks(proxy_ip, started_at DESC);");
    db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_error_code_started ON signup_tasks(error_code, started_at DESC);");
    db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_ip_risk_started ON signup_tasks(has_ip_rate_limit, started_at DESC);");
    db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_batch_id ON signup_tasks(batch_id);");

    return new TaskLedger(db, cfg);
  }

  close(): void {
    this.db.close(false);
  }

  dbPath(): string {
    return this.cfg.dbPath;
  }

  markStaleRunningAsFailed(staleMs = 10 * 60_000): number {
    const cutoffIso = new Date(Date.now() - Math.max(60_000, staleMs)).toISOString();
    const rows = this.db
      .prepare(
        `
        SELECT run_id AS runId, started_at AS startedAt
        FROM signup_tasks
        WHERE status = 'running'
          AND started_at <= ?
      `,
      )
      .all(cutoffIso) as Array<{ runId?: string; startedAt?: string }>;
    if (!rows.length) return 0;

    const now = new Date();
    const nowIsoText = now.toISOString();
    const stmt = this.db.prepare(
      `
      UPDATE signup_tasks
      SET status = 'failed',
          completed_at = ?,
          duration_ms = ?,
          failure_stage = COALESCE(failure_stage, 'process_exit'),
          error_code = COALESCE(error_code, 'runner_interrupted'),
          error_message = COALESCE(error_message, 'run interrupted before completion'),
          updated_at = ?
      WHERE run_id = ?
        AND status = 'running'
    `,
    );

    let updated = 0;
    const tx = this.db.transaction((items: Array<{ runId: string; durationMs: number }>) => {
      for (const item of items) {
        (stmt as any).run(nowIsoText, item.durationMs, nowIsoText, item.runId);
      }
    });

    const payload: Array<{ runId: string; durationMs: number }> = [];
    for (const row of rows) {
      const runId = (row.runId || "").trim();
      if (!runId) continue;
      const startedMs = Date.parse((row.startedAt || "").trim());
      const durationMs = Number.isFinite(startedMs) ? Math.max(0, now.getTime() - startedMs) : 0;
      payload.push({ runId, durationMs });
    }
    if (payload.length === 0) return 0;
    tx(payload);
    updated = payload.length;
    return updated;
  }

  upsertTask(record: SignupTaskRecord): void {
    const row = toRecordRow(record);
    const stmt = this.db.prepare(
        `
        INSERT INTO signup_tasks (
          run_id, batch_id, mode, attempt_index, mode_retry_max, status, started_at, completed_at, duration_ms,
          failure_stage, error_code, error_message, proxy_node, proxy_ip, proxy_country, proxy_city, proxy_timezone,
          browser_engine, browser_mode, browser_user_agent, browser_locale, browser_timezone, model_name,
          precheck_passed, verify_passed, signup_submitted, request_count, suspicious_hit_count, captcha_submit_count, max_captcha_length,
          has_ip_rate_limit, has_suspicious_activity, has_extensibility_error, has_invalid_captcha,
          email_address, email_domain, email_local_len, api_key_prefix, notes_json, details_json, updated_at
        ) VALUES (
          $runId, $batchId, $mode, $attemptIndex, $modeRetryMax, $status, $startedAt, $completedAt, $durationMs,
          $failureStage, $errorCode, $errorMessage, $proxyNode, $proxyIp, $proxyCountry, $proxyCity, $proxyTimezone,
          $browserEngine, $browserMode, $browserUserAgent, $browserLocale, $browserTimezone, $modelName,
          $precheckPassed, $verifyPassed, $signupSubmitted, $requestCount, $suspiciousHitCount, $captchaSubmitCount, $maxCaptchaLength,
          $hasIpRateLimit, $hasSuspiciousActivity, $hasExtensibilityError, $hasInvalidCaptcha,
          $emailAddress, $emailDomain, $emailLocalLen, $apiKeyPrefix, $notesJson, $detailsJson, $updatedAt
        )
        ON CONFLICT(run_id) DO UPDATE SET
          batch_id = excluded.batch_id,
          mode = excluded.mode,
          attempt_index = excluded.attempt_index,
          mode_retry_max = excluded.mode_retry_max,
          status = excluded.status,
          started_at = excluded.started_at,
          completed_at = excluded.completed_at,
          duration_ms = excluded.duration_ms,
          failure_stage = excluded.failure_stage,
          error_code = excluded.error_code,
          error_message = excluded.error_message,
          proxy_node = excluded.proxy_node,
          proxy_ip = excluded.proxy_ip,
          proxy_country = excluded.proxy_country,
          proxy_city = excluded.proxy_city,
          proxy_timezone = excluded.proxy_timezone,
          browser_engine = excluded.browser_engine,
          browser_mode = excluded.browser_mode,
          browser_user_agent = excluded.browser_user_agent,
          browser_locale = excluded.browser_locale,
          browser_timezone = excluded.browser_timezone,
          model_name = excluded.model_name,
          precheck_passed = excluded.precheck_passed,
          verify_passed = excluded.verify_passed,
          signup_submitted = excluded.signup_submitted,
          request_count = excluded.request_count,
          suspicious_hit_count = excluded.suspicious_hit_count,
          captcha_submit_count = excluded.captcha_submit_count,
          max_captcha_length = excluded.max_captcha_length,
          has_ip_rate_limit = excluded.has_ip_rate_limit,
          has_suspicious_activity = excluded.has_suspicious_activity,
          has_extensibility_error = excluded.has_extensibility_error,
          has_invalid_captcha = excluded.has_invalid_captcha,
          email_address = excluded.email_address,
          email_domain = excluded.email_domain,
          email_local_len = excluded.email_local_len,
          api_key_prefix = excluded.api_key_prefix,
          notes_json = excluded.notes_json,
          details_json = excluded.details_json,
          updated_at = excluded.updated_at
      `,
      );
    (stmt as any).run(row);
  }

  listRecentRateLimitedIps(): string[] {
    const sinceIso = new Date(Date.now() - Math.max(60_000, this.cfg.ipRateLimitCooldownMs)).toISOString();
    const rows = this.db
      .prepare(
        `
        SELECT proxy_ip AS proxyIp
        FROM signup_tasks
        WHERE status = 'failed'
          AND has_ip_rate_limit = 1
          AND proxy_ip IS NOT NULL
          AND proxy_ip <> ''
          AND started_at >= ?
        GROUP BY proxy_ip
        ORDER BY MAX(started_at) DESC
        LIMIT ?
      `,
      )
      .all(sinceIso, Math.max(1, this.cfg.ipRateLimitMax)) as Array<{ proxyIp?: string }>;

    const result: string[] = [];
    for (const row of rows) {
      const ip = (row.proxyIp || "").trim();
      if (!ip) continue;
      result.push(ip);
    }
    return result;
  }

  listRecentSuspiciousIps(): string[] {
    const sinceIso = new Date(Date.now() - Math.max(60_000, this.cfg.suspiciousCooldownMs)).toISOString();
    const rows = this.db
      .prepare(
        `
        SELECT proxy_ip AS proxyIp
        FROM signup_tasks
        WHERE status = 'failed'
          AND proxy_ip IS NOT NULL
          AND proxy_ip <> ''
          AND started_at >= ?
          AND (
            has_suspicious_activity = 1
            OR has_extensibility_error = 1
          )
        GROUP BY proxy_ip
        ORDER BY MAX(started_at) DESC
        LIMIT ?
      `,
      )
      .all(sinceIso, Math.max(1, this.cfg.suspiciousMax)) as Array<{ proxyIp?: string }>;

    const result: string[] = [];
    for (const row of rows) {
      const ip = (row.proxyIp || "").trim();
      if (!ip) continue;
      result.push(ip);
    }
    return result;
  }
}
