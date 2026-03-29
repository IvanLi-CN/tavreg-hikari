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

  const Database = require("better-sqlite3") as typeof import("better-sqlite3");
  const db = new Database(dbPath);
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
export type JobStatus = "idle" | "running" | "paused" | "stopping" | "force_stopping" | "completing" | "completed" | "failed" | "stopped";
export type AttemptStatus = "running" | "succeeded" | "failed" | "stopped";
export type ApiKeyStatus = "active" | "revoked" | "unknown";
export type ProofMailboxProvider = "moemail";
export type AccountSource = "manual" | "zhanghaoya" | "shanyouxiang" | "shankeyun" | "hotmail666";
export type AccountImportSource = "manual" | "extractor";
export type AccountExtractorProvider = "zhanghaoya" | "shanyouxiang" | "shankeyun" | "hotmail666";
export type AccountExtractorAccountType = "outlook";
export type AccountSkipReason =
  | "has_api_key"
  | "microsoft_password_incorrect"
  | "microsoft_account_locked"
  | "microsoft_unknown_recovery_email";
export type AccountExtractBatchStatus =
  | "accepted"
  | "rejected"
  | "invalid_key"
  | "insufficient_stock"
  | "parse_failed"
  | "error";
export type AccountExtractItemParseStatus = "parsed" | "invalid";
export type AccountExtractItemAcceptStatus = "accepted" | "rejected";
export type MailboxStatus = "preparing" | "available" | "failed" | "invalidated";

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
  extractorZhanghaoyaKey: string;
  extractorShanyouxiangKey: string;
  extractorShankeyunKey: string;
  extractorHotmail666Key: string;
  defaultAutoExtractSources: AccountExtractorProvider[];
  defaultAutoExtractQuantity: number;
  defaultAutoExtractMaxWaitSec: number;
  defaultAutoExtractAccountType: AccountExtractorAccountType;
  microsoftGraphClientId: string;
  microsoftGraphClientSecret: string;
  microsoftGraphRedirectUri: string;
  microsoftGraphAuthority: string;
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
  importSource: AccountImportSource;
  accountSource: AccountSource;
  sourceRawPayload: string | null;
  lastUsedAt: string | null;
  lastResultStatus: AccountStatus;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: AccountSkipReason | null;
  groupName: string | null;
  disabledAt: string | null;
  disabledReason: string | null;
  leaseJobId: number | null;
  leaseStartedAt: string | null;
  mailboxStatus: MailboxStatus;
  mailboxLastSyncedAt: string | null;
  mailboxLastErrorCode: string | null;
  mailboxUnreadCount: number;
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
  autoExtractSources: AccountExtractorProvider[];
  autoExtractQuantity: number;
  autoExtractMaxWaitSec: number;
  autoExtractAccountType: AccountExtractorAccountType;
  startedAt: string;
  pausedAt: string | null;
  completedAt: string | null;
  lastError: string | null;
  updatedAt: string;
}

export interface AccountExtractBatchRecord {
  id: number;
  jobId: number | null;
  provider: AccountExtractorProvider;
  accountType: AccountExtractorAccountType;
  requestedUsableCount: number;
  attemptBudget: number;
  acceptedCount: number;
  status: AccountExtractBatchStatus;
  errorMessage: string | null;
  rawResponse: string | null;
  maskedKey: string | null;
  startedAt: string;
  completedAt: string | null;
}

export interface AccountExtractItemRecord {
  id: number;
  batchId: number;
  provider: AccountExtractorProvider;
  rawPayload: string;
  email: string | null;
  password: string | null;
  parseStatus: AccountExtractItemParseStatus;
  acceptStatus: AccountExtractItemAcceptStatus;
  rejectReason: string | null;
  importedAccountId: number | null;
  createdAt: string;
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

export interface MicrosoftMailboxRecord {
  id: number;
  accountId: number;
  microsoftEmail: string;
  groupName: string | null;
  proofMailboxAddress: string | null;
  status: MailboxStatus;
  syncEnabled: boolean;
  refreshToken: string | null;
  accessToken: string | null;
  accessTokenExpiresAt: string | null;
  graphUserId: string | null;
  graphUserPrincipalName: string | null;
  graphDisplayName: string | null;
  authority: string;
  oauthState: string | null;
  oauthCodeVerifier: string | null;
  oauthStartedAt: string | null;
  oauthConnectedAt: string | null;
  deltaLink: string | null;
  unreadCount: number;
  lastSyncedAt: string | null;
  lastErrorCode: string | null;
  lastErrorMessage: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MicrosoftMailMessageRecord {
  id: number;
  mailboxId: number;
  graphMessageId: string;
  internetMessageId: string | null;
  conversationId: string | null;
  subject: string;
  fromName: string | null;
  fromAddress: string | null;
  receivedAt: string | null;
  isRead: boolean;
  hasAttachments: boolean;
  bodyContentType: "html" | "text";
  bodyPreview: string;
  bodyContent: string;
  webLink: string | null;
  createdAt: string;
  updatedAt: string;
}

interface SettingsRow {
  key: string;
  value_json: string;
}

const PINNED_PROXY_NODE_SETTING_KEY = "pinnedProxyNodeName";
const HARD_ACCOUNT_SKIP_REASONS = new Set<AccountSkipReason>([
  "microsoft_password_incorrect",
  "microsoft_account_locked",
  "microsoft_unknown_recovery_email",
]);

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

function isHardAccountSkipReason(reason: string | null | undefined): reason is Exclude<AccountSkipReason, "has_api_key"> {
  return HARD_ACCOUNT_SKIP_REASONS.has(String(reason || "").trim() as Exclude<AccountSkipReason, "has_api_key">);
}

function isBlockingAccountSkipReason(reason: string | null | undefined): boolean {
  return String(reason || "").trim().length > 0;
}

function deriveAccountSkipReasonFromErrorCode(errorCode: string | null | undefined): Exclude<AccountSkipReason, "has_api_key"> | null {
  const normalized = String(errorCode || "").trim();
  if (!normalized) return null;
  if (/^microsoft_password_incorrect/i.test(normalized)) return "microsoft_password_incorrect";
  if (/^microsoft_account_locked/i.test(normalized)) return "microsoft_account_locked";
  if (/^microsoft_unknown_recovery_email/i.test(normalized)) return "microsoft_unknown_recovery_email";
  return null;
}

function resolveAccountStatus(input: {
  disabledAt: string | null;
  hasApiKey: boolean;
  leaseJobId: number | null;
  lastResultStatus: AccountStatus;
  skipReason: string | null;
}): AccountStatus {
  if (input.disabledAt != null) return "disabled";
  if (input.hasApiKey) return "skipped_has_key";
  if (isHardAccountSkipReason(input.skipReason)) return "disabled";
  if (input.leaseJobId != null) {
    return input.lastResultStatus === "running" ? "running" : "leased";
  }
  return isBlockingAccountSkipReason(input.skipReason) ? "failed" : "ready";
}

function resolveFailureResultStatus(input: { disabledAt: string | null; skipReason: string | null }): AccountStatus {
  return input.disabledAt != null || isHardAccountSkipReason(input.skipReason) ? "disabled" : "failed";
}

function resolveReleasedLeaseAccountStatus(input: {
  disabledAt: string | null;
  hasApiKey: boolean;
  skipReason: string | null;
}): AccountStatus {
  return resolveAccountStatus({
    disabledAt: input.disabledAt,
    hasApiKey: input.hasApiKey,
    leaseJobId: null,
    lastResultStatus: "ready",
    skipReason: input.skipReason,
  });
}

function deriveLegacyHardBlockReason(
  reason: string | null | undefined,
  errorCode: string | null | undefined,
): Exclude<AccountSkipReason, "has_api_key"> | null {
  const fromErrorCode = deriveAccountSkipReasonFromErrorCode(errorCode);
  if (fromErrorCode) return fromErrorCode;
  const normalizedReason = String(reason || "").trim().toLowerCase();
  if (!normalizedReason) return null;
  if (normalizedReason.includes("锁定") || normalizedReason.includes("locked")) return "microsoft_account_locked";
  if (normalizedReason.includes("辅助邮箱") || normalizedReason.includes("recovery")) return "microsoft_unknown_recovery_email";
  if (normalizedReason.includes("密码错误") || normalizedReason.includes("incorrect password")) return "microsoft_password_incorrect";
  return null;
}

function resolveFailureSkipReason(input: {
  hasApiKey: boolean;
  currentSkipReason: string | null;
  errorCode: string | null | undefined;
}): AccountSkipReason | null {
  if (input.hasApiKey) return "has_api_key";
  const derived = deriveAccountSkipReasonFromErrorCode(input.errorCode);
  if (derived) return derived;
  return isHardAccountSkipReason(input.currentSkipReason) ? (input.currentSkipReason as AccountSkipReason) : null;
}

function accountSelectSql(whereClause = "", orderClause = ""): string {
  return `
    SELECT
      a.*,
      COALESCE(m.status, 'preparing') AS mailbox_status,
      m.last_synced_at AS mailbox_last_synced_at,
      m.last_error_code AS mailbox_last_error_code,
      COALESCE(m.unread_count, 0) AS mailbox_unread_count
    FROM microsoft_accounts a
    LEFT JOIN microsoft_mailboxes m ON m.account_id = a.id
    ${whereClause}
    ${orderClause}
  `;
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
    importSource: String(row.import_source || "manual") as AccountImportSource,
    accountSource: String(row.account_source || "manual") as AccountSource,
    sourceRawPayload: row.source_raw_payload == null ? null : String(row.source_raw_payload),
    lastUsedAt: row.last_used_at == null ? null : String(row.last_used_at),
    lastResultStatus: String(row.last_result_status || "ready") as AccountStatus,
    lastResultAt: row.last_result_at == null ? null : String(row.last_result_at),
    lastErrorCode: row.last_error_code == null ? null : String(row.last_error_code),
    skipReason: row.skip_reason == null ? null : (String(row.skip_reason) as AccountSkipReason),
    groupName: row.group_name == null ? null : String(row.group_name),
    disabledAt: row.disabled_at == null ? null : String(row.disabled_at),
    disabledReason: row.disabled_reason == null ? null : String(row.disabled_reason),
    leaseJobId: row.lease_job_id == null ? null : Number(row.lease_job_id),
    leaseStartedAt: row.lease_started_at == null ? null : String(row.lease_started_at),
    mailboxStatus: String(row.mailbox_status || "preparing") as MailboxStatus,
    mailboxLastSyncedAt: row.mailbox_last_synced_at == null ? null : String(row.mailbox_last_synced_at),
    mailboxLastErrorCode: row.mailbox_last_error_code == null ? null : String(row.mailbox_last_error_code),
    mailboxUnreadCount: Number(row.mailbox_unread_count || 0),
  };
}

function mapMailboxRow(row: Record<string, unknown>): MicrosoftMailboxRecord {
  return {
    id: Number(row.id),
    accountId: Number(row.account_id),
    microsoftEmail: String(row.microsoft_email || ""),
    groupName: row.group_name == null ? null : String(row.group_name),
    proofMailboxAddress: row.proof_mailbox_address == null ? null : String(row.proof_mailbox_address),
    status: String(row.status || "preparing") as MailboxStatus,
    syncEnabled: asBoolean(row.sync_enabled),
    refreshToken: row.refresh_token == null ? null : String(row.refresh_token),
    accessToken: row.access_token == null ? null : String(row.access_token),
    accessTokenExpiresAt: row.access_token_expires_at == null ? null : String(row.access_token_expires_at),
    graphUserId: row.graph_user_id == null ? null : String(row.graph_user_id),
    graphUserPrincipalName: row.graph_user_principal_name == null ? null : String(row.graph_user_principal_name),
    graphDisplayName: row.graph_display_name == null ? null : String(row.graph_display_name),
    authority: String(row.authority || "common"),
    oauthState: row.oauth_state == null ? null : String(row.oauth_state),
    oauthCodeVerifier: row.oauth_code_verifier == null ? null : String(row.oauth_code_verifier),
    oauthStartedAt: row.oauth_started_at == null ? null : String(row.oauth_started_at),
    oauthConnectedAt: row.oauth_connected_at == null ? null : String(row.oauth_connected_at),
    deltaLink: row.delta_link == null ? null : String(row.delta_link),
    unreadCount: Number(row.unread_count || 0),
    lastSyncedAt: row.last_synced_at == null ? null : String(row.last_synced_at),
    lastErrorCode: row.last_error_code == null ? null : String(row.last_error_code),
    lastErrorMessage: row.last_error_message == null ? null : String(row.last_error_message),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function mapMailboxMessageRow(row: Record<string, unknown>): MicrosoftMailMessageRecord {
  return {
    id: Number(row.id),
    mailboxId: Number(row.mailbox_id),
    graphMessageId: String(row.graph_message_id || ""),
    internetMessageId: row.internet_message_id == null ? null : String(row.internet_message_id),
    conversationId: row.conversation_id == null ? null : String(row.conversation_id),
    subject: String(row.subject || ""),
    fromName: row.from_name == null ? null : String(row.from_name),
    fromAddress: row.from_address == null ? null : String(row.from_address),
    receivedAt: row.received_at == null ? null : String(row.received_at),
    isRead: asBoolean(row.is_read),
    hasAttachments: asBoolean(row.has_attachments),
    bodyContentType: String(row.body_content_type || "text") === "html" ? "html" : "text",
    bodyPreview: String(row.body_preview || ""),
    bodyContent: String(row.body_content || ""),
    webLink: row.web_link == null ? null : String(row.web_link),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
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
    autoExtractSources: parseJson<AccountExtractorProvider[]>(
      typeof row.auto_extract_sources_json === "string" ? row.auto_extract_sources_json : "[]",
      [],
    ),
    autoExtractQuantity: Number(row.auto_extract_quantity || 0),
    autoExtractMaxWaitSec: Number(row.auto_extract_max_wait_sec || 0),
    autoExtractAccountType: String(row.auto_extract_account_type || "outlook") as AccountExtractorAccountType,
    startedAt: String(row.started_at),
    pausedAt: row.paused_at == null ? null : String(row.paused_at),
    completedAt: row.completed_at == null ? null : String(row.completed_at),
    lastError: row.last_error == null ? null : String(row.last_error),
    updatedAt: String(row.updated_at),
  };
}

function mapAccountExtractBatchRow(row: Record<string, unknown>): AccountExtractBatchRecord {
  return {
    id: Number(row.id),
    jobId: row.job_id == null ? null : Number(row.job_id),
    provider: String(row.provider) as AccountExtractorProvider,
    accountType: String(row.account_type || "outlook") as AccountExtractorAccountType,
    requestedUsableCount: Number(row.requested_usable_count || 0),
    attemptBudget: Number(row.attempt_budget || 0),
    acceptedCount: Number(row.accepted_count || 0),
    status: String(row.status || "error") as AccountExtractBatchStatus,
    errorMessage: row.error_message == null ? null : String(row.error_message),
    rawResponse: row.raw_response == null ? null : String(row.raw_response),
    maskedKey: row.masked_key == null ? null : String(row.masked_key),
    startedAt: String(row.started_at),
    completedAt: row.completed_at == null ? null : String(row.completed_at),
  };
}

function mapAccountExtractItemRow(row: Record<string, unknown>): AccountExtractItemRecord {
  return {
    id: Number(row.id),
    batchId: Number(row.batch_id),
    provider: String(row.provider) as AccountExtractorProvider,
    rawPayload: String(row.raw_payload || ""),
    email: row.email == null ? null : String(row.email),
    password: row.password == null ? null : String(row.password),
    parseStatus: String(row.parse_status || "invalid") as AccountExtractItemParseStatus,
    acceptStatus: String(row.accept_status || "rejected") as AccountExtractItemAcceptStatus,
    rejectReason: row.reject_reason == null ? null : String(row.reject_reason),
    importedAccountId: row.imported_account_id == null ? null : Number(row.imported_account_id),
    createdAt: String(row.created_at),
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

export function normalizeJobMaxAttempts(need: number, maxAttempts: number): number {
  const normalizedNeed = Math.max(1, Number.isFinite(need) ? Math.trunc(need) : 1);
  const normalizedMaxAttempts = Math.max(1, Number.isFinite(maxAttempts) ? Math.trunc(maxAttempts) : 1);
  if (normalizedMaxAttempts >= normalizedNeed) {
    return normalizedMaxAttempts;
  }
  return Math.max(normalizedNeed, Math.ceil(normalizedNeed * 1.5));
}

export function shouldEnterCompleting(job: Pick<JobRecord, "need" | "successCount" | "maxAttempts" | "launchedCount">): boolean {
  return job.successCount >= job.need || job.launchedCount >= job.maxAttempts;
}

function shouldPreserveManualStopStatus(status: JobStatus): boolean {
  return status === "stopping" || status === "force_stopping";
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
        account_source TEXT NOT NULL DEFAULT 'manual',
        source_raw_payload TEXT,
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
        auto_extract_sources_json TEXT NOT NULL DEFAULT '[]',
        auto_extract_quantity INTEGER NOT NULL DEFAULT 0,
        auto_extract_max_wait_sec INTEGER NOT NULL DEFAULT 0,
        auto_extract_account_type TEXT NOT NULL DEFAULT 'outlook',
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

      CREATE TABLE IF NOT EXISTS account_extract_batches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
        provider TEXT NOT NULL,
        account_type TEXT NOT NULL DEFAULT 'outlook',
        requested_usable_count INTEGER NOT NULL DEFAULT 0,
        attempt_budget INTEGER NOT NULL DEFAULT 0,
        accepted_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        error_message TEXT,
        raw_response TEXT,
        masked_key TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT
      );

      CREATE TABLE IF NOT EXISTS account_extract_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id INTEGER NOT NULL REFERENCES account_extract_batches(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        raw_payload TEXT NOT NULL,
        email TEXT,
        password TEXT,
        parse_status TEXT NOT NULL,
        accept_status TEXT NOT NULL,
        reject_reason TEXT,
        imported_account_id INTEGER REFERENCES microsoft_accounts(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS microsoft_mailboxes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL UNIQUE REFERENCES microsoft_accounts(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'preparing',
        sync_enabled INTEGER NOT NULL DEFAULT 1,
        refresh_token TEXT,
        access_token TEXT,
        access_token_expires_at TEXT,
        graph_user_id TEXT,
        graph_user_principal_name TEXT,
        graph_display_name TEXT,
        authority TEXT NOT NULL DEFAULT 'common',
        oauth_state TEXT,
        oauth_code_verifier TEXT,
        oauth_started_at TEXT,
        oauth_connected_at TEXT,
        delta_link TEXT,
        unread_count INTEGER NOT NULL DEFAULT 0,
        last_synced_at TEXT,
        last_error_code TEXT,
        last_error_message TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE IF NOT EXISTS microsoft_mail_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mailbox_id INTEGER NOT NULL REFERENCES microsoft_mailboxes(id) ON DELETE CASCADE,
        graph_message_id TEXT NOT NULL,
        internet_message_id TEXT,
        conversation_id TEXT,
        subject TEXT NOT NULL DEFAULT '',
        from_name TEXT,
        from_address TEXT,
        received_at TEXT,
        is_read INTEGER NOT NULL DEFAULT 0,
        has_attachments INTEGER NOT NULL DEFAULT 0,
        body_content_type TEXT NOT NULL DEFAULT 'text',
        body_preview TEXT NOT NULL DEFAULT '',
        body_content TEXT NOT NULL DEFAULT '',
        web_link TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        UNIQUE(mailbox_id, graph_message_id)
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
    if (!accountColumns.has("account_source")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN account_source TEXT NOT NULL DEFAULT 'manual';");
    }
    if (!accountColumns.has("source_raw_payload")) {
      this.db.exec("ALTER TABLE microsoft_accounts ADD COLUMN source_raw_payload TEXT;");
    }
    const jobTableInfo = this.db.query("PRAGMA table_info(jobs);").all() as Array<Record<string, unknown>>;
    const jobColumns = new Set(jobTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!jobColumns.has("auto_extract_sources_json")) {
      this.db.exec("ALTER TABLE jobs ADD COLUMN auto_extract_sources_json TEXT NOT NULL DEFAULT '[]';");
    }
    if (!jobColumns.has("auto_extract_quantity")) {
      this.db.exec("ALTER TABLE jobs ADD COLUMN auto_extract_quantity INTEGER NOT NULL DEFAULT 0;");
    }
    if (!jobColumns.has("auto_extract_max_wait_sec")) {
      this.db.exec("ALTER TABLE jobs ADD COLUMN auto_extract_max_wait_sec INTEGER NOT NULL DEFAULT 0;");
    }
    if (!jobColumns.has("auto_extract_account_type")) {
      this.db.exec("ALTER TABLE jobs ADD COLUMN auto_extract_account_type TEXT NOT NULL DEFAULT 'outlook';");
    }
    const apiKeyTableInfo = this.db.query("PRAGMA table_info(api_keys);").all() as Array<Record<string, unknown>>;
    const apiKeyColumns = new Set(apiKeyTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!apiKeyColumns.has("extracted_ip")) {
      this.db.exec("ALTER TABLE api_keys ADD COLUMN extracted_ip TEXT;");
    }
    const mailboxTableInfo = this.db.query("PRAGMA table_info(microsoft_mailboxes);").all() as Array<Record<string, unknown>>;
    const mailboxColumns = new Set(mailboxTableInfo.map((item) => String(item.name || "").toLowerCase()));
    if (!mailboxColumns.has("authority")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN authority TEXT NOT NULL DEFAULT 'common';");
    }
    if (!mailboxColumns.has("oauth_state")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN oauth_state TEXT;");
    }
    if (!mailboxColumns.has("oauth_code_verifier")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN oauth_code_verifier TEXT;");
    }
    if (!mailboxColumns.has("oauth_started_at")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN oauth_started_at TEXT;");
    }
    if (!mailboxColumns.has("oauth_connected_at")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN oauth_connected_at TEXT;");
    }
    if (!mailboxColumns.has("delta_link")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN delta_link TEXT;");
    }
    if (!mailboxColumns.has("last_error_message")) {
      this.db.exec("ALTER TABLE microsoft_mailboxes ADD COLUMN last_error_message TEXT;");
    }

    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_result ON microsoft_accounts(last_result_status, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_skip_reason ON microsoft_accounts(skip_reason, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_group_name ON microsoft_accounts(group_name, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_proof_mailbox ON microsoft_accounts(proof_mailbox_address, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_accounts_source ON microsoft_accounts(account_source, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(account_id);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_jobs_status_started ON jobs(status, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_job_attempts_job_status ON job_attempts(job_id, status, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_proxy_checks_node_checked ON proxy_checks(node_name, checked_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_account_extract_batches_job_started ON account_extract_batches(job_id, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_account_extract_batches_provider_started ON account_extract_batches(provider, started_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_account_extract_items_batch_created ON account_extract_items(batch_id, created_at ASC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_account_extract_items_email ON account_extract_items(email, created_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_mailboxes_status_updated ON microsoft_mailboxes(status, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_mailboxes_sync_updated ON microsoft_mailboxes(sync_enabled, updated_at DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_mail_messages_mailbox_received ON microsoft_mail_messages(mailbox_id, received_at DESC, id DESC);");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_microsoft_mail_messages_mailbox_unread ON microsoft_mail_messages(mailbox_id, is_read, received_at DESC);");
    if (signupTaskTableExists) {
      this.db.exec("CREATE INDEX IF NOT EXISTS idx_signup_tasks_job_account ON signup_tasks(job_id, account_id, started_at DESC);");
    }

    this.db.exec(`
      INSERT INTO microsoft_mailboxes (account_id, status, sync_enabled, authority)
      SELECT id, 'preparing', 1, 'common'
      FROM microsoft_accounts
      WHERE id NOT IN (SELECT account_id FROM microsoft_mailboxes)
    `);
  }

  recoverStaleState(): void {
    const now = nowIso();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .query(
          "UPDATE job_attempts SET status = 'stopped', stage = 'stopped', completed_at = ?, duration_ms = 0, error_code = COALESCE(error_code, 'force_stopped'), error_message = COALESCE(error_message, 'stopped by user') WHERE status = 'running' AND job_id IN (SELECT id FROM jobs WHERE status IN ('stopping', 'force_stopping'))",
        )
        .run(now);
      this.db
        .query("UPDATE jobs SET status = 'stopped', paused_at = NULL, completed_at = ?, updated_at = ?, last_error = NULL WHERE status IN ('stopping', 'force_stopping')")
        .run(now, now);
      this.db
        .query("UPDATE jobs SET status = 'failed', completed_at = ?, updated_at = ?, last_error = COALESCE(last_error, 'server_restart') WHERE status IN ('running', 'completing', 'paused')")
        .run(now, now);
      this.db
        .query("UPDATE job_attempts SET status = 'failed', stage = 'server_restart', completed_at = ?, duration_ms = 0 WHERE status = 'running'")
        .run(now);
      this.db
        .query(
          "UPDATE microsoft_accounts SET lease_job_id = NULL, lease_started_at = NULL, last_result_status = CASE WHEN disabled_at IS NOT NULL THEN 'disabled' WHEN has_api_key = 1 THEN 'skipped_has_key' WHEN skip_reason IN ('microsoft_password_incorrect', 'microsoft_account_locked', 'microsoft_unknown_recovery_email') THEN 'disabled' WHEN COALESCE(skip_reason, '') <> '' THEN 'failed' ELSE 'ready' END WHERE lease_job_id IS NOT NULL",
        )
        .run();
      const legacyHardBlockedRows = this.db
        .query(`
          SELECT id, skip_reason, disabled_reason, last_error_code
          FROM microsoft_accounts
          WHERE disabled_at IS NOT NULL OR COALESCE(disabled_reason, '') <> ''
        `)
        .all() as Array<Record<string, unknown>>;
      const normalizeLegacyHardBlock = this.db.query(`
        UPDATE microsoft_accounts
        SET skip_reason = ?,
            disabled_at = NULL,
            disabled_reason = NULL,
            last_result_status = 'disabled',
            last_error_code = ?,
            last_result_at = COALESCE(last_result_at, ?)
        WHERE id = ?
      `);
      for (const row of legacyHardBlockedRows) {
        const currentSkipReason = row.skip_reason == null ? null : String(row.skip_reason);
        const nextSkipReason = isHardAccountSkipReason(currentSkipReason)
          ? currentSkipReason
          : deriveLegacyHardBlockReason(
              row.disabled_reason == null ? null : String(row.disabled_reason),
              row.last_error_code == null ? null : String(row.last_error_code),
            );
        if (!nextSkipReason) continue;
        const nextErrorCode = row.last_error_code == null ? nextSkipReason : String(row.last_error_code);
        normalizeLegacyHardBlock.run(nextSkipReason, nextErrorCode, now, Number(row.id));
      }
      this.db
        .query(
          "UPDATE microsoft_accounts SET last_result_status = 'disabled' WHERE disabled_at IS NOT NULL OR skip_reason IN ('microsoft_password_incorrect', 'microsoft_account_locked', 'microsoft_unknown_recovery_email')",
        )
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
    options?: {
      source?: AccountImportSource;
      accountSource?: AccountSource;
      groupName?: string | null;
      rawPayloadByEmail?: Record<string, string | null | undefined>;
    },
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
    const accountSource = options?.accountSource || "manual";
    const normalizedGroupName = options?.groupName?.trim() ? options.groupName.trim() : null;
    const rawPayloadByEmail = options?.rawPayloadByEmail || {};
    let created = 0;
    let updated = 0;
    const affectedIds: number[] = [];
    const selectStmt = this.db.query("SELECT * FROM microsoft_accounts WHERE microsoft_email = ?");
    const insertStmt = this.db.query(`
      INSERT INTO microsoft_accounts (
        microsoft_email, password_plaintext, has_api_key, api_key_id, imported_at, updated_at, import_source, account_source, source_raw_payload, group_name,
        last_result_status, skip_reason
      ) VALUES (?, ?, 0, NULL, ?, ?, ?, ?, ?, ?, 'ready', NULL)
    `);
    const updateStmt = this.db.query(`
      UPDATE microsoft_accounts
      SET password_plaintext = ?,
          updated_at = ?,
          import_source = ?,
          account_source = ?,
          source_raw_payload = ?,
          group_name = COALESCE(?, group_name),
          skip_reason = ?,
          last_result_status = ?,
          last_error_code = ?
      WHERE id = ?
    `);
    const ensureMailboxStmt = this.db.query(`
      INSERT INTO microsoft_mailboxes (account_id, status, sync_enabled, authority, updated_at)
      VALUES (?, 'preparing', 1, 'common', ?)
      ON CONFLICT(account_id) DO UPDATE SET
        sync_enabled = 1,
        updated_at = excluded.updated_at
    `);

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      for (const [email, password] of deduped.entries()) {
        const existing = selectStmt.get(email) as Record<string, unknown> | null;
        const rawPayload = rawPayloadByEmail[email] == null ? null : String(rawPayloadByEmail[email] || "");
        if (!existing) {
          insertStmt.run(email, password, now, now, source, accountSource, rawPayload, normalizedGroupName);
          const inserted = selectStmt.get(email) as Record<string, unknown> | null;
          if (inserted?.id != null) {
            const accountId = Number(inserted.id);
            affectedIds.push(accountId);
            ensureMailboxStmt.run(accountId, now);
          }
          created += 1;
          continue;
        }
        const current = mapAccountRow(existing);
        const shouldClearPasswordBlock =
          current.skipReason === "microsoft_password_incorrect" && current.passwordPlaintext.trim() !== password;
        const nextSkipReason: AccountSkipReason | null = current.hasApiKey
          ? "has_api_key"
          : shouldClearPasswordBlock
            ? null
            : current.skipReason;
        const nextStatus = resolveAccountStatus({
          disabledAt: current.disabledAt,
          hasApiKey: current.hasApiKey,
          leaseJobId: current.leaseJobId,
          lastResultStatus: current.lastResultStatus,
          skipReason: nextSkipReason,
        });
        const nextErrorCode =
          shouldClearPasswordBlock && /^microsoft_password_incorrect/i.test(current.lastErrorCode || "") ? null : current.lastErrorCode;
        updateStmt.run(
          password,
          now,
          source,
          accountSource,
          rawPayload,
          normalizedGroupName,
          nextSkipReason,
          nextStatus,
          nextErrorCode,
          Number(existing.id),
        );
        affectedIds.push(Number(existing.id));
        ensureMailboxStmt.run(Number(existing.id), now);
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
  }): { rows: MicrosoftAccountRecord[]; total: number; summary: { ready: number; linked: number; failed: number; disabled: number } } {
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
          SUM(CASE WHEN last_result_status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
          SUM(CASE WHEN last_result_status = 'disabled' THEN 1 ELSE 0 END) AS disabled_count
        FROM microsoft_accounts
        ${whereSql}
      `)
      .get(...(params as any[])) as { total?: number; ready_count?: number; linked_count?: number; failed_count?: number; disabled_count?: number } | null;
    const total = Number(summaryRow?.total || 0);
    const rows = this.db
      .query(accountSelectSql(whereSql, "ORDER BY a.updated_at DESC LIMIT ? OFFSET ?"))
      .all(...([...(params as any[]), pageSize, (page - 1) * pageSize] as any[])) as Record<string, unknown>[];
    return {
      rows: rows.map(mapAccountRow),
      total,
      summary: {
        ready: Number(summaryRow?.ready_count || 0),
        linked: Number(summaryRow?.linked_count || 0),
        failed: Number(summaryRow?.failed_count || 0),
        disabled: Number(summaryRow?.disabled_count || 0),
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
      .query(accountSelectSql(`WHERE a.microsoft_email IN (${placeholders})`))
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

    const shouldClearRecoveryBlock = Boolean(normalizedAddress) && current.skipReason === "microsoft_unknown_recovery_email";
    const nextSkipReason: AccountSkipReason | null = current.hasApiKey
      ? "has_api_key"
      : shouldClearRecoveryBlock
        ? null
        : current.skipReason;
    const nextStatus = resolveAccountStatus({
      disabledAt: current.disabledAt,
      hasApiKey: current.hasApiKey,
      leaseJobId: current.leaseJobId,
      lastResultStatus: current.lastResultStatus,
      skipReason: nextSkipReason,
    });
    const nextErrorCode =
      shouldClearRecoveryBlock && /^microsoft_unknown_recovery_email/i.test(current.lastErrorCode || "") ? null : current.lastErrorCode;

    this.db
      .query(`
        UPDATE microsoft_accounts
        SET proof_mailbox_provider = ?,
            proof_mailbox_address = ?,
            proof_mailbox_id = ?,
            skip_reason = ?,
            last_result_status = ?,
            last_error_code = ?,
            updated_at = ?
        WHERE id = ?
      `)
      .run(normalizedProvider, normalizedAddress, normalizedMailboxId, nextSkipReason, nextStatus, nextErrorCode, nowIso(), accountId);

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
    const nextSkipReason: AccountSkipReason | null = disabled
      ? current.hasApiKey
        ? "has_api_key"
        : current.skipReason
      : current.hasApiKey
        ? "has_api_key"
        : null;
    const nextStatus = disabled
      ? "disabled"
      : resolveAccountStatus({
          disabledAt: null,
          hasApiKey: current.hasApiKey,
          leaseJobId: current.leaseJobId,
          lastResultStatus: current.lastResultStatus,
          skipReason: nextSkipReason,
        });
    const nextErrorCode =
      disabled || current.skipReason == null || current.skipReason === "has_api_key" ? current.lastErrorCode : null;

    this.db
      .query(`
        UPDATE microsoft_accounts
        SET disabled_at = ?,
            disabled_reason = ?,
            skip_reason = ?,
            last_result_status = ?,
            last_error_code = ?,
            last_result_at = ?,
            updated_at = ?
        WHERE id = ?
      `)
      .run(disabledAt, normalizedReason, nextSkipReason, nextStatus, nextErrorCode, now, now, accountId);

    return this.getAccount(accountId)!;
  }

  markAccountUnavailable(
    accountId: number,
    reason: string,
    errorCode?: string | null,
    options?: { releaseLease?: boolean },
  ): void {
    const current = this.getAccount(accountId);
    if (!current) {
      throw new Error(`account not found: ${accountId}`);
    }
    const now = nowIso();
    const releaseLease = options?.releaseLease !== false;
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET disabled_at = COALESCE(disabled_at, ?),
            disabled_reason = ?,
            skip_reason = ?,
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
      .run(now, reason.trim(), current.skipReason, now, errorCode ?? null, now, accountId);
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

  createJob(input: {
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
    autoExtractSources?: AccountExtractorProvider[];
    autoExtractQuantity?: number;
    autoExtractMaxWaitSec?: number;
    autoExtractAccountType?: AccountExtractorAccountType;
  }): JobRecord {
    const active = this.getCurrentJob();
    if (active && ["running", "paused", "stopping", "force_stopping", "completing"].includes(active.status)) {
      throw new Error(`active job exists: ${active.id}`);
    }
    const now = nowIso();
    const need = Math.max(1, Math.trunc(input.need));
    const parallel = Math.max(1, Math.trunc(input.parallel));
    const maxAttempts = normalizeJobMaxAttempts(need, input.maxAttempts);
    const result = this.db
      .query(`
        INSERT INTO jobs (
          status, run_mode, need, parallel, max_attempts, success_count, failure_count, skip_count, launched_count,
          auto_extract_sources_json, auto_extract_quantity, auto_extract_max_wait_sec, auto_extract_account_type,
          started_at, paused_at, completed_at, last_error, updated_at
        ) VALUES ('running', ?, ?, ?, ?, 0, 0, 0, 0, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)
        RETURNING *
      `)
      .get(
        input.runMode,
        need,
        parallel,
        maxAttempts,
        JSON.stringify(input.autoExtractSources || []),
        Math.max(0, Number(input.autoExtractQuantity || 0)),
        Math.max(0, Number(input.autoExtractMaxWaitSec || 0)),
        (input.autoExtractAccountType || "outlook") as AccountExtractorAccountType,
        now,
        now,
      ) as Record<string, unknown>;
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

  updateJobState(
    jobId: number,
    patch: Partial<
      Pick<
        JobRecord,
        | "status"
        | "parallel"
        | "need"
        | "maxAttempts"
        | "autoExtractSources"
        | "autoExtractQuantity"
        | "autoExtractMaxWaitSec"
        | "autoExtractAccountType"
        | "pausedAt"
        | "completedAt"
        | "lastError"
        | "successCount"
        | "failureCount"
        | "skipCount"
        | "launchedCount"
      >
    >,
  ): JobRecord {
    const current = this.getJob(jobId);
    if (!current) throw new Error(`job not found: ${jobId}`);
    const next: JobRecord = {
      ...current,
      ...patch,
      updatedAt: nowIso(),
    };
    next.parallel = Math.max(1, Math.trunc(next.parallel));
    next.need = Math.max(1, Math.trunc(next.need));
    next.maxAttempts = normalizeJobMaxAttempts(next.need, next.maxAttempts);
    this.db
      .query(`
        UPDATE jobs
        SET status = ?, parallel = ?, need = ?, max_attempts = ?, success_count = ?, failure_count = ?,
            skip_count = ?, launched_count = ?, auto_extract_sources_json = ?, auto_extract_quantity = ?, auto_extract_max_wait_sec = ?,
            auto_extract_account_type = ?, paused_at = ?, completed_at = ?, last_error = ?, updated_at = ?
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
        JSON.stringify(next.autoExtractSources),
        next.autoExtractQuantity,
        next.autoExtractMaxWaitSec,
        next.autoExtractAccountType,
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
            AND COALESCE(skip_reason, '') = ''
            AND lease_job_id IS NULL
            AND NOT EXISTS (
              SELECT 1
              FROM job_attempts attempts
              WHERE attempts.job_id = ?
                AND attempts.account_id = microsoft_accounts.id
                AND attempts.status IN ('running', 'succeeded')
            )
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
          AND COALESCE(skip_reason, '') = ''
          AND lease_job_id IS NULL
          AND NOT EXISTS (
            SELECT 1
            FROM job_attempts attempts
            WHERE attempts.job_id = ?
              AND attempts.account_id = microsoft_accounts.id
              AND attempts.status IN ('running', 'succeeded')
          )
      `)
      .get(jobId) as { count?: number } | null;
    return Number(row?.count || 0);
  }

  getAccount(accountId: number): MicrosoftAccountRecord | null {
    const row = this.db.query(accountSelectSql("WHERE a.id = ?")).get(accountId) as Record<string, unknown> | null;
    return row ? mapAccountRow(row) : null;
  }

  ensureMailboxForAccount(accountId: number): MicrosoftMailboxRecord {
    const now = nowIso();
    this.db
      .query(`
        INSERT INTO microsoft_mailboxes (account_id, status, sync_enabled, authority, updated_at)
        VALUES (?, 'preparing', 1, 'common', ?)
        ON CONFLICT(account_id) DO UPDATE SET
          sync_enabled = 1,
          updated_at = excluded.updated_at
      `)
      .run(accountId, now);
    return this.getMailboxByAccountId(accountId)!;
  }

  listMailboxes(): MicrosoftMailboxRecord[] {
    const rows = this.db
      .query(`
        SELECT
          m.*,
          a.microsoft_email,
          a.group_name,
          a.proof_mailbox_address
        FROM microsoft_mailboxes m
        JOIN microsoft_accounts a ON a.id = m.account_id
        ORDER BY
          CASE WHEN m.last_synced_at IS NULL THEN 1 ELSE 0 END,
          m.last_synced_at DESC,
          a.updated_at DESC,
          LOWER(a.microsoft_email) ASC
      `)
      .all() as Record<string, unknown>[];
    return rows.map(mapMailboxRow);
  }

  getMailbox(mailboxId: number): MicrosoftMailboxRecord | null {
    const row = this.db
      .query(`
        SELECT
          m.*,
          a.microsoft_email,
          a.group_name,
          a.proof_mailbox_address
        FROM microsoft_mailboxes m
        JOIN microsoft_accounts a ON a.id = m.account_id
        WHERE m.id = ?
      `)
      .get(mailboxId) as Record<string, unknown> | null;
    return row ? mapMailboxRow(row) : null;
  }

  getMailboxByAccountId(accountId: number): MicrosoftMailboxRecord | null {
    const row = this.db
      .query(`
        SELECT
          m.*,
          a.microsoft_email,
          a.group_name,
          a.proof_mailbox_address
        FROM microsoft_mailboxes m
        JOIN microsoft_accounts a ON a.id = m.account_id
        WHERE m.account_id = ?
      `)
      .get(accountId) as Record<string, unknown> | null;
    return row ? mapMailboxRow(row) : null;
  }

  getMailboxByOauthState(oauthState: string): MicrosoftMailboxRecord | null {
    const normalizedState = oauthState.trim();
    if (!normalizedState) return null;
    const row = this.db
      .query(`
        SELECT
          m.*,
          a.microsoft_email,
          a.group_name,
          a.proof_mailbox_address
        FROM microsoft_mailboxes m
        JOIN microsoft_accounts a ON a.id = m.account_id
        WHERE m.oauth_state = ?
      `)
      .get(normalizedState) as Record<string, unknown> | null;
    return row ? mapMailboxRow(row) : null;
  }

  saveMailboxOauthStart(
    mailboxId: number,
    input: {
      oauthState: string;
      oauthCodeVerifier: string;
      authority?: string;
    },
  ): MicrosoftMailboxRecord {
    const now = nowIso();
    this.db
      .query(`
        UPDATE microsoft_mailboxes
        SET status = 'preparing',
            sync_enabled = 1,
            authority = ?,
            oauth_state = ?,
            oauth_code_verifier = ?,
            oauth_started_at = ?,
            last_error_code = NULL,
            last_error_message = NULL,
            updated_at = ?
        WHERE id = ?
      `)
      .run((input.authority || "common").trim() || "common", input.oauthState, input.oauthCodeVerifier, now, now, mailboxId);
    return this.getMailbox(mailboxId)!;
  }

  completeMailboxOAuth(
    mailboxId: number,
    input: {
      refreshToken: string;
      accessToken: string | null;
      accessTokenExpiresAt: string | null;
      authority: string;
      graphUserId?: string | null;
      graphUserPrincipalName?: string | null;
      graphDisplayName?: string | null;
    },
  ): MicrosoftMailboxRecord {
    const now = nowIso();
    this.db
      .query(`
        UPDATE microsoft_mailboxes
        SET status = CASE WHEN last_synced_at IS NULL THEN 'preparing' ELSE 'available' END,
            sync_enabled = 1,
            refresh_token = ?,
            access_token = ?,
            access_token_expires_at = ?,
            graph_user_id = ?,
            graph_user_principal_name = ?,
            graph_display_name = ?,
            authority = ?,
            oauth_state = NULL,
            oauth_code_verifier = NULL,
            oauth_started_at = NULL,
            oauth_connected_at = ?,
            last_error_code = NULL,
            last_error_message = NULL,
            updated_at = ?
        WHERE id = ?
      `)
      .run(
        input.refreshToken,
        input.accessToken,
        input.accessTokenExpiresAt,
        input.graphUserId ?? null,
        input.graphUserPrincipalName ?? null,
        input.graphDisplayName ?? null,
        input.authority.trim() || "common",
        now,
        now,
        mailboxId,
      );
    return this.getMailbox(mailboxId)!;
  }

  updateMailboxTokens(
    mailboxId: number,
    input: {
      refreshToken?: string | null;
      accessToken?: string | null;
      accessTokenExpiresAt?: string | null;
      authority?: string;
    },
  ): MicrosoftMailboxRecord {
    const current = this.getMailbox(mailboxId);
    if (!current) {
      throw new Error(`mailbox not found: ${mailboxId}`);
    }
    const now = nowIso();
    this.db
      .query(`
        UPDATE microsoft_mailboxes
        SET refresh_token = ?,
            access_token = ?,
            access_token_expires_at = ?,
            authority = ?,
            updated_at = ?
        WHERE id = ?
      `)
      .run(
        input.refreshToken === undefined ? current.refreshToken : input.refreshToken,
        input.accessToken === undefined ? current.accessToken : input.accessToken,
        input.accessTokenExpiresAt === undefined ? current.accessTokenExpiresAt : input.accessTokenExpiresAt,
        input.authority === undefined ? current.authority : input.authority.trim() || "common",
        now,
        mailboxId,
      );
    return this.getMailbox(mailboxId)!;
  }

  markMailboxStatus(
    mailboxId: number,
    input: {
      status: MailboxStatus;
      lastErrorCode?: string | null;
      lastErrorMessage?: string | null;
      accessToken?: string | null;
      accessTokenExpiresAt?: string | null;
      refreshToken?: string | null;
      deltaLink?: string | null;
      unreadCount?: number;
      lastSyncedAt?: string | null;
    },
  ): MicrosoftMailboxRecord {
    const current = this.getMailbox(mailboxId);
    if (!current) {
      throw new Error(`mailbox not found: ${mailboxId}`);
    }
    const now = nowIso();
    this.db
      .query(`
        UPDATE microsoft_mailboxes
        SET status = ?,
            refresh_token = ?,
            access_token = ?,
            access_token_expires_at = ?,
            delta_link = ?,
            unread_count = ?,
            last_synced_at = ?,
            last_error_code = ?,
            last_error_message = ?,
            updated_at = ?
        WHERE id = ?
      `)
      .run(
        input.status,
        input.refreshToken === undefined ? current.refreshToken : input.refreshToken,
        input.accessToken === undefined ? current.accessToken : input.accessToken,
        input.accessTokenExpiresAt === undefined ? current.accessTokenExpiresAt : input.accessTokenExpiresAt,
        input.deltaLink === undefined ? current.deltaLink : input.deltaLink,
        input.unreadCount === undefined ? current.unreadCount : Math.max(0, Math.trunc(input.unreadCount)),
        input.lastSyncedAt === undefined ? current.lastSyncedAt : input.lastSyncedAt,
        input.lastErrorCode === undefined ? current.lastErrorCode : input.lastErrorCode,
        input.lastErrorMessage === undefined ? current.lastErrorMessage : input.lastErrorMessage,
        now,
        mailboxId,
      );
    return this.getMailbox(mailboxId)!;
  }

  upsertMailboxMessages(
    mailboxId: number,
    messages: Array<{
      graphMessageId: string;
      internetMessageId?: string | null;
      conversationId?: string | null;
      subject?: string | null;
      fromName?: string | null;
      fromAddress?: string | null;
      receivedAt?: string | null;
      isRead?: boolean;
      hasAttachments?: boolean;
      bodyContentType?: "html" | "text";
      bodyPreview?: string | null;
      bodyContent?: string | null;
      webLink?: string | null;
    }>,
    options?: {
      removedGraphMessageIds?: string[];
      keepLatest?: number;
    },
  ): { insertedOrUpdated: number; removed: number } {
    const keepLatest = Math.max(1, Math.trunc(options?.keepLatest || 500));
    const normalizedRemovedIds = Array.from(
      new Set((options?.removedGraphMessageIds || []).map((item) => item.trim()).filter(Boolean)),
    );
    const now = nowIso();
    let insertedOrUpdated = 0;
    let removed = 0;
    const upsertStmt = this.db.query(`
      INSERT INTO microsoft_mail_messages (
        mailbox_id, graph_message_id, internet_message_id, conversation_id, subject, from_name, from_address, received_at,
        is_read, has_attachments, body_content_type, body_preview, body_content, web_link, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(mailbox_id, graph_message_id) DO UPDATE SET
        internet_message_id = excluded.internet_message_id,
        conversation_id = excluded.conversation_id,
        subject = excluded.subject,
        from_name = excluded.from_name,
        from_address = excluded.from_address,
        received_at = excluded.received_at,
        is_read = excluded.is_read,
        has_attachments = excluded.has_attachments,
        body_content_type = excluded.body_content_type,
        body_preview = excluded.body_preview,
        body_content = excluded.body_content,
        web_link = excluded.web_link,
        updated_at = excluded.updated_at
    `);
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      for (const message of messages) {
        const graphMessageId = message.graphMessageId.trim();
        if (!graphMessageId) continue;
        upsertStmt.run(
          mailboxId,
          graphMessageId,
          message.internetMessageId ?? null,
          message.conversationId ?? null,
          message.subject ?? "",
          message.fromName ?? null,
          message.fromAddress ?? null,
          message.receivedAt ?? null,
          message.isRead ? 1 : 0,
          message.hasAttachments ? 1 : 0,
          message.bodyContentType === "html" ? "html" : "text",
          message.bodyPreview ?? "",
          message.bodyContent ?? "",
          message.webLink ?? null,
          now,
          now,
        );
        insertedOrUpdated += 1;
      }
      if (normalizedRemovedIds.length > 0) {
        const placeholders = normalizedRemovedIds.map(() => "?").join(", ");
        this.db
          .query(`DELETE FROM microsoft_mail_messages WHERE mailbox_id = ? AND graph_message_id IN (${placeholders})`)
          .run(mailboxId, ...normalizedRemovedIds);
        removed += Number((this.db.query("SELECT changes() AS count").get() as { count?: number } | null)?.count || 0);
      }
      this.db
        .query(`
          DELETE FROM microsoft_mail_messages
          WHERE id IN (
            SELECT id
            FROM microsoft_mail_messages
            WHERE mailbox_id = ?
            ORDER BY
              CASE WHEN received_at IS NULL THEN 1 ELSE 0 END,
              received_at DESC,
              id DESC
            LIMIT -1 OFFSET ?
          )
        `)
        .run(mailboxId, keepLatest);
      removed += Number((this.db.query("SELECT changes() AS count").get() as { count?: number } | null)?.count || 0);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
    return { insertedOrUpdated, removed };
  }

  countMailboxUnread(mailboxId: number): number {
    const row = this.db
      .query("SELECT COUNT(*) AS count FROM microsoft_mail_messages WHERE mailbox_id = ? AND is_read = 0")
      .get(mailboxId) as { count?: number } | null;
    return Number(row?.count || 0);
  }

  listMailboxMessages(mailboxId: number, options?: { limit?: number; offset?: number }): { rows: MicrosoftMailMessageRecord[]; total: number } {
    const limit = Math.max(1, Math.min(100, Math.trunc(options?.limit || 50)));
    const offset = Math.max(0, Math.trunc(options?.offset || 0));
    const total = Number(
      (
        this.db
          .query("SELECT COUNT(*) AS count FROM microsoft_mail_messages WHERE mailbox_id = ?")
          .get(mailboxId) as { count?: number } | null
      )?.count || 0,
    );
    const rows = this.db
      .query(`
        SELECT *
        FROM microsoft_mail_messages
        WHERE mailbox_id = ?
        ORDER BY
          CASE WHEN received_at IS NULL THEN 1 ELSE 0 END,
          received_at DESC,
          id DESC
        LIMIT ? OFFSET ?
      `)
      .all(mailboxId, limit, offset) as Record<string, unknown>[];
    return {
      rows: rows.map(mapMailboxMessageRow),
      total,
    };
  }

  getMailboxMessage(messageId: number): MicrosoftMailMessageRecord | null {
    const row = this.db.query("SELECT * FROM microsoft_mail_messages WHERE id = ?").get(messageId) as Record<string, unknown> | null;
    return row ? mapMailboxMessageRow(row) : null;
  }

  getMailboxMessageByGraphId(mailboxId: number, graphMessageId: string): MicrosoftMailMessageRecord | null {
    const normalizedGraphMessageId = graphMessageId.trim();
    if (!normalizedGraphMessageId) return null;
    const row = this.db
      .query("SELECT * FROM microsoft_mail_messages WHERE mailbox_id = ? AND graph_message_id = ?")
      .get(mailboxId, normalizedGraphMessageId) as Record<string, unknown> | null;
    return row ? mapMailboxMessageRow(row) : null;
  }

  private hasNonRetryableAttemptForJob(jobId: number, accountId: number): boolean {
    const attempted = this.db
      .query(`
        SELECT 1 AS blocked
        FROM job_attempts
        WHERE job_id = ?
          AND account_id = ?
          AND status IN ('running', 'succeeded')
        LIMIT 1
      `)
      .get(jobId, accountId) as { blocked?: number } | null;
    return Boolean(attempted?.blocked);
  }

  isAccountSchedulableForJob(jobId: number, accountId: number): boolean {
    const account = this.getAccount(accountId);
    if (!account) return false;
    if (account.disabledAt != null) return false;
    if (account.hasApiKey) return false;
    if (isBlockingAccountSkipReason(account.skipReason)) return false;
    if (account.leaseJobId != null) return false;
    return !this.hasNonRetryableAttemptForJob(jobId, accountId);
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

  createAccountExtractBatch(input: {
    jobId?: number | null;
    provider: AccountExtractorProvider;
    accountType?: AccountExtractorAccountType;
    requestedUsableCount: number;
    attemptBudget: number;
    acceptedCount?: number;
    status: AccountExtractBatchStatus;
    errorMessage?: string | null;
    rawResponse?: string | null;
    maskedKey?: string | null;
    startedAt?: string;
    completedAt?: string | null;
  }): AccountExtractBatchRecord {
    const row = this.db
      .query(`
        INSERT INTO account_extract_batches (
          job_id, provider, account_type, requested_usable_count, attempt_budget, accepted_count, status,
          error_message, raw_response, masked_key, started_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *
      `)
      .get(
        input.jobId ?? null,
        input.provider,
        input.accountType || "outlook",
        Math.max(0, input.requestedUsableCount),
        Math.max(0, input.attemptBudget),
        Math.max(0, input.acceptedCount || 0),
        input.status,
        input.errorMessage ?? null,
        input.rawResponse ?? null,
        input.maskedKey ?? null,
        input.startedAt || nowIso(),
        input.completedAt ?? null,
      ) as Record<string, unknown>;
    return mapAccountExtractBatchRow(row);
  }

  updateAccountExtractBatch(
    batchId: number,
    patch: Partial<Pick<AccountExtractBatchRecord, "acceptedCount" | "status" | "errorMessage" | "rawResponse" | "maskedKey" | "completedAt">>,
  ): AccountExtractBatchRecord {
    const current = this.db.query("SELECT * FROM account_extract_batches WHERE id = ?").get(batchId) as Record<string, unknown> | null;
    if (!current) {
      throw new Error(`account extract batch not found: ${batchId}`);
    }
    const next = {
      ...mapAccountExtractBatchRow(current),
      ...patch,
    };
    this.db
      .query(`
        UPDATE account_extract_batches
        SET accepted_count = ?,
            status = ?,
            error_message = ?,
            raw_response = ?,
            masked_key = ?,
            completed_at = ?
        WHERE id = ?
      `)
      .run(next.acceptedCount, next.status, next.errorMessage, next.rawResponse, next.maskedKey, next.completedAt, batchId);
    return mapAccountExtractBatchRow(this.db.query("SELECT * FROM account_extract_batches WHERE id = ?").get(batchId) as Record<string, unknown>);
  }

  createAccountExtractItem(input: {
    batchId: number;
    provider: AccountExtractorProvider;
    rawPayload: string;
    email?: string | null;
    password?: string | null;
    parseStatus: AccountExtractItemParseStatus;
    acceptStatus: AccountExtractItemAcceptStatus;
    rejectReason?: string | null;
    importedAccountId?: number | null;
    createdAt?: string;
  }): AccountExtractItemRecord {
    const row = this.db
      .query(`
        INSERT INTO account_extract_items (
          batch_id, provider, raw_payload, email, password, parse_status, accept_status, reject_reason, imported_account_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *
      `)
      .get(
        input.batchId,
        input.provider,
        input.rawPayload,
        input.email ?? null,
        input.password ?? null,
        input.parseStatus,
        input.acceptStatus,
        input.rejectReason ?? null,
        input.importedAccountId ?? null,
        input.createdAt || nowIso(),
      ) as Record<string, unknown>;
    return mapAccountExtractItemRow(row);
  }

  listAccountExtractHistory(filters: {
    provider?: AccountExtractorProvider;
    status?: string;
    q?: string;
    page?: number;
    pageSize?: number;
  }): {
    rows: Array<AccountExtractBatchRecord & { items: AccountExtractItemRecord[] }>;
    total: number;
    page: number;
    pageSize: number;
  } {
    const page = Math.max(1, filters.page || 1);
    const pageSize = Math.max(1, Math.min(100, filters.pageSize || 20));
    const where: string[] = [];
    const params: unknown[] = [];
    if (filters.provider) {
      where.push("b.provider = ?");
      params.push(filters.provider);
    }
    if (filters.status?.trim()) {
      where.push("b.status = ?");
      params.push(filters.status.trim());
    }
    if (filters.q?.trim()) {
      const pattern = `%${filters.q.trim().toLowerCase()}%`;
      where.push(`
        EXISTS (
          SELECT 1
          FROM account_extract_items i
          WHERE i.batch_id = b.id
            AND (
              LOWER(COALESCE(i.email, '')) LIKE ?
              OR LOWER(COALESCE(i.raw_payload, '')) LIKE ?
              OR LOWER(COALESCE(i.reject_reason, '')) LIKE ?
            )
        )
      `);
      params.push(pattern, pattern, pattern);
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const total = Number(
      (
        this.db
          .query(`SELECT COUNT(*) AS count FROM account_extract_batches b ${whereSql}`)
          .get(...(params as any[])) as { count?: number } | null
      )?.count || 0,
    );
    const batchRows = this.db
      .query(`
        SELECT b.*
        FROM account_extract_batches b
        ${whereSql}
        ORDER BY b.started_at DESC, b.id DESC
        LIMIT ? OFFSET ?
      `)
      .all(...([...(params as any[]), pageSize, (page - 1) * pageSize] as any[])) as Record<string, unknown>[];
    const batches = batchRows.map(mapAccountExtractBatchRow);
    if (batches.length === 0) {
      return { rows: [], total, page, pageSize };
    }
    const placeholders = batches.map(() => "?").join(", ");
    const itemRows = this.db
      .query(`
        SELECT *
        FROM account_extract_items
        WHERE batch_id IN (${placeholders})
        ORDER BY created_at ASC, id ASC
      `)
      .all(...batches.map((row) => row.id)) as Record<string, unknown>[];
    const itemsByBatch = new Map<number, AccountExtractItemRecord[]>();
    for (const row of itemRows.map(mapAccountExtractItemRow)) {
      const current = itemsByBatch.get(row.batchId) || [];
      current.push(row);
      itemsByBatch.set(row.batchId, current);
    }
    return {
      rows: batches.map((batch) => ({
        ...batch,
        items: itemsByBatch.get(batch.id) || [],
      })),
      total,
      page,
      pageSize,
    };
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
      status: shouldPreserveManualStopStatus(currentJob.status)
        ? currentJob.status
        : shouldEnterCompleting({
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
    const current = this.getAccount(accountId);
    if (!current) {
      throw new Error(`account not found: ${accountId}`);
    }
    const now = nowIso();
    const releaseLease = options?.releaseLease !== false;
    const nextSkipReason = resolveFailureSkipReason({
      hasApiKey: current.hasApiKey,
      currentSkipReason: current.skipReason,
      errorCode,
    });
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = ?,
            skip_reason = ?,
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
      .run(resolveFailureResultStatus({ disabledAt: current.disabledAt, skipReason: nextSkipReason }), nextSkipReason, now, errorCode ?? null, now, accountId);
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
    const currentAccount = this.getAccount(accountId);
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
    const nextSkipReason = resolveFailureSkipReason({
      hasApiKey: currentAccount?.hasApiKey ?? false,
      currentSkipReason: currentAccount?.skipReason ?? null,
      errorCode,
    });
    this.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = ?,
            skip_reason = ?,
            last_result_at = ?,
            last_error_code = ?,
            updated_at = ?,
            lease_job_id = NULL,
            lease_started_at = NULL
        WHERE id = ?
      `)
      .run(resolveFailureResultStatus({ disabledAt: currentAccount?.disabledAt ?? null, skipReason: nextSkipReason }), nextSkipReason, now, errorCode, now, accountId);
    const job = this.updateJobState(jobId, {
      failureCount: currentJob.failureCount + 1,
      status: shouldPreserveManualStopStatus(currentJob.status)
        ? currentJob.status
        : shouldEnterCompleting(currentJob)
          ? "completing"
          : currentJob.status,
    });
    return { job, attempt };
  }

  rollbackAttemptBeforeLaunch(jobId: number, attemptId: number, accountId: number): { job: JobRecord; account: MicrosoftAccountRecord | null } {
    const currentJob = this.getJob(jobId);
    if (!currentJob) throw new Error(`job not found: ${jobId}`);
    const currentAccount = this.getAccount(accountId);
    if (!currentAccount) throw new Error(`account not found: ${accountId}`);
    if (!this.getAttempt(attemptId)) {
      throw new Error(`attempt not found: ${attemptId}`);
    }
    const now = nowIso();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db.query("DELETE FROM job_attempts WHERE id = ?").run(attemptId);
      this.db
        .query(`
          UPDATE microsoft_accounts
          SET last_result_status = ?,
              updated_at = ?,
              lease_job_id = NULL,
              lease_started_at = NULL
          WHERE id = ?
        `)
        .run(resolveReleasedLeaseAccountStatus(currentAccount), now, accountId);
      this.db
        .query(`
          UPDATE jobs
          SET launched_count = ?, updated_at = ?
          WHERE id = ?
        `)
        .run(Math.max(0, currentJob.launchedCount - 1), now, jobId);
      this.db.exec("COMMIT;");
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
    return {
      job: this.getJob(jobId)!,
      account: this.getAccount(accountId),
    };
  }

  completeJob(jobId: number, success: boolean, errorMessage?: string): JobRecord {
    return this.updateJobState(jobId, {
      status: success ? "completed" : "failed",
      completedAt: nowIso(),
      lastError: errorMessage || null,
    });
  }

  stopJob(jobId: number): JobRecord {
    return this.updateJobState(jobId, {
      status: "stopped",
      pausedAt: null,
      completedAt: nowIso(),
      lastError: null,
    });
  }

  completeAttemptStopped(
    jobId: number,
    attemptId: number,
    accountId: number,
    input?: { errorCode?: string | null; errorMessage?: string | null },
    signupTask?: Record<string, unknown> | null,
  ): { job: JobRecord; attempt: JobAttemptRecord } {
    const now = nowIso();
    const currentJob = this.getJob(jobId);
    if (!currentJob) throw new Error(`job not found: ${jobId}`);
    const startedAt = this.getAttempt(attemptId)?.startedAt || now;
    const durationMs = Math.max(0, Date.parse(now) - Date.parse(startedAt));
    const errorCode = input?.errorCode || "force_stopped";
    const errorMessage = input?.errorMessage || "stopped by user";
    const attempt = this.updateAttempt(attemptId, {
      status: "stopped",
      stage: "stopped",
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
        SET last_result_status = CASE
              WHEN disabled_at IS NOT NULL THEN 'disabled'
              WHEN has_api_key = 1 THEN 'skipped_has_key'
              ELSE 'ready'
            END,
            last_result_at = ?,
            last_error_code = ?,
            updated_at = ?,
            lease_job_id = NULL,
            lease_started_at = NULL
        WHERE id = ?
      `)
      .run(now, errorCode, now, accountId);
    return {
      job: currentJob,
      attempt,
    };
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

  getProxyNodeLastStatus(nodeName: string): string | null {
    const normalized = nodeName.trim();
    if (!normalized) return null;
    const row = this.db
      .query("SELECT last_status FROM proxy_nodes WHERE node_name = ? LIMIT 1")
      .get(normalized) as { last_status?: string | null } | null;
    return row?.last_status == null ? null : String(row.last_status);
  }

  hasProxyNode(nodeName: string): boolean {
    const normalized = nodeName.trim();
    if (!normalized) return false;
    const row = this.db.query("SELECT 1 AS present FROM proxy_nodes WHERE node_name = ? LIMIT 1").get(normalized) as { present?: number } | null;
    return row?.present === 1;
  }
}
