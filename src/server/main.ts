import { config as loadDotenv } from "dotenv";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
  ensureCfMailMailbox,
  normalizeCfMailBaseUrl,
  type CfMailHttpJson,
} from "../cfmail-api.js";
import { buildChatGptDraft } from "./chatgpt-draft.js";
import { startMihomo } from "../proxy/mihomo.js";
import {
  createMihomoNodeCheckRunner,
  createProxyCheckCoordinator,
  resolveProxyCheckConcurrency,
  type ProxyCheckScope,
  type ProxyCheckState,
} from "./proxy-check-coordinator.js";
import {
  AppDatabase,
  normalizeAccountExtractorAccountType,
  normalizeJobMaxAttempts,
  type AccountExtractorProvider,
  type AppSettings,
  type ChatGptCredentialRecord,
  type GrokApiKeyRecord,
  type JobAttemptRecord,
  type JobSite,
  type MicrosoftMailboxRecord,
  type MicrosoftAccountRecord,
  type MicrosoftMailMessageRecord,
} from "../storage/app-db.js";
import {
  getAccountSessionBootstrapBlockMessage,
  hasConfiguredMicrosoftGraphBootstrap,
  isLockedAccountRecord,
  normalizeAccountBatchBootstrapMode,
  normalizeAccountSessionRebootstrapRequest,
  resolveAccountBatchBootstrapDecision,
  resolveBootstrapQueueDisposition,
  resolveRequestedSessionProxyNode,
  shouldReplayPendingAccountBootstrap,
  shouldForceImportedAccountBootstrap,
  shouldQueueImportedAccountBootstrap,
  type AccountBatchBootstrapMode,
} from "./account-session-bootstrap.js";
import { resolveTaskLedgerDbPath } from "../storage/db-paths.js";
import {
  buildNextSettings,
  buildNextProxySettings,
  listUnexpectedProxySettingsKeys,
  validateBeforePersist,
  validateProxySettingsBeforePersist,
  type ProxySettingsUpdate,
} from "./app-settings.js";
import { buildImportPreview, parseImportContent, type InvalidImportRow, type ParsedImportEntry } from "./account-import.js";
import { serializeAttemptForApi } from "./attempt-view.js";
import { createExclusiveRunner } from "./exclusive-runner.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import { JobScheduler, resolveWorkerRuntime, type ServerEvent } from "./scheduler.js";
import { ChatGptJobScheduler } from "./chatgpt-scheduler.js";
import {
  ChatGptUpstreamSupplementService,
  normalizeChatGptUpstreamGroupName,
  readChatGptJobUpstreamGroupName,
} from "./chatgpt-upstream-supplement.js";
import { assertRunModeAvailable, clampRunModeToAvailability } from "./run-mode-availability.js";
import { BrowserAvailabilityService } from "./browser-availability.js";
import { GrokJobScheduler } from "./grok-scheduler.js";
import { resolveStaticAssetPath, shouldServeSpaFallback } from "./static-assets.js";
import { buildApiKeyExportContent, buildGrokSsoExportContent } from "./api-key-export.js";
import { AccountExtractorRuntime } from "./account-extractor-runtime.js";
import {
  assertMicrosoftGraphSettings,
  buildMicrosoftAuthorizeUrl,
  createMicrosoftOauthState,
  createMicrosoftPkcePair,
  exchangeMicrosoftAuthCode,
  fetchMicrosoftMessageDetail,
  fetchMicrosoftProfile,
  getMailboxErrorCode,
  getMailboxErrorMessage,
  isMicrosoftOauthCompletionUrl,
  isLockedMailboxErrorCode,
  isMicrosoftTokenExpired,
  refreshMicrosoftAccessToken,
  syncMicrosoftInbox,
  toMailboxFailureStatus,
  type MicrosoftGraphSettingsInput,
} from "./microsoft-mail.js";
import {
  AccountBusinessFlowManager,
  type AccountBusinessFlowMode,
  type AccountBusinessFlowSite,
} from "./account-business-flow.js";
import {
  matchMailboxVerificationCodeForMessage,
  pickLatestMailboxVerificationCode,
} from "./microsoft-mailbox-verification.js";

loadDotenv({ path: ".env.local", quiet: true });

const REPO_ROOT = process.cwd();
const OUTPUT_ROOT = path.join(REPO_ROOT, "output");
const LEGACY_PROXY_USAGE_PATH = path.join(OUTPUT_ROOT, "proxy", "node-usage.json");
const DEFAULT_DB_PATH = resolveTaskLedgerDbPath(OUTPUT_ROOT, process.env.TASK_LEDGER_DB_PATH);
const WEB_DIST_DIR = path.join(REPO_ROOT, "web", "dist");
const DEFAULT_CFMAIL_ROOT_DOMAIN = String(process.env.CHATGPT_CFMAIL_ROOT_DOMAIN || "").trim() || undefined;
let appDbRef: AppDatabase | null = null;
let accountBusinessFlowManager: AccountBusinessFlowManager | null = null;
let browserAvailabilityService: BrowserAvailabilityService | null = null;

async function ensureBrowserAvailabilityFresh(): Promise<void> {
  await browserAvailabilityService?.ensureFresh();
}

function getBrowserRunModeAvailability() {
  return browserAvailabilityService?.getRunModeAvailability() || {
    headed: false,
    headless: true as const,
    headedReason: "正在检测当前环境的浏览器能力。",
  };
}

function getDefaultAccountBusinessFlowAvailability() {
  return browserAvailabilityService?.getAccountBusinessFlowAvailability() || {
    headless: true as const,
    headed: false,
    fingerprint: false,
    headedReason: "正在检测当前环境的浏览器能力。",
    fingerprintReason: "正在检测当前环境的浏览器能力。",
    deAvailable: false,
  };
}

function toInt(value: string | undefined, fallback: number): number {
  if (!value || !value.trim()) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function nowIso(): string {
  return new Date().toISOString();
}

function json(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(data), {
    status: init?.status || 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...init?.headers,
    },
  });
}

function badRequest(message: string, status = 400): Response {
  return json({ error: message }, { status });
}

function parseBody(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed;
  }
}

const serverHttpJson: CfMailHttpJson = async (method, url, options) => {
  const headers: Record<string, string> = { ...(options?.headers || {}) };
  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
    body = JSON.stringify(options.body);
  }
  const resp = await fetch(url, {
    method,
    headers,
    body,
  });
  const text = await resp.text();
  const parsed = parseBody(text);
  if (!resp.ok) {
    throw new Error(`http_failed:${resp.status}:${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed as never;
};

function splitEmailAddress(email: string): { local: string; domain: string } | null {
  const normalized = email.trim().toLowerCase();
  const atIndex = normalized.indexOf("@");
  if (atIndex <= 0 || atIndex === normalized.length - 1) {
    return null;
  }
  return {
    local: normalized.slice(0, atIndex),
    domain: normalized.slice(atIndex + 1),
  };
}

function shouldRetryAccountBootstrapWithFreshProxy(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET|ERR_TIMED_OUT|network_connection_closed|network_connection_reset|network_timeout|page\.goto:\s*net::ERR_CONNECTION_CLOSED|page\.goto:\s*net::ERR_CONNECTION_RESET|page\.goto:\s*net::ERR_TIMED_OUT|chromium_net_error:ERR_CONNECTION_CLOSED|chromium_net_error:ERR_CONNECTION_RESET|chromium_net_error:ERR_TIMED_OUT|proxy_node_unavailable/i.test(
    message,
  );
}

async function ensureSavedProofMailbox(input: {
  address: string;
  mailboxId?: string | null;
}): Promise<{ provider: "cfmail"; address: string; mailboxId: string }> {
  const address = input.address.trim().toLowerCase();
  const hintedMailboxId = String(input.mailboxId || "").trim();
  const apiKey = (process.env.CFMAIL_API_KEY || "").trim();
  if (!apiKey) {
    if (hintedMailboxId) {
      return {
        provider: "cfmail",
        address,
        mailboxId: hintedMailboxId,
      };
    }
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test");
  const ensured = await ensureCfMailMailbox({
    baseUrl,
    apiKey,
    httpJson: serverHttpJson,
    address,
  });
  if (ensured.address.trim().toLowerCase() !== address) {
    throw new Error(`cfmail_mailbox_not_found:${address}`);
  }
  return {
    provider: "cfmail",
    address,
    mailboxId: ensured.id || hintedMailboxId,
  };
}

function parseBool(value: string | null): boolean | undefined {
  if (value == null) return undefined;
  if (["1", "true", "yes", "on"].includes(value.toLowerCase())) return true;
  if (["0", "false", "no", "off"].includes(value.toLowerCase())) return false;
  return undefined;
}

function maskSecret(secret: string, visible = 4): string {
  if (!secret) return "";
  if (secret.length <= visible) return "*".repeat(secret.length);
  return `${"*".repeat(Math.max(4, secret.length - visible))}${secret.slice(-visible)}`;
}

function normalizeServerHost(host: string | undefined): string {
  const normalized = String(host || "").trim();
  return normalized || "127.0.0.1";
}

function normalizeExtractorSources(value: unknown): AccountExtractorProvider[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value.filter(
        (item): item is AccountExtractorProvider =>
          item === "zhanghaoya" || item === "shanyouxiang" || item === "shankeyun" || item === "hotmail666",
      ),
    ),
  );
}

function normalizeExtractorAccountType(value: unknown, fallback?: AppSettings["defaultAutoExtractAccountType"]) {
  return normalizeAccountExtractorAccountType(value, fallback);
}

function toOptionalPositiveInt(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(1, Math.trunc(value));
  if (typeof value === "string" && value.trim()) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) return Math.max(1, parsed);
  }
  return undefined;
}

function serializeExtractorSettings(settings: AppSettings) {
  return {
    extractorZhanghaoyaKey: settings.extractorZhanghaoyaKey,
    extractorShanyouxiangKey: settings.extractorShanyouxiangKey,
    extractorShankeyunKey: settings.extractorShankeyunKey,
    extractorHotmail666Key: settings.extractorHotmail666Key,
    defaultAutoExtractSources: settings.defaultAutoExtractSources,
    defaultAutoExtractQuantity: settings.defaultAutoExtractQuantity,
    defaultAutoExtractMaxWaitSec: settings.defaultAutoExtractMaxWaitSec,
    defaultAutoExtractAccountType: settings.defaultAutoExtractAccountType,
    availability: {
      zhanghaoya: Boolean(settings.extractorZhanghaoyaKey.trim()),
      shanyouxiang: Boolean(settings.extractorShanyouxiangKey.trim()),
      shankeyun: Boolean(settings.extractorShankeyunKey.trim()),
      hotmail666: Boolean(settings.extractorHotmail666Key.trim()),
    },
  };
}

function serializeMicrosoftGraphSettings(settings: AppSettings) {
  return {
    microsoftGraphClientId: settings.microsoftGraphClientId,
    microsoftGraphClientSecretMasked: settings.microsoftGraphClientSecret ? maskSecret(settings.microsoftGraphClientSecret) : "",
    microsoftGraphRedirectUri: settings.microsoftGraphRedirectUri,
    microsoftGraphAuthority: settings.microsoftGraphAuthority || "common",
    configured: Boolean(
      settings.microsoftGraphClientId.trim() &&
        settings.microsoftGraphClientSecret.trim() &&
        settings.microsoftGraphRedirectUri.trim(),
    ),
  };
}

function buildSettingsCodeDefaults(): AppSettings {
  return {
    subscriptionUrl: "",
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: "https://www.cloudflare.com/cdn-cgi/trace",
    timeoutMs: 8000,
    maxLatencyMs: 3000,
    apiPort: 39090,
    mixedPort: 49090,
    serverHost: "127.0.0.1",
    serverPort: 3717,
    defaultRunMode: "headed",
    defaultNeed: 1,
    defaultParallel: 1,
    defaultMaxAttempts: 5,
    extractorZhanghaoyaKey: "",
    extractorShanyouxiangKey: "",
    extractorShankeyunKey: "",
    extractorHotmail666Key: "",
    defaultAutoExtractSources: [],
    defaultAutoExtractQuantity: 1,
    defaultAutoExtractMaxWaitSec: 60,
    defaultAutoExtractAccountType: "outlook",
    microsoftGraphClientId: "",
    microsoftGraphClientSecret: "",
    microsoftGraphRedirectUri: "",
    microsoftGraphAuthority: "common",
  };
}

function buildInitialSettingsFromEnv(baseDefaults: AppSettings): AppSettings {
  return {
    ...baseDefaults,
    subscriptionUrl: (process.env.MIHOMO_SUBSCRIPTION_URL || "").trim(),
    groupName: (process.env.MIHOMO_GROUP_NAME || baseDefaults.groupName).trim() || baseDefaults.groupName,
    routeGroupName: (process.env.MIHOMO_ROUTE_GROUP_NAME || baseDefaults.routeGroupName).trim() || baseDefaults.routeGroupName,
    checkUrl: (process.env.PROXY_CHECK_URL || baseDefaults.checkUrl).trim(),
    timeoutMs: toInt(process.env.PROXY_CHECK_TIMEOUT_MS, baseDefaults.timeoutMs),
    maxLatencyMs: toInt(process.env.PROXY_LATENCY_MAX_MS, baseDefaults.maxLatencyMs),
    apiPort: toInt(process.env.MIHOMO_API_PORT, baseDefaults.apiPort),
    mixedPort: toInt(process.env.MIHOMO_MIXED_PORT, baseDefaults.mixedPort),
    serverHost: normalizeServerHost(process.env.WEB_HOST || baseDefaults.serverHost),
    serverPort: toInt(process.env.WEB_PORT, baseDefaults.serverPort),
    defaultRunMode: (process.env.RUN_MODE || "").trim().toLowerCase() === "headless" ? "headless" : baseDefaults.defaultRunMode,
    defaultNeed: toInt(process.env.WEB_DEFAULT_NEED, baseDefaults.defaultNeed),
    defaultParallel: toInt(process.env.WEB_DEFAULT_PARALLEL, baseDefaults.defaultParallel),
    defaultMaxAttempts: toInt(process.env.WEB_DEFAULT_MAX_ATTEMPTS, baseDefaults.defaultMaxAttempts),
    extractorZhanghaoyaKey: (process.env.EXTRACTOR_ZHANGHAOYA_KEY || "").trim(),
    extractorShanyouxiangKey: (process.env.EXTRACTOR_SHANYOUXIANG_KEY || "").trim(),
    extractorShankeyunKey: (process.env.EXTRACTOR_SHANKEYUN_KEY || "").trim(),
    extractorHotmail666Key: (process.env.EXTRACTOR_HOTMAIL666_KEY || "").trim(),
    defaultAutoExtractSources: normalizeExtractorSources(
      (process.env.WEB_DEFAULT_AUTO_EXTRACT_SOURCES || "")
        .split(",")
        .map((item: string) => item.trim())
        .filter(Boolean),
    ),
    defaultAutoExtractQuantity: toInt(process.env.WEB_DEFAULT_AUTO_EXTRACT_QUANTITY, baseDefaults.defaultAutoExtractQuantity),
    defaultAutoExtractMaxWaitSec: toInt(process.env.WEB_DEFAULT_AUTO_EXTRACT_MAX_WAIT_SEC, baseDefaults.defaultAutoExtractMaxWaitSec),
    microsoftGraphClientId: (process.env.MICROSOFT_GRAPH_CLIENT_ID || "").trim(),
    microsoftGraphClientSecret: (process.env.MICROSOFT_GRAPH_CLIENT_SECRET || "").trim(),
    microsoftGraphRedirectUri: (process.env.MICROSOFT_GRAPH_REDIRECT_URI || "").trim(),
    microsoftGraphAuthority: (process.env.MICROSOFT_GRAPH_AUTHORITY || baseDefaults.microsoftGraphAuthority).trim() || "common",
  };
}

function getRuntimeServerBinding(settings: AppSettings): { host: string; port: number } {
  const envHost = (process.env.WEB_HOST || "").trim();
  const envPort = (process.env.WEB_PORT || "").trim();
  return {
    host: normalizeServerHost(envHost || settings.serverHost),
    port: envPort ? toInt(envPort, settings.serverPort) : settings.serverPort,
  };
}

function serializeAccount(row: MicrosoftAccountRecord): Record<string, unknown> {
  const businessFlow = accountBusinessFlowManager?.serializeAccount(row) ?? {
    businessFlowAvailability: getDefaultAccountBusinessFlowAvailability(),
    businessFlowState: null,
  };
  return {
    id: row.id,
    microsoftEmail: row.microsoftEmail,
    passwordPlaintext: row.passwordPlaintext,
    passwordMasked: maskSecret(row.passwordPlaintext),
    proofMailboxProvider: row.proofMailboxProvider,
    proofMailboxAddress: row.proofMailboxAddress,
    proofMailboxId: row.proofMailboxId,
    hasApiKey: row.hasApiKey,
    apiKeyId: row.apiKeyId,
    importedAt: row.importedAt,
    updatedAt: row.updatedAt,
    importSource: row.importSource,
    accountSource: row.accountSource,
    sourceRawPayload: row.sourceRawPayload,
    lastUsedAt: row.lastUsedAt,
    lastResultStatus: row.lastResultStatus,
    lastResultAt: row.lastResultAt,
    lastErrorCode: row.lastErrorCode,
    skipReason: row.skipReason,
    groupName: row.groupName,
    disabledAt: row.disabledAt,
    disabledReason: row.disabledReason,
    mailboxStatus: row.mailboxStatus,
    mailboxLastSyncedAt: row.mailboxLastSyncedAt,
    mailboxLastErrorCode: row.mailboxLastErrorCode,
    mailboxUnreadCount: row.mailboxUnreadCount,
    browserSession: serializeBrowserSession(row),
    businessFlowAvailability: businessFlow.businessFlowAvailability,
    businessFlowState: businessFlow.businessFlowState,
  };
}

function serializeImportedAccount(row: MicrosoftAccountRecord): Record<string, unknown> {
  return {
    id: row.id,
    microsoftEmail: row.microsoftEmail,
    passwordPlaintext: row.passwordPlaintext,
    passwordMasked: maskSecret(row.passwordPlaintext),
    mailboxStatus: row.mailboxStatus,
    browserSession: serializeBrowserSession(row),
  };
}

function serializeBrowserSession(account: Pick<MicrosoftAccountRecord, "browserSession">): Record<string, unknown> | null {
  const session = account.browserSession;
  if (!session) return null;
  return {
    id: session.id,
    status: session.status,
    profilePath: session.profilePath,
    browserEngine: session.browserEngine,
    proxyNode: session.proxyNode,
    proxyIp: session.proxyIp,
    proxyCountry: session.proxyCountry,
    proxyRegion: session.proxyRegion,
    proxyCity: session.proxyCity,
    proxyTimezone: session.proxyTimezone,
    lastBootstrappedAt: session.lastBootstrappedAt,
    lastUsedAt: session.lastUsedAt,
    lastErrorCode: session.lastErrorCode,
    lastErrorMessage: session.lastErrorMessage,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
  };
}

function toVerificationCodeMessage(message: Pick<MicrosoftMailMessageRecord, "subject" | "fromName" | "fromAddress" | "bodyPreview" | "bodyContent" | "receivedAt">) {
  return {
    subject: message.subject,
    fromName: message.fromName,
    fromAddress: message.fromAddress,
    bodyPreview: message.bodyPreview,
    bodyContent: message.bodyContent,
    receivedAt: message.receivedAt,
  };
}

function resolveLatestMailboxVerificationCode(mailboxId: number) {
  if (!appDbRef) return null;
  return pickLatestMailboxVerificationCode(
    appDbRef.listMailboxMessagesForVerification(mailboxId, { limit: 500 }).map((message) => toVerificationCodeMessage(message)),
  );
}

function resolveLatestMailboxVerificationCodes(mailboxes: readonly MicrosoftMailboxRecord[]) {
  const latestByMailboxId = new Map<number, ReturnType<typeof pickLatestMailboxVerificationCode>>();
  if (!appDbRef || mailboxes.length === 0) return latestByMailboxId;
  const grouped = appDbRef.listMailboxMessagesForVerificationBatch(
    mailboxes.map((mailbox) => mailbox.id),
    { limitPerMailbox: 500 },
  );
  for (const mailbox of mailboxes) {
    latestByMailboxId.set(
      mailbox.id,
      pickLatestMailboxVerificationCode((grouped.get(mailbox.id) || []).map((message) => toVerificationCodeMessage(message))),
    );
  }
  return latestByMailboxId;
}

function serializeMailbox(
  row: MicrosoftMailboxRecord,
  latestVerificationCode = resolveLatestMailboxVerificationCode(row.id),
): Record<string, unknown> {
  return {
    id: row.id,
    accountId: row.accountId,
    microsoftEmail: row.microsoftEmail,
    groupName: row.groupName,
    proofMailboxAddress: row.proofMailboxAddress,
    status: row.status,
    syncEnabled: row.syncEnabled,
    graphUserId: row.graphUserId,
    graphUserPrincipalName: row.graphUserPrincipalName,
    graphDisplayName: row.graphDisplayName,
    authority: row.authority,
    oauthStartedAt: row.oauthStartedAt,
    oauthConnectedAt: row.oauthConnectedAt,
    deltaLink: row.deltaLink,
    unreadCount: row.unreadCount,
    lastSyncedAt: row.lastSyncedAt,
    lastErrorCode: row.lastErrorCode,
    lastErrorMessage: row.lastErrorMessage,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    isAuthorized: Boolean(row.refreshToken),
    latestVerificationCode,
  };
}

function serializeMailboxMessageSummary(row: MicrosoftMailMessageRecord): Record<string, unknown> {
  const verificationCode = matchMailboxVerificationCodeForMessage({
    subject: row.subject,
    fromName: row.fromName,
    fromAddress: row.fromAddress,
    bodyPreview: row.bodyPreview,
    bodyContent: row.bodyContent,
    receivedAt: row.receivedAt,
  });
  return {
    id: row.id,
    mailboxId: row.mailboxId,
    graphMessageId: row.graphMessageId,
    internetMessageId: row.internetMessageId,
    conversationId: row.conversationId,
    subject: row.subject,
    fromName: row.fromName,
    fromAddress: row.fromAddress,
    receivedAt: row.receivedAt,
    isRead: row.isRead,
    hasAttachments: row.hasAttachments,
    bodyContentType: row.bodyContentType,
    bodyPreview: row.bodyPreview,
    webLink: row.webLink,
    updatedAt: row.updatedAt,
    verificationCode,
  };
}

function serializeMailboxMessageDetail(row: MicrosoftMailMessageRecord): Record<string, unknown> {
  const verificationCode = matchMailboxVerificationCodeForMessage({
    subject: row.subject,
    fromName: row.fromName,
    fromAddress: row.fromAddress,
    bodyPreview: row.bodyPreview,
    bodyContent: row.bodyContent,
    receivedAt: row.receivedAt,
  });
  return {
    ...serializeMailboxMessageSummary(row),
    bodyContent: row.bodyContent,
    createdAt: row.createdAt,
    verificationCode,
  };
}

function readMicrosoftGraphSettings(settings: AppSettings): MicrosoftGraphSettingsInput {
  return {
    clientId: settings.microsoftGraphClientId,
    clientSecret: settings.microsoftGraphClientSecret,
    redirectUri: settings.microsoftGraphRedirectUri,
    authority: settings.microsoftGraphAuthority || "common",
  };
}

function buildRequestOriginUrl(req: Request): URL {
  const target = new URL(req.url);
  const forwardedProto = String(req.headers.get("x-forwarded-proto") || "")
    .split(",")[0]
    ?.trim();
  const forwardedHost = String(req.headers.get("x-forwarded-host") || "")
    .split(",")[0]
    ?.trim();
  if (forwardedProto) {
    target.protocol = `${forwardedProto}:`;
  }
  if (forwardedHost) {
    target.host = forwardedHost;
  }
  return target;
}

function buildMailboxRedirect(req: Request, accountId: number | null, outcome: "success" | "error"): Response {
  const target = new URL("/mailboxes", buildRequestOriginUrl(req));
  if (accountId) {
    target.searchParams.set("accountId", String(accountId));
  }
  target.searchParams.set("oauth", outcome);
  return Response.redirect(target.toString(), 302);
}

function getAccountConnectBlockMessage(
  account: Pick<MicrosoftAccountRecord, "leaseJobId" | "skipReason" | "lastErrorCode" | "disabledAt" | "hasApiKey" | "mailboxStatus" | "browserSession">,
): string | null {
  return getAccountSessionBootstrapBlockMessage(account);
}

function buildAccountBatchBootstrapPreview(
  db: AppDatabase,
  accountIds: number[],
  mode: AccountBatchBootstrapMode,
  queuedAccountIds?: ReadonlySet<number>,
): {
  mode: AccountBatchBootstrapMode;
  requestedCount: number;
  queueIds: number[];
  items: Array<{
    accountId: number | null;
    microsoftEmail: string | null;
    decision: "queue" | "blocked" | "already_bootstrapped" | "bootstrapping" | "missing";
    reason: string | null;
  }>;
  summary: {
    queueableCount: number;
    blockedCount: number;
    alreadyBootstrappedCount: number;
    bootstrappingCount: number;
    missingCount: number;
  };
} {
  const normalizedIds = Array.from(new Set(accountIds.filter((id) => Number.isInteger(id) && id > 0)));
  const items = normalizedIds.map((accountId) => {
    const account = db.getAccount(accountId);
    const result =
      queuedAccountIds?.has(accountId)
        ? { decision: "bootstrapping" as const, reason: "账号已在 Bootstrap 队列中" }
        : resolveAccountBatchBootstrapDecision(account, mode);
    return {
      accountId: account?.id ?? accountId,
      microsoftEmail: account?.microsoftEmail ?? null,
      decision: result.decision,
      reason: result.reason,
    };
  });
  const queueIds = items
    .filter((item) => item.decision === "queue" && item.accountId != null)
    .map((item) => item.accountId as number);
  return {
    mode,
    requestedCount: normalizedIds.length,
    queueIds,
    items,
    summary: {
      queueableCount: queueIds.length,
      blockedCount: items.filter((item) => item.decision === "blocked").length,
      alreadyBootstrappedCount: items.filter((item) => item.decision === "already_bootstrapped").length,
      bootstrappingCount: items.filter((item) => item.decision === "bootstrapping").length,
      missingCount: items.filter((item) => item.decision === "missing").length,
    },
  };
}

function applyMailboxFailureState(input: {
  db: AppDatabase;
  mailbox: MicrosoftMailboxRecord;
  error: unknown;
  action: "oauth_error" | "sync_failed";
  broadcast: (event: ServerEvent) => void;
}): MicrosoftMailboxRecord {
  const errorCode = getMailboxErrorCode(input.error);
  const errorMessage = getMailboxErrorMessage(input.error);
  const status = toMailboxFailureStatus(input.error);
  const failedMailbox = input.db.markMailboxStatus(input.mailbox.id, {
    status,
    lastErrorCode: errorCode,
    lastErrorMessage: errorMessage,
  });
  if (status === "locked" || isLockedMailboxErrorCode(errorCode)) {
    input.db.markAccountLocked(input.mailbox.accountId, errorMessage, errorCode || "microsoft_account_locked");
  }
  input.broadcast({
    type: "mailbox.updated",
    payload: { mailboxIds: [failedMailbox.id], action: input.action },
    timestamp: nowIso(),
  });
  input.broadcast({
    type: "account.updated",
    payload: { affectedIds: [input.mailbox.accountId], action: "mailbox_status" },
    timestamp: nowIso(),
  });
  return failedMailbox;
}

function broadcastAccountAction(
  broadcast: (event: ServerEvent) => void,
  accountId: number,
  action: string,
): void {
  broadcast({
    type: "account.updated",
    payload: { affectedIds: [accountId], action },
    timestamp: nowIso(),
  });
}

function broadcastChatGptUpstreamSettingsUpdated(
  broadcast: (event: ServerEvent) => void,
  payload: Record<string, unknown> = {},
): void {
  broadcast({
    type: "chatgpt.upstream-settings.updated",
    payload,
    timestamp: nowIso(),
  });
}

function parseJobSite(value: string | null | undefined): JobSite {
  if (value === "chatgpt") return "chatgpt";
  if (value === "grok") return "grok";
  return "tavily";
}

function parseAccountBusinessFlowSite(value: unknown): AccountBusinessFlowSite | null {
  if (value === "none" || value === "chatgpt" || value === "grok" || value === "tavily") return value;
  return null;
}

function parseAccountBusinessFlowMode(value: unknown): AccountBusinessFlowMode | null {
  if (value === "headless" || value === "headed" || value === "fingerprint") return value;
  return null;
}

type SiteScheduler = {
  activeAttemptRows(): JobAttemptRecord[];
  getAutoExtractSnapshot(jobId: number): unknown;
  getCooldownSnapshot?: () => unknown;
};

function serializeJobRecordForApi(job: NonNullable<ReturnType<AppDatabase["getCurrentJob"]>>) {
  const { payloadJson: _payloadJson, ...rest } = job;
  return {
    ...rest,
    ...(job.site === "chatgpt"
      ? {
          upstreamGroupName: readChatGptJobUpstreamGroupName(job),
        }
      : {}),
  };
}

async function serializeJobSnapshot(site: JobSite, db: AppDatabase, scheduler: SiteScheduler) {
  await ensureBrowserAvailabilityFresh();
  const runModeAvailability = getBrowserRunModeAvailability();
  const job = db.getCurrentJob(site);
  if (!job) {
    return {
      site,
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
      runModeAvailability,
      cooldown: scheduler.getCooldownSnapshot?.() ?? null,
    };
  }
  return {
    site,
    job: serializeJobRecordForApi(job),
    activeAttempts: scheduler.activeAttemptRows().map((row) => serializeAttemptForApi(db, row)),
    recentAttempts: db
      .listAttempts(job.id, false)
      .slice(0, 20)
      .map((row) => serializeAttemptForApi(db, row)),
    eligibleCount: site === "tavily" ? db.countEligibleAccounts(job.id) : 0,
    autoExtractState: scheduler.getAutoExtractSnapshot(job.id),
    runModeAvailability,
    cooldown: scheduler.getCooldownSnapshot?.() ?? null,
  };
}

function randomPassword(length = 18): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
  let output = "";
  for (let index = 0; index < length; index += 1) {
    output += alphabet[Math.floor(Math.random() * alphabet.length)] || "A";
  }
  return output;
}

function randomNickname(): string {
  const firstNames = ["Mika", "Luna", "Rin", "Sora", "Aiko", "Hana", "Nora", "Yuna"];
  const lastNames = ["Hoshino", "Amano", "Kobayashi", "Hayashi", "Minase", "Sakurai", "Kisaragi", "Morita"];
  const first = firstNames[Math.floor(Math.random() * firstNames.length)] || "Mika";
  const last = lastNames[Math.floor(Math.random() * lastNames.length)] || "Hoshino";
  return `${first} ${last}`;
}

function randomBirthDate(): string {
  const start = Date.UTC(1990, 0, 1);
  const end = Date.UTC(2005, 11, 31);
  const picked = new Date(start + Math.floor(Math.random() * (end - start + 1)));
  return picked.toISOString().slice(0, 10);
}

function serializeChatGptCredential(row: ChatGptCredentialRecord, includeSecrets = false) {
  const mask = (value: string): string => maskSecret(value, 6);
  return {
    id: row.id,
    jobId: row.jobId,
    attemptId: row.attemptId,
    email: row.email,
    accountId: row.accountId,
    accessTokenMasked: mask(row.accessToken),
    refreshTokenMasked: mask(row.refreshToken),
    idTokenMasked: mask(row.idToken),
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    hasSecrets: true,
    ...(includeSecrets
      ? {
          accessToken: row.accessToken,
          refreshToken: row.refreshToken,
          idToken: row.idToken,
          credentialJson: row.credentialJson,
        }
      : {}),
  };
}

function serializeGrokApiKey(row: GrokApiKeyRecord, includeSecret = false) {
  return {
    id: row.id,
    jobId: row.jobId,
    attemptId: row.attemptId,
    email: row.email,
    password: row.password,
    sso: row.sso,
    ssoRw: row.ssoRw,
    status: row.status,
    extractedIp: row.extractedIp,
    extractedAt: row.extractedAt,
    lastVerifiedAt: row.lastVerifiedAt,
    createdAt: row.createdAt,
    birthDate: row.birthDate,
    checkoutUrl: row.checkoutUrl,
    hasCfClearance: Boolean(row.cfClearance),
    ...(includeSecret
      ? {
          cfClearance: row.cfClearance,
        }
      : {}),
  };
}

function toEventMessage(event: ServerEvent): string {
  return JSON.stringify(event);
}

function toSseEventMessage(event: ServerEvent): string {
  return `data: ${JSON.stringify(event)}\n\n`;
}

async function createProxyController(settings: AppSettings) {
  if (!settings.subscriptionUrl.trim()) {
    throw new Error("MIHOMO_SUBSCRIPTION_URL is not configured");
  }
  return await startMihomo({
    subscriptionUrl: settings.subscriptionUrl,
    groupName: settings.groupName,
    routeGroupName: settings.routeGroupName,
    checkUrl: settings.checkUrl,
    apiPort: settings.apiPort,
    mixedPort: settings.mixedPort,
    workDir: path.join(OUTPUT_ROOT, "mihomo", "web-admin"),
    downloadDir: path.join(REPO_ROOT, "downloads", "mihomo"),
  });
}

async function fetchProxyInventory(settings: AppSettings): Promise<{ nodeNames: string[] }> {
  const controller = await createProxyController(settings);
  try {
    const nodes = await controller.listGroupNodes();
    return {
      nodeNames: nodes.map((item) => item.name),
    };
  } finally {
    await controller.stop().catch(() => {});
  }
}

async function syncProxyInventory(db: AppDatabase, settings: AppSettings) {
  const inventory = await fetchProxyInventory(settings);
  db.upsertProxyInventory(inventory.nodeNames);
  return { nodes: db.listProxyNodes() };
}

function recordProxyCheckResult(db: AppDatabase, result: {
  name: string;
  ok: boolean;
  latencyMs?: number | null;
  geo?: { ip?: string; country?: string; region?: string; city?: string; org?: string };
  error?: string;
}): void {
  db.recordProxyCheck({
    nodeName: String(result.name),
    status: result.ok ? "ok" : "fail",
    latencyMs: typeof result.latencyMs === "number" ? result.latencyMs : null,
    egressIp: result.geo?.ip || null,
    country: result.geo?.country || null,
    region: result.geo?.region || null,
    city: result.geo?.city || null,
    org: result.geo?.org || null,
    error: typeof result.error === "string" ? result.error : null,
  });
}

function serializeProxyPayload(input: {
  settings: AppSettings;
  nodes: ReturnType<AppDatabase["listProxyNodes"]>;
  checkState: ProxyCheckState;
  syncError?: string | null;
}) {
  return {
    settings: input.settings,
    nodes: input.nodes,
    checkState: input.checkState,
    syncError: input.syncError ?? null,
  };
}

async function serveStatic(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const targetPath = resolveStaticAssetPath(WEB_DIST_DIR, url.pathname);
  if (!targetPath) {
    return new Response("Not found", { status: 404 });
  }
  const file = Bun.file(targetPath);
  if (await file.exists()) {
    return new Response(file);
  }
  if (!shouldServeSpaFallback(url.pathname)) {
    return new Response("Not found", { status: 404 });
  }
  const indexFile = Bun.file(path.join(WEB_DIST_DIR, "index.html"));
  if (await indexFile.exists()) {
    return new Response(indexFile);
  }
  return new Response("Frontend build not found. Run `bun run web:build` first.", { status: 503 });
}

async function ensureMailboxAccessToken(db: AppDatabase, mailbox: MicrosoftMailboxRecord, settings: AppSettings): Promise<{
  mailbox: MicrosoftMailboxRecord;
  accessToken: string;
}> {
  const graphSettings = readMicrosoftGraphSettings(settings);
  assertMicrosoftGraphSettings(graphSettings);
  if (mailbox.accessToken && !isMicrosoftTokenExpired(mailbox.accessTokenExpiresAt)) {
    return {
      mailbox,
      accessToken: mailbox.accessToken,
    };
  }
  if (!mailbox.refreshToken) {
    throw new Error("mailbox_not_authorized");
  }
  const token = await refreshMicrosoftAccessToken({
    clientId: graphSettings.clientId,
    clientSecret: graphSettings.clientSecret,
    redirectUri: graphSettings.redirectUri,
    authority: mailbox.authority || graphSettings.authority,
    refreshToken: mailbox.refreshToken,
  });
  const nextMailbox = db.updateMailboxTokens(mailbox.id, {
    refreshToken: token.refreshToken || mailbox.refreshToken,
    accessToken: token.accessToken,
    accessTokenExpiresAt: token.expiresAt,
    authority: mailbox.authority || graphSettings.authority,
  });
  if (!token.accessToken) {
    throw new Error("mailbox_access_token_missing");
  }
  return {
    mailbox: nextMailbox,
    accessToken: token.accessToken,
  };
}

async function syncMailboxInbox(db: AppDatabase, mailbox: MicrosoftMailboxRecord, settings: AppSettings): Promise<MicrosoftMailboxRecord> {
  const { mailbox: refreshedMailbox, accessToken } = await ensureMailboxAccessToken(db, mailbox, settings);
  const syncResult = await syncMicrosoftInbox({
    accessToken,
    deltaLink: refreshedMailbox.deltaLink,
  });
  db.upsertMailboxMessages(refreshedMailbox.id, syncResult.messages, {
    removedGraphMessageIds: syncResult.removedGraphMessageIds,
    keepLatest: 500,
  });
  const unreadCount = db.countMailboxUnread(refreshedMailbox.id);
  return db.markMailboxStatus(refreshedMailbox.id, {
    status: "available",
    accessToken,
    accessTokenExpiresAt: refreshedMailbox.accessTokenExpiresAt,
    refreshToken: refreshedMailbox.refreshToken,
    deltaLink: syncResult.deltaLink ?? refreshedMailbox.deltaLink,
    unreadCount,
    lastSyncedAt: nowIso(),
    lastErrorCode: null,
    lastErrorMessage: null,
  });
}

interface MailboxOauthWorkerResult {
  ok: boolean;
  finalUrl?: string | null;
  oauthOutcome?: string | null;
  profilePath?: string | null;
  proxy?: {
    nodeName: string;
    ip: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
    timezone: string | null;
  } | null;
  error?: string | null;
}

async function runMailboxOauthWorker(input: {
  account: MicrosoftAccountRecord;
  mailboxId: number;
  settings: AppSettings;
  proxyNode: string;
  profilePath: string;
  redirectUri: string;
  authUrl: string;
}): Promise<MailboxOauthWorkerResult> {
  const runId = `mailbox-${input.account.id}-${Date.now()}`;
  const outputDir = path.join(OUTPUT_ROOT, "mailbox-oauth", runId);
  const resultPath = path.join(outputDir, "result.json");
  const runtimeBinding = getRuntimeServerBinding(input.settings);
  const localServerHost =
    runtimeBinding.host === "0.0.0.0" || runtimeBinding.host === "::" || runtimeBinding.host === "[::]"
      ? "127.0.0.1"
      : runtimeBinding.host;
  const localServerOrigin = `http://${localServerHost}:${runtimeBinding.port}`;
  await mkdir(outputDir, { recursive: true });
  const portLeases = await reserveMihomoPortLeases();
  try {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      OUTPUT_ROOT_DIR: outputDir,
      TASK_LEDGER_DB_PATH: DEFAULT_DB_PATH,
      TASK_LEDGER_ACCOUNT_ID: String(input.account.id),
      CHROME_PROFILE_DIR: input.profilePath,
      CHROME_PROFILE_STRATEGY: "exact",
      INSPECT_CHROME_PROFILE_DIR: path.join(outputDir, "chrome-inspect-profile"),
      MICROSOFT_ACCOUNT_EMAIL: input.account.microsoftEmail,
      MICROSOFT_ACCOUNT_PASSWORD: input.account.passwordPlaintext,
      MICROSOFT_PROOF_MAILBOX_PROVIDER: input.account.proofMailboxProvider || "",
      MICROSOFT_PROOF_MAILBOX_ADDRESS: input.account.proofMailboxAddress || "",
      MICROSOFT_PROOF_MAILBOX_ID: input.account.proofMailboxId || "",
      MIHOMO_SUBSCRIPTION_URL: input.settings.subscriptionUrl,
      MIHOMO_GROUP_NAME: input.settings.groupName,
      MIHOMO_ROUTE_GROUP_NAME: input.settings.routeGroupName,
      MIHOMO_API_PORT: String(portLeases.apiPort.port),
      MIHOMO_MIXED_PORT: String(portLeases.mixedPort.port),
      PROXY_CHECK_URL: input.settings.checkUrl,
      PROXY_CHECK_TIMEOUT_MS: String(input.settings.timeoutMs),
      PROXY_LATENCY_MAX_MS: String(input.settings.maxLatencyMs),
      KEEP_BROWSER_OPEN_ON_FAILURE: process.env.KEEP_BROWSER_OPEN_ON_FAILURE || "false",
      KEEP_BROWSER_OPEN_MS: process.env.KEEP_BROWSER_OPEN_MS || "0",
      CHROME_AUTO_OPEN_DEVTOOLS: process.env.CHROME_AUTO_OPEN_DEVTOOLS || "false",
    };

    return await new Promise<MailboxOauthWorkerResult>((resolve, reject) => {
      const keepBrowserOpenOnFailure = /^(1|true|yes|on)$/i.test(
        String(env.KEEP_BROWSER_OPEN_ON_FAILURE || "").trim(),
      );
      const workerTimeoutMs = keepBrowserOpenOnFailure ? 30 * 60_000 : 5 * 60_000;
      let listenersReleased = false;
      const releasePortListeners = async () => {
        if (listenersReleased) return;
        listenersReleased = true;
        await Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]).catch(() => {});
      };
      const workerRuntime = resolveWorkerRuntime(env);
      const workerArgs = [...workerRuntime.bootstrapArgs];
      workerArgs[workerArgs.length - 1] = "src/server/microsoft-oauth-worker.ts";
      const child = spawn(
        workerRuntime.command,
        [
          ...workerArgs,
          `--auth-url=${input.authUrl}`,
          `--mailbox-id=${input.mailboxId}`,
          `--redirect-uri=${input.redirectUri}`,
          `--local-server-origin=${localServerOrigin}`,
          `--proxy-node=${input.proxyNode}`,
          `--result-path=${resultPath}`,
        ],
        {
          cwd: REPO_ROOT,
          env,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      child.once("spawn", () => {
        void releasePortListeners();
      });
      let stderr = "";
      let stdout = "";
      const workerLogPath = path.join(outputDir, "worker.log");
      const timeout = setTimeout(() => {
        child.kill("SIGTERM");
      }, workerTimeoutMs);
      child.stdout?.on("data", (chunk) => {
        const text = chunk.toString();
        stdout += text;
        void writeFile(workerLogPath, [stdout.trim(), stderr.trim()].filter(Boolean).join("\n"), "utf8").catch(() => {});
      });
      child.stderr?.on("data", (chunk) => {
        const text = chunk.toString();
        stderr += text;
        void writeFile(workerLogPath, [stdout.trim(), stderr.trim()].filter(Boolean).join("\n"), "utf8").catch(() => {});
      });
      child.once("error", (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once("close", async (code) => {
        clearTimeout(timeout);
        const combinedLog = [stdout.trim(), stderr.trim()].filter(Boolean).join("\n");
        if (combinedLog) {
          await writeFile(workerLogPath, combinedLog, "utf8").catch(() => {});
        }
        try {
          const raw = await readFile(resultPath, "utf8");
          const parsed = JSON.parse(raw) as MailboxOauthWorkerResult;
          resolve(parsed);
        } catch (error) {
          const tail = [stdout.trim(), stderr.trim()].filter(Boolean).join("\n").slice(-4000);
          reject(new Error(`oauth worker failed (code=${code ?? "unknown"}): ${tail || (error instanceof Error ? error.message : String(error))}`));
        }
      });
    });
  } finally {
    await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]).catch(() => {});
  }
}

async function authorizeMailboxWithBrowserAutomation(input: {
  db: AppDatabase;
  accountId: number;
  readSettings: () => AppSettings;
  broadcast: (event: ServerEvent) => void;
  requestedProxyNode?: string | null;
}): Promise<{ mailbox: MicrosoftMailboxRecord; workerResult: MailboxOauthWorkerResult }> {
  const account = input.db.getAccount(input.accountId);
  if (!account) {
    throw new Error(`account not found: ${input.accountId}`);
  }
  const runtimeSettings = input.readSettings();
  const graphSettings = readMicrosoftGraphSettings(runtimeSettings);
  if (!graphSettings.clientId.trim() || !graphSettings.clientSecret.trim() || !graphSettings.redirectUri.trim()) {
    input.db.markBrowserSessionFailure(input.accountId, {
      status: "blocked",
      browserEngine: "chrome",
      errorCode: "microsoft_graph_settings_incomplete",
      errorMessage: "Microsoft Graph 设置不完整，无法完成账号 bootstrap",
    });
    broadcastAccountAction(input.broadcast, input.accountId, "session_blocked");
    throw new Error("Microsoft Graph 设置不完整，无法完成账号 bootstrap");
  }
  assertMicrosoftGraphSettings(graphSettings);
  const requestedProxyNode = String(input.requestedProxyNode || "").trim() || null;
  const selectedProxyNode = requestedProxyNode
    ? input.db.getProxyNode(requestedProxyNode)
    : input.db.selectReusableProxyNodeForAccount(input.accountId);
  const proxyNode = selectedProxyNode?.nodeName || null;
  if (!proxyNode) {
    input.db.markBrowserSessionFailure(input.accountId, {
      status: "failed",
      browserEngine: "chrome",
      errorCode: "proxy_node_unavailable",
      errorMessage: requestedProxyNode
        ? `指定代理节点不可用：${requestedProxyNode}`
        : "当前代理池中没有可复用的健康节点",
    });
    broadcastAccountAction(input.broadcast, input.accountId, "session_failed");
    throw new Error(
      requestedProxyNode
        ? `指定代理节点不可用：${requestedProxyNode}`
        : "当前代理池中没有可复用的健康节点",
    );
  }
  const session = input.db.markBrowserSessionBootstrapping(input.accountId, {
    browserEngine: "chrome",
    proxyNode,
  });
  input.db.touchProxyLease(proxyNode);
  broadcastAccountAction(input.broadcast, input.accountId, "session_bootstrap_started");
  const mailbox = input.db.ensureMailboxForAccount(input.accountId);
  const { codeVerifier, codeChallenge } = createMicrosoftPkcePair();
  const oauthState = createMicrosoftOauthState();
  const nextMailbox = input.db.saveMailboxOauthStart(mailbox.id, {
    oauthState,
    oauthCodeVerifier: codeVerifier,
    authority: graphSettings.authority,
  });
  const authUrl = buildMicrosoftAuthorizeUrl({
    clientId: graphSettings.clientId,
    redirectUri: graphSettings.redirectUri,
    authority: graphSettings.authority,
    state: oauthState,
    codeChallenge,
    loginHint: account.microsoftEmail,
  });
  input.broadcast({
    type: "mailbox.updated",
    payload: { mailboxIds: [nextMailbox.id], action: "oauth_start" },
    timestamp: nowIso(),
  });
  broadcastAccountAction(input.broadcast, input.accountId, "mailbox_status");

  let workerResult: MailboxOauthWorkerResult | null = null;
  try {
    workerResult = await runMailboxOauthWorker({
      account,
      mailboxId: nextMailbox.id,
      settings: runtimeSettings,
      proxyNode,
      profilePath: session.profilePath,
      redirectUri: graphSettings.redirectUri,
      authUrl,
    });
    let refreshedMailbox = input.db.getMailbox(nextMailbox.id) || nextMailbox;
    const oauthOutcome = String(workerResult.oauthOutcome || "").trim().toLowerCase();
    input.broadcast({
      type: "mailbox.updated",
      payload: { mailboxIds: [refreshedMailbox.id], action: oauthOutcome === "success" ? "oauth_success" : "oauth_finished" },
      timestamp: nowIso(),
    });
    broadcastAccountAction(input.broadcast, input.accountId, "mailbox_status");
    if (!workerResult.ok) {
      throw new Error(workerResult.error || "microsoft oauth automation failed");
    }
    if (!isMicrosoftOauthCompletionUrl(workerResult.finalUrl || null, graphSettings.redirectUri) || (!workerResult.oauthOutcome && !refreshedMailbox.refreshToken)) {
      throw new Error(`microsoft_oauth_incomplete:${workerResult.finalUrl || "unknown"}`);
    }
    if (oauthOutcome === "error") {
      throw new Error(refreshedMailbox.lastErrorMessage || refreshedMailbox.lastErrorCode || "microsoft oauth failed");
    }
    refreshedMailbox = await syncMailboxInbox(input.db, refreshedMailbox, runtimeSettings);
    input.broadcast({
      type: "mailbox.updated",
      payload: { mailboxIds: [refreshedMailbox.id], action: "sync" },
      timestamp: nowIso(),
    });
    broadcastAccountAction(input.broadcast, input.accountId, "mailbox_status");
    if (workerResult.proxy) {
      input.db.recordProxyCheck({
        nodeName: proxyNode,
        status: "ok",
        egressIp: workerResult.proxy.ip,
        country: workerResult.proxy.country,
        region: workerResult.proxy.region,
        city: workerResult.proxy.city,
        error: null,
      });
      input.db.touchProxyLease(proxyNode, {
        status: "ok",
        egressIp: workerResult.proxy.ip,
        country: workerResult.proxy.country,
        region: workerResult.proxy.region,
        city: workerResult.proxy.city,
        leasedAt: nowIso(),
      });
    } else {
      input.db.touchProxyLease(proxyNode, { status: "ok" });
    }
    input.db.markBrowserSessionReady(input.accountId, {
      browserEngine: "chrome",
      proxyNode,
      proxyIp: workerResult.proxy?.ip ?? null,
      proxyCountry: workerResult.proxy?.country ?? null,
      proxyRegion: workerResult.proxy?.region ?? null,
      proxyCity: workerResult.proxy?.city ?? null,
      proxyTimezone: workerResult.proxy?.timezone ?? null,
    });
    broadcastAccountAction(input.broadcast, input.accountId, "session_ready");
    return {
      mailbox: refreshedMailbox,
      workerResult,
    };
  } catch (error) {
    let currentMailbox = input.db.getMailbox(nextMailbox.id) || nextMailbox;
    if (currentMailbox.status === "preparing") {
      currentMailbox = applyMailboxFailureState({
        db: input.db,
        mailbox: currentMailbox,
        error,
        action: "oauth_error",
        broadcast: input.broadcast,
      });
    }
    const sessionStatus = currentMailbox.status === "locked" || currentMailbox.status === "invalidated" ? "blocked" : "failed";
    const errorCode = getMailboxErrorCode(error);
    const errorMessage = getMailboxErrorMessage(error);
    if (shouldRetryAccountBootstrapWithFreshProxy(error)) {
      input.db.recordProxyCheck({
        nodeName: proxyNode,
        status: "failed",
        egressIp: workerResult?.proxy?.ip ?? null,
        country: workerResult?.proxy?.country ?? null,
        region: workerResult?.proxy?.region ?? null,
        city: workerResult?.proxy?.city ?? null,
        error: errorMessage || errorCode || "session_bootstrap_failed",
      });
      input.db.touchProxyLease(proxyNode, {
        status: "failed",
        egressIp: workerResult?.proxy?.ip ?? null,
        country: workerResult?.proxy?.country ?? null,
        region: workerResult?.proxy?.region ?? null,
        city: workerResult?.proxy?.city ?? null,
      });
    }
    input.db.markBrowserSessionFailure(input.accountId, {
      status: sessionStatus,
      browserEngine: "chrome",
      proxyNode,
      proxyIp: workerResult?.proxy?.ip ?? null,
      proxyCountry: workerResult?.proxy?.country ?? null,
      proxyRegion: workerResult?.proxy?.region ?? null,
      proxyCity: workerResult?.proxy?.city ?? null,
      proxyTimezone: workerResult?.proxy?.timezone ?? null,
      errorCode: errorCode || currentMailbox.lastErrorCode || "session_bootstrap_failed",
      errorMessage: errorMessage || currentMailbox.lastErrorMessage || "账号 bootstrap 失败",
    });
    broadcastAccountAction(input.broadcast, input.accountId, sessionStatus === "blocked" ? "session_blocked" : "session_failed");
    throw error;
  }
}

async function main(): Promise<void> {
  const db = await AppDatabase.open(DEFAULT_DB_PATH, LEGACY_PROXY_USAGE_PATH);
  appDbRef = db;
  const settingsDefaults = buildSettingsCodeDefaults();
  const bootstrapSettings = buildInitialSettingsFromEnv(settingsDefaults);
  const defaults = db.ensureSettings(bootstrapSettings);
  const readSettings = () => db.getSettings(settingsDefaults);
  const runtimeBinding = getRuntimeServerBinding(defaults);
  const clients = new Set<any>();
  const accountEventSubscribers = new Set<(event: ServerEvent) => void>();
  const proxyEventSubscribers = new Set<(event: ServerEvent) => void>();
  const sseEncoder = new TextEncoder();
  const runExclusiveProxyOp = createExclusiveRunner();
  const runExclusiveMailboxOauth = createExclusiveRunner();
  const sessionBootstrapQueuedIds = new Set<number>();
  const sessionBootstrapPendingForceIds = new Set<number>();
  const sessionBootstrapRequestedProxyNodes = new Map<number, string | null>();
  let latestProxySyncError: string | null = null;
  const proxyCheckCoordinator = createProxyCheckCoordinator({
    defaultConcurrency: resolveProxyCheckConcurrency(process.env.PROXY_CHECK_CONCURRENCY, 5),
    readSettings,
    resolveNodeNames: async ({ settings, scope, nodeName }) => {
      if (scope === "node") {
        return [String(nodeName || "").trim()].filter(Boolean);
      }
      const inventory = await runExclusiveProxyOp(() => fetchProxyInventory(settings));
      db.upsertProxyInventory(inventory.nodeNames);
      latestProxySyncError = null;
      return inventory.nodeNames;
    },
    createWorker: createMihomoNodeCheckRunner({
      repoRoot: REPO_ROOT,
      outputRoot: OUTPUT_ROOT,
      ipinfoToken: (process.env.IPINFO_TOKEN || "").trim() || undefined,
    }),
    recordResult: (result) => {
      recordProxyCheckResult(db, result);
    },
    listNodes: () => db.listProxyNodes(),
    publish: (event) => {
      broadcast(event);
    },
  });
  const broadcast = (event: ServerEvent) => {
    const message = toEventMessage(event);
    for (const ws of clients) {
      ws.send(message);
    }
    for (const subscriber of accountEventSubscribers) {
      subscriber(event);
    }
    if (event.type.startsWith("proxy.")) {
      for (const subscriber of proxyEventSubscribers) {
        subscriber(event);
      }
    }
  };
  const queueAccountSessionBootstrap = (accountId: number, options?: { force?: boolean; reason?: "auto" | "manual"; proxyNode?: string | null }): boolean => {
    const account = db.getAccount(accountId);
    if (!account || getAccountConnectBlockMessage(account)) {
      return false;
    }
    const requestedProxyNode = options?.proxyNode !== undefined ? String(options.proxyNode || "").trim() || null : undefined;
    if (
      options?.reason !== "manual"
      && !hasConfiguredMicrosoftGraphBootstrap(readMicrosoftGraphSettings(readSettings()))
    ) {
      return false;
    }
    const replayPendingBootstrap = options?.reason === "auto" && shouldReplayPendingAccountBootstrap(account);
    if (!options?.force) {
      if (options?.reason === "manual") {
        if (resolveAccountBatchBootstrapDecision(account, "pending_only").decision !== "queue") {
          return false;
        }
      } else if (!replayPendingBootstrap && !shouldQueueImportedAccountBootstrap(account)) {
        return false;
      }
    }
    const queueDisposition = resolveBootstrapQueueDisposition({
      alreadyQueued: sessionBootstrapQueuedIds.has(accountId),
      force: options?.force,
    });
    if (queueDisposition === "skip") {
      return false;
    }
    if (queueDisposition === "defer_force") {
      if (requestedProxyNode) {
        return false;
      }
      sessionBootstrapPendingForceIds.add(accountId);
      return true;
    }
    if (requestedProxyNode !== undefined) {
      if (requestedProxyNode) {
        sessionBootstrapRequestedProxyNodes.set(accountId, requestedProxyNode);
      } else {
        sessionBootstrapRequestedProxyNodes.delete(accountId);
      }
    }
    db.queueBrowserSessionBootstrap(accountId, {
      browserEngine: "chrome",
      proxyNode: requestedProxyNode,
      clearProxySnapshot: requestedProxyNode !== undefined,
    });
    sessionBootstrapQueuedIds.add(accountId);
    void runExclusiveMailboxOauth(async () => {
      try {
        const latest = db.getAccount(accountId);
        if (!latest || getAccountConnectBlockMessage(latest)) {
          return;
        }
        const maxAttempts = 2;
        let lastError: unknown = null;
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
          try {
            const requestedProxyNode = sessionBootstrapRequestedProxyNodes.get(accountId) ?? null;
            await authorizeMailboxWithBrowserAutomation({
              db,
              accountId,
              readSettings,
              broadcast,
              requestedProxyNode,
            });
            lastError = null;
            break;
          } catch (error) {
            lastError = error;
            const requestedProxyNode = sessionBootstrapRequestedProxyNodes.get(accountId) ?? null;
            if (
              attempt >= maxAttempts
              || requestedProxyNode
              || !shouldRetryAccountBootstrapWithFreshProxy(error)
            ) {
              break;
            }
            console.warn(
              `[mailbox-bootstrap] account ${accountId} retrying with fresh proxy after attempt ${attempt}/${maxAttempts}: ${
                error instanceof Error ? error.message : String(error)
              }`,
            );
          }
        }
        if (lastError) {
          throw lastError;
        }
      } catch {
        // mailbox/session state is updated inside the bootstrap flow
      } finally {
        sessionBootstrapQueuedIds.delete(accountId);
        if (sessionBootstrapPendingForceIds.delete(accountId)) {
          queueAccountSessionBootstrap(accountId, {
            force: true,
            reason: "manual",
            proxyNode: sessionBootstrapRequestedProxyNodes.get(accountId) ?? null,
          });
        } else {
          sessionBootstrapRequestedProxyNodes.delete(accountId);
        }
      }
    });
    return true;
  };
  const accountExtractorRuntime = new AccountExtractorRuntime(db, readSettings, broadcast, queueAccountSessionBootstrap);
  const tavilyScheduler = new JobScheduler(db, "tavily", REPO_ROOT, DEFAULT_DB_PATH, readSettings, broadcast, {
    onImportedAccounts: (accountIds) => {
      for (const accountId of accountIds) {
        queueAccountSessionBootstrap(accountId, { reason: "auto" });
      }
    },
  });
  const grokScheduler = new GrokJobScheduler(db, REPO_ROOT, readSettings, broadcast);
  const chatGptUpstreamSupplement = new ChatGptUpstreamSupplementService(db, {
    projectLabel: path.basename(REPO_ROOT),
  });
  const chatgptScheduler = new ChatGptJobScheduler(db, REPO_ROOT, readSettings, broadcast, {
    createAttemptDraft: () =>
      buildChatGptDraft({
        apiKey: (process.env.CFMAIL_API_KEY || "").trim(),
        baseUrl: process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test",
        httpJson: serverHttpJson,
        rootDomain: DEFAULT_CFMAIL_ROOT_DOMAIN,
        createPassword: randomPassword,
        createNickname: randomNickname,
        createBirthDate: randomBirthDate,
        nowIso,
      }),
    supplementCredential: async ({ credential, groupName }) => {
      const result = await chatGptUpstreamSupplement.supplementCredential(credential, groupName);
      if (!result.success) {
        throw new Error(result.message);
      }
    },
  });
  browserAvailabilityService = new BrowserAvailabilityService({ cwd: REPO_ROOT });
  void browserAvailabilityService.ensureFresh().catch(() => {});
  accountBusinessFlowManager = new AccountBusinessFlowManager(
    db,
    REPO_ROOT,
    DEFAULT_DB_PATH,
    readSettings,
    broadcast,
    serverHttpJson,
    browserAvailabilityService,
  );
  const getSchedulerBySite = (site: JobSite) => {
    if (site === "chatgpt") return chatgptScheduler;
    if (site === "grok") return grokScheduler;
    return tavilyScheduler;
  };

  for (const accountId of db.listPendingBrowserSessionAccountIds()) {
    queueAccountSessionBootstrap(accountId, { reason: "auto" });
  }

  const server = Bun.serve({
    hostname: runtimeBinding.host,
    port: runtimeBinding.port,
    idleTimeout: 60,
    websocket: {
      open(ws: any) {
        clients.add(ws);
        ws.send(
          toEventMessage({
            type: "toast",
            payload: { level: "info", message: "websocket connected" },
            timestamp: nowIso(),
          }),
        );
      },
      message() {},
      close(ws: any) {
        clients.delete(ws);
      },
    },
    async fetch(req, server) {
      const url = new URL(req.url);
      const pathname = url.pathname;
      const accountDetailMatch = pathname.match(/^\/api\/accounts\/(\d+)$/);
      const accountBusinessFlowStartMatch = pathname.match(/^\/api\/accounts\/(\d+)\/business-flow\/start$/);
      const accountSessionRebootstrapMatch = pathname.match(/^\/api\/accounts\/(\d+)\/session\/rebootstrap$/);
      const accountSessionBootstrapPreviewMatch = pathname === "/api/accounts/session-bootstrap/preview";
      const mailboxOauthStartMatch = pathname.match(/^\/api\/microsoft-mail\/accounts\/(\d+)\/oauth\/start$/);
      const mailboxDetailMatch = pathname.match(/^\/api\/microsoft-mail\/mailboxes\/(\d+)$/);
      const mailboxSyncMatch = pathname.match(/^\/api\/microsoft-mail\/mailboxes\/(\d+)\/sync$/);
      const mailboxMessagesMatch = pathname.match(/^\/api\/microsoft-mail\/mailboxes\/(\d+)\/messages$/);
      const mailboxMessageDetailMatch = pathname.match(/^\/api\/microsoft-mail\/messages\/(\d+)$/);

      try {
        if (pathname === "/api/events/ws") {
          if (server.upgrade(req)) {
            return new Response(null);
          }
          return badRequest("websocket upgrade failed", 500);
        }

        if (pathname === "/api/accounts/events" && req.method === "GET") {
          let cleanup = () => {};
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              let closed = false;
              const write = (chunk: string) => {
                if (closed) return;
                controller.enqueue(sseEncoder.encode(chunk));
              };
              const sendEvent = (event: ServerEvent) => {
                write(toSseEventMessage(event));
              };
              const heartbeat = setInterval(() => {
                write(`: ping ${Date.now()}\n\n`);
              }, 15_000);
              const closeStream = () => {
                if (closed) return;
                closed = true;
                clearInterval(heartbeat);
                accountEventSubscribers.delete(sendEvent);
                req.signal.removeEventListener("abort", closeStream);
                try {
                  controller.close();
                } catch {}
              };
              cleanup = closeStream;
              accountEventSubscribers.add(sendEvent);
              req.signal.addEventListener("abort", closeStream, { once: true });
              write(": connected\n\n");
              sendEvent({
                type: "extractor.updated",
                payload: { runtime: accountExtractorRuntime.getSnapshot() },
                timestamp: nowIso(),
              });
            },
            cancel() {
              cleanup();
            },
          });
          return new Response(stream, {
            headers: {
              "content-type": "text/event-stream; charset=utf-8",
              "cache-control": "no-cache, no-transform",
              connection: "keep-alive",
              "x-accel-buffering": "no",
            },
          });
        }

        if (pathname === "/api/proxies/events" && req.method === "GET") {
          let cleanup = () => {};
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              let closed = false;
              const write = (chunk: string) => {
                if (closed) return;
                controller.enqueue(sseEncoder.encode(chunk));
              };
              const sendEvent = (event: ServerEvent) => {
                write(toSseEventMessage(event));
              };
              const heartbeat = setInterval(() => {
                write(`: ping ${Date.now()}\n\n`);
              }, 15_000);
              const closeStream = () => {
                if (closed) return;
                closed = true;
                clearInterval(heartbeat);
                proxyEventSubscribers.delete(sendEvent);
                req.signal.removeEventListener("abort", closeStream);
                try {
                  controller.close();
                } catch {}
              };
              cleanup = closeStream;
              proxyEventSubscribers.add(sendEvent);
              req.signal.addEventListener("abort", closeStream, { once: true });
              write(": connected\n\n");
              sendEvent({
                type: "proxy.check.state",
                payload: {
                  checkState: proxyCheckCoordinator.getState(),
                  nodes: db.listProxyNodes(),
                },
                timestamp: nowIso(),
              });
            },
            cancel() {
              cleanup();
            },
          });
          return new Response(stream, {
            headers: {
              "content-type": "text/event-stream; charset=utf-8",
              "cache-control": "no-cache, no-transform",
              connection: "keep-alive",
              "x-accel-buffering": "no",
            },
          });
        }

        if (pathname === "/api/health") {
          return json({ ok: true, now: nowIso() });
        }

        if (pathname === "/api/accounts/import-preview" && req.method === "POST") {
          const body = (await req.json().catch(() => null)) as {
            entries?: ParsedImportEntry[];
            invalidRows?: InvalidImportRow[];
          } | null;
          const entries = Array.isArray(body?.entries) ? body.entries : [];
          const invalidRows = Array.isArray(body?.invalidRows) ? body.invalidRows : [];
          const existingAccounts = db.getAccountsByEmails(entries.map((entry) => String(entry?.email || "")));
          const preview = buildImportPreview(
            entries.map((entry, index) => ({
              lineNumber: Number(entry.lineNumber || index + 1),
              rawLine: String(entry.rawLine || ""),
              email: String(entry.email || "").trim(),
              normalizedEmail: String(entry.normalizedEmail || String(entry.email || "").trim().toLowerCase()),
              password: String(entry.password || ""),
            })),
            invalidRows.map((row, index) => ({
              lineNumber: Number(row.lineNumber || index + 1),
              rawLine: String(row.rawLine || ""),
              reason: String(row.reason || "invalid"),
            })),
            existingAccounts.map((account) => ({
              id: account.id,
              microsoftEmail: account.microsoftEmail,
              passwordPlaintext: account.passwordPlaintext,
              hasApiKey: account.hasApiKey,
              groupName: account.groupName,
            })),
          );
          return json(preview);
        }

        if (pathname === "/api/accounts/import" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as {
          content?: string;
          entries?: Array<{ email?: string; password?: string }>;
          groupName?: string | null;
        } | null;
        const content = String(body?.content || "");
        const parsedEntries = Array.isArray(body?.entries)
          ? body.entries.map((entry) => ({
              email: String(entry?.email || "").trim(),
              password: String(entry?.password || ""),
            }))
          : parseImportContent(content).entries.map((entry) => ({ email: entry.email, password: entry.password }));
        const effectiveEntries = Array.from(
          new Map(
            parsedEntries
              .filter((entry) => entry.email && entry.password)
              .map((entry) => [entry.email.trim().toLowerCase(), entry.password]),
          ).entries(),
        ).map(([email, password]) => ({ email, password }));
        if (effectiveEntries.length === 0) {
          return badRequest("no valid account entries to import");
        }
        const previousAccountsByEmail = new Map(
          db.getAccountsByEmails(effectiveEntries.map((entry) => entry.email)).map((account) => [account.microsoftEmail, account]),
        );
        const forceBootstrapByEmail = new Map(
          effectiveEntries.map((entry) => [
            entry.email,
            shouldForceImportedAccountBootstrap(previousAccountsByEmail.get(entry.email) || null, entry.password),
          ]),
        );
        const summary = db.importAccounts(effectiveEntries, {
          source: "manual",
          groupName: body?.groupName ?? null,
        });
        broadcast({
          type: "account.updated",
          payload: { affectedIds: summary.affectedIds, action: "import" },
          timestamp: nowIso(),
        });
        for (const accountId of summary.affectedIds) {
          const account = db.getAccount(accountId);
          const forceBootstrap = account ? forceBootstrapByEmail.get(account.microsoftEmail) === true : false;
          queueAccountSessionBootstrap(accountId, {
            force: forceBootstrap,
            reason: "auto",
          });
        }
        return json({
          ok: true,
          summary: { created: summary.created, updated: summary.updated, total: summary.total },
          affectedIds: summary.affectedIds,
          revealedAccounts: summary.affectedIds
            .map((accountId) => db.getAccount(accountId))
            .filter((account): account is MicrosoftAccountRecord => account != null)
            .map((account) => serializeImportedAccount(account)),
        });
      }

        if (pathname === "/api/accounts" && req.method === "GET") {
        await accountBusinessFlowManager?.ensureAvailability();
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const data = db.listAccounts({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          hasApiKey: parseBool(url.searchParams.get("hasApiKey")),
          sessionStatus: (url.searchParams.get("sessionStatus") || undefined) as any,
          mailboxStatus: (url.searchParams.get("mailboxStatus") || undefined) as any,
          skipReason: url.searchParams.get("skipReason") || undefined,
          groupName: url.searchParams.get("groupName") || undefined,
          sortBy: url.searchParams.get("sortBy") || undefined,
          sortDir: url.searchParams.get("sortDir") || undefined,
          page,
          pageSize,
        });
        return json({
          total: data.total,
          page,
          pageSize,
          summary: data.summary,
          groups: db.listAccountGroups(),
          rows: data.rows.map((row) => serializeAccount(row)),
        });
      }

      if (accountSessionBootstrapPreviewMatch && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { ids?: number[]; mode?: unknown } | null;
        const ids = Array.isArray(body?.ids) ? body.ids.map((id) => Number(id)) : [];
        const preview = buildAccountBatchBootstrapPreview(
          db,
          ids,
          normalizeAccountBatchBootstrapMode(body?.mode),
          sessionBootstrapQueuedIds,
        );
        return json({
          ok: true,
          ...preview,
        });
      }

        if (pathname === "/api/accounts/group" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { ids?: number[]; groupName?: string | null } | null;
        const ids = Array.isArray(body?.ids) ? body.ids.map((id) => Number(id)) : [];
        const result = db.updateAccountsGroup(ids, body?.groupName ?? null);
        broadcast({
          type: "account.updated",
          payload: { ids, action: "group", groupName: result.groupName },
          timestamp: nowIso(),
        });
        return json({ ok: true, ...result });
      }

        if (accountDetailMatch && req.method === "PATCH") {
        const accountId = Number.parseInt(accountDetailMatch[1] || "", 10);
        if (!Number.isInteger(accountId) || accountId < 1) {
          return badRequest("invalid account id");
        }
        const body = (await req.json().catch(() => null)) as {
          proofMailboxProvider?: string | null;
          proofMailboxAddress?: string | null;
          proofMailboxId?: string | null;
          disabled?: boolean;
          disabledReason?: string | null;
        } | null;
        const hasProofMailboxAddress = !!body && Object.prototype.hasOwnProperty.call(body, "proofMailboxAddress");
        const hasProofMailboxId = !!body && Object.prototype.hasOwnProperty.call(body, "proofMailboxId");
        const hasProofMailboxProvider = !!body && Object.prototype.hasOwnProperty.call(body, "proofMailboxProvider");
        const proofMailboxAddress = !hasProofMailboxAddress ? undefined : body?.proofMailboxAddress == null ? null : String(body.proofMailboxAddress).trim() || null;
        const proofMailboxId = !hasProofMailboxId ? undefined : body?.proofMailboxId == null ? null : String(body.proofMailboxId).trim() || null;
        const rawProvider = !hasProofMailboxProvider ? undefined : body?.proofMailboxProvider == null ? null : String(body.proofMailboxProvider).trim().toLowerCase() || null;
        const disabled = body?.disabled == null ? undefined : Boolean(body.disabled);
        const disabledReason = body?.disabledReason == null ? undefined : String(body.disabledReason).trim() || null;
        if (rawProvider != null && rawProvider !== "cfmail") {
          return badRequest("unsupported proof mailbox provider");
        }
        if (proofMailboxAddress && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(proofMailboxAddress)) {
          return badRequest("invalid proof mailbox address");
        }
        if (disabled === true && !disabledReason) {
          return badRequest("disabled reason is required");
        }
        const currentAccount = db.getAccount(accountId);
        if (!currentAccount) {
          return badRequest(`account not found: ${accountId}`, 404);
        }
        try {
          if (rawProvider !== undefined || proofMailboxAddress !== undefined || proofMailboxId !== undefined) {
            const requestedProofMailboxId = proofMailboxId?.trim() || null;
            const requestedProofMailboxAddress = proofMailboxAddress?.trim().toLowerCase() || null;
            const unchangedSavedProofMailbox =
              requestedProofMailboxAddress != null &&
              requestedProofMailboxId != null &&
              currentAccount.proofMailboxAddress?.trim().toLowerCase() === requestedProofMailboxAddress &&
              currentAccount.proofMailboxId === requestedProofMailboxId;
            const nextProofMailbox: {
              provider?: "cfmail" | null;
              address?: string | null;
              mailboxId?: string | null;
            } =
              proofMailboxAddress == null
                ? {
                    provider: rawProvider === "cfmail" ? "cfmail" : rawProvider === null ? null : undefined,
                    address: proofMailboxAddress,
                    mailboxId: proofMailboxId,
                  }
                : unchangedSavedProofMailbox
                  ? {
                      provider: currentAccount.proofMailboxProvider || "cfmail",
                      address: currentAccount.proofMailboxAddress,
                      mailboxId: currentAccount.proofMailboxId,
                    }
                  : await ensureSavedProofMailbox({
                      address: proofMailboxAddress,
                      mailboxId: proofMailboxId,
                    });
            db.updateAccountProofMailbox(accountId, {
              provider: nextProofMailbox.provider,
              address: nextProofMailbox.address,
              mailboxId: nextProofMailbox.mailboxId,
            });
          }
          if (disabled !== undefined || disabledReason !== undefined) {
            db.updateAccountAvailability(accountId, {
              disabled,
              reason: disabledReason,
            });
          }
          const account = db.getAccount(accountId);
          if (!account) {
            return badRequest(`account not found: ${accountId}`, 404);
          }
          broadcast({
            type: "account.updated",
            payload: { ids: [accountId], action: "account_meta" },
            timestamp: nowIso(),
          });
          return json({ ok: true, account: serializeAccount(account) });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (/account not found/i.test(message)) {
            return badRequest(message, 404);
          }
          return badRequest(message);
        }
      }

      if (accountBusinessFlowStartMatch && req.method === "POST") {
        const accountId = Number.parseInt(accountBusinessFlowStartMatch[1] || "", 10);
        if (!Number.isInteger(accountId) || accountId < 1) {
          return badRequest("invalid account id");
        }
        const body = (await req.json().catch(() => null)) as { site?: unknown; mode?: unknown } | null;
        const site = parseAccountBusinessFlowSite(body?.site);
        const mode = parseAccountBusinessFlowMode(body?.mode);
        if (!site) {
          return badRequest("invalid business flow site");
        }
        if (!mode) {
          return badRequest("invalid business flow mode");
        }
        const account = db.getAccount(accountId);
        if (!account) {
          return badRequest(`account not found: ${accountId}`, 404);
        }
        try {
          await accountBusinessFlowManager?.start({ accountId, site, mode });
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
        return json({
          ok: true,
          account: serializeAccount(db.getAccount(accountId) || account),
        });
      }

      if (accountSessionRebootstrapMatch && req.method === "POST") {
        const accountId = Number.parseInt(accountSessionRebootstrapMatch[1] || "", 10);
        if (!Number.isInteger(accountId) || accountId < 1) {
          return badRequest("invalid account id");
        }
        const account = db.getAccount(accountId);
        if (!account) {
          return badRequest(`account not found: ${accountId}`, 404);
        }
        const body = (await req.json().catch(() => null)) as { force?: boolean | null } | null;
        const connectBlockMessage = getAccountConnectBlockMessage(account);
        if (connectBlockMessage) {
          return badRequest(connectBlockMessage, 409);
        }
        const rebootstrapRequest = normalizeAccountSessionRebootstrapRequest(body);
        const proxySelection = resolveRequestedSessionProxyNode(
          rebootstrapRequest.proxyNode,
          db.listProxyNodes().map((node) => node.nodeName),
        );
        if (proxySelection.error) {
          return badRequest(proxySelection.error, 404);
        }
        if (proxySelection.proxyNode && account.browserSession?.status === "bootstrapping") {
          return badRequest("账号当前正在 Bootstrap，暂时不能切换 Session Proxy", 409);
        }
        const queued = queueAccountSessionBootstrap(accountId, {
          force: rebootstrapRequest.force,
          reason: "manual",
          proxyNode: proxySelection.proxyNode,
        });
        return json({
          ok: true,
          queued,
          account: serializeAccount(db.getAccount(accountId) || account),
        });
      }

        if (pathname === "/api/accounts" && req.method === "DELETE") {
        const body = (await req.json().catch(() => null)) as { ids?: number[] } | null;
        const ids = Array.isArray(body?.ids) ? body.ids.map((id) => Number(id)) : [];
        const result = db.deleteAccounts(ids);
        broadcast({
          type: "account.updated",
          payload: { ids, action: "delete", blockedIds: result.blockedIds },
          timestamp: nowIso(),
        });
        return json({ ok: true, ...result });
      }

        if (pathname === "/api/api-keys" && req.method === "GET") {
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const data = db.listApiKeys({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          groupName: url.searchParams.get("groupName") || undefined,
          sortBy: (url.searchParams.get("sortBy") as "extractedAt" | "lastVerifiedAt" | null) || undefined,
          sortDir: (url.searchParams.get("sortDir") as "desc" | "asc" | null) || undefined,
          page,
          pageSize,
        });
        return json({
          total: data.total,
          page,
          pageSize,
          summary: data.summary,
          groups: db.listAccountGroups(),
          rows: data.rows,
        });
      }

      if (pathname === "/api/api-keys/export" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { ids?: number[] } | null;
        const ids = Array.isArray(body?.ids)
          ? Array.from(new Set(body.ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)))
          : [];
        if (ids.length === 0) {
          return badRequest("api key ids are required");
        }
        const items = db.listApiKeysForExport(ids).map((row) => ({
          id: row.id,
          apiKey: row.apiKey,
          extractedIp: row.extractedIp,
        }));
        return json({
          items,
          content: buildApiKeyExportContent(items),
        });
      }

      if ((pathname === "/api/grok/keys" || pathname === "/api/grok/accounts") && req.method === "GET") {
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const data = db.listGrokApiKeys({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          sortBy: (url.searchParams.get("sortBy") as "extractedAt" | "lastVerifiedAt" | null) || undefined,
          sortDir: (url.searchParams.get("sortDir") as "desc" | "asc" | null) || undefined,
          page,
          pageSize,
        });
        return json({
          ok: true,
          total: data.total,
          page,
          pageSize,
          summary: data.summary,
          rows: data.rows.map((row) => serializeGrokApiKey(row)),
        });
      }

      if ((pathname === "/api/grok/keys/export" || pathname === "/api/grok/accounts/export") && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { ids?: number[] } | null;
        const ids = Array.isArray(body?.ids)
          ? Array.from(new Set(body.ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)))
          : [];
        if (ids.length === 0) {
          return badRequest("grok account ids are required");
        }
        const items = db.listGrokApiKeysForExport(ids).map((row) => ({
          id: row.id,
          email: row.email,
          password: row.password,
          sso: row.sso,
          ssoRw: row.ssoRw,
          cfClearance: row.cfClearance,
          checkoutUrl: row.checkoutUrl,
          birthDate: row.birthDate,
        }));
        return json({
          ok: true,
          items,
          content: buildGrokSsoExportContent(items),
        });
      }

      const grokApiKeyDetailMatch = pathname.match(/^\/api\/grok\/(?:keys|accounts)\/(\d+)$/);
      if (grokApiKeyDetailMatch && req.method === "GET") {
        const keyId = Number.parseInt(grokApiKeyDetailMatch[1] || "", 10);
        if (!Number.isInteger(keyId) || keyId < 1) {
          return badRequest("invalid grok account id");
        }
        const key = db.getGrokApiKey(keyId);
        if (!key) {
          return badRequest(`grok account not found: ${keyId}`, 404);
        }
        const includeSecret = parseBool(url.searchParams.get("includeSecret")) === true;
        return json({
          ok: true,
          key: serializeGrokApiKey(key, includeSecret),
        });
      }

      if (pathname === "/favicon.ico" && req.method === "GET") {
        return Response.redirect(new URL("/favicon.svg", req.url), 302);
      }

      if (pathname === "/api/jobs/current" && req.method === "GET") {
        const site = parseJobSite(url.searchParams.get("site"));
        return json(await serializeJobSnapshot(site, db, getSchedulerBySite(site)));
      }

      if (pathname === "/api/chatgpt/credentials" && req.method === "GET") {
        const limit = Math.max(1, Math.min(100, toInt(url.searchParams.get("limit") || undefined, 20)));
        const sortBy = (url.searchParams.get("sortBy") as "createdAt" | "expiresAt" | null) || "createdAt";
        const sortDir = (url.searchParams.get("sortDir") as "desc" | "asc" | null) || "desc";
        const q = url.searchParams.get("q") || undefined;
        const expiryStatus = (url.searchParams.get("expiryStatus") as "valid" | "expired" | "noExpiry" | null) || undefined;
        return json({
          ok: true,
          rows: chatgptScheduler.getRecentCredentials({ limit, sortBy, sortDir, q, expiryStatus }).map((row) => serializeChatGptCredential(row)),
        });
      }

      if (pathname === "/api/chatgpt/attempt-draft" && req.method === "POST") {
        const draft = await buildChatGptDraft({
          apiKey: (process.env.CFMAIL_API_KEY || "").trim(),
          baseUrl: process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test",
          httpJson: serverHttpJson,
          rootDomain: DEFAULT_CFMAIL_ROOT_DOMAIN,
          createPassword: randomPassword,
          createNickname: randomNickname,
          createBirthDate: randomBirthDate,
          nowIso,
        });
        return json({ ok: true, draft });
      }

      const chatgptCredentialDetailMatch = pathname.match(/^\/api\/chatgpt\/credentials\/(\d+)$/);
      if (chatgptCredentialDetailMatch && req.method === "GET") {
        const credentialId = Number.parseInt(chatgptCredentialDetailMatch[1] || "", 10);
        if (!Number.isInteger(credentialId) || credentialId < 1) {
          return badRequest("invalid credential id");
        }
        const credential = db.getChatGptCredential(credentialId);
        if (!credential) {
          return badRequest(`credential not found: ${credentialId}`, 404);
        }
        const includeSecrets = parseBool(url.searchParams.get("includeSecrets")) === true;
        return json({
          ok: true,
          credential: serializeChatGptCredential(credential, includeSecrets),
        });
      }

      if (pathname === "/api/chatgpt/upstream-settings" && req.method === "GET") {
        return json({
          ok: true,
          settings: chatGptUpstreamSupplement.serializeSettings(),
        });
      }

      if (pathname === "/api/chatgpt/upstream-settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as {
          baseUrl?: unknown;
          apiKey?: unknown;
          clearBaseUrl?: unknown;
          clearApiKey?: unknown;
          groupHistory?: unknown;
        } | null;
        try {
          const settings = chatGptUpstreamSupplement.updateSettings({
            baseUrl: typeof body?.baseUrl === "string" ? body.baseUrl : undefined,
            apiKey: typeof body?.apiKey === "string" ? body.apiKey : undefined,
            clearBaseUrl: body?.clearBaseUrl === true,
            clearApiKey: body?.clearApiKey === true,
            groupHistory: Array.isArray(body?.groupHistory) ? body?.groupHistory.map((item) => String(item || "")) : undefined,
          });
          broadcastChatGptUpstreamSettingsUpdated(broadcast, {
            reason: "settings_saved",
            configured: settings.configured,
            groupHistory: settings.groupHistory,
          });
          return json({
            ok: true,
            settings,
          });
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/chatgpt/credentials/supplement" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as {
          ids?: unknown;
          groupName?: unknown;
        } | null;
        const ids = Array.isArray(body?.ids) ? body.ids.map((item) => Number(item)).filter((item) => Number.isInteger(item) && item > 0) : [];
        const groupName = normalizeChatGptUpstreamGroupName(body?.groupName);
        if (ids.length === 0) {
          return badRequest("at least one credential id is required");
        }
        if (!groupName) {
          return badRequest("groupName is required");
        }
        try {
          const result = await chatGptUpstreamSupplement.supplementCredentials(ids, groupName);
          if (result.succeeded > 0) {
            broadcastChatGptUpstreamSettingsUpdated(broadcast, {
              reason: "manual_supplement",
              groupName: result.groupName,
              succeeded: result.succeeded,
            });
          }
          return json({
            ok: true,
            ...result,
          });
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/account-extractors/settings" && req.method === "GET") {
        const settings = readSettings();
        return json({
          ok: true,
          settings: serializeExtractorSettings(settings),
        });
      }

      if (pathname === "/api/account-extractors/runtime" && req.method === "GET") {
        return json({
          ok: true,
          runtime: accountExtractorRuntime.getSnapshot(),
        });
      }

      if (pathname === "/api/account-extractors/run" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as {
          sources?: unknown;
          quantity?: unknown;
          maxWaitSec?: unknown;
          accountType?: unknown;
        } | null;
        const settings = readSettings();
        try {
          const runtime = await accountExtractorRuntime.start({
            sources: normalizeExtractorSources(body?.sources ?? settings.defaultAutoExtractSources),
            quantity: toOptionalPositiveInt(body?.quantity) ?? settings.defaultAutoExtractQuantity,
            maxWaitSec: toOptionalPositiveInt(body?.maxWaitSec) ?? settings.defaultAutoExtractMaxWaitSec,
            accountType: normalizeExtractorAccountType(body?.accountType, settings.defaultAutoExtractAccountType),
          });
          return json({ ok: true, runtime });
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/account-extractors/stop" && req.method === "POST") {
        try {
          const runtime = await accountExtractorRuntime.stop();
          return json({ ok: true, runtime });
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/account-extractors/settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Partial<AppSettings> | null;
        const current = readSettings();
        const next = buildNextSettings(current, {
          extractorZhanghaoyaKey: typeof body?.extractorZhanghaoyaKey === "string" ? body.extractorZhanghaoyaKey : undefined,
          extractorShanyouxiangKey:
            typeof body?.extractorShanyouxiangKey === "string" ? body.extractorShanyouxiangKey : undefined,
          extractorShankeyunKey: typeof body?.extractorShankeyunKey === "string" ? body.extractorShankeyunKey : undefined,
          extractorHotmail666Key: typeof body?.extractorHotmail666Key === "string" ? body.extractorHotmail666Key : undefined,
          defaultAutoExtractSources:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractSources")
              ? normalizeExtractorSources(body.defaultAutoExtractSources)
              : undefined,
          defaultAutoExtractQuantity:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractQuantity")
              ? toOptionalPositiveInt(body.defaultAutoExtractQuantity)
              : undefined,
          defaultAutoExtractMaxWaitSec:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractMaxWaitSec")
              ? toOptionalPositiveInt(body.defaultAutoExtractMaxWaitSec)
              : undefined,
          defaultAutoExtractAccountType:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractAccountType")
              ? normalizeExtractorAccountType(body.defaultAutoExtractAccountType, current.defaultAutoExtractAccountType)
              : undefined,
        });
        db.setSettings(next);
        return json({
          ok: true,
          settings: serializeExtractorSettings(next),
        });
      }

      if (pathname === "/api/microsoft-mail/settings" && req.method === "GET") {
        return json({
          ok: true,
          settings: serializeMicrosoftGraphSettings(readSettings()),
        });
      }

      if (pathname === "/api/microsoft-mail/settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Partial<AppSettings> | null;
        const current = readSettings();
        const next = buildNextSettings(current, {
          microsoftGraphClientId:
            body && Object.prototype.hasOwnProperty.call(body, "microsoftGraphClientId")
              ? typeof body.microsoftGraphClientId === "string"
                ? body.microsoftGraphClientId
                : ""
              : undefined,
          microsoftGraphClientSecret:
            body && Object.prototype.hasOwnProperty.call(body, "microsoftGraphClientSecret")
              ? typeof body.microsoftGraphClientSecret === "string"
                ? body.microsoftGraphClientSecret.trim()
                  ? body.microsoftGraphClientSecret
                  : current.microsoftGraphClientSecret
                : ""
              : undefined,
          microsoftGraphRedirectUri:
            body && Object.prototype.hasOwnProperty.call(body, "microsoftGraphRedirectUri")
              ? typeof body.microsoftGraphRedirectUri === "string"
                ? body.microsoftGraphRedirectUri
                : ""
              : undefined,
          microsoftGraphAuthority:
            body && Object.prototype.hasOwnProperty.call(body, "microsoftGraphAuthority")
              ? typeof body.microsoftGraphAuthority === "string"
                ? body.microsoftGraphAuthority
                : "common"
              : undefined,
        });
        db.setSettings(next);
        return json({
          ok: true,
          settings: serializeMicrosoftGraphSettings(next),
        });
      }

      if (pathname === "/api/microsoft-mail/mailboxes" && req.method === "GET") {
        const mailboxes = db.listMailboxes({ connectedOnly: true });
        const latestVerificationCodes = resolveLatestMailboxVerificationCodes(mailboxes);
        return json({
          ok: true,
          rows: mailboxes.map((row) => serializeMailbox(row, latestVerificationCodes.get(row.id) || null)),
        });
      }

      if (mailboxDetailMatch && req.method === "GET") {
        const mailboxId = Number.parseInt(mailboxDetailMatch[1] || "", 10);
        if (!Number.isInteger(mailboxId) || mailboxId < 1) {
          return badRequest("invalid mailbox id");
        }
        const mailbox = db.getMailbox(mailboxId);
        if (!mailbox) {
          return badRequest(`mailbox not found: ${mailboxId}`, 404);
        }
        return json({
          ok: true,
          row: serializeMailbox(mailbox),
        });
      }

      if (mailboxOauthStartMatch && req.method === "POST") {
        const accountId = Number.parseInt(mailboxOauthStartMatch[1] || "", 10);
        if (!Number.isInteger(accountId) || accountId < 1) {
          return badRequest("invalid account id");
        }
        const account = db.getAccount(accountId);
        if (!account) {
          return badRequest(`account not found: ${accountId}`, 404);
        }
        const body = (await req.json().catch(() => null)) as { force?: boolean | null } | null;
        const connectBlockMessage = getAccountConnectBlockMessage(account);
        if (connectBlockMessage) {
          return badRequest(connectBlockMessage, 409);
        }
        const rebootstrapRequest = normalizeAccountSessionRebootstrapRequest(body);
        const proxySelection = resolveRequestedSessionProxyNode(
          rebootstrapRequest.proxyNode,
          db.listProxyNodes().map((node) => node.nodeName),
        );
        if (proxySelection.error) {
          return badRequest(proxySelection.error, 404);
        }
        if (proxySelection.proxyNode && account.browserSession?.status === "bootstrapping") {
          return badRequest("账号当前正在 Bootstrap，暂时不能切换 Session Proxy", 409);
        }
        const queued = queueAccountSessionBootstrap(accountId, {
          force: rebootstrapRequest.force,
          reason: "manual",
          proxyNode: proxySelection.proxyNode,
        });
        return json({
          ok: true,
          queued,
          account: serializeAccount(db.getAccount(accountId) || account),
        });
      }

      if (pathname === "/api/microsoft-mail/oauth/callback" && req.method === "GET") {
        const state = String(url.searchParams.get("state") || "").trim();
        const oauthError = String(url.searchParams.get("error") || "").trim();
        const oauthErrorDescription = String(url.searchParams.get("error_description") || "").trim();
        const code = String(url.searchParams.get("code") || "").trim();
        const mailbox = state ? db.getMailboxByOauthState(state) : null;
        if (!mailbox) {
          return buildMailboxRedirect(req, null, "error");
        }
        try {
          if (oauthError) {
            applyMailboxFailureState({
              db,
              mailbox,
              error: new Error(`${oauthError}:${oauthErrorDescription || oauthError}`),
              action: "oauth_error",
              broadcast,
            });
            return buildMailboxRedirect(req, mailbox.accountId, "error");
          }
          if (!code) {
            throw new Error("oauth_code_missing");
          }
          if (!mailbox.oauthCodeVerifier) {
            throw new Error("oauth_code_verifier_missing");
          }
          const graphSettings = readMicrosoftGraphSettings(readSettings());
          assertMicrosoftGraphSettings(graphSettings);
          const token = await exchangeMicrosoftAuthCode({
            clientId: graphSettings.clientId,
            clientSecret: graphSettings.clientSecret,
            redirectUri: graphSettings.redirectUri,
            authority: mailbox.authority || graphSettings.authority,
            code,
            codeVerifier: mailbox.oauthCodeVerifier,
          });
          if (!token.refreshToken) {
            throw new Error("refresh_token_missing");
          }
          const profile = token.accessToken ? await fetchMicrosoftProfile(token.accessToken) : null;
          const nextMailbox = db.completeMailboxOAuth(mailbox.id, {
            refreshToken: token.refreshToken,
            accessToken: token.accessToken,
            accessTokenExpiresAt: token.expiresAt,
            authority: mailbox.authority || graphSettings.authority,
            graphUserId: profile?.id ?? null,
            graphUserPrincipalName: profile?.userPrincipalName ?? profile?.mail ?? null,
            graphDisplayName: profile?.displayName ?? null,
          });
          broadcast({
            type: "mailbox.updated",
            payload: { mailboxIds: [nextMailbox.id], action: "oauth_success" },
            timestamp: nowIso(),
          });
          broadcast({
            type: "account.updated",
            payload: { affectedIds: [mailbox.accountId], action: "mailbox_status" },
            timestamp: nowIso(),
          });
          return buildMailboxRedirect(req, mailbox.accountId, "success");
        } catch (error) {
          applyMailboxFailureState({
            db,
            mailbox,
            error,
            action: "oauth_error",
            broadcast,
          });
          return buildMailboxRedirect(req, mailbox.accountId, "error");
        }
      }

      if (mailboxSyncMatch && req.method === "POST") {
        const mailboxId = Number.parseInt(mailboxSyncMatch[1] || "", 10);
        if (!Number.isInteger(mailboxId) || mailboxId < 1) {
          return badRequest("invalid mailbox id");
        }
        const mailbox = db.getMailbox(mailboxId);
        if (!mailbox) {
          return badRequest(`mailbox not found: ${mailboxId}`, 404);
        }
        if (!mailbox.refreshToken && !mailbox.accessToken) {
          return badRequest("mailbox not authorized", 409);
        }
        try {
          const nextMailbox = await syncMailboxInbox(db, mailbox, readSettings());
          broadcast({
            type: "mailbox.updated",
            payload: { mailboxIds: [nextMailbox.id], action: "sync" },
            timestamp: nowIso(),
          });
          broadcast({
            type: "account.updated",
            payload: { affectedIds: [mailbox.accountId], action: "mailbox_status" },
            timestamp: nowIso(),
          });
          return json({
            ok: true,
            mailbox: serializeMailbox(nextMailbox),
          });
        } catch (error) {
          const failedMailbox = applyMailboxFailureState({
            db,
            mailbox,
            error,
            action: "sync_failed",
            broadcast,
          });
          return badRequest(getMailboxErrorMessage(error), failedMailbox.status === "invalidated" || failedMailbox.status === "locked" ? 409 : 502);
        }
      }

      if (mailboxMessagesMatch && req.method === "GET") {
        const mailboxId = Number.parseInt(mailboxMessagesMatch[1] || "", 10);
        if (!Number.isInteger(mailboxId) || mailboxId < 1) {
          return badRequest("invalid mailbox id");
        }
        const mailbox = db.getMailbox(mailboxId);
        if (!mailbox) {
          return badRequest(`mailbox not found: ${mailboxId}`, 404);
        }
        const limit = toInt(url.searchParams.get("limit") || undefined, 50);
        const offset = toInt(url.searchParams.get("offset") || undefined, 0);
        const payload = db.listMailboxMessages(mailboxId, { limit, offset });
        return json({
          ok: true,
          mailbox: serializeMailbox(mailbox),
          rows: payload.rows.map((row) => serializeMailboxMessageSummary(row)),
          total: payload.total,
          limit,
          offset,
          hasMore: offset + payload.rows.length < payload.total,
        });
      }

      if (mailboxMessageDetailMatch && req.method === "GET") {
        const messageId = Number.parseInt(mailboxMessageDetailMatch[1] || "", 10);
        if (!Number.isInteger(messageId) || messageId < 1) {
          return badRequest("invalid message id");
        }
        let message = db.getMailboxMessage(messageId);
        if (!message) {
          return badRequest(`message not found: ${messageId}`, 404);
        }
        if (!message.bodyContent.trim()) {
          const mailbox = db.getMailbox(message.mailboxId);
          if (mailbox?.refreshToken || mailbox?.accessToken) {
            try {
              const { accessToken } = await ensureMailboxAccessToken(db, mailbox, readSettings());
              const detail = await fetchMicrosoftMessageDetail({
                accessToken,
                graphMessageId: message.graphMessageId,
              });
              db.upsertMailboxMessages(mailbox.id, [detail], { keepLatest: 500 });
              message = db.getMailboxMessageByGraphId(mailbox.id, message.graphMessageId) || message;
            } catch {}
          }
        }
        return json({
          ok: true,
          message: serializeMailboxMessageDetail(message),
        });
      }

        if (pathname === "/api/account-extractors/history" && req.method === "GET") {
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const providerParam = url.searchParams.get("provider");
        const provider =
          providerParam === "zhanghaoya"
          || providerParam === "shanyouxiang"
          || providerParam === "shankeyun"
          || providerParam === "hotmail666"
            ? providerParam
            : undefined;
        return json(
          db.listAccountExtractHistory({
            provider,
            status: url.searchParams.get("status") || undefined,
            q: url.searchParams.get("q") || undefined,
            page,
            pageSize,
          }),
        );
      }

        if (pathname === "/api/jobs/current/control" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
        const action = String(body?.action || "");
        const site = parseJobSite(
          typeof body?.site === "string" ? body.site : url.searchParams.get("site"),
        );
        const scheduler = getSchedulerBySite(site);
        try {
          if (action === "start") {
            await ensureBrowserAvailabilityFresh();
            const runModeAvailability = getBrowserRunModeAvailability();
            if (site === "chatgpt") {
              const explicitRunMode = body?.runMode === "headless" || body?.runMode === "headed" ? body.runMode : null;
              if (explicitRunMode) {
                assertRunModeAvailable(explicitRunMode, runModeAvailability);
              }
              const runMode = explicitRunMode || clampRunModeToAvailability("headed", runModeAvailability);
              const need = toOptionalPositiveInt(body?.need) ?? 1;
              const parallel = toOptionalPositiveInt(body?.parallel) ?? 1;
              const maxAttempts = normalizeJobMaxAttempts(need, toOptionalPositiveInt(body?.maxAttempts) ?? 1);
              const job = await chatgptScheduler.startJob({
                runMode,
                need,
                parallel,
                maxAttempts,
                upstreamGroupName: normalizeChatGptUpstreamGroupName(body?.upstreamGroupName),
              });
              return json({ ok: true, job: serializeJobRecordForApi(job) });
            }
            const settings = readSettings();
            const explicitRunMode = body?.runMode === "headless" || body?.runMode === "headed" ? body.runMode : null;
            if (explicitRunMode) {
              assertRunModeAvailable(explicitRunMode, runModeAvailability);
            }
            const requestedRunMode = explicitRunMode || clampRunModeToAvailability(settings.defaultRunMode, runModeAvailability);
            if (site === "grok") {
              const job = await grokScheduler.startJob({
                runMode: requestedRunMode,
                need: Math.max(1, Number(body?.need || settings.defaultNeed)),
                parallel: Math.max(1, Number(body?.parallel || settings.defaultParallel)),
                maxAttempts: Math.max(1, Number(body?.maxAttempts || settings.defaultMaxAttempts)),
              });
              return json({ ok: true, job: serializeJobRecordForApi(job) });
            }
            const job = await tavilyScheduler.startJob({
              runMode: requestedRunMode,
              need: Math.max(1, Number(body?.need || settings.defaultNeed)),
              parallel: Math.max(1, Number(body?.parallel || settings.defaultParallel)),
              maxAttempts: Math.max(1, Number(body?.maxAttempts || settings.defaultMaxAttempts)),
              autoExtractSources: normalizeExtractorSources(body?.autoExtractSources ?? settings.defaultAutoExtractSources),
              autoExtractQuantity:
                toOptionalPositiveInt(body?.autoExtractQuantity) ?? settings.defaultAutoExtractQuantity,
              autoExtractMaxWaitSec:
                toOptionalPositiveInt(body?.autoExtractMaxWaitSec) ?? settings.defaultAutoExtractMaxWaitSec,
              autoExtractAccountType: normalizeExtractorAccountType(
                body?.autoExtractAccountType,
                settings.defaultAutoExtractAccountType,
              ),
            });
            return json({ ok: true, job: serializeJobRecordForApi(job) });
          }
          if (action === "pause") {
            if (site === "chatgpt") {
              return json({ ok: true, job: serializeJobRecordForApi(chatgptScheduler.pauseCurrentJob()) });
            }
            return json({
              ok: true,
              job: serializeJobRecordForApi(site === "grok" ? grokScheduler.pauseCurrentJob() : tavilyScheduler.pauseCurrentJob()),
            });
          }
          if (action === "resume") {
            if (site === "chatgpt") {
              return json({ ok: true, job: serializeJobRecordForApi(chatgptScheduler.resumeCurrentJob()) });
            }
            return json({
              ok: true,
              job: serializeJobRecordForApi(site === "grok" ? grokScheduler.resumeCurrentJob() : tavilyScheduler.resumeCurrentJob()),
            });
          }
          if (action === "stop") {
            return json({ ok: true, job: serializeJobRecordForApi(scheduler.stopCurrentJob()) });
          }
          if (action === "force_stop") {
            return json({
              ok: true,
              job: serializeJobRecordForApi(scheduler.forceStopCurrentJob(body?.confirmForceStop === true)),
            });
          }
          if (action === "update_limits") {
            if (site === "chatgpt") {
              const job = chatgptScheduler.updateCurrentJobLimits({
                parallel: body?.parallel == null ? undefined : Number(body.parallel),
                need: body?.need == null ? undefined : Number(body.need),
                maxAttempts: body?.maxAttempts == null ? undefined : Number(body.maxAttempts),
                upstreamGroupName:
                  body && Object.prototype.hasOwnProperty.call(body, "upstreamGroupName")
                    ? normalizeChatGptUpstreamGroupName(body?.upstreamGroupName)
                    : undefined,
              });
              return json({ ok: true, job: serializeJobRecordForApi(job) });
            }
            if (site === "grok") {
              const job = grokScheduler.updateCurrentJobLimits({
                parallel: body?.parallel == null ? undefined : Number(body.parallel),
                need: body?.need == null ? undefined : Number(body.need),
                maxAttempts: body?.maxAttempts == null ? undefined : Number(body.maxAttempts),
              });
              return json({ ok: true, job: serializeJobRecordForApi(job) });
            }
            const job = tavilyScheduler.updateCurrentJobLimits({
              parallel: body?.parallel == null ? undefined : Number(body.parallel),
              need: body?.need == null ? undefined : Number(body.need),
              maxAttempts: body?.maxAttempts == null ? undefined : Number(body.maxAttempts),
              autoExtractSources:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractSources")
                  ? normalizeExtractorSources(body.autoExtractSources)
                  : undefined,
              autoExtractQuantity:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractQuantity")
                  ? toOptionalPositiveInt(body.autoExtractQuantity)
                  : undefined,
              autoExtractMaxWaitSec:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractMaxWaitSec")
                  ? toOptionalPositiveInt(body.autoExtractMaxWaitSec)
                  : undefined,
              autoExtractAccountType:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractAccountType")
                  ? normalizeExtractorAccountType(
                      body.autoExtractAccountType,
                      scheduler.currentJob()?.autoExtractAccountType
                        ?? readSettings().defaultAutoExtractAccountType,
                    )
                  : undefined,
            });
            return json({ ok: true, job: serializeJobRecordForApi(job) });
          }
          return badRequest(`unsupported action: ${action}`);
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/proxies" && req.method === "GET") {
        const settings = readSettings();
        const nodes = settings.subscriptionUrl.trim() ? db.listProxyNodes() : [];
        return json(
          serializeProxyPayload({
            settings,
            nodes,
            checkState: proxyCheckCoordinator.getState(),
            syncError: latestProxySyncError,
          }),
        );
      }

      if (pathname === "/api/proxies/settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
        if (body !== null && (typeof body !== "object" || Array.isArray(body))) {
          return badRequest("proxy settings payload must be a JSON object");
        }
        if (proxyCheckCoordinator.isRunning()) {
          return badRequest("proxy check is running; wait until it finishes before saving settings", 409);
        }
        const unexpectedProxySettingsKeys = listUnexpectedProxySettingsKeys(body);
        if (unexpectedProxySettingsKeys.length > 0) {
          return badRequest(`unsupported proxy settings keys: ${unexpectedProxySettingsKeys.join(", ")}`);
        }
        const current = readSettings();
        const optimisticNext = buildNextProxySettings(current, body as Partial<ProxySettingsUpdate> | null);
        if (!optimisticNext.subscriptionUrl.trim()) {
          latestProxySyncError = null;
          db.setSettings(optimisticNext);
          db.upsertProxyInventory([]);
          return json(
            serializeProxyPayload({
              settings: optimisticNext,
              nodes: [],
              checkState: proxyCheckCoordinator.getState(),
              syncError: null,
            }),
          );
        }
        try {
          const { settings: next, result: inventory } = await runExclusiveProxyOp(() =>
            validateProxySettingsBeforePersist({
              current,
              input: body as Partial<ProxySettingsUpdate> | null,
              sync: fetchProxyInventory,
              persist: (validatedSettings) => db.setSettings(validatedSettings),
            }),
          );
          latestProxySyncError = null;
          db.upsertProxyInventory(inventory.nodeNames);
          return json(
            serializeProxyPayload({
              settings: next,
              nodes: db.listProxyNodes(),
              checkState: proxyCheckCoordinator.getState(),
              syncError: null,
            }),
          );
        } catch (error) {
          latestProxySyncError = error instanceof Error ? error.message : String(error);
          throw error;
        }
      }

      if (pathname === "/api/proxies/check" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { scope?: string; nodeName?: string } | null;
        const scope = body?.scope === "node" ? "node" : body?.scope == null || body.scope === "all" ? "all" : null;
        if (!scope) {
          return badRequest(`unsupported proxy check scope: ${String(body?.scope)}`);
        }
        const started = await proxyCheckCoordinator.startCheck({
          scope: scope as ProxyCheckScope,
          nodeName: body?.nodeName,
        });
        return json({
          ok: true,
          accepted: started.accepted,
          checkState: started.checkState,
        });
      }

        return await serveStatic(req);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[web-admin] ${req.method} ${pathname} failed: ${message}`);
        if (error instanceof Error && error.stack) {
          console.error(error.stack);
        }
        return badRequest(message, 500);
      }
    },
  });

  console.log(`Tavreg Hikari web admin ready at http://${server.hostname}:${server.port}`);

  void runExclusiveProxyOp(() => syncProxyInventory(db, defaults))
    .then((inventory) => {
      latestProxySyncError = null;
      broadcast({
        type: "proxy.updated",
        payload: {
          nodes: inventory.nodes,
          checkState: proxyCheckCoordinator.getState(),
        },
        timestamp: nowIso(),
      });
    })
    .catch((error) => {
      latestProxySyncError = error instanceof Error ? error.message : String(error);
    });

  const shutdown = async () => {
    await Promise.all([tavilyScheduler.shutdown(), grokScheduler.shutdown(), chatgptScheduler.shutdown()]).catch(() => {});
    db.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
