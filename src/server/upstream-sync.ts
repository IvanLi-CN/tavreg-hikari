import {
  type AppSettings,
  type AppDatabase,
  type ChatGptCredentialRecord,
  type GrokApiKeyRecord,
  type MicrosoftAccountRecord,
  type UpstreamChatGptCredentialSyncInput,
  type UpstreamGrokKeySyncInput,
  type UpstreamMicrosoftAccountSyncInput,
} from "../storage/app-db.js";

export const DEFAULT_UPSTREAM_TAVREG_BASE_URL = "https://tavreg-hikari.ivanli.cc";
export type UpstreamTavregWritebackMode = "off" | "success_only";

export interface UpstreamSyncConfig {
  enabled: boolean;
  baseUrl: string;
  apiKey: string;
  writeback: UpstreamTavregWritebackMode;
  localInstanceId?: string | null;
}

export type UpstreamSyncSettingsInput = Pick<
  AppSettings,
  "upstreamTavregSyncEnabled" | "upstreamTavregBaseUrl" | "upstreamTavregApiKey" | "upstreamTavregWriteback" | "localInstanceId"
>;

export interface UpstreamAccountSyncSummary {
  ok: true;
  upstreamOrigin: string;
  startedAt: string;
  completedAt: string;
  total: number;
  created: number;
  updated: number;
  linkedApiKeys: number;
  syncedKeys: {
    tavily: number;
    chatgpt: number;
    grok: number;
  };
}

export interface UpstreamTavilySuccessPayload {
  site?: "tavily";
  account: MicrosoftAccountRecord;
  keyId?: number | null;
  apiKey: string;
  extractedIp?: string | null;
  lastSuccessAt?: string | null;
  cookiesSnapshot?: unknown[];
  browserFingerprintSnapshot?: unknown | null;
  apiKeyPrefix?: string | null;
}

export interface UpstreamChatGptSuccessPayload {
  site: "chatgpt";
  credential: ChatGptCredentialRecord;
}

export interface UpstreamGrokSuccessPayload {
  site: "grok";
  key: GrokApiKeyRecord;
}

export type UpstreamSuccessPayload = UpstreamTavilySuccessPayload | UpstreamChatGptSuccessPayload | UpstreamGrokSuccessPayload;

type JsonRecord = Record<string, unknown>;

const DEFAULT_UPSTREAM_DETAIL_CONCURRENCY = 12;

function nowIso(): string {
  return new Date().toISOString();
}

export function normalizeUpstreamBaseUrl(value: unknown): string {
  const raw = String(value || "").trim() || DEFAULT_UPSTREAM_TAVREG_BASE_URL;
  const parsed = new URL(raw);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("upstream base url must use http or https");
  }
  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/+$/, "");
}

export function normalizeUpstreamWritebackMode(value: unknown): UpstreamTavregWritebackMode {
  return String(value || "").trim() === "success_only" ? "success_only" : "off";
}

export function buildUpstreamSyncConfig(settings: Partial<UpstreamSyncSettingsInput>): UpstreamSyncConfig {
  return {
    enabled: settings.upstreamTavregSyncEnabled === true,
    baseUrl: normalizeUpstreamBaseUrl(settings.upstreamTavregBaseUrl),
    apiKey: String(settings.upstreamTavregApiKey || "").trim(),
    writeback: normalizeUpstreamWritebackMode(settings.upstreamTavregWriteback),
    localInstanceId: String(settings.localInstanceId || "").trim() || null,
  };
}

export function buildLocalWritebackSourceOrigin(site: "chatgpt" | "grok", localInstanceId?: string | null): string {
  const instanceId = String(localInstanceId || "").trim();
  return instanceId ? `local:${site}:${instanceId}` : `local:${site}`;
}

async function fetchJson<T>(
  url: string,
  config: Pick<UpstreamSyncConfig, "apiKey">,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers || {});
  headers.set("authorization", `Bearer ${config.apiKey}`);
  if (init?.body != null && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const resp = await fetch(url, {
    ...init,
    headers,
  });
  const text = await resp.text();
  let parsed: unknown = text;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = text;
  }
  if (!resp.ok) {
    const message = typeof parsed === "string" ? parsed : JSON.stringify(parsed);
    throw new Error(`upstream_http_failed:${resp.status}:${message}`);
  }
  return parsed as T;
}

function asString(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized || null;
}

function asNumber(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const limit = Math.max(1, Math.min(concurrency, items.length || 1));
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: limit }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await task(items[index]!, index);
    }
  });
  await Promise.all(workers);
  return results;
}

function toSyncInput(account: JsonRecord, upstreamOrigin: string, syncedAt: string): UpstreamMicrosoftAccountSyncInput {
  const accountId = asNumber(account.id);
  const microsoftEmail = asString(account.microsoftEmail);
  const passwordPlaintext = asString(account.passwordPlaintext);
  const importedAt = asString(account.importedAt);
  const updatedAt = asString(account.updatedAt);
  if (!accountId) throw new Error("upstream account detail is missing id");
  if (!microsoftEmail) throw new Error(`upstream account ${accountId} is missing microsoftEmail`);
  if (!passwordPlaintext) throw new Error(`upstream account ${microsoftEmail} is missing passwordPlaintext`);
  if (!importedAt) throw new Error(`upstream account ${microsoftEmail} is missing importedAt`);
  if (!updatedAt) throw new Error(`upstream account ${microsoftEmail} is missing updatedAt`);

  const proofMailbox = asRecord(account.proofMailbox);
  const tavily = asRecord(account.tavily);
  const microsoftMail = asRecord(account.microsoftMail);
  return {
    upstreamOrigin,
    upstreamAccountId: accountId,
    upstreamSyncedAt: syncedAt,
    microsoftEmail,
    passwordPlaintext,
    proofMailboxProvider: proofMailbox.provider === "cfmail" ? "cfmail" : null,
    proofMailboxAddress: asString(proofMailbox.address),
    proofMailboxId: asString(proofMailbox.mailboxId),
    groupName: asString(account.groupName),
    importedAt,
    updatedAt,
    importSource: asString(account.importSource),
    accountSource: asString(account.accountSource),
    sourceRawPayload: asString(account.sourceRawPayload),
    lastUsedAt: asString(account.lastUsedAt),
    lastResultStatus: asString(account.lastResultStatus),
    lastResultAt: asString(account.lastResultAt),
    lastErrorCode: asString(account.lastErrorCode),
    skipReason: asString(account.skipReason),
    disabledAt: asString(account.disabledAt),
    disabledReason: asString(account.disabledReason),
    mailbox: {
      status: asString(microsoftMail.status),
      unreadCount: Number(microsoftMail.unreadCount || 0),
      lastSyncedAt: asString(microsoftMail.lastSyncedAt),
      lastErrorCode: asString(microsoftMail.lastErrorCode),
      lastErrorMessage: asString(microsoftMail.lastErrorMessage),
    },
    tavily: {
      apiKey: asString(tavily.apiKey),
      apiKeyPrefix: asString(tavily.apiKeyPrefix),
      extractedIp: asString(tavily.extractedIp),
      lastSuccessAt: asString(tavily.lastSuccessAt),
      cookiesSnapshot: Array.isArray(tavily.cookiesSnapshot) ? tavily.cookiesSnapshot : [],
      browserFingerprintSnapshot:
        tavily.browserFingerprintSnapshot && typeof tavily.browserFingerprintSnapshot === "object"
          ? tavily.browserFingerprintSnapshot
          : null,
    },
  };
}

function toChatGptSyncInput(key: JsonRecord, upstreamOrigin: string, syncedAt: string): UpstreamChatGptCredentialSyncInput {
  const upstreamKeyId = asNumber(key.id);
  if (!upstreamKeyId) throw new Error("upstream chatgpt key is missing id");
  const email = asString(key.email);
  const accountId = asString(key.accountId);
  const accessToken = asString(key.accessToken);
  const refreshToken = asString(key.refreshToken);
  const idToken = asString(key.idToken);
  if (!email) throw new Error(`upstream chatgpt key ${upstreamKeyId} is missing email`);
  if (!accountId) throw new Error(`upstream chatgpt key ${upstreamKeyId} is missing accountId`);
  if (!accessToken) throw new Error(`upstream chatgpt key ${upstreamKeyId} is missing accessToken`);
  if (!refreshToken) throw new Error(`upstream chatgpt key ${upstreamKeyId} is missing refreshToken`);
  if (!idToken) throw new Error(`upstream chatgpt key ${upstreamKeyId} is missing idToken`);
  return {
    upstreamOrigin,
    upstreamKeyId,
    upstreamSyncedAt: syncedAt,
    email,
    accountId,
    accessToken,
    refreshToken,
    idToken,
    expiresAt: asString(key.expiresAt),
    credentialJson: asString(key.credentialJson) || "{}",
    createdAt: asString(key.createdAt),
  };
}

function toGrokSyncInput(key: JsonRecord, upstreamOrigin: string, syncedAt: string): UpstreamGrokKeySyncInput {
  const upstreamKeyId = asNumber(key.id);
  if (!upstreamKeyId) throw new Error("upstream grok key is missing id");
  const email = asString(key.email);
  const password = asString(key.password);
  const sso = asString(key.sso);
  if (!email) throw new Error(`upstream grok key ${upstreamKeyId} is missing email`);
  if (!password) throw new Error(`upstream grok key ${upstreamKeyId} is missing password`);
  if (!sso) throw new Error(`upstream grok key ${upstreamKeyId} is missing sso`);
  return {
    upstreamOrigin,
    upstreamKeyId,
    upstreamSyncedAt: syncedAt,
    email,
    password,
    sso,
    ssoRw: asString(key.ssoRw),
    cfClearance: asString(key.cfClearance),
    checkoutUrl: asString(key.checkoutUrl),
    birthDate: asString(key.birthDate),
    extractedIp: asString(key.extractedIp),
    extractedAt: asString(key.extractedAt),
    lastVerifiedAt: asString(key.lastVerifiedAt),
    createdAt: asString(key.createdAt),
  };
}

async function fetchKeyDetails(config: UpstreamSyncConfig, site: "tavily" | "chatgpt" | "grok", pageSize: number): Promise<JsonRecord[]> {
  const details: JsonRecord[] = [];
  let page = 1;
  let total = 0;
  while (true) {
    const listUrl = new URL("/api/integration/v1/keys", `${config.baseUrl}/`);
    listUrl.searchParams.set("site", site);
    listUrl.searchParams.set("page", String(page));
    listUrl.searchParams.set("pageSize", String(pageSize));
    let payload: { rows?: unknown[]; total?: unknown };
    try {
      payload = await fetchJson<{ rows?: unknown[]; total?: unknown }>(listUrl.toString(), config);
    } catch (error) {
      if (error instanceof Error && /upstream_http_failed:404:/.test(error.message)) return [];
      throw error;
    }
    const rows = Array.isArray(payload.rows) ? payload.rows.map(asRecord) : [];
    total = Number(payload.total || rows.length);
    const pageDetails = await mapWithConcurrency(rows, DEFAULT_UPSTREAM_DETAIL_CONCURRENCY, async (row) => {
      const keyId = asNumber(row.id);
      if (!keyId) throw new Error(`upstream ${site} key list row is missing id`);
      const detailUrl = new URL(`/api/integration/v1/keys/${site}/${keyId}`, `${config.baseUrl}/`);
      const detailPayload = await fetchJson<{ key?: unknown }>(detailUrl.toString(), config);
      return asRecord(detailPayload.key);
    });
    details.push(...pageDetails);
    if (rows.length === 0 || page * pageSize >= total) break;
    page += 1;
  }
  return details;
}

export async function syncAccountsFromUpstream(
  db: AppDatabase,
  options: {
    config?: UpstreamSyncConfig;
    pageSize?: number;
  },
): Promise<UpstreamAccountSyncSummary> {
  const config = options.config;
  if (!config) {
    throw new Error("upstream sync settings are required");
  }
  if (!config.enabled) {
    throw new Error("upstream sync is disabled");
  }
  if (!config.apiKey) {
    throw new Error("upstream sync API key is not configured");
  }
  const pageSize = Math.max(1, Math.min(100, options.pageSize || 100));
  const startedAt = nowIso();
  const details: JsonRecord[] = [];
  let page = 1;
  let total = 0;
  while (true) {
    const listUrl = new URL("/api/integration/v1/microsoft-accounts", `${config.baseUrl}/`);
    listUrl.searchParams.set("page", String(page));
    listUrl.searchParams.set("pageSize", String(pageSize));
    const payload = await fetchJson<{ rows?: unknown[]; total?: unknown }>(listUrl.toString(), config);
    const rows = Array.isArray(payload.rows) ? payload.rows.map(asRecord) : [];
    total = Number(payload.total || rows.length);
    const pageDetails = await mapWithConcurrency(rows, DEFAULT_UPSTREAM_DETAIL_CONCURRENCY, async (row) => {
      const accountId = asNumber(row.id);
      if (!accountId) throw new Error("upstream account list row is missing id");
      const detailUrl = new URL(`/api/integration/v1/microsoft-accounts/${accountId}`, `${config.baseUrl}/`);
      const detailPayload = await fetchJson<{ account?: unknown }>(detailUrl.toString(), config);
      return asRecord(detailPayload.account);
    });
    details.push(...pageDetails);
    if (rows.length === 0 || page * pageSize >= total) break;
    page += 1;
  }

  let created = 0;
  let updated = 0;
  let linkedApiKeys = 0;
  const syncedAt = nowIso();
  const syncInputs = details.map((detail) => toSyncInput(detail, config.baseUrl, syncedAt));
  for (const input of syncInputs) {
    const result = db.upsertUpstreamAccount(input);
    if (result.created) created += 1;
    if (result.updated) updated += 1;
    if (result.linkedApiKey) linkedApiKeys += 1;
  }
  const syncedKeys = { tavily: 0, chatgpt: 0, grok: 0 };
  const [tavilyKeys, chatGptKeys, grokKeys] = await Promise.all([
    fetchKeyDetails(config, "tavily", pageSize),
    fetchKeyDetails(config, "chatgpt", pageSize),
    fetchKeyDetails(config, "grok", pageSize),
  ]);
  for (const key of tavilyKeys) {
    const apiKey = asString(key.apiKey);
    if (!apiKey) continue;
    const microsoftAccount = asRecord(key.microsoftAccount);
    const email = asString(microsoftAccount.microsoftEmail);
    const account = email ? db.getAccountsByEmails([email])[0] : null;
    if (!account) continue;
    const apiKeyRecord = db.recordApiKey(account.id, apiKey, asString(key.extractedIp), { preserveLease: true });
    db.upsertAccountServiceAccess({
      accountId: account.id,
      service: "tavily",
      status: "succeeded",
      apiKeyId: apiKeyRecord.id,
      extractedIp: asString(key.extractedIp),
      lastSuccessAt: asString(key.lastSuccessAt) || asString(key.extractedAt) || syncedAt,
      snapshotJson: JSON.stringify({
        cookiesSnapshot: Array.isArray(key.cookiesSnapshot) ? key.cookiesSnapshot : [],
        browserFingerprintSnapshot:
          key.browserFingerprintSnapshot && typeof key.browserFingerprintSnapshot === "object" ? key.browserFingerprintSnapshot : null,
        extractedIp: asString(key.extractedIp),
        apiKeyPrefix: asString(key.apiKeyPrefix) || apiKeyRecord.apiKeyPrefix,
      }),
    });
    syncedKeys.tavily += 1;
  }
  for (const key of chatGptKeys) {
    db.upsertUpstreamChatGptCredential(toChatGptSyncInput(key, config.baseUrl, syncedAt));
    syncedKeys.chatgpt += 1;
  }
  for (const key of grokKeys) {
    db.upsertUpstreamGrokApiKey(toGrokSyncInput(key, config.baseUrl, syncedAt));
    syncedKeys.grok += 1;
  }

  return {
    ok: true,
    upstreamOrigin: config.baseUrl,
    startedAt,
    completedAt: nowIso(),
    total: details.length,
    created,
    updated,
    linkedApiKeys,
    syncedKeys,
  };
}

export async function writeBackUpstreamTavilySuccess(
  payload: UpstreamTavilySuccessPayload,
  options: {
    config?: UpstreamSyncConfig;
  },
): Promise<{ ok: true; skipped: false } | { ok: true; skipped: true; reason: string }> {
  const config = options.config;
  if (!config) {
    return { ok: true, skipped: true, reason: "settings_missing" };
  }
  if (!config.enabled) {
    return { ok: true, skipped: true, reason: "sync_disabled" };
  }
  if (config.writeback !== "success_only") {
    return { ok: true, skipped: true, reason: "writeback_disabled" };
  }
  if (!config.apiKey) {
    return { ok: true, skipped: true, reason: "api_key_missing" };
  }
  if (!payload.account.upstreamOrigin || !payload.account.upstreamAccountId) {
    return { ok: true, skipped: true, reason: "account_not_linked_to_upstream" };
  }
  const apiKey = payload.apiKey.trim();
  if (!apiKey) {
    return { ok: true, skipped: true, reason: "api_key_empty" };
  }
  const url = new URL(
    `/api/integration/v1/microsoft-accounts/${payload.account.upstreamAccountId}/tavily-success`,
    `${payload.account.upstreamOrigin}/`,
  );
  await fetchJson(url.toString(), config, {
    method: "POST",
    body: JSON.stringify({
      microsoftEmail: payload.account.microsoftEmail,
      apiKey,
      extractedIp: payload.extractedIp || null,
      lastSuccessAt: payload.lastSuccessAt || nowIso(),
      cookiesSnapshot: Array.isArray(payload.cookiesSnapshot) ? payload.cookiesSnapshot : [],
      browserFingerprintSnapshot: payload.browserFingerprintSnapshot || null,
      apiKeyPrefix: payload.apiKeyPrefix || apiKey.slice(0, Math.min(apiKey.length, 12)),
    }),
  });
  return { ok: true, skipped: false };
}

function validateWritebackConfig(
  config: UpstreamSyncConfig | undefined,
): { ok: true; config: UpstreamSyncConfig } | { ok: false; reason: string } {
  if (!config) return { ok: false, reason: "settings_missing" };
  if (!config.enabled) return { ok: false, reason: "sync_disabled" };
  if (config.writeback !== "success_only") return { ok: false, reason: "writeback_disabled" };
  if (!config.apiKey) return { ok: false, reason: "api_key_missing" };
  return { ok: true, config };
}

export async function writeBackUpstreamSuccess(
  payload: UpstreamSuccessPayload,
  options: {
    config?: UpstreamSyncConfig;
    sourceOrigin?: string;
  },
): Promise<{ ok: true; skipped: false } | { ok: true; skipped: true; reason: string }> {
  const validated = validateWritebackConfig(options.config);
  if (!validated.ok) return { ok: true, skipped: true, reason: validated.reason };
  const config = validated.config;
  const sourceOrigin = (options.sourceOrigin || "local").trim() || "local";
  if (payload.site === "chatgpt") {
    const credential = payload.credential;
    const url = new URL("/api/integration/v1/keys/chatgpt/success", `${config.baseUrl}/`);
    await fetchJson(url.toString(), config, {
      method: "POST",
      body: JSON.stringify({
        sourceOrigin,
        sourceKeyId: credential.id,
        email: credential.email,
        accountId: credential.accountId,
        accessToken: credential.accessToken,
        refreshToken: credential.refreshToken,
        idToken: credential.idToken,
        expiresAt: credential.expiresAt,
        credentialJson: credential.credentialJson,
        createdAt: credential.createdAt,
      }),
    });
    return { ok: true, skipped: false };
  }
  if (payload.site === "grok") {
    const key = payload.key;
    const url = new URL("/api/integration/v1/keys/grok/success", `${config.baseUrl}/`);
    await fetchJson(url.toString(), config, {
      method: "POST",
      body: JSON.stringify({
        sourceOrigin,
        sourceKeyId: key.id,
        email: key.email,
        password: key.password,
        sso: key.sso,
        ssoRw: key.ssoRw,
        cfClearance: key.cfClearance,
        checkoutUrl: key.checkoutUrl,
        birthDate: key.birthDate,
        extractedIp: key.extractedIp,
        extractedAt: key.extractedAt,
        lastVerifiedAt: key.lastVerifiedAt,
        createdAt: key.createdAt,
      }),
    });
    return { ok: true, skipped: false };
  }
  return writeBackUpstreamTavilySuccess(payload, { config });
}
