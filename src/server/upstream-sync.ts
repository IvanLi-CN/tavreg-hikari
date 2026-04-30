import {
  type AppSettings,
  type AppDatabase,
  type MicrosoftAccountRecord,
  type UpstreamMicrosoftAccountSyncInput,
} from "../storage/app-db.js";

export const DEFAULT_UPSTREAM_TAVREG_BASE_URL = "https://tavreg-hikari.ivanli.cc";
export type UpstreamTavregWritebackMode = "off" | "success_only";

export interface UpstreamSyncConfig {
  baseUrl: string;
  apiKey: string;
  writeback: UpstreamTavregWritebackMode;
}

export type UpstreamSyncSettingsInput = Pick<
  AppSettings,
  "upstreamTavregBaseUrl" | "upstreamTavregApiKey" | "upstreamTavregWriteback"
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
}

export interface UpstreamTavilySuccessPayload {
  account: MicrosoftAccountRecord;
  apiKey: string;
  extractedIp?: string | null;
  lastSuccessAt?: string | null;
  cookiesSnapshot?: unknown[];
  browserFingerprintSnapshot?: unknown | null;
  apiKeyPrefix?: string | null;
}

type JsonRecord = Record<string, unknown>;

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
    baseUrl: normalizeUpstreamBaseUrl(settings.upstreamTavregBaseUrl),
    apiKey: String(settings.upstreamTavregApiKey || "").trim(),
    writeback: normalizeUpstreamWritebackMode(settings.upstreamTavregWriteback),
  };
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

function toSyncInput(account: JsonRecord, upstreamOrigin: string, syncedAt: string): UpstreamMicrosoftAccountSyncInput {
  const accountId = asNumber(account.id);
  const microsoftEmail = asString(account.microsoftEmail);
  const passwordPlaintext = asString(account.passwordPlaintext);
  if (!accountId) throw new Error("upstream account detail is missing id");
  if (!microsoftEmail) throw new Error(`upstream account ${accountId} is missing microsoftEmail`);
  if (!passwordPlaintext) throw new Error(`upstream account ${microsoftEmail} is missing passwordPlaintext`);

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
    importedAt: asString(account.importedAt),
    updatedAt: asString(account.updatedAt),
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
    for (const row of rows) {
      const accountId = asNumber(row.id);
      if (!accountId) throw new Error("upstream account list row is missing id");
      const detailUrl = new URL(`/api/integration/v1/microsoft-accounts/${accountId}`, `${config.baseUrl}/`);
      const detailPayload = await fetchJson<{ account?: unknown }>(detailUrl.toString(), config);
      details.push(asRecord(detailPayload.account));
    }
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

  return {
    ok: true,
    upstreamOrigin: config.baseUrl,
    startedAt,
    completedAt: nowIso(),
    total: details.length,
    created,
    updated,
    linkedApiKeys,
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
