import {
  buildCfMailRawMessageUrl,
  getCfMailMessage,
  listCfMailMessages,
  normalizeCfMailBaseUrl,
  type CfMailHttpJson,
  type CfMailHttpJsonOptions,
  type CfMailMessageSummary,
} from "../cfmail-api.js";
import {
  type AccountServiceAccessRecord,
  type ApiKeyRecord,
  type AppSettings,
  type AppDatabase,
  type ChatGptCredentialRecord,
  type GrokApiKeyRecord,
  type MicrosoftAccountRecord,
  type MicrosoftMailboxRecord,
  type MicrosoftMailMessageRecord,
} from "../storage/app-db.js";
import {
  assertMicrosoftGraphSettings,
  fetchMicrosoftMessageDetail,
  isMicrosoftTokenExpired,
  refreshMicrosoftAccessToken,
} from "./microsoft-mail.js";
import {
  parseMailboxVerificationCodes,
  parseProofMailboxVerificationCodes,
  type ParsedVerificationCode,
} from "./verification-codes.js";

type JsonRecord = Record<string, unknown>;

export interface IntegrationMicrosoftAccountRecord {
  id: number;
  microsoftEmail: string;
  groupName: string | null;
  importedAt: string;
  updatedAt: string;
  importSource: string;
  accountSource: string;
  sourceRawPayload: string | null;
  lastUsedAt: string | null;
  lastResultStatus: string;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: string | null;
  disabledAt: string | null;
  disabledReason: string | null;
  passwordPlaintext?: string;
  proofMailbox: {
    provider: "cfmail";
    address: string;
    mailboxId: string | null;
  } | null;
  session: {
    status: string;
    proxyNode: string | null;
    proxyIp: string | null;
    proxyCountry: string | null;
    proxyRegion: string | null;
    proxyCity: string | null;
    proxyTimezone: string | null;
    lastBootstrappedAt: string | null;
    lastUsedAt: string | null;
    lastErrorCode: string | null;
  } | null;
  successfulServices: Array<"tavily" | "microsoftMail">;
  serviceSummary: {
    tavily: {
      available: boolean;
      lastSuccessAt: string | null;
      extractedIp: string | null;
      apiKeyPrefix: string | null;
    };
    microsoftMail: {
      available: boolean;
      mailboxId: number | null;
      status: string | null;
      unreadCount: number;
      lastSyncedAt: string | null;
      lastErrorCode: string | null;
    };
  };
  tavily?: {
    available: boolean;
    apiKey: string | null;
    apiKeyPrefix: string | null;
    extractedIp: string | null;
    lastSuccessAt: string | null;
    cookiesSnapshot: unknown[];
    browserFingerprintSnapshot: unknown | null;
  };
  microsoftMail?: {
    available: boolean;
    mailboxId: number | null;
    status: string | null;
    syncEnabled: boolean;
    unreadCount: number;
    graphUserPrincipalName: string | null;
    graphDisplayName: string | null;
    oauthConnectedAt: string | null;
    lastSyncedAt: string | null;
    lastErrorCode: string | null;
    lastErrorMessage: string | null;
  };
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

function normalizePage(value: string | null, fallback: number, max: number): number {
  const parsed = Number.parseInt(String(value || "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(max, parsed);
}

function parseOptionalPositiveInteger(value: string | null): number | null {
  const trimmed = String(value || "").trim();
  if (!trimmed) return null;
  if (!/^\d+$/.test(trimmed)) return null;
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) return null;
  return parsed;
}

function parseSnapshotJson(record: AccountServiceAccessRecord | null): JsonRecord {
  if (!record?.snapshotJson?.trim()) return {};
  try {
    const parsed = JSON.parse(record.snapshotJson) as JsonRecord;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function serializeMailboxMessageSummary(row: MicrosoftMailMessageRecord): Record<string, unknown> {
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
    parsedVerificationCodes: parseMailboxVerificationCodes({
      subject: row.subject,
      bodyPreview: row.bodyPreview,
    }),
  };
}

function serializeMailboxMessageDetail(row: MicrosoftMailMessageRecord): Record<string, unknown> {
  return {
    ...serializeMailboxMessageSummary(row),
    parsedVerificationCodes: parseMailboxVerificationCodes({
      subject: row.subject,
      bodyPreview: row.bodyPreview,
      bodyContent: row.bodyContent,
    }),
    bodyContent: row.bodyContent,
    createdAt: row.createdAt,
  };
}

function serializeMailboxRecord(row: MicrosoftMailboxRecord): Record<string, unknown> {
  return {
    id: row.id,
    accountId: row.accountId,
    microsoftEmail: row.microsoftEmail,
    groupName: row.groupName,
    proofMailboxAddress: row.proofMailboxAddress,
    status: row.status,
    syncEnabled: row.syncEnabled,
    unreadCount: row.unreadCount,
    graphUserId: row.graphUserId,
    graphUserPrincipalName: row.graphUserPrincipalName,
    graphDisplayName: row.graphDisplayName,
    authority: row.authority,
    oauthStartedAt: row.oauthStartedAt,
    oauthConnectedAt: row.oauthConnectedAt,
    deltaLink: row.deltaLink,
    lastSyncedAt: row.lastSyncedAt,
    lastErrorCode: row.lastErrorCode,
    lastErrorMessage: row.lastErrorMessage,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    isAuthorized: Boolean(row.refreshToken),
  };
}

function serializeIntegrationTavilyKey(input: {
  key: ApiKeyRecord;
  account: MicrosoftAccountRecord | null;
  access: AccountServiceAccessRecord | null;
  detailed: boolean;
}): Record<string, unknown> {
  const snapshot = parseSnapshotJson(input.access);
  return {
    site: "tavily",
    id: input.key.id,
    status: input.key.status,
    apiKeyPrefix: input.key.apiKeyPrefix,
    extractedIp: input.key.extractedIp || input.access?.extractedIp || null,
    extractedAt: input.key.extractedAt,
    lastVerifiedAt: input.key.lastVerifiedAt,
    lastSuccessAt: input.access?.lastSuccessAt || input.key.extractedAt,
    microsoftAccount: input.account
      ? {
          id: input.account.id,
          microsoftEmail: input.account.microsoftEmail,
          groupName: input.account.groupName,
          upstreamOrigin: input.account.upstreamOrigin,
          upstreamAccountId: input.account.upstreamAccountId,
        }
      : null,
    ...(input.detailed
      ? {
          apiKey: input.key.apiKey,
          cookiesSnapshot: Array.isArray(snapshot.cookiesSnapshot) ? snapshot.cookiesSnapshot : [],
          browserFingerprintSnapshot:
            snapshot.browserFingerprintSnapshot && typeof snapshot.browserFingerprintSnapshot === "object"
              ? snapshot.browserFingerprintSnapshot
              : null,
        }
      : {}),
  };
}

function serializeIntegrationChatGptKey(row: ChatGptCredentialRecord, detailed: boolean): Record<string, unknown> {
  return {
    site: "chatgpt",
    id: row.id,
    email: row.email,
    accountId: row.accountId,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    upstreamOrigin: row.upstreamOrigin,
    upstreamKeyId: row.upstreamKeyId,
    ...(detailed
      ? {
          accessToken: row.accessToken,
          refreshToken: row.refreshToken,
          idToken: row.idToken,
          credentialJson: row.credentialJson,
        }
      : {}),
  };
}

function serializeIntegrationGrokKey(row: GrokApiKeyRecord, detailed: boolean): Record<string, unknown> {
  return {
    site: "grok",
    id: row.id,
    email: row.email,
    ssoPrefix: row.ssoPrefix,
    status: row.status,
    extractedIp: row.extractedIp,
    extractedAt: row.extractedAt,
    lastVerifiedAt: row.lastVerifiedAt,
    createdAt: row.createdAt,
    birthDate: row.birthDate,
    checkoutUrl: row.checkoutUrl,
    upstreamOrigin: row.upstreamOrigin,
    upstreamKeyId: row.upstreamKeyId,
    ...(detailed
      ? {
          password: row.password,
          sso: row.sso,
          ssoRw: row.ssoRw,
          cfClearance: row.cfClearance,
        }
      : {}),
  };
}

function isMailboxServiceAvailable(mailbox: MicrosoftMailboxRecord | null): boolean {
  return Boolean(mailbox && mailbox.status === "available" && (mailbox.refreshToken || mailbox.oauthConnectedAt || mailbox.lastSyncedAt));
}

function buildSuccessfulServices(
  tavilyAccess: AccountServiceAccessRecord | null,
  mailbox: MicrosoftMailboxRecord | null,
): Array<"tavily" | "microsoftMail"> {
  const services: Array<"tavily" | "microsoftMail"> = [];
  if (tavilyAccess?.lastSuccessAt) {
    services.push("tavily");
  }
  if (isMailboxServiceAvailable(mailbox)) {
    services.push("microsoftMail");
  }
  return services;
}

function readMicrosoftGraphSettings(settings: AppSettings): {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authority: string;
} {
  return {
    clientId: settings.microsoftGraphClientId,
    clientSecret: settings.microsoftGraphClientSecret,
    redirectUri: settings.microsoftGraphRedirectUri,
    authority: settings.microsoftGraphAuthority || "common",
  };
}

async function ensureMailboxAccessToken(
  db: AppDatabase,
  mailbox: MicrosoftMailboxRecord,
  readSettings: () => AppSettings,
): Promise<{ mailbox: MicrosoftMailboxRecord; accessToken: string }> {
  if (mailbox.accessToken && !isMicrosoftTokenExpired(mailbox.accessTokenExpiresAt)) {
    return {
      mailbox,
      accessToken: mailbox.accessToken,
    };
  }
  if (!mailbox.refreshToken) {
    throw new Error("mailbox_not_authorized");
  }
  const graphSettings = readMicrosoftGraphSettings(readSettings());
  assertMicrosoftGraphSettings(graphSettings);
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

async function hydrateMailboxMessageDetail(input: {
  db: AppDatabase;
  message: MicrosoftMailMessageRecord;
  readSettings?: (() => AppSettings) | undefined;
}): Promise<MicrosoftMailMessageRecord> {
  if (input.message.bodyContent.trim() || !input.readSettings) {
    return input.message;
  }
  const mailbox = input.db.getMailbox(input.message.mailboxId);
  if (!mailbox || (!mailbox.refreshToken && !mailbox.accessToken)) {
    return input.message;
  }
  try {
    const { accessToken } = await ensureMailboxAccessToken(input.db, mailbox, input.readSettings);
    const detail = await fetchMicrosoftMessageDetail({
      accessToken,
      graphMessageId: input.message.graphMessageId,
    });
    input.db.upsertMailboxMessages(mailbox.id, [detail], { keepLatest: 500 });
    return input.db.getMailboxMessageByGraphId(mailbox.id, input.message.graphMessageId) || input.message;
  } catch {
    return input.message;
  }
}

function serializeIntegrationMicrosoftAccount(input: {
  account: MicrosoftAccountRecord;
  mailbox: MicrosoftMailboxRecord | null;
  tavilyAccess: AccountServiceAccessRecord | null;
  currentApiKey: ApiKeyRecord | null;
  detailed: boolean;
}): IntegrationMicrosoftAccountRecord {
  const snapshot = parseSnapshotJson(input.tavilyAccess);
  const cookiesSnapshot = Array.isArray(snapshot.cookiesSnapshot) ? snapshot.cookiesSnapshot : [];
  const browserFingerprintSnapshot =
    snapshot.browserFingerprintSnapshot && typeof snapshot.browserFingerprintSnapshot === "object"
      ? snapshot.browserFingerprintSnapshot
      : null;
  const apiKeyPrefix = input.currentApiKey?.apiKeyPrefix || (typeof snapshot.apiKeyPrefix === "string" ? snapshot.apiKeyPrefix : null);
  const extractedIp = input.tavilyAccess?.extractedIp || (typeof snapshot.extractedIp === "string" ? snapshot.extractedIp : null);
  const lastSuccessAt = input.tavilyAccess?.lastSuccessAt || null;
  const successfulServices = buildSuccessfulServices(input.tavilyAccess, input.mailbox);

  const result: IntegrationMicrosoftAccountRecord = {
    id: input.account.id,
    microsoftEmail: input.account.microsoftEmail,
    groupName: input.account.groupName,
    importedAt: input.account.importedAt,
    updatedAt: input.account.updatedAt,
    importSource: input.account.importSource,
    accountSource: input.account.accountSource,
    sourceRawPayload: input.account.sourceRawPayload,
    lastUsedAt: input.account.lastUsedAt,
    lastResultStatus: input.account.lastResultStatus,
    lastResultAt: input.account.lastResultAt,
    lastErrorCode: input.account.lastErrorCode,
    skipReason: input.account.skipReason,
    disabledAt: input.account.disabledAt,
    disabledReason: input.account.disabledReason,
    proofMailbox:
      input.account.proofMailboxProvider && input.account.proofMailboxAddress
        ? {
            provider: input.account.proofMailboxProvider,
            address: input.account.proofMailboxAddress,
            mailboxId: input.account.proofMailboxId,
          }
        : null,
    session: input.account.browserSession
      ? {
          status: input.account.browserSession.status,
          proxyNode: input.account.browserSession.proxyNode,
          proxyIp: input.account.browserSession.proxyIp,
          proxyCountry: input.account.browserSession.proxyCountry,
          proxyRegion: input.account.browserSession.proxyRegion,
          proxyCity: input.account.browserSession.proxyCity,
          proxyTimezone: input.account.browserSession.proxyTimezone,
          lastBootstrappedAt: input.account.browserSession.lastBootstrappedAt,
          lastUsedAt: input.account.browserSession.lastUsedAt,
          lastErrorCode: input.account.browserSession.lastErrorCode,
        }
      : null,
    successfulServices,
    serviceSummary: {
      tavily: {
        available: Boolean(lastSuccessAt),
        lastSuccessAt,
        extractedIp,
        apiKeyPrefix: apiKeyPrefix || null,
      },
      microsoftMail: {
        available: isMailboxServiceAvailable(input.mailbox),
        mailboxId: input.mailbox?.id ?? null,
        status: input.mailbox?.status ?? null,
        unreadCount: input.mailbox?.unreadCount ?? 0,
        lastSyncedAt: input.mailbox?.lastSyncedAt ?? null,
        lastErrorCode: input.mailbox?.lastErrorCode ?? null,
      },
    },
  };

  if (input.detailed) {
    result.passwordPlaintext = input.account.passwordPlaintext;
    result.tavily = {
      available: Boolean(lastSuccessAt),
      apiKey: input.currentApiKey?.apiKey || null,
      apiKeyPrefix: apiKeyPrefix || null,
      extractedIp,
      lastSuccessAt,
      cookiesSnapshot,
      browserFingerprintSnapshot,
    };
    result.microsoftMail = {
      available: isMailboxServiceAvailable(input.mailbox),
      mailboxId: input.mailbox?.id ?? null,
      status: input.mailbox?.status ?? null,
      syncEnabled: input.mailbox?.syncEnabled ?? false,
      unreadCount: input.mailbox?.unreadCount ?? 0,
      graphUserPrincipalName: input.mailbox?.graphUserPrincipalName ?? null,
      graphDisplayName: input.mailbox?.graphDisplayName ?? null,
      oauthConnectedAt: input.mailbox?.oauthConnectedAt ?? null,
      lastSyncedAt: input.mailbox?.lastSyncedAt ?? null,
      lastErrorCode: input.mailbox?.lastErrorCode ?? null,
      lastErrorMessage: input.mailbox?.lastErrorMessage ?? null,
    };
  }

  return result;
}

const cfMailHttpJson: CfMailHttpJson = async <T>(method: string, url: string, options?: CfMailHttpJsonOptions) => {
  const headers: Record<string, string> = { ...(options?.headers || {}) };
  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    headers["content-type"] = headers["content-type"] || "application/json";
    body = JSON.stringify(options.body);
  }
  const resp = await fetch(url, {
    method,
    headers,
    body,
  });
  const text = await resp.text();
  let parsed: unknown = text;
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = text;
  }
  if (!resp.ok) {
    throw new Error(`http_failed:${resp.status}:${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed as T;
};

async function listProofMailboxMessages(account: MicrosoftAccountRecord): Promise<Array<Record<string, unknown>>> {
  if (account.proofMailboxProvider !== "cfmail") {
    throw new Error("proof_mailbox_provider_unsupported");
  }
  if (!account.proofMailboxAddress) {
    throw new Error("proof_mailbox_not_configured");
  }
  const apiKey = String(process.env.CFMAIL_API_KEY || "").trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test");
  const summaries = await listCfMailMessages({
    baseUrl,
    apiKey,
    mailboxId: account.proofMailboxId || undefined,
    address: account.proofMailboxAddress,
    httpJson: cfMailHttpJson,
  });
  const rows: Array<Record<string, unknown>> = [];
  for (const summary of summaries.slice(0, 20)) {
    const detail = await getCfMailMessage({
      baseUrl,
      apiKey,
      messageId: summary.id,
      httpJson: cfMailHttpJson,
    }).catch(() => null);
    rows.push(serializeProofMailboxMessage(baseUrl, summary, detail));
  }
  return rows;
}

function serializeProofMailboxMessage(
  baseUrl: string,
  summary: CfMailMessageSummary,
  detail: JsonRecord | null,
): Record<string, unknown> {
  const parsedVerificationCodes: ParsedVerificationCode[] = parseProofMailboxVerificationCodes({
    summary,
    detail,
  });
  return {
    id: summary.id,
    mailboxId: summary.mailboxId,
    mailboxAddress: summary.mailboxAddress,
    subject: summary.subject,
    previewText: summary.previewText,
    fromName: summary.fromName,
    fromAddress: summary.fromAddress,
    receivedAt: summary.receivedAt,
    sizeBytes: summary.sizeBytes,
    attachmentCount: summary.attachmentCount,
    hasHtml: summary.hasHtml,
    rawUrl: buildCfMailRawMessageUrl(baseUrl, summary.id),
    detail,
    parsedVerificationCodes,
  };
}

export async function handleIntegrationApiRequest(input: {
  req: Request;
  pathname: string;
  url: URL;
  db: AppDatabase;
  readSettings?: () => AppSettings;
}): Promise<Response | null> {
  const accountDetailMatch = input.pathname.match(/^\/api\/integration\/v1\/microsoft-accounts\/(\d+)$/);
  const accountTavilySuccessMatch = input.pathname.match(/^\/api\/integration\/v1\/microsoft-accounts\/(\d+)\/tavily-success$/);
  const keyDetailMatch = input.pathname.match(/^\/api\/integration\/v1\/keys\/(tavily|chatgpt|grok)\/(\d+)$/);
  const keySuccessMatch = input.pathname.match(/^\/api\/integration\/v1\/keys\/(tavily|chatgpt|grok)\/success$/);
  const proofMailboxCodesMatch = input.pathname.match(/^\/api\/integration\/v1\/microsoft-accounts\/(\d+)\/proof-mailbox\/codes$/);
  const mailboxMessagesMatch = input.pathname.match(/^\/api\/integration\/v1\/mailboxes\/(\d+)\/messages$/);
  const messageDetailMatch = input.pathname.match(/^\/api\/integration\/v1\/messages\/(\d+)$/);

  if (input.pathname === "/api/integration/v1/microsoft-accounts" && input.req.method === "GET") {
    const page = normalizePage(input.url.searchParams.get("page"), 1, 500);
    const pageSize = normalizePage(input.url.searchParams.get("pageSize"), 20, 100);
    const q = input.url.searchParams.get("q") || "";
    const payload = input.db.listAccounts({ page, pageSize, q });
    const rows = payload.rows.map((account) =>
      serializeIntegrationMicrosoftAccount({
        account,
        mailbox: input.db.getMailboxByAccountId(account.id),
        tavilyAccess: input.db.getAccountServiceAccess(account.id, "tavily"),
        currentApiKey: account.apiKeyId != null ? input.db.getApiKey(account.apiKeyId) : null,
        detailed: false,
      }),
    );
    return json({
      ok: true,
      rows,
      page,
      pageSize,
      total: payload.total,
    });
  }

  if (input.pathname === "/api/integration/v1/keys" && input.req.method === "GET") {
    const site = input.url.searchParams.get("site");
    const page = normalizePage(input.url.searchParams.get("page"), 1, 500);
    const pageSize = normalizePage(input.url.searchParams.get("pageSize"), 20, 100);
    if (site === "tavily") {
      const payload = input.db.listApiKeys({ page, pageSize, status: "active" });
      return json({
        ok: true,
        site,
        rows: payload.rows.map((key) =>
          serializeIntegrationTavilyKey({
            key,
            account: input.db.getAccount(key.accountId),
            access: input.db.getAccountServiceAccess(key.accountId, "tavily"),
            detailed: false,
          }),
        ),
        page,
        pageSize,
        total: payload.total,
      });
    }
    if (site === "chatgpt") {
      const payload = input.db.listChatGptCredentials({ page, pageSize });
      return json({
        ok: true,
        site,
        rows: payload.rows.map((row) => serializeIntegrationChatGptKey(row, false)),
        page,
        pageSize,
        total: payload.total,
      });
    }
    if (site === "grok") {
      const payload = input.db.listGrokApiKeys({ page, pageSize, status: "active" });
      return json({
        ok: true,
        site,
        rows: payload.rows.map((row) => serializeIntegrationGrokKey(row, false)),
        page,
        pageSize,
        total: payload.total,
      });
    }
    return badRequest("site must be tavily, chatgpt, or grok", 422);
  }

  if (keyDetailMatch && input.req.method === "GET") {
    const site = keyDetailMatch[1] as "tavily" | "chatgpt" | "grok";
    const keyId = Number.parseInt(keyDetailMatch[2] || "", 10);
    if (!Number.isInteger(keyId) || keyId < 1) return badRequest("invalid key id");
    if (site === "tavily") {
      const key = input.db.getApiKey(keyId);
      if (!key) return badRequest(`key not found: ${keyId}`, 404);
      return json({
        ok: true,
        key: serializeIntegrationTavilyKey({
          key,
          account: input.db.getAccount(key.accountId),
          access: input.db.getAccountServiceAccess(key.accountId, "tavily"),
          detailed: true,
        }),
      });
    }
    if (site === "chatgpt") {
      const credential = input.db.getChatGptCredential(keyId);
      if (!credential) return badRequest(`key not found: ${keyId}`, 404);
      return json({ ok: true, key: serializeIntegrationChatGptKey(credential, true) });
    }
    const key = input.db.getGrokApiKey(keyId);
    if (!key) return badRequest(`key not found: ${keyId}`, 404);
    return json({ ok: true, key: serializeIntegrationGrokKey(key, true) });
  }

  if (keySuccessMatch && input.req.method === "POST") {
    const site = keySuccessMatch[1] as "tavily" | "chatgpt" | "grok";
    const body = (await input.req.json().catch(() => null)) as JsonRecord | null;
    if (site === "tavily") {
      const accountId = parseOptionalPositiveInteger(body?.accountId == null ? null : String(body.accountId));
      if (!accountId) return badRequest("accountId is required", 422);
      const account = input.db.getAccount(accountId);
      if (!account) return badRequest(`account not found: ${accountId}`, 404);
      const apiKey = String(body?.apiKey || "").trim();
      if (!apiKey) return badRequest("apiKey is required", 422);
      const extractedIp = body?.extractedIp == null ? null : String(body.extractedIp).trim() || null;
      const lastSuccessAt = body?.lastSuccessAt == null ? null : String(body.lastSuccessAt).trim() || null;
      const key = input.db.recordApiKey(account.id, apiKey, extractedIp, { preserveLease: true });
      const access = input.db.upsertAccountServiceAccess({
        accountId: account.id,
        service: "tavily",
        status: "succeeded",
        apiKeyId: key.id,
        extractedIp,
        lastSuccessAt: lastSuccessAt || key.extractedAt,
        snapshotJson: JSON.stringify({
          cookiesSnapshot: Array.isArray(body?.cookiesSnapshot) ? body.cookiesSnapshot : [],
          browserFingerprintSnapshot:
            body?.browserFingerprintSnapshot && typeof body.browserFingerprintSnapshot === "object"
              ? body.browserFingerprintSnapshot
              : null,
          extractedIp,
          apiKeyPrefix: body?.apiKeyPrefix == null ? key.apiKeyPrefix : String(body.apiKeyPrefix).trim() || key.apiKeyPrefix,
        }),
      });
      return json({
        ok: true,
        key: serializeIntegrationTavilyKey({
          key,
          account: input.db.getAccount(account.id),
          access,
          detailed: true,
        }),
      });
    }
    if (site === "chatgpt") {
      const sourceKeyId = parseOptionalPositiveInteger(body?.sourceKeyId == null ? null : String(body.sourceKeyId));
      if (!sourceKeyId) return badRequest("sourceKeyId is required", 422);
      const sourceOrigin = String(body?.sourceOrigin || "").trim();
      if (!sourceOrigin) return badRequest("sourceOrigin is required", 422);
      const email = String(body?.email || "").trim();
      const accountId = String(body?.accountId || "").trim();
      const accessToken = String(body?.accessToken || "").trim();
      const refreshToken = String(body?.refreshToken || "").trim();
      const idToken = String(body?.idToken || "").trim();
      if (!email) return badRequest("email is required", 422);
      if (!accountId) return badRequest("accountId is required", 422);
      if (!accessToken) return badRequest("accessToken is required", 422);
      if (!refreshToken) return badRequest("refreshToken is required", 422);
      if (!idToken) return badRequest("idToken is required", 422);
      const credential = input.db.upsertUpstreamChatGptCredential({
        upstreamOrigin: sourceOrigin,
        upstreamKeyId: sourceKeyId,
        upstreamSyncedAt: new Date().toISOString(),
        email,
        accountId,
        accessToken,
        refreshToken,
        idToken,
        expiresAt: body?.expiresAt == null ? null : String(body.expiresAt),
        credentialJson: String(body?.credentialJson || "{}"),
        createdAt: body?.createdAt == null ? null : String(body.createdAt),
      }).credential;
      return json({ ok: true, key: serializeIntegrationChatGptKey(credential, true) });
    }
    const sourceKeyId = parseOptionalPositiveInteger(body?.sourceKeyId == null ? null : String(body.sourceKeyId));
    if (!sourceKeyId) return badRequest("sourceKeyId is required", 422);
    const sourceOrigin = String(body?.sourceOrigin || "").trim();
    if (!sourceOrigin) return badRequest("sourceOrigin is required", 422);
    const email = String(body?.email || "").trim();
    const password = String(body?.password || "").trim();
    const sso = String(body?.sso || "").trim();
    if (!email) return badRequest("email is required", 422);
    if (!password) return badRequest("password is required", 422);
    if (!sso) return badRequest("sso is required", 422);
    const key = input.db.upsertUpstreamGrokApiKey({
      upstreamOrigin: sourceOrigin,
      upstreamKeyId: sourceKeyId,
      upstreamSyncedAt: new Date().toISOString(),
      email,
      password,
      sso,
      ssoRw: body?.ssoRw == null ? null : String(body.ssoRw),
      cfClearance: body?.cfClearance == null ? null : String(body.cfClearance),
      checkoutUrl: body?.checkoutUrl == null ? null : String(body.checkoutUrl),
      birthDate: body?.birthDate == null ? null : String(body.birthDate),
      extractedIp: body?.extractedIp == null ? null : String(body.extractedIp),
      extractedAt: body?.extractedAt == null ? null : String(body.extractedAt),
      lastVerifiedAt: body?.lastVerifiedAt == null ? null : String(body.lastVerifiedAt),
      createdAt: body?.createdAt == null ? null : String(body.createdAt),
    }).key;
    return json({ ok: true, key: serializeIntegrationGrokKey(key, true) });
  }

  if (accountDetailMatch && input.req.method === "GET") {
    const accountId = Number.parseInt(accountDetailMatch[1] || "", 10);
    if (!Number.isInteger(accountId) || accountId < 1) {
      return badRequest("invalid account id");
    }
    const account = input.db.getAccount(accountId);
    if (!account) {
      return badRequest(`account not found: ${accountId}`, 404);
    }
    return json({
      ok: true,
      account: serializeIntegrationMicrosoftAccount({
        account,
        mailbox: input.db.getMailboxByAccountId(account.id),
        tavilyAccess: input.db.getAccountServiceAccess(account.id, "tavily"),
        currentApiKey: account.apiKeyId != null ? input.db.getApiKey(account.apiKeyId) : null,
        detailed: true,
      }),
    });
  }

  if (accountTavilySuccessMatch && input.req.method === "POST") {
    const accountId = Number.parseInt(accountTavilySuccessMatch[1] || "", 10);
    if (!Number.isInteger(accountId) || accountId < 1) {
      return badRequest("invalid account id");
    }
    const account = input.db.getAccount(accountId);
    if (!account) {
      return badRequest(`account not found: ${accountId}`, 404);
    }
    const body = (await input.req.json().catch(() => null)) as {
      microsoftEmail?: unknown;
      apiKey?: unknown;
      extractedIp?: unknown;
      lastSuccessAt?: unknown;
      apiKeyPrefix?: unknown;
      cookiesSnapshot?: unknown;
      browserFingerprintSnapshot?: unknown;
    } | null;
    const microsoftEmail = String(body?.microsoftEmail || "").trim().toLowerCase();
    const apiKey = String(body?.apiKey || "").trim();
    if (!microsoftEmail || microsoftEmail !== account.microsoftEmail.trim().toLowerCase()) {
      return badRequest("microsoft email does not match account id", 409);
    }
    if (!apiKey) {
      return badRequest("apiKey is required", 422);
    }
    const extractedIp = body?.extractedIp == null ? null : String(body.extractedIp).trim() || null;
    const lastSuccessAt = body?.lastSuccessAt == null ? null : String(body.lastSuccessAt).trim() || null;
    const apiKeyPrefix = body?.apiKeyPrefix == null ? null : String(body.apiKeyPrefix).trim() || null;
    const cookiesSnapshot = Array.isArray(body?.cookiesSnapshot) ? body.cookiesSnapshot : [];
    const browserFingerprintSnapshot =
      body?.browserFingerprintSnapshot && typeof body.browserFingerprintSnapshot === "object"
        ? body.browserFingerprintSnapshot
        : null;
    const key = input.db.recordApiKey(account.id, apiKey, extractedIp, { preserveLease: true });
    const access = input.db.upsertAccountServiceAccess({
      accountId: account.id,
      service: "tavily",
      status: "succeeded",
      apiKeyId: key.id,
      extractedIp,
      lastSuccessAt: lastSuccessAt || key.extractedAt,
      snapshotJson: JSON.stringify({
        cookiesSnapshot,
        browserFingerprintSnapshot,
        extractedIp,
        apiKeyPrefix: apiKeyPrefix || key.apiKeyPrefix,
      }),
    });
    return json({
      ok: true,
      account: serializeIntegrationMicrosoftAccount({
        account: input.db.getAccount(account.id) || account,
        mailbox: input.db.getMailboxByAccountId(account.id),
        tavilyAccess: access,
        currentApiKey: key,
        detailed: true,
      }),
    });
  }

  if (proofMailboxCodesMatch && input.req.method === "GET") {
    const accountId = Number.parseInt(proofMailboxCodesMatch[1] || "", 10);
    if (!Number.isInteger(accountId) || accountId < 1) {
      return badRequest("invalid account id");
    }
    const account = input.db.getAccount(accountId);
    if (!account) {
      return badRequest(`account not found: ${accountId}`, 404);
    }
    if (!account.proofMailboxProvider || !account.proofMailboxAddress) {
      return badRequest("proof mailbox not configured", 409);
    }
    if (account.proofMailboxProvider !== "cfmail") {
      return badRequest(`unsupported proof mailbox provider: ${account.proofMailboxProvider}`, 422);
    }
    try {
      const rows = await listProofMailboxMessages(account);
      return json({
        ok: true,
        accountId,
        provider: "cfmail",
        mailboxAddress: account.proofMailboxAddress,
        rows,
      });
    } catch (error) {
      return badRequest(error instanceof Error ? error.message : String(error), 409);
    }
  }

  if (input.pathname === "/api/integration/v1/mailboxes" && input.req.method === "GET") {
    const page = normalizePage(input.url.searchParams.get("page"), 1, 500);
    const pageSize = normalizePage(input.url.searchParams.get("pageSize"), 20, 100);
    const rawAccountId = input.url.searchParams.get("accountId");
    const accountId = parseOptionalPositiveInteger(rawAccountId);
    if (rawAccountId != null && accountId == null) {
      return badRequest("invalid accountId");
    }
    const rows = input.db.listMailboxes().filter((row) => (accountId != null ? row.accountId === accountId : true));
    const offset = (page - 1) * pageSize;
    const pagedRows = rows.slice(offset, offset + pageSize);
    return json({
      ok: true,
      rows: pagedRows.map((row) => serializeMailboxRecord(row)),
      page,
      pageSize,
      total: rows.length,
    });
  }

  if (mailboxMessagesMatch && input.req.method === "GET") {
    const mailboxId = Number.parseInt(mailboxMessagesMatch[1] || "", 10);
    if (!Number.isInteger(mailboxId) || mailboxId < 1) {
      return badRequest("invalid mailbox id");
    }
    const mailbox = input.db.getMailbox(mailboxId);
    if (!mailbox) {
      return badRequest(`mailbox not found: ${mailboxId}`, 404);
    }
    const limit = normalizePage(input.url.searchParams.get("limit"), 50, 100);
    const offset = Math.max(0, Number.parseInt(String(input.url.searchParams.get("offset") || "0"), 10) || 0);
    const payload = input.db.listMailboxMessages(mailboxId, { limit, offset });
    return json({
      ok: true,
      mailbox: serializeMailboxRecord(mailbox),
      rows: payload.rows.map((row) => serializeMailboxMessageSummary(row)),
      limit,
      offset,
      total: payload.total,
      hasMore: offset + payload.rows.length < payload.total,
    });
  }

  if (messageDetailMatch && input.req.method === "GET") {
    const messageId = Number.parseInt(messageDetailMatch[1] || "", 10);
    if (!Number.isInteger(messageId) || messageId < 1) {
      return badRequest("invalid message id");
    }
    const storedMessage = input.db.getMailboxMessage(messageId);
    const message = storedMessage
      ? await hydrateMailboxMessageDetail({
          db: input.db,
          message: storedMessage,
          readSettings: input.readSettings,
        })
      : null;
    if (!message) {
      return badRequest(`message not found: ${messageId}`, 404);
    }
    return json({
      ok: true,
      message: serializeMailboxMessageDetail(message),
    });
  }

  return null;
}
