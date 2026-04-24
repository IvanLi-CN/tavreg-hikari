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
      bodyContent: row.bodyContent,
    }),
  };
}

function serializeMailboxMessageDetail(row: MicrosoftMailMessageRecord): Record<string, unknown> {
  return {
    ...serializeMailboxMessageSummary(row),
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
    const hydratedRows = await Promise.all(
      payload.rows.map((row) =>
        hydrateMailboxMessageDetail({
          db: input.db,
          message: row,
          readSettings: input.readSettings,
        }),
      ),
    );
    return json({
      ok: true,
      mailbox: serializeMailboxRecord(mailbox),
      rows: hydratedRows.map((row) => serializeMailboxMessageSummary(row)),
      limit,
      offset,
      total: payload.total,
      hasMore: offset + hydratedRows.length < payload.total,
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
