import { createHash, randomBytes } from "node:crypto";

export const MICROSOFT_GRAPH_SCOPES = ["openid", "offline_access", "User.Read", "Mail.Read"] as const;
const GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0";
const INVALIDATED_ERROR_CODES = new Set(["invalid_grant", "interaction_required", "consent_required"]);
const LOCKED_ERROR_CODES = new Set(["microsoft_account_locked"]);

export interface MicrosoftGraphSettingsInput {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authority: string;
}

export interface MicrosoftTokenResult {
  accessToken: string | null;
  refreshToken: string | null;
  expiresAt: string | null;
  scope: string;
}

export interface MicrosoftProfile {
  id: string | null;
  displayName: string | null;
  userPrincipalName: string | null;
  mail: string | null;
}

export interface MicrosoftSyncedMessage {
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
}

export interface MicrosoftInboxSyncResult {
  messages: MicrosoftSyncedMessage[];
  removedGraphMessageIds: string[];
  deltaLink: string | null;
}

type MicrosoftGraphBody = {
  error?: {
    code?: string;
    message?: string;
    innerError?: {
      code?: string;
      message?: string;
    };
  };
  error_description?: string;
};

export class MicrosoftGraphError extends Error {
  readonly code: string | null;
  readonly status: number | null;
  readonly isInvalidated: boolean;

  constructor(message: string, options?: { code?: string | null; status?: number | null }) {
    super(message);
    this.name = "MicrosoftGraphError";
    this.code = options?.code ?? null;
    this.status = options?.status ?? null;
    this.isInvalidated = this.code != null && INVALIDATED_ERROR_CODES.has(this.code);
  }
}

function parseMicrosoftOauthUrl(finalUrl: string | null | undefined, redirectUri: string): URL | null {
  const normalizedFinalUrl = String(finalUrl || "").trim();
  const normalizedRedirectUri = String(redirectUri || "").trim();
  if (!normalizedFinalUrl || !normalizedRedirectUri) return null;
  try {
    const current = new URL(normalizedFinalUrl);
    const redirect = new URL(normalizedRedirectUri);
    if (current.origin === redirect.origin) {
      return current;
    }
    const relayDestination = String(current.searchParams.get("rd") || "").trim();
    if (!relayDestination) {
      return null;
    }
    const relayed = new URL(relayDestination);
    return relayed.origin === redirect.origin ? relayed : null;
  } catch {
    return null;
  }
}

export function isMicrosoftOauthCompletionUrl(finalUrl: string | null | undefined, redirectUri: string): boolean {
  const current = parseMicrosoftOauthUrl(finalUrl, redirectUri);
  if (!current) return false;
  try {
    const redirect = new URL(String(redirectUri || "").trim());
    if (current.pathname === redirect.pathname) {
      return true;
    }
    if (current.pathname === "/mailboxes") {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function isMicrosoftOauthCallbackUrl(finalUrl: string | null | undefined, redirectUri: string): boolean {
  const normalizedFinalUrl = String(finalUrl || "").trim();
  const normalizedRedirectUri = String(redirectUri || "").trim();
  if (!normalizedFinalUrl || !normalizedRedirectUri) return false;
  try {
    const current = new URL(normalizedFinalUrl);
    const redirect = new URL(normalizedRedirectUri);
    return current.origin === redirect.origin && current.pathname === redirect.pathname;
  } catch {
    return false;
  }
}

export function getMicrosoftOauthBrowserOutcome(
  finalUrl: string | null | undefined,
  redirectUri: string,
): "success" | "error" | null {
  const current = parseMicrosoftOauthUrl(finalUrl, redirectUri);
  if (!current || current.pathname !== "/mailboxes") {
    return null;
  }
  const oauth = String(current.searchParams.get("oauth") || "").trim().toLowerCase();
  return oauth === "success" || oauth === "error" ? oauth : null;
}

function normalizeAuthority(authority: string): string {
  const normalized = authority.trim().replace(/^\/+|\/+$/g, "");
  return normalized || "common";
}

function encodeBase64Url(input: Buffer): string {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function resolveTokenEndpoint(authority: string): string {
  return `https://login.microsoftonline.com/${normalizeAuthority(authority)}/oauth2/v2.0/token`;
}

function resolveAuthorizeEndpoint(authority: string): string {
  return `https://login.microsoftonline.com/${normalizeAuthority(authority)}/oauth2/v2.0/authorize`;
}

function buildMicrosoftError(status: number | null, payload: MicrosoftGraphBody | null, fallback: string): MicrosoftGraphError {
  const code = payload?.error?.code || payload?.error?.innerError?.code || null;
  const message =
    payload?.error_description ||
    payload?.error?.message ||
    payload?.error?.innerError?.message ||
    fallback;
  return new MicrosoftGraphError(message, { code, status });
}

function extractOpaqueErrorCode(error: unknown): string | null {
  if (!(error instanceof Error)) return null;
  const firstLine = String(error.message || "")
    .split(/\r?\n/, 1)[0]
    ?.trim();
  if (!firstLine) return null;
  const match = firstLine.match(/^(?:[A-Za-z]*Error:\s*)?([a-z0-9_]+)(?::|$)/i);
  return match?.[1]?.trim() || null;
}

function normalizeOpaqueErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const firstLine = String(error.message || "")
    .split(/\r?\n/, 1)[0]
    ?.trim();
  return firstLine?.replace(/^[A-Za-z]*Error:\s*/i, "") || error.message;
}

function normalizeTokenResult(payload: Record<string, unknown>): MicrosoftTokenResult {
  const expiresInRaw = Number(payload.expires_in || 0);
  const expiresAt = expiresInRaw > 0 ? new Date(Date.now() + expiresInRaw * 1000).toISOString() : null;
  return {
    accessToken: typeof payload.access_token === "string" ? payload.access_token : null,
    refreshToken: typeof payload.refresh_token === "string" ? payload.refresh_token : null,
    expiresAt,
    scope: typeof payload.scope === "string" ? payload.scope : MICROSOFT_GRAPH_SCOPES.join(" "),
  };
}

async function fetchJson<T>(input: string, init?: RequestInit): Promise<T> {
  const response = await fetch(input, init);
  const payload = (await response.json().catch(() => null)) as MicrosoftGraphBody | Record<string, unknown> | null;
  if (!response.ok) {
    throw buildMicrosoftError(response.status, payload as MicrosoftGraphBody | null, `${response.status} ${response.statusText}`);
  }
  return (payload || {}) as T;
}

async function postForm<T>(url: string, form: URLSearchParams): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
  const payload = (await response.json().catch(() => null)) as MicrosoftGraphBody | Record<string, unknown> | null;
  if (!response.ok) {
    throw buildMicrosoftError(response.status, payload as MicrosoftGraphBody | null, `${response.status} ${response.statusText}`);
  }
  return (payload || {}) as T;
}

export function createMicrosoftPkcePair(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = encodeBase64Url(randomBytes(64));
  const codeChallenge = encodeBase64Url(createHash("sha256").update(codeVerifier).digest());
  return { codeVerifier, codeChallenge };
}

export function createMicrosoftOauthState(): string {
  return encodeBase64Url(randomBytes(32));
}

export function buildMicrosoftAuthorizeUrl(input: {
  clientId: string;
  redirectUri: string;
  authority: string;
  state: string;
  codeChallenge: string;
  loginHint?: string | null;
}): string {
  const params = new URLSearchParams({
    client_id: input.clientId.trim(),
    response_type: "code",
    redirect_uri: input.redirectUri.trim(),
    response_mode: "query",
    scope: MICROSOFT_GRAPH_SCOPES.join(" "),
    state: input.state,
    code_challenge: input.codeChallenge,
    code_challenge_method: "S256",
  });
  const loginHint = input.loginHint?.trim();
  if (loginHint) {
    params.set("login_hint", loginHint);
  }
  return `${resolveAuthorizeEndpoint(input.authority)}?${params.toString()}`;
}

export async function exchangeMicrosoftAuthCode(input: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authority: string;
  code: string;
  codeVerifier: string;
}): Promise<MicrosoftTokenResult> {
  const payload = await postForm<Record<string, unknown>>(resolveTokenEndpoint(input.authority), new URLSearchParams({
    client_id: input.clientId.trim(),
    client_secret: input.clientSecret.trim(),
    redirect_uri: input.redirectUri.trim(),
    grant_type: "authorization_code",
    code: input.code,
    code_verifier: input.codeVerifier,
    scope: MICROSOFT_GRAPH_SCOPES.join(" "),
  }));
  return normalizeTokenResult(payload);
}

export async function refreshMicrosoftAccessToken(input: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authority: string;
  refreshToken: string;
}): Promise<MicrosoftTokenResult> {
  const payload = await postForm<Record<string, unknown>>(resolveTokenEndpoint(input.authority), new URLSearchParams({
    client_id: input.clientId.trim(),
    client_secret: input.clientSecret.trim(),
    redirect_uri: input.redirectUri.trim(),
    grant_type: "refresh_token",
    refresh_token: input.refreshToken,
    scope: MICROSOFT_GRAPH_SCOPES.join(" "),
  }));
  return normalizeTokenResult(payload);
}

export function isMicrosoftTokenExpired(expiresAt: string | null | undefined, nowMs = Date.now()): boolean {
  if (!expiresAt) return true;
  const expiresMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresMs)) return true;
  return expiresMs - 60_000 <= nowMs;
}

export async function fetchMicrosoftProfile(accessToken: string): Promise<MicrosoftProfile> {
  const payload = await fetchJson<Record<string, unknown>>(`${GRAPH_BASE_URL}/me?$select=id,displayName,userPrincipalName,mail`, {
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });
  return {
    id: typeof payload.id === "string" ? payload.id : null,
    displayName: typeof payload.displayName === "string" ? payload.displayName : null,
    userPrincipalName: typeof payload.userPrincipalName === "string" ? payload.userPrincipalName : null,
    mail: typeof payload.mail === "string" ? payload.mail : null,
  };
}

function normalizeMessage(item: Record<string, unknown>): MicrosoftSyncedMessage | null {
  const graphMessageId = typeof item.id === "string" ? item.id.trim() : "";
  if (!graphMessageId) return null;
  const body = (item.body || {}) as Record<string, unknown>;
  const from = ((item.from || {}) as Record<string, unknown>).emailAddress as Record<string, unknown> | undefined;
  return {
    graphMessageId,
    internetMessageId: typeof item.internetMessageId === "string" ? item.internetMessageId : null,
    conversationId: typeof item.conversationId === "string" ? item.conversationId : null,
    subject: typeof item.subject === "string" ? item.subject : "",
    fromName: typeof from?.name === "string" ? from.name : null,
    fromAddress: typeof from?.address === "string" ? from.address : null,
    receivedAt: typeof item.receivedDateTime === "string" ? item.receivedDateTime : null,
    isRead: Boolean(item.isRead),
    hasAttachments: Boolean(item.hasAttachments),
    bodyContentType: typeof body.contentType === "string" && body.contentType.toLowerCase() === "html" ? "html" : "text",
    bodyPreview: typeof item.bodyPreview === "string" ? item.bodyPreview : "",
    bodyContent: typeof body.content === "string" ? body.content : "",
    webLink: typeof item.webLink === "string" ? item.webLink : null,
  };
}

async function fetchGraphPage(input: { url: string; accessToken: string }): Promise<Record<string, unknown>> {
  return await fetchJson<Record<string, unknown>>(input.url, {
    headers: {
      authorization: `Bearer ${input.accessToken}`,
      prefer: 'outlook.body-content-type="html"',
    },
  });
}

export async function syncMicrosoftInbox(input: { accessToken: string; deltaLink?: string | null }): Promise<MicrosoftInboxSyncResult> {
  const select = "$select=id,internetMessageId,conversationId,subject,from,receivedDateTime,isRead,hasAttachments,bodyPreview,body,webLink";
  let nextUrl: string | null = input.deltaLink?.trim()
    ? input.deltaLink.trim()
    : `${GRAPH_BASE_URL}/me/mailFolders/inbox/messages/delta?${select}&$top=100`;
  const messages: MicrosoftSyncedMessage[] = [];
  const removedGraphMessageIds: string[] = [];
  let deltaLink: string | null = null;
  let pageCount = 0;

  while (nextUrl && pageCount < 10) {
    pageCount += 1;
    const page = await fetchGraphPage({ url: nextUrl, accessToken: input.accessToken });
    const value = Array.isArray(page.value) ? (page.value as Record<string, unknown>[]) : [];
    for (const item of value) {
      const removed = item["@removed"] as Record<string, unknown> | undefined;
      const itemId = typeof item.id === "string" ? item.id.trim() : "";
      if (removed && itemId) {
        removedGraphMessageIds.push(itemId);
        continue;
      }
      const normalized = normalizeMessage(item);
      if (normalized) {
        messages.push(normalized);
      }
    }
    const pageNext = typeof page["@odata.nextLink"] === "string" ? page["@odata.nextLink"] : null;
    const pageDelta = typeof page["@odata.deltaLink"] === "string" ? page["@odata.deltaLink"] : null;
    deltaLink = pageDelta || deltaLink;
    nextUrl = pageNext;
  }

  return {
    messages,
    removedGraphMessageIds: Array.from(new Set(removedGraphMessageIds)),
    deltaLink,
  };
}

export async function fetchMicrosoftMessageDetail(input: { accessToken: string; graphMessageId: string }): Promise<MicrosoftSyncedMessage> {
  const payload = await fetchJson<Record<string, unknown>>(
    `${GRAPH_BASE_URL}/me/messages/${encodeURIComponent(input.graphMessageId)}?$select=id,internetMessageId,conversationId,subject,from,receivedDateTime,isRead,hasAttachments,bodyPreview,body,webLink`,
    {
      headers: {
        authorization: `Bearer ${input.accessToken}`,
        prefer: 'outlook.body-content-type="html"',
      },
    },
  );
  const message = normalizeMessage(payload);
  if (!message) {
    throw new MicrosoftGraphError("message_not_found", { code: "message_not_found", status: 404 });
  }
  return message;
}

export function assertMicrosoftGraphSettings(settings: MicrosoftGraphSettingsInput): void {
  if (!settings.clientId.trim()) {
    throw new Error("Microsoft Graph client id is required");
  }
  if (!settings.clientSecret.trim()) {
    throw new Error("Microsoft Graph client secret is required");
  }
  if (!settings.redirectUri.trim()) {
    throw new Error("Microsoft Graph redirect uri is required");
  }
}

export function isLockedMailboxErrorCode(code: string | null | undefined): boolean {
  return LOCKED_ERROR_CODES.has(String(code || "").trim());
}

export function toMailboxFailureStatus(error: unknown): "failed" | "invalidated" | "locked" {
  const opaqueCode = extractOpaqueErrorCode(error);
  if (isLockedMailboxErrorCode(opaqueCode)) {
    return "locked";
  }
  if (opaqueCode != null && INVALIDATED_ERROR_CODES.has(opaqueCode)) {
    return "invalidated";
  }
  if (error instanceof MicrosoftGraphError && error.isInvalidated) {
    return "invalidated";
  }
  return "failed";
}

export function getMailboxErrorCode(error: unknown): string | null {
  if (error instanceof MicrosoftGraphError) {
    return error.code || null;
  }
  return extractOpaqueErrorCode(error) || (error instanceof Error ? error.name || null : null);
}

export function getMailboxErrorMessage(error: unknown): string {
  const code = getMailboxErrorCode(error);
  if (isLockedMailboxErrorCode(code)) {
    return "Microsoft 账户已锁定";
  }
  return normalizeOpaqueErrorMessage(error);
}
