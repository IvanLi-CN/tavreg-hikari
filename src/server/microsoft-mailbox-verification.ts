import {
  extractMailboxVerificationCode,
  matchMailboxVerificationCode,
  type MailboxVerificationCodeMatch,
  type MailboxVerificationCodeProvider,
} from "../mailbox-verification-code.js";
import {
  isMicrosoftTokenExpired,
  refreshMicrosoftAccessToken,
  syncMicrosoftInbox,
  type MicrosoftGraphSettingsInput,
  type MicrosoftSyncedMessage,
} from "./microsoft-mail.js";

export interface MailboxVerificationMessageShape {
  subject?: string | null;
  fromName?: string | null;
  fromAddress?: string | null;
  bodyPreview?: string | null;
  bodyContent?: string | null;
  receivedAt?: string | null;
}

export interface MicrosoftMailboxVerificationSession {
  refreshToken?: string | null;
  accessToken?: string | null;
  accessTokenExpiresAt?: string | null;
  authority?: string | null;
  deltaLink?: string | null;
}

export interface MicrosoftMailboxVerificationResult {
  code: string;
  provider: MailboxVerificationCodeMatch["provider"];
  evidence: string;
  receivedAt: string | null;
  graphMessageId: string | null;
  deltaLink: string | null;
}

function toMillis(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function sortMessagesByReceivedAt<T extends MailboxVerificationMessageShape>(messages: readonly T[]): T[] {
  return [...messages].sort((left, right) => {
    const rightMs = toMillis(right.receivedAt);
    const leftMs = toMillis(left.receivedAt);
    if (rightMs != null && leftMs != null && rightMs !== leftMs) return rightMs - leftMs;
    if (rightMs != null && leftMs == null) return -1;
    if (rightMs == null && leftMs != null) return 1;
    return 0;
  });
}

export function matchMailboxVerificationCodeForMessage(
  message: MailboxVerificationMessageShape,
): MailboxVerificationCodeMatch | null {
  return matchMailboxVerificationCode({
    subject: message.subject,
    fromName: message.fromName,
    fromAddress: message.fromAddress,
    preview: message.bodyPreview,
    body: message.bodyContent,
  });
}

export function extractMailboxVerificationCodeForMessage(message: MailboxVerificationMessageShape): string | null {
  return extractMailboxVerificationCode({
    subject: message.subject,
    fromName: message.fromName,
    fromAddress: message.fromAddress,
    preview: message.bodyPreview,
    body: message.bodyContent,
  });
}

export function pickLatestMailboxVerificationCode<T extends MailboxVerificationMessageShape>(
  messages: readonly T[],
  options?: { providers?: readonly MailboxVerificationCodeProvider[] },
): MailboxVerificationCodeMatch | null {
  const allowedProviders = options?.providers?.length ? new Set(options.providers) : null;
  for (const message of sortMessagesByReceivedAt(messages)) {
    const match = matchMailboxVerificationCodeForMessage(message);
    if (allowedProviders && (!match || !allowedProviders.has(match.provider))) {
      continue;
    }
    if (match) return match;
  }
  return null;
}

async function resolveAccessToken(
  graphSettings: MicrosoftGraphSettingsInput,
  session: MicrosoftMailboxVerificationSession,
): Promise<{ accessToken: string; accessTokenExpiresAt: string | null }> {
  const existingToken = String(session.accessToken || "").trim();
  const existingExpiresAt = session.accessTokenExpiresAt || null;
  if (existingToken && !isMicrosoftTokenExpired(existingExpiresAt)) {
    return {
      accessToken: existingToken,
      accessTokenExpiresAt: existingExpiresAt,
    };
  }
  const refreshToken = String(session.refreshToken || "").trim();
  if (!refreshToken) {
    throw new Error("microsoft_mailbox_refresh_token_missing");
  }
  const token = await refreshMicrosoftAccessToken({
    clientId: graphSettings.clientId,
    clientSecret: graphSettings.clientSecret,
    redirectUri: graphSettings.redirectUri,
    authority: String(session.authority || graphSettings.authority || "common").trim() || "common",
    refreshToken,
  });
  const accessToken = String(token.accessToken || "").trim();
  if (!accessToken) {
    throw new Error("microsoft_mailbox_access_token_refresh_failed");
  }
  return {
    accessToken,
    accessTokenExpiresAt: token.expiresAt,
  };
}

function normalizeNotBeforeIso(value: string | null | undefined): number | null {
  return toMillis(value);
}

function findMessageVerificationCode(
  messages: readonly MicrosoftSyncedMessage[],
  notBeforeMs: number | null,
  providers?: readonly MailboxVerificationCodeProvider[],
): MicrosoftMailboxVerificationResult | null {
  const allowedProviders = providers?.length ? new Set(providers) : null;
  for (const message of sortMessagesByReceivedAt(messages)) {
    const receivedAtMs = toMillis(message.receivedAt);
    if (notBeforeMs != null && receivedAtMs != null && receivedAtMs < notBeforeMs) {
      continue;
    }
    const match = matchMailboxVerificationCodeForMessage(message);
    if (!match || (allowedProviders && !allowedProviders.has(match.provider))) continue;
    return {
      code: match.code,
      provider: match.provider,
      evidence: match.evidence,
      receivedAt: message.receivedAt || null,
      graphMessageId: message.graphMessageId || null,
      deltaLink: null,
    };
  }
  return null;
}

export async function waitForMicrosoftMailboxVerificationCode(input: {
  graphSettings: MicrosoftGraphSettingsInput;
  mailbox: MicrosoftMailboxVerificationSession;
  notBefore?: string | null;
  timeoutMs: number;
  pollMs: number;
  providers?: readonly MailboxVerificationCodeProvider[];
}): Promise<MicrosoftMailboxVerificationResult> {
  const deadline = Date.now() + Math.max(1_000, input.timeoutMs);
  const notBeforeMs = normalizeNotBeforeIso(input.notBefore);
  let deltaLink = input.mailbox.deltaLink || null;
  let latestAccessToken = String(input.mailbox.accessToken || "").trim() || null;
  let latestAccessTokenExpiresAt = input.mailbox.accessTokenExpiresAt || null;
  while (Date.now() < deadline) {
    const token = await resolveAccessToken(input.graphSettings, {
      ...input.mailbox,
      accessToken: latestAccessToken,
      accessTokenExpiresAt: latestAccessTokenExpiresAt,
      deltaLink,
    });
    latestAccessToken = token.accessToken;
    latestAccessTokenExpiresAt = token.accessTokenExpiresAt;
    const sync = await syncMicrosoftInbox({
      accessToken: latestAccessToken,
      deltaLink,
    });
    deltaLink = sync.deltaLink || deltaLink;
    const match = findMessageVerificationCode(sync.messages, notBeforeMs, input.providers);
    if (match) {
      return {
        ...match,
        deltaLink,
      };
    }
    await new Promise((resolve) => setTimeout(resolve, Math.max(1_000, input.pollMs)));
  }
  throw new Error("microsoft_mailbox_verification_code_timeout");
}
