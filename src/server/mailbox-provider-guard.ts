import { createHash } from "node:crypto";

import { normalizeCfMailBaseUrl } from "../cfmail-api.js";

export type MailboxProviderCooldownCode = "mailbox_rate_limited" | "mailbox_provider_unavailable";

export interface MailboxProviderIdentityInput {
  provider: "cfmail";
  baseUrl: string;
  credential: string;
}

export interface MailboxProviderIdentity {
  provider: "cfmail";
  baseUrl: string;
  credentialFingerprint: string;
  key: string;
}

export interface MailboxProviderCooldownSnapshot {
  active: boolean;
  until: string;
  sourceAttemptId: number | null;
  sourceJobId: number | null;
  sourceErrorCode: string;
  reason: string;
}

interface GuardState {
  cooldownUntilMs: number;
  cooldownCode: MailboxProviderCooldownCode | null;
  pending: Promise<void> | null;
}

const mailboxProviderStates = new Map<string, GuardState>();

const MAILBOX_PROVIDER_COOLDOWN_MS: Record<MailboxProviderCooldownCode, number> = {
  mailbox_rate_limited: 5 * 60_000,
  mailbox_provider_unavailable: 60_000,
};

function nowMs(): number {
  return Date.now();
}

function getGuardState(key: string): GuardState {
  const current = mailboxProviderStates.get(key);
  if (current) return current;
  const next: GuardState = {
    cooldownUntilMs: 0,
    cooldownCode: null,
    pending: null,
  };
  mailboxProviderStates.set(key, next);
  return next;
}

export function resolveMailboxProviderIdentity(input: MailboxProviderIdentityInput | null | undefined): MailboxProviderIdentity | null {
  if (!input) return null;
  const credential = String(input.credential || "").trim();
  const baseUrl = String(input.baseUrl || "").trim();
  if (!credential || !baseUrl) {
    return null;
  }
  const normalizedBaseUrl = normalizeCfMailBaseUrl(baseUrl);
  const credentialFingerprint = createHash("sha256").update(credential).digest("hex").slice(0, 12);
  return {
    provider: input.provider,
    baseUrl: normalizedBaseUrl,
    credentialFingerprint,
    key: `${input.provider}:${normalizedBaseUrl}:${credentialFingerprint}`,
  };
}

function parseHttpStatus(message: string): number | null {
  const matched = String(message || "").match(/http_failed:(\d{3}):/i);
  if (!matched?.[1]) return null;
  const status = Number.parseInt(matched[1], 10);
  return Number.isFinite(status) ? status : null;
}

export function normalizeMailboxProviderError(error: unknown): Error {
  if (error instanceof Error) {
    const normalized = String(error.message || "").trim();
    if (normalized === "mailbox_rate_limited" || normalized === "mailbox_provider_unavailable") {
      return error;
    }
  }
  const message = error instanceof Error ? error.message : String(error || "");
  const lower = message.toLowerCase();
  const status = parseHttpStatus(message);
  if (status === 429 || lower.includes("too many requests") || lower.includes("rate limit")) {
    return new Error("mailbox_rate_limited");
  }
  if (
    (status != null && status >= 500 && status <= 599)
    || /service unavailable|bad gateway|gateway timeout|internal server error|temporarily unavailable/i.test(message)
  ) {
    return new Error("mailbox_provider_unavailable");
  }
  return error instanceof Error ? error : new Error(message);
}

export function formatMailboxProviderCooldownReason(errorCode: string): string {
  switch (String(errorCode || "").trim().toLowerCase()) {
    case "mailbox_rate_limited":
      return "recent mailbox provider rate limit detected";
    case "mailbox_provider_unavailable":
      return "recent mailbox provider outage detected";
    default:
      return "recent mailbox provider risk detected";
  }
}

export function isMailboxProviderCooldownErrorCode(errorCode: string | null | undefined): errorCode is MailboxProviderCooldownCode {
  return errorCode === "mailbox_rate_limited" || errorCode === "mailbox_provider_unavailable";
}

function clearExpiredCooldown(state: GuardState, atMs: number): void {
  if (state.cooldownUntilMs > 0 && state.cooldownUntilMs <= atMs) {
    state.cooldownUntilMs = 0;
    state.cooldownCode = null;
  }
}

export function getMailboxProviderCooldownSnapshot(
  identity: MailboxProviderIdentity | null | undefined,
): MailboxProviderCooldownSnapshot | null {
  if (!identity) return null;
  const state = getGuardState(identity.key);
  const currentMs = nowMs();
  clearExpiredCooldown(state, currentMs);
  if (!state.cooldownCode || state.cooldownUntilMs <= currentMs) {
    return null;
  }
  return {
    active: true,
    until: new Date(state.cooldownUntilMs).toISOString(),
    sourceAttemptId: null,
    sourceJobId: null,
    sourceErrorCode: state.cooldownCode,
    reason: formatMailboxProviderCooldownReason(state.cooldownCode),
  };
}

function activateCooldown(identity: MailboxProviderIdentity, errorCode: MailboxProviderCooldownCode): void {
  const state = getGuardState(identity.key);
  state.cooldownCode = errorCode;
  state.cooldownUntilMs = nowMs() + MAILBOX_PROVIDER_COOLDOWN_MS[errorCode];
}

export async function withMailboxProviderProvisioningGuard<T>(
  identity: MailboxProviderIdentity | null | undefined,
  operation: () => Promise<T>,
): Promise<T> {
  if (!identity) {
    try {
      return await operation();
    } catch (error) {
      throw normalizeMailboxProviderError(error);
    }
  }
  const state = getGuardState(identity.key);
  const previous = state.pending;
  let releasePending: (value?: void | PromiseLike<void>) => void = () => undefined;
  const currentPending = new Promise<void>((resolve) => {
    releasePending = resolve;
  });
  const queueTail = previous ? previous.finally(() => currentPending) : currentPending;
  state.pending = queueTail;

  if (previous) {
    await previous;
  }

  const cooldown = getMailboxProviderCooldownSnapshot(identity);
  if (cooldown?.active) {
    releasePending();
    if (state.pending === queueTail) {
      state.pending = null;
    }
    throw new Error(cooldown.sourceErrorCode);
  }

  try {
    return await operation();
  } catch (error) {
    const normalized = normalizeMailboxProviderError(error);
    if (isMailboxProviderCooldownErrorCode(normalized.message)) {
      activateCooldown(identity, normalized.message);
    }
    throw normalized;
  } finally {
    releasePending();
    if (state.pending === queueTail) {
      state.pending = null;
    }
  }
}

export function resetMailboxProviderGuardStateForTests(): void {
  mailboxProviderStates.clear();
}

export function setMailboxProviderCooldownForTests(
  identity: MailboxProviderIdentity,
  errorCode: MailboxProviderCooldownCode,
  untilIso?: string,
): void {
  const state = getGuardState(identity.key);
  state.cooldownCode = errorCode;
  state.cooldownUntilMs = untilIso ? Date.parse(untilIso) : nowMs() + MAILBOX_PROVIDER_COOLDOWN_MS[errorCode];
}
