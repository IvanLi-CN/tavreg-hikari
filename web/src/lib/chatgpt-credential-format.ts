import type { ChatGptCredentialRecord } from "./app-types";

type ParsedCredentialJson = Record<string, unknown>;

function parseCredentialJson(raw: string | undefined): ParsedCredentialJson | null {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as ParsedCredentialJson)
      : null;
  } catch {
    return null;
  }
}

function pickString(source: ParsedCredentialJson | null, ...keys: string[]): string | null {
  if (!source) {
    return null;
  }
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

export function buildCodexVibeMonitorCredentialObject(
  credential: Pick<
    ChatGptCredentialRecord,
    "email" | "accountId" | "accessToken" | "refreshToken" | "idToken" | "expiresAt" | "createdAt" | "credentialJson"
  >,
): Record<string, unknown> {
  const parsed = parseCredentialJson(credential.credentialJson);
  return {
    type: "codex",
    email: pickString(parsed, "email") || credential.email,
    account_id: pickString(parsed, "account_id", "accountId") || credential.accountId || "",
    expired:
      pickString(parsed, "expired", "expires_at", "expiresAt")
      || (credential.expiresAt && credential.expiresAt.trim() ? credential.expiresAt.trim() : undefined),
    access_token: pickString(parsed, "access_token", "accessToken") || credential.accessToken || "",
    refresh_token: pickString(parsed, "refresh_token", "refreshToken") || credential.refreshToken || "",
    id_token: pickString(parsed, "id_token", "idToken") || credential.idToken || "",
    last_refresh:
      pickString(parsed, "last_refresh", "lastRefresh")
      || (credential.createdAt && credential.createdAt.trim() ? credential.createdAt.trim() : undefined),
    token_type: pickString(parsed, "token_type", "tokenType") || "Bearer",
  };
}

export function buildCodexVibeMonitorCredentialJson(
  credential: Pick<
    ChatGptCredentialRecord,
    "email" | "accountId" | "accessToken" | "refreshToken" | "idToken" | "expiresAt" | "createdAt" | "credentialJson"
  >,
): string {
  return JSON.stringify(buildCodexVibeMonitorCredentialObject(credential), null, 2);
}
