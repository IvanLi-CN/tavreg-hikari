import type { ChatGptCredentialRecord } from "./app-types";

type ParsedCredentialJson = Record<string, unknown>;

type ParsedJwtClaims = {
  email?: string | null;
  chatgptAccountId?: string | null;
};

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

function decodeJwtPayload(token: string | undefined): ParsedCredentialJson | null {
  if (!token) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length < 2 || !parts[1]) {
    return null;
  }
  try {
    const raw = parts[1];
    const padded = raw + "=".repeat((4 - (raw.length % 4 || 4)) % 4);
    const json = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
    const parsed = JSON.parse(json) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as ParsedCredentialJson)
      : null;
  } catch {
    return null;
  }
}

function extractClaimsFromIdToken(token: string | undefined): ParsedJwtClaims {
  const payload = decodeJwtPayload(token);
  const authSection = payload?.["https://api.openai.com/auth"];
  const auth = authSection && typeof authSection === "object" && !Array.isArray(authSection)
    ? (authSection as ParsedCredentialJson)
    : null;
  return {
    email: pickString(payload, "email"),
    chatgptAccountId: pickString(auth, "chatgpt_account_id"),
  };
}

export function buildCodexVibeMonitorCredentialObject(
  credential: Pick<
    ChatGptCredentialRecord,
    "email" | "accountId" | "accessToken" | "refreshToken" | "idToken" | "expiresAt" | "createdAt" | "credentialJson"
  >,
): Record<string, unknown> {
  const parsed = parseCredentialJson(credential.credentialJson);
  const idToken =
    pickString(parsed, "id_token", "idToken")
    || credential.idToken
    || "";
  const claims = extractClaimsFromIdToken(idToken);
  return {
    type: "codex",
    email: claims.email || pickString(parsed, "email") || credential.email,
    account_id: claims.chatgptAccountId || pickString(parsed, "account_id", "accountId") || credential.accountId || "",
    expired:
      pickString(parsed, "expired", "expires_at", "expiresAt")
      || (credential.expiresAt && credential.expiresAt.trim() ? credential.expiresAt.trim() : undefined),
    access_token: pickString(parsed, "access_token", "accessToken") || credential.accessToken || "",
    refresh_token: pickString(parsed, "refresh_token", "refreshToken") || credential.refreshToken || "",
    id_token: idToken,
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
