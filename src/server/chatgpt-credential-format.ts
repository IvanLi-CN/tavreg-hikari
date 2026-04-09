type ParsedCredentialJson = Record<string, unknown>;

type ParsedJwtClaims = {
  email?: string | null;
  chatgptAccountId?: string | null;
};

type ChatGptCredentialExportInput = {
  email: string;
  accountId: string;
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresAt?: string | null;
  createdAt?: string | null;
  tokenType?: string | null;
  credentialJson?: string | null;
};

function parseCredentialJson(raw: string | null | undefined): ParsedCredentialJson | null {
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

function decodeJwtPayload(token: string | null | undefined): ParsedCredentialJson | null {
  if (!token || typeof token !== "string") {
    return null;
  }
  const parts = token.split(".");
  if (parts.length < 2 || !parts[1]) {
    return null;
  }
  try {
    const raw = parts[1];
    const padded = raw + "=".repeat((4 - (raw.length % 4 || 4)) % 4);
    const json = Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const parsed = JSON.parse(json) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as ParsedCredentialJson)
      : null;
  } catch {
    return null;
  }
}

function extractClaimsFromIdToken(token: string | null | undefined): ParsedJwtClaims {
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
  input: ChatGptCredentialExportInput,
): Record<string, unknown> {
  const parsed = parseCredentialJson(input.credentialJson);
  const idToken =
    pickString(parsed, "id_token", "idToken")
    || input.idToken.trim();
  const claims = extractClaimsFromIdToken(idToken);
  const expired =
    pickString(parsed, "expired", "expires_at", "expiresAt")
    || (typeof input.expiresAt === "string" && input.expiresAt.trim() ? input.expiresAt.trim() : null);
  const lastRefresh =
    pickString(parsed, "last_refresh", "lastRefresh")
    || (typeof input.createdAt === "string" && input.createdAt.trim() ? input.createdAt.trim() : null);
  const tokenType =
    pickString(parsed, "token_type", "tokenType")
    || (typeof input.tokenType === "string" && input.tokenType.trim() ? input.tokenType.trim() : "Bearer");
  return {
    type: "codex",
    email: claims.email || pickString(parsed, "email") || input.email.trim(),
    account_id: claims.chatgptAccountId || pickString(parsed, "account_id", "accountId") || input.accountId.trim(),
    expired: expired || undefined,
    access_token: pickString(parsed, "access_token", "accessToken") || input.accessToken.trim(),
    refresh_token: pickString(parsed, "refresh_token", "refreshToken") || input.refreshToken.trim(),
    id_token: idToken,
    last_refresh: lastRefresh || undefined,
    token_type: tokenType || undefined,
  };
}

export function buildCodexVibeMonitorCredentialJson(
  input: ChatGptCredentialExportInput,
): string {
  return JSON.stringify(buildCodexVibeMonitorCredentialObject(input), null, 2);
}
