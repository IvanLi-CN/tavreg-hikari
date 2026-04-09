type ParsedCredentialJson = Record<string, unknown>;

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

export function buildCodexVibeMonitorCredentialObject(
  input: ChatGptCredentialExportInput,
): Record<string, unknown> {
  const parsed = parseCredentialJson(input.credentialJson);
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
    email: pickString(parsed, "email") || input.email.trim(),
    account_id: pickString(parsed, "account_id", "accountId") || input.accountId.trim(),
    expired: expired || undefined,
    access_token: pickString(parsed, "access_token", "accessToken") || input.accessToken.trim(),
    refresh_token: pickString(parsed, "refresh_token", "refreshToken") || input.refreshToken.trim(),
    id_token: pickString(parsed, "id_token", "idToken") || input.idToken.trim(),
    last_refresh: lastRefresh || undefined,
    token_type: tokenType || undefined,
  };
}

export function buildCodexVibeMonitorCredentialJson(
  input: ChatGptCredentialExportInput,
): string {
  return JSON.stringify(buildCodexVibeMonitorCredentialObject(input), null, 2);
}
