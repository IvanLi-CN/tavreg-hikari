export type ServerAuthScope = "public" | "internal" | "integration";

export interface ServerAuthConfig {
  forwardedUserHeader: string;
  forwardedEmailHeader: string;
  forwardedSecretHeader: string;
  forwardedSecret: string | null;
}

export interface ForwardedIdentity {
  user: string | null;
  email: string | null;
  principal: string;
}

export type TrustedForwardAuthResult =
  | {
      ok: true;
      identity: ForwardedIdentity;
    }
  | {
      ok: false;
      reason: "missing_identity" | "missing_secret" | "invalid_secret" | "misconfigured_secret";
    };

function normalizeHeaderName(value: string | undefined, fallback: string): string {
  const normalized = String(value || "").trim();
  return normalized || fallback;
}

function readTrimmedHeader(headers: Headers, name: string): string | null {
  const value = headers.get(name);
  return value?.trim() ? value.trim() : null;
}

function readForwardedClientIp(req: Request): string | null {
  const forwardedFor = readTrimmedHeader(req.headers, "x-forwarded-for");
  if (forwardedFor) {
    const first = forwardedFor
      .split(",")
      .map((item) => item.trim())
      .find(Boolean);
    if (first) return first;
  }
  return (
    readTrimmedHeader(req.headers, "x-real-ip") ||
    readTrimmedHeader(req.headers, "cf-connecting-ip") ||
    readTrimmedHeader(req.headers, "fly-client-ip") ||
    null
  );
}

function hasTrustedForwardedSecret(req: Request, config: ServerAuthConfig): boolean {
  if (!config.forwardedSecret) {
    return false;
  }
  const providedSecret = readTrimmedHeader(req.headers, config.forwardedSecretHeader);
  return Boolean(providedSecret && providedSecret === config.forwardedSecret);
}

export function buildServerAuthConfig(env: NodeJS.ProcessEnv = process.env): ServerAuthConfig {
  const forwardedSecret = String(env.FORWARD_AUTH_SECRET || "").trim();
  return {
    forwardedUserHeader: normalizeHeaderName(env.FORWARD_AUTH_USER_HEADER, "X-Forwarded-User"),
    forwardedEmailHeader: normalizeHeaderName(env.FORWARD_AUTH_EMAIL_HEADER, "X-Forwarded-Email"),
    forwardedSecretHeader: normalizeHeaderName(env.FORWARD_AUTH_SECRET_HEADER, "X-Forwarded-Auth-Secret"),
    forwardedSecret: forwardedSecret || null,
  };
}

export function classifyRequestPath(pathname: string): ServerAuthScope {
  if (pathname === "/api/health" || pathname === "/api/microsoft-mail/oauth/callback") {
    return "public";
  }
  if (pathname.startsWith("/api/integration/v1/")) {
    return "integration";
  }
  return "internal";
}

export function readForwardedIdentity(req: Request, config: ServerAuthConfig): ForwardedIdentity | null {
  const user = readTrimmedHeader(req.headers, config.forwardedUserHeader);
  const email = readTrimmedHeader(req.headers, config.forwardedEmailHeader);
  const principal = user || email;
  if (!principal) {
    return null;
  }
  return {
    user,
    email,
    principal,
  };
}

export function authenticateTrustedForwardAuth(req: Request, config: ServerAuthConfig): TrustedForwardAuthResult {
  if (!config.forwardedSecret) {
    return { ok: false, reason: "misconfigured_secret" };
  }

  const providedSecret = readTrimmedHeader(req.headers, config.forwardedSecretHeader);
  if (!providedSecret) {
    return { ok: false, reason: "missing_secret" };
  }
  if (!hasTrustedForwardedSecret(req, config)) {
    return { ok: false, reason: "invalid_secret" };
  }

  const identity = readForwardedIdentity(req, config);
  if (!identity) {
    return { ok: false, reason: "missing_identity" };
  }

  return {
    ok: true,
    identity,
  };
}

export function extractIntegrationApiKey(req: Request): string | null {
  const authorization = readTrimmedHeader(req.headers, "authorization");
  if (authorization) {
    const matched = authorization.match(/^Bearer\s+(.+)$/i);
    if (matched?.[1]?.trim()) {
      return matched[1].trim();
    }
  }
  return readTrimmedHeader(req.headers, "x-api-key");
}

export function resolveClientIp(
  req: Request,
  configOrTrustedPeerAddress?: ServerAuthConfig | string | null,
  trustedPeerAddress?: string | null,
): string | null {
  const config =
    configOrTrustedPeerAddress && typeof configOrTrustedPeerAddress === "object" ? configOrTrustedPeerAddress : null;
  const peerAddress =
    typeof configOrTrustedPeerAddress === "string" || configOrTrustedPeerAddress == null
      ? configOrTrustedPeerAddress
      : trustedPeerAddress;
  if (config && hasTrustedForwardedSecret(req, config)) {
    const forwardedIp = readForwardedClientIp(req);
    if (forwardedIp) {
      return forwardedIp;
    }
  }
  const normalizedPeerAddress = String(peerAddress || "").trim();
  return normalizedPeerAddress || null;
}
