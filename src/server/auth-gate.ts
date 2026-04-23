export type ServerAuthScope = "public" | "internal" | "integration";

export interface ServerAuthConfig {
  forwardedUserHeader: string;
  forwardedEmailHeader: string;
}

export interface ForwardedIdentity {
  user: string | null;
  email: string | null;
  principal: string;
}

function normalizeHeaderName(value: string | undefined, fallback: string): string {
  const normalized = String(value || "").trim();
  return normalized || fallback;
}

function readTrimmedHeader(headers: Headers, name: string): string | null {
  const value = headers.get(name);
  return value?.trim() ? value.trim() : null;
}

export function buildServerAuthConfig(env: NodeJS.ProcessEnv = process.env): ServerAuthConfig {
  return {
    forwardedUserHeader: normalizeHeaderName(env.FORWARD_AUTH_USER_HEADER, "X-Forwarded-User"),
    forwardedEmailHeader: normalizeHeaderName(env.FORWARD_AUTH_EMAIL_HEADER, "X-Forwarded-Email"),
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

export function resolveClientIp(req: Request): string | null {
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
