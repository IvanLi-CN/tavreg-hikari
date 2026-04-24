import { BlockList, isIP } from "node:net";

export type ServerAuthScope = "public" | "internal" | "integration";

export interface ServerAuthConfig {
  forwardedUserHeader: string;
  forwardedEmailHeader: string;
  forwardedSecretHeader: string;
  forwardedSecret: string | null;
  trustedProxyCidrs: string[];
  trustedProxyList: BlockList;
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

function normalizeIpAddress(value: string | null | undefined): string | null {
  const trimmed = String(value || "").trim();
  if (!trimmed) return null;
  const zoneIndex = trimmed.indexOf("%");
  const withoutZone = zoneIndex >= 0 ? trimmed.slice(0, zoneIndex) : trimmed;
  const mappedV4Match = withoutZone.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  const normalized = mappedV4Match?.[1] || withoutZone;
  return isIP(normalized) ? normalized : null;
}

function parseTrustedProxyCidrs(value: string | undefined): string[] {
  const normalized = String(value || "").trim();
  if (!normalized) return [];
  return normalized
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildTrustedProxyList(cidrs: string[]): BlockList {
  const list = new BlockList();
  for (const entry of cidrs) {
    const match = entry.match(/^(.+)\/(\d{1,3})$/);
    if (match) {
      const address = normalizeIpAddress(match[1]);
      const prefix = Number.parseInt(match[2] || "", 10);
      if (!address || !Number.isInteger(prefix) || prefix < 0) {
        continue;
      }
      try {
        list.addSubnet(address, prefix, isIP(address) === 6 ? "ipv6" : "ipv4");
      } catch {
        continue;
      }
      continue;
    }
    const address = normalizeIpAddress(entry);
    if (!address) continue;
    try {
      list.addAddress(address, isIP(address) === 6 ? "ipv6" : "ipv4");
    } catch {
      continue;
    }
  }
  return list;
}

function readForwardedClientIp(req: Request): string | null {
  const forwardedFor = readTrimmedHeader(req.headers, "x-forwarded-for");
  if (forwardedFor) {
    const first = forwardedFor
      .split(",")
      .map((item) => normalizeIpAddress(item))
      .find(Boolean);
    if (first) return first;
  }
  return (
    normalizeIpAddress(readTrimmedHeader(req.headers, "x-real-ip")) ||
    normalizeIpAddress(readTrimmedHeader(req.headers, "cf-connecting-ip")) ||
    normalizeIpAddress(readTrimmedHeader(req.headers, "fly-client-ip")) ||
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

function isTrustedProxyPeer(peerAddress: string | null | undefined, config: ServerAuthConfig): boolean {
  const normalizedPeerAddress = normalizeIpAddress(peerAddress);
  if (!normalizedPeerAddress) {
    return false;
  }
  return config.trustedProxyList.check(normalizedPeerAddress, isIP(normalizedPeerAddress) === 6 ? "ipv6" : "ipv4");
}

export function buildServerAuthConfig(env: NodeJS.ProcessEnv = process.env): ServerAuthConfig {
  const forwardedSecret = String(env.FORWARD_AUTH_SECRET || "").trim();
  const trustedProxyCidrs = parseTrustedProxyCidrs(env.TRUSTED_PROXY_CIDRS);
  return {
    forwardedUserHeader: normalizeHeaderName(env.FORWARD_AUTH_USER_HEADER, "X-Forwarded-User"),
    forwardedEmailHeader: normalizeHeaderName(env.FORWARD_AUTH_EMAIL_HEADER, "X-Forwarded-Email"),
    forwardedSecretHeader: normalizeHeaderName(env.FORWARD_AUTH_SECRET_HEADER, "X-Forwarded-Auth-Secret"),
    forwardedSecret: forwardedSecret || null,
    trustedProxyCidrs,
    trustedProxyList: buildTrustedProxyList(trustedProxyCidrs),
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
  if (config && (hasTrustedForwardedSecret(req, config) || isTrustedProxyPeer(peerAddress, config))) {
    const forwardedIp = readForwardedClientIp(req);
    if (forwardedIp) {
      return forwardedIp;
    }
  }
  return normalizeIpAddress(peerAddress);
}
