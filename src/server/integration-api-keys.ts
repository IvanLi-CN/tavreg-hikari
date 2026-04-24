import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const INTEGRATION_API_KEY_PREFIX = "thki_";

export class IntegrationApiKeyNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntegrationApiKeyNotFoundError";
  }
}

export class IntegrationApiKeyStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntegrationApiKeyStateError";
  }
}

export function generateIntegrationApiKeySecret(): string {
  return `${INTEGRATION_API_KEY_PREFIX}${randomBytes(24).toString("base64url")}`;
}

export function hashIntegrationApiKey(secret: string): string {
  return createHash("sha256").update(secret.trim(), "utf8").digest("hex");
}

export function buildIntegrationApiKeyPrefix(secret: string, visible = 16): string {
  const normalized = secret.trim();
  return normalized.slice(0, Math.max(8, Math.min(visible, normalized.length)));
}

export function compareIntegrationApiKeyHash(secret: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashIntegrationApiKey(secret), "utf8");
  const expected = Buffer.from(String(expectedHash || "").trim(), "utf8");
  if (actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(actual, expected);
}
