import { describe, expect, test } from "bun:test";
import {
  authenticateTrustedForwardAuth,
  buildServerAuthConfig,
  classifyRequestPath,
  extractIntegrationApiKey,
  readForwardedIdentity,
  resolveClientIp,
} from "../src/server/auth-gate.ts";

describe("auth gate helpers", () => {
  test("classifies public, integration and internal paths", () => {
    expect(classifyRequestPath("/api/health")).toBe("public");
    expect(classifyRequestPath("/api/microsoft-mail/oauth/callback")).toBe("public");
    expect(classifyRequestPath("/api/integration/v1/microsoft-accounts")).toBe("integration");
    expect(classifyRequestPath("/api/accounts")).toBe("internal");
    expect(classifyRequestPath("/")).toBe("internal");
  });

  test("reads forwarded identity using default and overridden headers", () => {
    const defaultConfig = buildServerAuthConfig({});
    const defaultReq = new Request("https://console.example.test/accounts", {
      headers: {
        "X-Forwarded-User": "operator",
        "X-Forwarded-Email": "operator@example.test",
      },
    });
    expect(readForwardedIdentity(defaultReq, defaultConfig)).toEqual({
      user: "operator",
      email: "operator@example.test",
      principal: "operator",
    });

    const customConfig = buildServerAuthConfig({
      FORWARD_AUTH_USER_HEADER: "X-Auth-User",
      FORWARD_AUTH_EMAIL_HEADER: "X-Auth-Email",
      FORWARD_AUTH_SECRET: "shared-secret",
      FORWARD_AUTH_SECRET_HEADER: "X-Auth-Secret",
    } as NodeJS.ProcessEnv);
    const customReq = new Request("https://console.example.test/accounts", {
      headers: {
        "X-Auth-Email": "relay@example.test",
      },
    });
    expect(readForwardedIdentity(customReq, customConfig)).toEqual({
      user: null,
      email: "relay@example.test",
      principal: "relay@example.test",
    });
    expect(customConfig.forwardedSecretHeader).toBe("X-Auth-Secret");
    expect(customConfig.forwardedSecret).toBe("shared-secret");
  });

  test("requires a trusted forward-auth secret before accepting identity headers", () => {
    const config = buildServerAuthConfig({
      FORWARD_AUTH_SECRET: "shared-secret",
    } as NodeJS.ProcessEnv);

    const spoofedReq = new Request("https://console.example.test/accounts", {
      headers: {
        "X-Forwarded-User": "operator",
      },
    });
    expect(authenticateTrustedForwardAuth(spoofedReq, config)).toEqual({
      ok: false,
      reason: "missing_secret",
    });

    const trustedReq = new Request("https://console.example.test/accounts", {
      headers: {
        "X-Forwarded-User": "operator",
        "X-Forwarded-Email": "operator@example.test",
        "X-Forwarded-Auth-Secret": "shared-secret",
      },
    });
    expect(authenticateTrustedForwardAuth(trustedReq, config)).toEqual({
      ok: true,
      identity: {
        user: "operator",
        email: "operator@example.test",
        principal: "operator",
      },
    });
  });

  test("fails closed when the trusted forward-auth secret is missing or invalid", () => {
    const missingSecretConfig = buildServerAuthConfig({});
    const missingSecretReq = new Request("https://console.example.test/accounts", {
      headers: {
        "X-Forwarded-User": "operator",
        "X-Forwarded-Auth-Secret": "shared-secret",
      },
    });
    expect(authenticateTrustedForwardAuth(missingSecretReq, missingSecretConfig)).toEqual({
      ok: false,
      reason: "misconfigured_secret",
    });

    const invalidSecretConfig = buildServerAuthConfig({
      FORWARD_AUTH_SECRET: "shared-secret",
      FORWARD_AUTH_SECRET_HEADER: "X-Auth-Secret",
    } as NodeJS.ProcessEnv);
    const invalidSecretReq = new Request("https://console.example.test/accounts", {
      headers: {
        "X-Forwarded-User": "operator",
        "X-Auth-Secret": "wrong-secret",
      },
    });
    expect(authenticateTrustedForwardAuth(invalidSecretReq, invalidSecretConfig)).toEqual({
      ok: false,
      reason: "invalid_secret",
    });
  });

  test("extracts api key from bearer and x-api-key headers", () => {
    const bearerReq = new Request("https://console.example.test/api/integration/v1/mailboxes", {
      headers: {
        Authorization: "Bearer thki_secret_123",
      },
    });
    expect(extractIntegrationApiKey(bearerReq)).toBe("thki_secret_123");

    const headerReq = new Request("https://console.example.test/api/integration/v1/mailboxes", {
      headers: {
        "X-API-Key": "thki_secret_456",
      },
    });
    expect(extractIntegrationApiKey(headerReq)).toBe("thki_secret_456");
  });

  test("resolves client ip from the trusted peer address only", () => {
    const spoofedReq = new Request("https://console.example.test/api/accounts", {
      headers: {
        "X-Forwarded-For": "198.51.100.7, 10.0.0.1",
        "X-Real-IP": "203.0.113.9",
      },
    });
    expect(resolveClientIp(spoofedReq)).toBeNull();
    expect(resolveClientIp(spoofedReq, "192.0.2.55")).toBe("192.0.2.55");
  });
});
