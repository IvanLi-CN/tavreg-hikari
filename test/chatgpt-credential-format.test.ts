import { describe, expect, test } from "bun:test";
import {
  buildCodexVibeMonitorCredentialJson,
  buildCodexVibeMonitorCredentialObject,
} from "../src/server/chatgpt-credential-format.js";

function fakeJwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.signature`;
}

describe("chatgpt credential export format", () => {
  test("builds codex-vibe-monitor import shape", () => {
    expect(
      buildCodexVibeMonitorCredentialObject({
        email: "alpha@example.com",
        accountId: "acct_alpha",
        accessToken: "access-alpha",
        refreshToken: "refresh-alpha",
        idToken: "id-alpha",
        expiresAt: "2026-04-09T12:34:56.000Z",
        createdAt: "2026-04-09T10:00:00.000Z",
      }),
    ).toEqual({
      type: "codex",
      email: "alpha@example.com",
      account_id: "acct_alpha",
      expired: "2026-04-09T12:34:56.000Z",
      access_token: "access-alpha",
      refresh_token: "refresh-alpha",
      id_token: "id-alpha",
      last_refresh: "2026-04-09T10:00:00.000Z",
      token_type: "Bearer",
    });
  });

  test("normalizes legacy credential json fields into import shape", () => {
    const json = buildCodexVibeMonitorCredentialJson({
      email: "fallback@example.com",
      accountId: "acct_fallback",
      accessToken: "access-fallback",
      refreshToken: "refresh-fallback",
      idToken: "id-fallback",
      expiresAt: "2026-04-09T12:34:56.000Z",
      createdAt: "2026-04-09T10:00:00.000Z",
      credentialJson: JSON.stringify({
        email: "legacy@example.com",
        account_id: "acct_legacy",
        expires_at: "2026-05-01T00:00:00.000Z",
        access_token: "legacy-access",
        refresh_token: "legacy-refresh",
        id_token: "legacy-id",
      }),
    });

    expect(JSON.parse(json)).toEqual({
      type: "codex",
      email: "legacy@example.com",
      account_id: "acct_legacy",
      expired: "2026-05-01T00:00:00.000Z",
      access_token: "legacy-access",
      refresh_token: "legacy-refresh",
      id_token: "legacy-id",
      last_refresh: "2026-04-09T10:00:00.000Z",
      token_type: "Bearer",
    });
  });

  test("prefers chatgpt_account_id from id_token claims over auth subject style account id", () => {
    const idToken = fakeJwt({
      email: "jwt@example.com",
      "https://api.openai.com/auth": {
        chatgpt_account_id: "chatgpt-account-123",
      },
      sub: "auth0|should_not_be_exported",
    });

    expect(
      buildCodexVibeMonitorCredentialObject({
        email: "fallback@example.com",
        accountId: "auth0|fallback",
        accessToken: "access-token",
        refreshToken: "refresh-token",
        idToken,
        expiresAt: "2026-04-09T12:34:56.000Z",
        createdAt: "2026-04-09T10:00:00.000Z",
      }),
    ).toEqual({
      type: "codex",
      email: "jwt@example.com",
      account_id: "chatgpt-account-123",
      expired: "2026-04-09T12:34:56.000Z",
      access_token: "access-token",
      refresh_token: "refresh-token",
      id_token: idToken,
      last_refresh: "2026-04-09T10:00:00.000Z",
      token_type: "Bearer",
    });
  });
});
