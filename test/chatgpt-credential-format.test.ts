import { describe, expect, test } from "bun:test";
import {
  buildCodexVibeMonitorCredentialJson,
  buildCodexVibeMonitorCredentialObject,
} from "../src/server/chatgpt-credential-format.js";

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
});
