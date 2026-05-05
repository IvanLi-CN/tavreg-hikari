import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  syncAccountsFromUpstream,
  writeBackUpstreamTavilySuccess,
} from "../src/server/upstream-sync.js";
import { AppDatabase } from "../src/storage/app-db.js";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-upstream-sync-"));
  tempDirs.push(tempDir);
  const appDb = await AppDatabase.open(path.join(tempDir, "registry", "tavreg-hikari.sqlite"));
  return { tempDir, appDb };
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  while (tempDirs.length > 0) {
    const tempDir = tempDirs.pop();
    if (!tempDir) continue;
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("syncAccountsFromUpstream imports account details without marking remote sessions ready", async () => {
  const { appDb, tempDir } = await createTempDb();
  const requests: Array<{ url: string; authorization: string | null }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({
      url,
      authorization: String(new Headers(init?.headers || {}).get("authorization") || ""),
    });
    if (url.includes("/api/integration/v1/microsoft-accounts?")) {
      return Response.json({
        ok: true,
        rows: [{ id: 77, microsoftEmail: "sync@example.test" }],
        total: 1,
      });
    }
    if (url.endsWith("/api/integration/v1/microsoft-accounts/77")) {
      return Response.json({
        ok: true,
        account: {
          id: 77,
          microsoftEmail: "sync@example.test",
          passwordPlaintext: "sync-pass",
          groupName: "production",
          importedAt: "2026-04-29T08:00:00.000Z",
          updatedAt: "2026-04-29T08:30:00.000Z",
          importSource: "manual",
          accountSource: "manual",
          sourceRawPayload: null,
          lastUsedAt: null,
          lastResultStatus: "skipped_has_key",
          lastResultAt: "2026-04-29T08:20:00.000Z",
          lastErrorCode: null,
          skipReason: "has_api_key",
          disabledAt: null,
          disabledReason: null,
          proofMailbox: {
            provider: "cfmail",
            address: "sync-proof@example.test",
            mailboxId: "mailbox-sync",
          },
          session: {
            status: "ready",
            proxyNode: "Tokyo-01",
            proxyIp: "198.51.100.7",
          },
          tavily: {
            available: true,
            apiKey: "tvly-upstream-sync",
            apiKeyPrefix: "tvly-upstream",
            extractedIp: "198.51.100.7",
            lastSuccessAt: "2026-04-29T08:20:00.000Z",
            cookiesSnapshot: [{ name: "tvly_session", value: "cookie" }],
            browserFingerprintSnapshot: { navigatorUserAgent: "demo" },
          },
          microsoftMail: {
            status: "available",
            unreadCount: 2,
            lastSyncedAt: "2026-04-29T08:25:00.000Z",
            lastErrorCode: null,
            lastErrorMessage: null,
          },
        },
      });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }) as typeof fetch;

  const summary = await syncAccountsFromUpstream(appDb, {
    config: {
      enabled: true,
      baseUrl: "https://upstream.example.test",
      apiKey: "secret-key",
      writeback: "off",
    },
  });

  expect(summary).toMatchObject({
    ok: true,
    upstreamOrigin: "https://upstream.example.test",
    total: 1,
    created: 1,
    updated: 0,
    linkedApiKeys: 1,
  });
  expect(requests.every((request) => request.authorization === "Bearer secret-key")).toBe(true);

  const account = appDb.getAccountsByEmails(["sync@example.test"])[0]!;
  expect(account).toMatchObject({
    microsoftEmail: "sync@example.test",
    passwordPlaintext: "sync-pass",
    proofMailboxAddress: "sync-proof@example.test",
    groupName: "production",
    hasApiKey: true,
    upstreamOrigin: "https://upstream.example.test",
    upstreamAccountId: 77,
    mailboxStatus: "available",
    mailboxUnreadCount: 2,
  });
  expect(account.browserSession?.status).toBe("pending");
  expect(account.browserSession?.profilePath).toBe(path.join(tempDir, "browser-profiles", "accounts", String(account.id), "chrome"));
  expect(appDb.getApiKey(account.apiKeyId!)?.apiKey).toBe("tvly-upstream-sync");
  expect(JSON.parse(appDb.getAccountServiceAccess(account.id, "tavily")!.snapshotJson)).toMatchObject({
    cookiesSnapshot: [{ name: "tvly_session", value: "cookie" }],
    browserFingerprintSnapshot: { navigatorUserAgent: "demo" },
  });

  appDb.close();
});

test("syncAccountsFromUpstream imports ChatGPT and Grok keys through unified integration keys", async () => {
  const { appDb } = await createTempDb();
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/integration/v1/microsoft-accounts?")) {
      return Response.json({ ok: true, rows: [], total: 0 });
    }
    if (url.includes("/api/integration/v1/keys?site=tavily")) {
      return Response.json({ ok: true, site: "tavily", rows: [], total: 0 });
    }
    if (url.includes("/api/integration/v1/keys?site=chatgpt")) {
      return Response.json({ ok: true, site: "chatgpt", rows: [{ id: 701 }], total: 1 });
    }
    if (url.endsWith("/api/integration/v1/keys/chatgpt/701")) {
      return Response.json({
        ok: true,
        key: {
          site: "chatgpt",
          id: 701,
          email: "cgpt@example.test",
          accountId: "chatgpt-account-701",
          accessToken: "access-701",
          refreshToken: "refresh-701",
          idToken: "id-701",
          expiresAt: "2026-05-01T00:00:00.000Z",
          credentialJson: JSON.stringify({ account_id: "chatgpt-account-701" }),
          createdAt: "2026-04-30T12:00:00.000Z",
        },
      });
    }
    if (url.includes("/api/integration/v1/keys?site=grok")) {
      return Response.json({ ok: true, site: "grok", rows: [{ id: 801 }], total: 1 });
    }
    if (url.endsWith("/api/integration/v1/keys/grok/801")) {
      return Response.json({
        ok: true,
        key: {
          site: "grok",
          id: 801,
          email: "grok@example.test",
          password: "grok-pass",
          sso: "grok-sso-801",
          ssoRw: "grok-rw-801",
          cfClearance: "cf-801",
          checkoutUrl: "https://grok.example.test/checkout",
          birthDate: "1999-01-02",
          extractedIp: "198.51.100.81",
          extractedAt: "2026-04-30T12:10:00.000Z",
          lastVerifiedAt: "2026-04-30T12:11:00.000Z",
          createdAt: "2026-04-30T12:10:00.000Z",
        },
      });
    }
    return Response.json({ error: "not found", url }, { status: 404 });
  }) as typeof fetch;

  const summary = await syncAccountsFromUpstream(appDb, {
    config: {
      enabled: true,
      baseUrl: "https://upstream.example.test",
      apiKey: "secret-key",
      writeback: "off",
    },
  });

  expect(summary.syncedKeys).toEqual({ tavily: 0, chatgpt: 1, grok: 1 });
  expect(appDb.listChatGptCredentials({ pageSize: 10 }).rows[0]).toMatchObject({
    email: "cgpt@example.test",
    accountId: "chatgpt-account-701",
    accessToken: "access-701",
    upstreamOrigin: "https://upstream.example.test",
    upstreamKeyId: 701,
  });
  expect(appDb.listGrokApiKeys({ pageSize: 10 }).rows[0]).toMatchObject({
    email: "grok@example.test",
    password: "grok-pass",
    sso: "grok-sso-801",
    upstreamOrigin: "https://upstream.example.test",
    upstreamKeyId: 801,
  });

  const second = await syncAccountsFromUpstream(appDb, {
    config: {
      enabled: true,
      baseUrl: "https://upstream.example.test",
      apiKey: "secret-key",
      writeback: "off",
    },
  });
  expect(second.syncedKeys).toEqual({ tavily: 0, chatgpt: 1, grok: 1 });
  expect(appDb.listChatGptCredentials({ pageSize: 10 }).total).toBe(1);
  expect(appDb.listGrokApiKeys({ pageSize: 10 }).total).toBe(1);

  appDb.close();
});

test("syncAccountsFromUpstream validates every detail before writing local accounts", async () => {
  const { appDb } = await createTempDb();
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/integration/v1/microsoft-accounts?")) {
      return Response.json({
        ok: true,
        rows: [
          { id: 101, microsoftEmail: "valid-prefix@example.test" },
          { id: 102, microsoftEmail: "invalid-tail@example.test" },
        ],
        total: 2,
      });
    }
    if (url.endsWith("/api/integration/v1/microsoft-accounts/101")) {
      return Response.json({
        ok: true,
        account: {
          id: 101,
          microsoftEmail: "valid-prefix@example.test",
          passwordPlaintext: "valid-pass",
          importedAt: "2026-04-29T08:00:00.000Z",
          updatedAt: "2026-04-29T08:30:00.000Z",
        },
      });
    }
    if (url.endsWith("/api/integration/v1/microsoft-accounts/102")) {
      return Response.json({
        ok: true,
        account: {
          id: 102,
          microsoftEmail: "invalid-tail@example.test",
          passwordPlaintext: "",
        },
      });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }) as typeof fetch;

  await expect(
    syncAccountsFromUpstream(appDb, {
      config: {
        enabled: true,
        baseUrl: "https://upstream.example.test",
        apiKey: "secret-key",
        writeback: "off",
      },
    }),
  ).rejects.toThrow("missing passwordPlaintext");

  expect(appDb.getAccountsByEmails(["valid-prefix@example.test"])).toHaveLength(0);
  appDb.close();
});

test("syncAccountsFromUpstream fetches account details concurrently", async () => {
  const { appDb } = await createTempDb();
  let activeDetails = 0;
  let maxActiveDetails = 0;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/integration/v1/microsoft-accounts?")) {
      return Response.json({
        ok: true,
        rows: Array.from({ length: 16 }, (_, index) => ({
          id: index + 1,
          microsoftEmail: `concurrent-${index + 1}@example.test`,
        })),
        total: 16,
      });
    }
    const match = url.match(/\/api\/integration\/v1\/microsoft-accounts\/(\d+)$/);
    if (match) {
      activeDetails += 1;
      maxActiveDetails = Math.max(maxActiveDetails, activeDetails);
      await new Promise((resolve) => setTimeout(resolve, 10));
      activeDetails -= 1;
      const id = Number(match[1]);
      return Response.json({
        ok: true,
        account: {
          id,
          microsoftEmail: `concurrent-${id}@example.test`,
          passwordPlaintext: "valid-pass",
          importedAt: "2026-04-29T08:00:00.000Z",
          updatedAt: "2026-04-29T08:30:00.000Z",
        },
      });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }) as typeof fetch;

  const summary = await syncAccountsFromUpstream(appDb, {
    config: {
      enabled: true,
      baseUrl: "https://upstream.example.test",
      apiKey: "secret-key",
      writeback: "off",
    },
  });

  expect(summary.total).toBe(16);
  expect(maxActiveDetails).toBeGreaterThan(1);
  expect(maxActiveDetails).toBeLessThanOrEqual(12);
  appDb.close();
});

test("upstream sync switch blocks imports and writeback calls", async () => {
  const { appDb } = await createTempDb();
  let fetchCount = 0;
  globalThis.fetch = (async () => {
    fetchCount += 1;
    return Response.json({ ok: true });
  }) as unknown as typeof fetch;

  await expect(
    syncAccountsFromUpstream(appDb, {
      config: {
        enabled: false,
        baseUrl: "https://upstream.example.test",
        apiKey: "secret-key",
        writeback: "success_only",
      },
    }),
  ).rejects.toThrow("upstream sync is disabled");

  const { account } = appDb.upsertUpstreamAccount({
    upstreamOrigin: "https://upstream.example.test",
    upstreamAccountId: 501,
    microsoftEmail: "disabled-switch@example.test",
    passwordPlaintext: "pw123456",
  });
  await expect(
    writeBackUpstreamTavilySuccess({
      account,
      apiKey: "tvly-local-success",
    }, {
      config: {
        enabled: false,
        baseUrl: "https://upstream.example.test",
        apiKey: "secret-key",
        writeback: "success_only",
      },
    }),
  ).resolves.toEqual({ ok: true, skipped: true, reason: "sync_disabled" });
  expect(fetchCount).toBe(0);
  appDb.close();
});

test("upstream sync preserves an existing local key when production has no key", async () => {
  const { appDb } = await createTempDb();
  const imported = appDb.importAccounts([{ email: "local-key@example.test", password: "old-pass" }]);
  const accountId = imported.affectedIds[0]!;
  const localKey = appDb.recordApiKey(accountId, "tvly-local-only", "203.0.113.7");

  const result = appDb.upsertUpstreamAccount({
    upstreamOrigin: "https://upstream.example.test",
    upstreamAccountId: 91,
    microsoftEmail: "local-key@example.test",
    passwordPlaintext: "new-pass",
    importedAt: "2026-04-29T08:00:00.000Z",
    groupName: "production",
    lastResultStatus: "ready",
    skipReason: null,
    tavily: null,
  });

  expect(result.updated).toBe(true);
  const account = appDb.getAccount(accountId)!;
  expect(account.passwordPlaintext).toBe("new-pass");
  expect(account.hasApiKey).toBe(true);
  expect(account.apiKeyId).toBe(localKey.id);
  expect(account.importedAt).toBe("2026-04-29T08:00:00.000Z");
  expect(account.skipReason).toBe("has_api_key");
  expect(appDb.getApiKey(localKey.id)?.apiKey).toBe("tvly-local-only");

  appDb.close();
});

test("syncAccountsFromUpstream rejects details with missing import timestamps", async () => {
  const { appDb } = await createTempDb();
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/integration/v1/microsoft-accounts?")) {
      return Response.json({
        ok: true,
        rows: [{ id: 191, microsoftEmail: "missing-imported-at@example.test" }],
        total: 1,
      });
    }
    if (url.endsWith("/api/integration/v1/microsoft-accounts/191")) {
      return Response.json({
        ok: true,
        account: {
          id: 191,
          microsoftEmail: "missing-imported-at@example.test",
          passwordPlaintext: "new-pass",
        },
      });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }) as typeof fetch;

  await expect(
    syncAccountsFromUpstream(appDb, {
      config: {
        enabled: true,
        baseUrl: "https://upstream.example.test",
        apiKey: "secret-key",
        writeback: "off",
      },
    }),
  ).rejects.toThrow("missing importedAt");
  expect(appDb.getAccountsByEmails(["missing-imported-at@example.test"])).toHaveLength(0);

  appDb.close();
});

test("upstream sync keeps disabled account status while importing a Tavily key", async () => {
  const { appDb } = await createTempDb();
  const result = appDb.upsertUpstreamAccount({
    upstreamOrigin: "https://upstream.example.test",
    upstreamAccountId: 92,
    microsoftEmail: "disabled-key@example.test",
    passwordPlaintext: "disabled-pass",
    lastResultStatus: "disabled",
    skipReason: "has_api_key",
    disabledAt: "2026-04-29T09:00:00.000Z",
    disabledReason: "manual hold",
    tavily: {
      apiKey: "tvly-disabled-upstream",
      extractedIp: "198.51.100.11",
      lastSuccessAt: "2026-04-29T08:50:00.000Z",
    },
  });

  expect(result.linkedApiKey).toBe(true);
  const account = appDb.getAccountsByEmails(["disabled-key@example.test"])[0]!;
  expect(account).toMatchObject({
    hasApiKey: true,
    lastResultStatus: "disabled",
    skipReason: "has_api_key",
    disabledAt: "2026-04-29T09:00:00.000Z",
    disabledReason: "manual hold",
  });
  expect(appDb.getApiKey(account.apiKeyId!)?.apiKey).toBe("tvly-disabled-upstream");

  const disabledAccounts = appDb.listAccounts({ status: "disabled" });
  expect(disabledAccounts.total).toBe(1);
  expect(disabledAccounts.summary.disabled).toBe(1);

  appDb.close();
});

test("upstream sync preserves active local leases for existing accounts", async () => {
  const { appDb } = await createTempDb();
  const imported = appDb.importAccounts([{ email: "leased-sync@example.test", password: "old-pass" }]);
  const accountId = imported.affectedIds[0]!;
  const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
  const leased = appDb.leaseAccountForJob(job.id, accountId)!;
  expect(leased.leaseJobId).toBe(job.id);

  const result = appDb.upsertUpstreamAccount({
    upstreamOrigin: "https://upstream.example.test",
    upstreamAccountId: 93,
    microsoftEmail: "leased-sync@example.test",
    passwordPlaintext: "new-pass",
    lastResultStatus: "ready",
    tavily: {
      apiKey: "tvly-leased-upstream",
      extractedIp: "198.51.100.12",
    },
  });

  expect(result.updated).toBe(true);
  const account = appDb.getAccount(accountId)!;
  expect(account).toMatchObject({
    passwordPlaintext: "new-pass",
    hasApiKey: true,
    lastResultStatus: "leased",
    leaseJobId: job.id,
  });
  expect(account.leaseStartedAt).toBe(leased.leaseStartedAt);
  expect(appDb.getApiKey(account.apiKeyId!)?.apiKey).toBe("tvly-leased-upstream");

  appDb.close();
});

test("writeBackUpstreamTavilySuccess posts only linked success records", async () => {
  const { appDb } = await createTempDb();
  const result = appDb.upsertUpstreamAccount({
    upstreamOrigin: "https://upstream.example.test",
    upstreamAccountId: 123,
    microsoftEmail: "linked@example.test",
    passwordPlaintext: "linked-pass",
  });
  const calls: Array<{ url: string; body: Record<string, unknown>; authorization: string | null }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      body: JSON.parse(String(init?.body || "{}")),
      authorization: String(new Headers(init?.headers || {}).get("authorization") || ""),
    });
    return Response.json({ ok: true });
  }) as typeof fetch;

  await expect(
    writeBackUpstreamTavilySuccess({
      account: result.account,
      apiKey: "tvly-writeback",
      extractedIp: "198.51.100.9",
      cookiesSnapshot: [{ name: "session", value: "cookie" }],
    }, {
      config: {
        enabled: true,
        baseUrl: "https://ignored.example.test",
        apiKey: "secret-key",
        writeback: "success_only",
      },
    }),
  ).resolves.toEqual({ ok: true, skipped: false });

  expect(calls).toHaveLength(1);
  expect(calls[0]?.url).toBe("https://upstream.example.test/api/integration/v1/microsoft-accounts/123/tavily-success");
  expect(calls[0]?.authorization).toBe("Bearer secret-key");
  expect(calls[0]?.body).toMatchObject({
    microsoftEmail: "linked@example.test",
    apiKey: "tvly-writeback",
    extractedIp: "198.51.100.9",
  });

  appDb.close();
});
