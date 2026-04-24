import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { handleIntegrationApiRequest } from "../src/server/integration-api.ts";
import { AppDatabase, type AppSettings } from "../src/storage/app-db.ts";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;
const originalCfmailApiKey = process.env.CFMAIL_API_KEY;
const originalCfmailBaseUrl = process.env.CFMAIL_BASE_URL;

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-integration-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { tempDir, appDb };
}

async function seedAccount(appDb: AppDatabase) {
  const imported = appDb.importAccounts([{ email: "relay@example.test", password: "relay-pass" }], { groupName: "relay" });
  const accountId = imported.affectedIds[0]!;
  appDb.markBrowserSessionReady(accountId, {
    browserEngine: "chrome",
    proxyNode: "Tokyo-01",
    proxyIp: "198.51.100.10",
    proxyCountry: "JP",
    proxyRegion: "Tokyo",
    proxyCity: "Tokyo",
    proxyTimezone: "Asia/Tokyo",
  });
  const apiKey = appDb.recordApiKey(accountId, "tvly-demo-secret", "198.51.100.10");
  const mailbox = appDb.ensureMailboxForAccount(accountId);
  appDb.completeMailboxOAuth(mailbox.id, {
    refreshToken: "refresh-token",
    accessToken: "access-token",
    accessTokenExpiresAt: "2026-04-25T00:00:00.000Z",
    authority: "common",
    graphUserPrincipalName: "relay@example.test",
    graphDisplayName: "Relay Demo",
  });
  appDb.markMailboxStatus(mailbox.id, {
    status: "available",
    unreadCount: 1,
    lastSyncedAt: "2026-04-24T10:10:00.000Z",
  });
  appDb.upsertMailboxMessages(mailbox.id, [
    {
      graphMessageId: "graph-1",
      subject: "Your verification code is 456123",
      bodyPreview: "Use 456123 to continue sign in.",
      bodyContent: "Use 456123 to continue sign in right now.",
      receivedAt: "2026-04-24T10:12:00.000Z",
    },
  ]);
  appDb.upsertAccountServiceAccess({
    accountId,
    service: "tavily",
    apiKeyId: apiKey.id,
    extractedIp: "198.51.100.10",
    lastSuccessAt: "2026-04-24T10:11:00.000Z",
    snapshotJson: JSON.stringify({
      cookiesSnapshot: [{ name: "tvly_session", value: "cookie-value" }],
      browserFingerprintSnapshot: { navigatorUserAgent: "demo-agent" },
    }),
  });
  return { accountId, mailboxId: mailbox.id };
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  if (originalCfmailApiKey === undefined) {
    delete process.env.CFMAIL_API_KEY;
  } else {
    process.env.CFMAIL_API_KEY = originalCfmailApiKey;
  }
  if (originalCfmailBaseUrl === undefined) {
    delete process.env.CFMAIL_BASE_URL;
  } else {
    process.env.CFMAIL_BASE_URL = originalCfmailBaseUrl;
  }
  while (tempDirs.length > 0) {
    const tempDir = tempDirs.pop();
    if (!tempDir) continue;
    await rm(tempDir, { recursive: true, force: true });
  }
});

describe("integration api", () => {
  test("returns account summaries without plaintext passwords or local profile paths", async () => {
    const { appDb } = await createTempDb();
    const { accountId } = await seedAccount(appDb);
    const req = new Request("https://console.example.test/api/integration/v1/microsoft-accounts?page=1&pageSize=20");
    const resp = await handleIntegrationApiRequest({
      req,
      pathname: new URL(req.url).pathname,
      url: new URL(req.url),
      db: appDb,
    });

    expect(resp?.status).toBe(200);
    const payload = await resp!.json();
    expect(payload.rows).toHaveLength(1);
    expect(payload.rows[0]).toMatchObject({
      id: accountId,
      microsoftEmail: "relay@example.test",
      serviceSummary: {
        tavily: {
          available: true,
        },
      },
    });
    expect(payload.rows[0]).not.toHaveProperty("passwordPlaintext");
    expect(payload.rows[0].session).not.toHaveProperty("profilePath");
    appDb.close();
  });

  test("returns microsoft account detail with tavily and mailbox summaries", async () => {
    const { appDb } = await createTempDb();
    const { accountId } = await seedAccount(appDb);
    const req = new Request(`https://console.example.test/api/integration/v1/microsoft-accounts/${accountId}`);
    const resp = await handleIntegrationApiRequest({
      req,
      pathname: new URL(req.url).pathname,
      url: new URL(req.url),
      db: appDb,
    });

    expect(resp?.status).toBe(200);
    const payload = await resp!.json();
    expect(payload.account).toMatchObject({
      id: accountId,
      microsoftEmail: "relay@example.test",
      passwordPlaintext: "relay-pass",
      successfulServices: ["tavily", "microsoftMail"],
      tavily: {
        apiKey: "tvly-demo-secret",
        extractedIp: "198.51.100.10",
      },
      microsoftMail: {
        available: true,
        graphUserPrincipalName: "relay@example.test",
      },
    });
    expect(payload.account.tavily.cookiesSnapshot).toHaveLength(1);
    expect(payload.account.session).not.toHaveProperty("profilePath");
    appDb.close();
  });

  test("treats failed mailboxes as unavailable in microsoft account summaries", async () => {
    const { appDb } = await createTempDb();
    const { accountId } = await seedAccount(appDb);
    const mailbox = appDb.getMailboxByAccountId(accountId);
    expect(mailbox).toBeTruthy();
    appDb.markMailboxStatus(mailbox!.id, {
      status: "failed",
      unreadCount: 0,
      lastSyncedAt: mailbox!.lastSyncedAt,
      lastErrorCode: "graph_sync_failed",
      lastErrorMessage: "sync failed",
    });

    const listReq = new Request("https://console.example.test/api/integration/v1/microsoft-accounts?page=1&pageSize=20");
    const listResp = await handleIntegrationApiRequest({
      req: listReq,
      pathname: new URL(listReq.url).pathname,
      url: new URL(listReq.url),
      db: appDb,
    });

    expect(listResp?.status).toBe(200);
    const listPayload = await listResp!.json();
    expect(listPayload.rows[0]).toMatchObject({
      id: accountId,
      successfulServices: ["tavily"],
      serviceSummary: {
        microsoftMail: {
          available: false,
          status: "failed",
        },
      },
    });

    const detailReq = new Request(`https://console.example.test/api/integration/v1/microsoft-accounts/${accountId}`);
    const detailResp = await handleIntegrationApiRequest({
      req: detailReq,
      pathname: new URL(detailReq.url).pathname,
      url: new URL(detailReq.url),
      db: appDb,
    });

    expect(detailResp?.status).toBe(200);
    const detailPayload = await detailResp!.json();
    expect(detailPayload.account).toMatchObject({
      successfulServices: ["tavily"],
      microsoftMail: {
        available: false,
        status: "failed",
      },
    });

    appDb.close();
  });

  test("lists unavailable mailboxes in the mailbox index", async () => {
    const { appDb } = await createTempDb();
    const { accountId, mailboxId } = await seedAccount(appDb);
    appDb.markMailboxStatus(mailboxId, {
      status: "failed",
      unreadCount: 0,
      lastSyncedAt: "2026-04-24T10:15:00.000Z",
      lastErrorCode: "graph_sync_failed",
      lastErrorMessage: "sync failed",
    });

    const req = new Request(`https://console.example.test/api/integration/v1/mailboxes?accountId=${accountId}`);
    const resp = await handleIntegrationApiRequest({
      req,
      pathname: new URL(req.url).pathname,
      url: new URL(req.url),
      db: appDb,
    });

    expect(resp?.status).toBe(200);
    const payload = await resp!.json();
    expect(payload.rows).toHaveLength(1);
    expect(payload.rows[0]).toMatchObject({
      id: mailboxId,
      accountId,
      status: "failed",
      lastErrorCode: "graph_sync_failed",
      lastErrorMessage: "sync failed",
    });
    appDb.close();
  });

  test("returns parsed verification codes for message detail", async () => {
    const { appDb } = await createTempDb();
    const { mailboxId } = await seedAccount(appDb);
    const mailboxMessages = appDb.listMailboxMessages(mailboxId, { limit: 10, offset: 0 });
    const messageId = mailboxMessages.rows[0]!.id;
    const req = new Request(`https://console.example.test/api/integration/v1/messages/${messageId}`);
    const resp = await handleIntegrationApiRequest({
      req,
      pathname: new URL(req.url).pathname,
      url: new URL(req.url),
      db: appDb,
    });

    expect(resp?.status).toBe(200);
    const payload = await resp!.json();
    expect(payload.message.parsedVerificationCodes[0]).toMatchObject({
      code: "456123",
    });
    appDb.close();
  });

  test("hydrates integration message detail before parsing verification codes", async () => {
    const { appDb } = await createTempDb();
    const { mailboxId } = await seedAccount(appDb);
    appDb.upsertMailboxMessages(mailboxId, [
      {
        graphMessageId: "graph-1",
        subject: "Microsoft account security alert",
        bodyPreview: "Preview copy without the final code.",
        bodyContent: "",
        receivedAt: "2026-04-24T10:12:00.000Z",
      },
    ]);
    const mailboxMessages = appDb.listMailboxMessages(mailboxId, { limit: 10, offset: 0 });
    const messageId = mailboxMessages.rows[0]!.id;
    const graphSettings: AppSettings = {
      subscriptionUrl: "",
      groupName: "",
      routeGroupName: "",
      checkUrl: "",
      timeoutMs: 10_000,
      maxLatencyMs: 5_000,
      apiPort: 7890,
      mixedPort: 7891,
      serverHost: "127.0.0.1",
      serverPort: 9090,
      defaultRunMode: "headless",
      defaultNeed: 1,
      defaultParallel: 1,
      defaultMaxAttempts: 5,
      extractorZhanghaoyaKey: "",
      extractorShanyouxiangKey: "",
      extractorShankeyunKey: "",
      extractorHotmail666Key: "",
      defaultAutoExtractSources: [],
      defaultAutoExtractQuantity: 1,
      defaultAutoExtractMaxWaitSec: 60,
      defaultAutoExtractAccountType: "outlook",
      microsoftGraphClientId: "client-id",
      microsoftGraphClientSecret: "client-secret",
      microsoftGraphRedirectUri: "https://console.example.test/api/microsoft-mail/oauth/callback",
      microsoftGraphAuthority: "common",
    };
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      expect(url).toContain("/me/messages/graph-1?");
      return new Response(
        JSON.stringify({
          id: "graph-1",
          internetMessageId: "<graph-1@example.test>",
          conversationId: "conversation-1",
          subject: "Microsoft account security alert",
          from: {
            emailAddress: {
              name: "Microsoft",
              address: "account-security-noreply@accountprotection.microsoft.com",
            },
          },
          receivedDateTime: "2026-04-24T10:12:00.000Z",
          isRead: false,
          hasAttachments: false,
          bodyPreview: "Preview copy without the final code.",
          body: {
            contentType: "text",
            content: "Use security code 654321 to finish verifying your Microsoft account.",
          },
          webLink: "https://graph.example.test/messages/graph-1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    try {
      const req = new Request(`https://console.example.test/api/integration/v1/messages/${messageId}`);
      const resp = await handleIntegrationApiRequest({
        req,
        pathname: new URL(req.url).pathname,
        url: new URL(req.url),
        db: appDb,
        readSettings: () => graphSettings,
      });

      expect(resp?.status).toBe(200);
      const payload = await resp!.json();
      expect(payload.message.bodyContent).toContain("654321");
      expect(payload.message.parsedVerificationCodes[0]).toMatchObject({
        code: "654321",
      });
    } finally {
      globalThis.fetch = originalFetch;
      appDb.close();
    }
  });

  test("hydrates integration mailbox message list before parsing verification codes", async () => {
    const { appDb } = await createTempDb();
    const { mailboxId } = await seedAccount(appDb);
    appDb.upsertMailboxMessages(mailboxId, [
      {
        graphMessageId: "graph-1",
        subject: "Microsoft account security alert",
        bodyPreview: "Preview copy without the final code.",
        bodyContent: "",
        receivedAt: "2026-04-24T10:12:00.000Z",
      },
    ]);
    const graphSettings: AppSettings = {
      subscriptionUrl: "",
      groupName: "",
      routeGroupName: "",
      checkUrl: "",
      timeoutMs: 10_000,
      maxLatencyMs: 5_000,
      apiPort: 7890,
      mixedPort: 7891,
      serverHost: "127.0.0.1",
      serverPort: 9090,
      defaultRunMode: "headless",
      defaultNeed: 1,
      defaultParallel: 1,
      defaultMaxAttempts: 5,
      extractorZhanghaoyaKey: "",
      extractorShanyouxiangKey: "",
      extractorShankeyunKey: "",
      extractorHotmail666Key: "",
      defaultAutoExtractSources: [],
      defaultAutoExtractQuantity: 1,
      defaultAutoExtractMaxWaitSec: 60,
      defaultAutoExtractAccountType: "outlook",
      microsoftGraphClientId: "client-id",
      microsoftGraphClientSecret: "client-secret",
      microsoftGraphRedirectUri: "https://console.example.test/api/microsoft-mail/oauth/callback",
      microsoftGraphAuthority: "common",
    };
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          id: "graph-1",
          internetMessageId: "<graph-1@example.test>",
          conversationId: "conversation-1",
          subject: "Microsoft account security alert",
          from: {
            emailAddress: {
              name: "Microsoft",
              address: "account-security-noreply@accountprotection.microsoft.com",
            },
          },
          receivedDateTime: "2026-04-24T10:12:00.000Z",
          isRead: false,
          hasAttachments: false,
          bodyPreview: "Preview copy without the final code.",
          body: {
            contentType: "text",
            content: "Use security code 654321 to finish verifying your Microsoft account.",
          },
          webLink: "https://graph.example.test/messages/graph-1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as unknown as typeof fetch;

    try {
      const req = new Request(`https://console.example.test/api/integration/v1/mailboxes/${mailboxId}/messages?limit=50&offset=0`);
      const resp = await handleIntegrationApiRequest({
        req,
        pathname: new URL(req.url).pathname,
        url: new URL(req.url),
        db: appDb,
        readSettings: () => graphSettings,
      });

      expect(resp?.status).toBe(200);
      const payload = await resp!.json();
      expect(payload.rows[0].parsedVerificationCodes[0]).toMatchObject({
        code: "654321",
      });
    } finally {
      globalThis.fetch = originalFetch;
      appDb.close();
    }
  });

  test("reads proof mailbox codes from cfmail", async () => {
    const { appDb } = await createTempDb();
    const { accountId } = await seedAccount(appDb);
    appDb.updateAccountProofMailbox(accountId, {
      provider: "cfmail",
      address: "proof@alpha.example.test",
      mailboxId: "mbx-proof",
    });

    process.env.CFMAIL_API_KEY = "cfmail-demo-key";
    process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/messages?")) {
        return new Response(
          JSON.stringify({
            messages: [
              {
                id: "cfmail-msg-1",
                mailboxId: "mbx-proof",
                mailboxAddress: "proof@alpha.example.test",
                subject: "Microsoft account security code",
                previewText: "Your security code is 918273.",
                fromName: "Microsoft",
                fromAddress: "account-security-noreply@accountprotection.microsoft.com",
                receivedAt: "2026-04-24T10:12:00.000Z",
                sizeBytes: 123,
                attachmentCount: 0,
                hasHtml: true,
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          message: {
            id: "cfmail-msg-1",
            text: "Use security code 918273 to verify your Microsoft account.",
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    try {
      const req = new Request(`https://console.example.test/api/integration/v1/microsoft-accounts/${accountId}/proof-mailbox/codes`);
      const resp = await handleIntegrationApiRequest({
        req,
        pathname: new URL(req.url).pathname,
        url: new URL(req.url),
        db: appDb,
      });

      expect(resp?.status).toBe(200);
      const payload = await resp!.json();
      expect(payload.rows[0].parsedVerificationCodes[0]).toMatchObject({
        code: "918273",
        kind: "microsoftProof",
      });
    } finally {
      globalThis.fetch = originalFetch;
      appDb.close();
    }
  });

  test("rejects malformed mailbox accountId filters", async () => {
    const { appDb } = await createTempDb();
    await seedAccount(appDb);
    const req = new Request("https://console.example.test/api/integration/v1/mailboxes?accountId=abc");
    const resp = await handleIntegrationApiRequest({
      req,
      pathname: new URL(req.url).pathname,
      url: new URL(req.url),
      db: appDb,
    });

    expect(resp?.status).toBe(400);
    await expect(resp!.json()).resolves.toMatchObject({
      error: "invalid accountId",
    });
    appDb.close();
  });
});
