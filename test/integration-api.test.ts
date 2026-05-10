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

function markRowRevoked(appDb: AppDatabase, table: "api_keys" | "grok_api_keys", id: number) {
  const rawDb = (appDb as unknown as { db: { query: (sql: string) => { run: (...params: unknown[]) => void } } }).db;
  rawDb.query(`UPDATE ${table} SET status = 'revoked' WHERE id = ?`).run(id);
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
      groupName: "relay",
      importedAt: expect.any(String),
      updatedAt: expect.any(String),
      importSource: "manual",
      accountSource: "manual",
      lastResultStatus: "skipped_has_key",
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
      groupName: "relay",
      importedAt: expect.any(String),
      updatedAt: expect.any(String),
      importSource: "manual",
      accountSource: "manual",
      lastResultStatus: "skipped_has_key",
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

  test("records tavily success writeback with account id and email guard", async () => {
    const { appDb } = await createTempDb();
    const { accountId } = await seedAccount(appDb);

    const mismatchReq = new Request(`https://console.example.test/api/integration/v1/microsoft-accounts/${accountId}/tavily-success`, {
      method: "POST",
      body: JSON.stringify({
        microsoftEmail: "other@example.test",
        apiKey: "tvly-writeback-mismatch",
      }),
    });
    const mismatchResp = await handleIntegrationApiRequest({
      req: mismatchReq,
      pathname: new URL(mismatchReq.url).pathname,
      url: new URL(mismatchReq.url),
      db: appDb,
    });
    expect(mismatchResp?.status).toBe(409);

    const req = new Request(`https://console.example.test/api/integration/v1/microsoft-accounts/${accountId}/tavily-success`, {
      method: "POST",
      body: JSON.stringify({
        microsoftEmail: "relay@example.test",
        apiKey: "tvly-writeback-secret",
        extractedIp: "203.0.113.88",
        lastSuccessAt: "2026-04-24T12:00:00.000Z",
        cookiesSnapshot: [{ name: "tvly_session", value: "writeback-cookie" }],
        browserFingerprintSnapshot: { navigatorUserAgent: "writeback-agent" },
      }),
    });
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
      tavily: {
        apiKey: "tvly-writeback-secret",
        extractedIp: "203.0.113.88",
      },
    });
    const account = appDb.getAccount(accountId)!;
    expect(appDb.getApiKey(account.apiKeyId!)?.apiKey).toBe("tvly-writeback-secret");
    expect(JSON.parse(appDb.getAccountServiceAccess(accountId, "tavily")!.snapshotJson)).toMatchObject({
      cookiesSnapshot: [{ name: "tvly_session", value: "writeback-cookie" }],
      browserFingerprintSnapshot: { navigatorUserAgent: "writeback-agent" },
    });
    appDb.close();
  });

  test("exposes ChatGPT and Grok keys through integration keys API", async () => {
    const { appDb } = await createTempDb();
    const chatJob = appDb.createJob({ site: "chatgpt", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1, payloadJson: { hidden: true } });
    const chatAttempt = appDb.createAttempt(chatJob.id, { accountEmail: "cgpt@example.test", outputDir: "" });
    const { credential } = appDb.completeChatGptAttemptSuccess(chatJob.id, chatAttempt.id, {
      email: "cgpt@example.test",
      accountId: "chatgpt-account-1",
      accessToken: "access-secret",
      refreshToken: "refresh-secret",
      idToken: "id-secret",
      expiresAt: "2026-05-01T00:00:00.000Z",
      credentialJson: JSON.stringify({ account_id: "chatgpt-account-1" }),
    });
    const grokJob = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1, payloadJson: { hidden: true } });
    const grokAttempt = appDb.createAttempt(grokJob.id, { accountEmail: "grok@example.test", outputDir: "" });
    const { key: grokKey } = appDb.completeGrokAttemptSuccess(grokJob.id, grokAttempt.id, {
      email: "grok@example.test",
      password: "grok-pass",
      sso: "grok-sso-secret",
      ssoRw: "grok-sso-rw",
      cfClearance: "cf-clearance",
      checkoutUrl: "https://grok.example.test/checkout",
      birthDate: "1999-01-02",
      extractedIp: "198.51.100.80",
    });

    const chatListReq = new Request("https://console.example.test/api/integration/v1/keys?site=chatgpt&page=1&pageSize=20");
    const chatListResp = await handleIntegrationApiRequest({
      req: chatListReq,
      pathname: new URL(chatListReq.url).pathname,
      url: new URL(chatListReq.url),
      db: appDb,
    });
    expect(chatListResp?.status).toBe(200);
    const chatList = await chatListResp!.json();
    expect(chatList.rows[0]).toMatchObject({
      site: "chatgpt",
      id: credential.id,
      email: "cgpt@example.test",
      accountId: "chatgpt-account-1",
    });
    expect(chatList.rows[0]).not.toHaveProperty("accessToken");

    const grokListReq = new Request("https://console.example.test/api/integration/v1/keys?site=grok&page=1&pageSize=20");
    const grokListResp = await handleIntegrationApiRequest({
      req: grokListReq,
      pathname: new URL(grokListReq.url).pathname,
      url: new URL(grokListReq.url),
      db: appDb,
    });
    expect(grokListResp?.status).toBe(200);
    const grokList = await grokListResp!.json();
    expect(grokList.rows[0]).toMatchObject({
      site: "grok",
      id: grokKey.id,
      email: "grok@example.test",
    });
    expect(grokList.rows[0]).not.toHaveProperty("password");
    expect(grokList.rows[0]).not.toHaveProperty("sso");
    expect(grokList.rows[0]).not.toHaveProperty("ssoRw");
    expect(grokList.rows[0]).not.toHaveProperty("cfClearance");

    const chatDetailReq = new Request(`https://console.example.test/api/integration/v1/keys/chatgpt/${credential.id}`);
    const chatDetailResp = await handleIntegrationApiRequest({
      req: chatDetailReq,
      pathname: new URL(chatDetailReq.url).pathname,
      url: new URL(chatDetailReq.url),
      db: appDb,
    });
    expect((await chatDetailResp!.json()).key).toMatchObject({
      accessToken: "access-secret",
      refreshToken: "refresh-secret",
      idToken: "id-secret",
    });

    const grokDetailReq = new Request(`https://console.example.test/api/integration/v1/keys/grok/${grokKey.id}`);
    const grokDetailResp = await handleIntegrationApiRequest({
      req: grokDetailReq,
      pathname: new URL(grokDetailReq.url).pathname,
      url: new URL(grokDetailReq.url),
      db: appDb,
    });
    expect((await grokDetailResp!.json()).key).toMatchObject({
      site: "grok",
      id: grokKey.id,
      email: "grok@example.test",
      password: "grok-pass",
      sso: "grok-sso-secret",
      ssoRw: "grok-sso-rw",
      cfClearance: "cf-clearance",
    });

    appDb.close();
  });

  test("exports only active Tavily and Grok keys for integration sync", async () => {
    const { appDb } = await createTempDb();
    const active = await seedAccount(appDb);
    const revokedImport = appDb.importAccounts([{ email: "revoked@example.test", password: "revoked-pass" }], { groupName: "relay" });
    const revokedTavilyKey = appDb.recordApiKey(revokedImport.affectedIds[0]!, "tvly-revoked-secret", "198.51.100.99");
    markRowRevoked(appDb, "api_keys", revokedTavilyKey.id);

    const activeGrokJob = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1, payloadJson: { hidden: true } });
    const activeGrokAttempt = appDb.createAttempt(activeGrokJob.id, { accountEmail: "active-grok@example.test", outputDir: "" });
    const { key: activeGrokKey } = appDb.completeGrokAttemptSuccess(activeGrokJob.id, activeGrokAttempt.id, {
      email: "active-grok@example.test",
      password: "grok-pass",
      sso: "active-sso",
      ssoRw: "active-sso-rw",
      cfClearance: "active-cf-clearance",
      checkoutUrl: "https://grok.example.test/checkout",
      birthDate: "1999-01-02",
    });
    const revokedGrokJob = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1, payloadJson: { hidden: true } });
    const revokedGrokAttempt = appDb.createAttempt(revokedGrokJob.id, { accountEmail: "revoked-grok@example.test", outputDir: "" });
    const { key: revokedGrokKey } = appDb.completeGrokAttemptSuccess(revokedGrokJob.id, revokedGrokAttempt.id, {
      email: "revoked-grok@example.test",
      password: "grok-pass",
      sso: "revoked-sso",
      ssoRw: "revoked-sso-rw",
      cfClearance: "revoked-cf-clearance",
      checkoutUrl: "https://grok.example.test/checkout",
      birthDate: "1999-01-02",
    });
    markRowRevoked(appDb, "grok_api_keys", revokedGrokKey.id);

    const tavilyReq = new Request("https://console.example.test/api/integration/v1/keys?site=tavily&page=1&pageSize=20");
    const tavilyResp = await handleIntegrationApiRequest({
      req: tavilyReq,
      pathname: new URL(tavilyReq.url).pathname,
      url: new URL(tavilyReq.url),
      db: appDb,
    });
    expect(tavilyResp?.status).toBe(200);
    const tavilyList = await tavilyResp!.json();
    expect(tavilyList.total).toBe(1);
    expect(tavilyList.rows.map((row: { id: number }) => row.id)).toEqual([appDb.getAccount(active.accountId)!.apiKeyId]);

    const grokReq = new Request("https://console.example.test/api/integration/v1/keys?site=grok&page=1&pageSize=20");
    const grokResp = await handleIntegrationApiRequest({
      req: grokReq,
      pathname: new URL(grokReq.url).pathname,
      url: new URL(grokReq.url),
      db: appDb,
    });
    expect(grokResp?.status).toBe(200);
    const grokList = await grokResp!.json();
    expect(grokList.total).toBe(1);
    expect(grokList.rows.map((row: { id: number }) => row.id)).toEqual([activeGrokKey.id]);

    appDb.close();
  });

  test("preserves active production leases during tavily success writeback", async () => {
    const { appDb } = await createTempDb();
    const { accountId } = await seedAccount(appDb);
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseAccountForJob(job.id, accountId)!;
    expect(leased.leaseJobId).toBe(job.id);

    const req = new Request(`https://console.example.test/api/integration/v1/microsoft-accounts/${accountId}/tavily-success`, {
      method: "POST",
      body: JSON.stringify({
        microsoftEmail: "relay@example.test",
        apiKey: "tvly-writeback-while-leased",
        extractedIp: "203.0.113.89",
      }),
    });
    const resp = await handleIntegrationApiRequest({
      req,
      pathname: new URL(req.url).pathname,
      url: new URL(req.url),
      db: appDb,
    });

    expect(resp?.status).toBe(200);
    const account = appDb.getAccount(accountId)!;
    expect(account).toMatchObject({
      hasApiKey: true,
      lastResultStatus: "leased",
      leaseJobId: job.id,
    });
    expect(account.leaseStartedAt).toBe(leased.leaseStartedAt);
    expect(appDb.getApiKey(account.apiKeyId!)?.apiKey).toBe("tvly-writeback-while-leased");

    appDb.close();
  });

  test("requires source origin for ChatGPT and Grok success writeback", async () => {
    const { appDb } = await createTempDb();
    const chatReq = new Request("https://console.example.test/api/integration/v1/keys/chatgpt/success", {
      method: "POST",
      body: JSON.stringify({
        sourceKeyId: 1,
        email: "cgpt@example.test",
        accountId: "chatgpt-account-1",
        accessToken: "access-token",
        refreshToken: "refresh-token",
        idToken: "id-token",
        credentialJson: "{}",
      }),
    });
    const chatResp = await handleIntegrationApiRequest({
      req: chatReq,
      pathname: new URL(chatReq.url).pathname,
      url: new URL(chatReq.url),
      db: appDb,
    });
    expect(chatResp?.status).toBe(422);
    expect((await chatResp!.json()).error).toBe("sourceOrigin is required");

    const grokReq = new Request("https://console.example.test/api/integration/v1/keys/grok/success", {
      method: "POST",
      body: JSON.stringify({
        sourceOrigin: "   ",
        sourceKeyId: 1,
        email: "grok@example.test",
        password: "grok-pass",
        sso: "grok-sso-token",
      }),
    });
    const grokResp = await handleIntegrationApiRequest({
      req: grokReq,
      pathname: new URL(grokReq.url).pathname,
      url: new URL(grokReq.url),
      db: appDb,
    });
    expect(grokResp?.status).toBe(422);
    expect((await grokResp!.json()).error).toBe("sourceOrigin is required");

    appDb.close();
  });

  test("validates ChatGPT and Grok success writeback payloads before upsert", async () => {
    const { appDb } = await createTempDb();
    const chatReq = new Request("https://console.example.test/api/integration/v1/keys/chatgpt/success", {
      method: "POST",
      body: JSON.stringify({
        sourceOrigin: "local:chatgpt:test",
        sourceKeyId: 1,
        email: "cgpt@example.test",
        accountId: "chatgpt-account-1",
        accessToken: "access-token",
        refreshToken: "refresh-token",
      }),
    });
    const chatResp = await handleIntegrationApiRequest({
      req: chatReq,
      pathname: new URL(chatReq.url).pathname,
      url: new URL(chatReq.url),
      db: appDb,
    });
    expect(chatResp?.status).toBe(422);
    expect((await chatResp!.json()).error).toBe("idToken is required");

    const grokReq = new Request("https://console.example.test/api/integration/v1/keys/grok/success", {
      method: "POST",
      body: JSON.stringify({
        sourceOrigin: "local:grok:test",
        sourceKeyId: 1,
        email: "grok@example.test",
        password: "grok-pass",
      }),
    });
    const grokResp = await handleIntegrationApiRequest({
      req: grokReq,
      pathname: new URL(grokReq.url).pathname,
      url: new URL(grokReq.url),
      db: appDb,
    });
    expect(grokResp?.status).toBe(422);
    expect((await grokResp!.json()).error).toBe("sso is required");

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
    const futureAccessTokenExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    appDb.updateMailboxTokens(mailboxId, {
      accessToken: "access-token",
      accessTokenExpiresAt: futureAccessTokenExpiry,
    });
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
      microsoftAccountBootstrapConcurrency: 3,
      microsoftAccountBootstrapWorkerTimeoutMs: 300000,
      microsoftAccountBootstrapKillGraceMs: 10000,
      upstreamTavregBaseUrl: "https://tavreg-hikari.ivanli.cc",
      upstreamTavregSyncEnabled: false,
      upstreamTavregApiKey: "",
      upstreamTavregWriteback: "off",
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

  test("does not hydrate integration mailbox message list when only full-body fetch could reveal codes", async () => {
    const { appDb } = await createTempDb();
    const { mailboxId } = await seedAccount(appDb);
    const mailbox = appDb.getMailbox(mailboxId);
    expect(mailbox).toBeTruthy();
    appDb.updateMailboxTokens(mailboxId, {
      accessToken: "expired-access-token",
      accessTokenExpiresAt: "2026-04-20T10:00:00.000Z",
      refreshToken: mailbox!.refreshToken,
      authority: mailbox!.authority,
    });
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
      microsoftAccountBootstrapConcurrency: 3,
      microsoftAccountBootstrapWorkerTimeoutMs: 300000,
      microsoftAccountBootstrapKillGraceMs: 10000,
      upstreamTavregBaseUrl: "https://tavreg-hikari.ivanli.cc",
      upstreamTavregSyncEnabled: false,
      upstreamTavregApiKey: "",
      upstreamTavregWriteback: "off",
    };
    let fetchCount = 0;
    globalThis.fetch = (async () => {
      fetchCount += 1;
      throw new Error("mailbox list should not fetch message details");
    }) as unknown as typeof fetch;

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
      expect(fetchCount).toBe(0);
      expect(payload.rows[0].parsedVerificationCodes).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
      appDb.close();
    }
  });

  test("keeps full-body verification snippets out of integration mailbox message list summaries", async () => {
    const { appDb } = await createTempDb();
    const { mailboxId } = await seedAccount(appDb);
    appDb.upsertMailboxMessages(mailboxId, [
      {
        graphMessageId: "graph-1",
        subject: "Microsoft account security alert",
        bodyPreview: "Preview copy without the final code.",
        bodyContent: "Use security code 654321 to finish verifying your Microsoft account.",
        receivedAt: "2026-04-24T10:12:00.000Z",
      },
    ]);

    try {
      const req = new Request(`https://console.example.test/api/integration/v1/mailboxes/${mailboxId}/messages?limit=50&offset=0`);
      const resp = await handleIntegrationApiRequest({
        req,
        pathname: new URL(req.url).pathname,
        url: new URL(req.url),
        db: appDb,
      });

      expect(resp?.status).toBe(200);
      const payload = await resp!.json();
      expect(payload.rows[0].parsedVerificationCodes).toEqual([]);
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
