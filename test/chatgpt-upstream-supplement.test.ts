import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ChatGptUpstreamSupplementService } from "../src/server/chatgpt-upstream-supplement.js";
import { AppDatabase } from "../src/storage/app-db.js";

const tempDirs: string[] = [];
type FetchMockHandler = (input: URL | RequestInfo, init?: RequestInit) => Promise<Response>;

function createFetchMock(handler: FetchMockHandler): typeof fetch {
  const nativeFetch = fetch as typeof fetch & { preconnect?: typeof fetch.preconnect };
  const preconnect = typeof nativeFetch.preconnect === "function" ? nativeFetch.preconnect.bind(fetch) : undefined;
  return Object.assign(handler, preconnect ? { preconnect } : {}) as typeof fetch;
}

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-chatgpt-upstream-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { tempDir, dbPath, appDb };
}

async function seedCredential(appDb: AppDatabase, tempDir: string, suffix = "alpha") {
  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: {},
  });
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: `${suffix}@mail.example.test`,
    outputDir: path.join(tempDir, suffix),
  });
  const completed = appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
    email: `${suffix}@mail.example.test`,
    accountId: `acc-${suffix}`,
    accessToken: `access-${suffix}`,
    refreshToken: `refresh-${suffix}`,
    idToken: `id-${suffix}`,
    expiresAt: "2026-04-18T10:00:00.000Z",
    credentialJson: JSON.stringify({
      email: `${suffix}@mail.example.test`,
      account_id: `acc-${suffix}`,
      access_token: `access-${suffix}`,
      refresh_token: `refresh-${suffix}`,
      id_token: `id-${suffix}`,
      expired: "2026-04-18T10:00:00.000Z",
      token_type: "Bearer",
    }),
  });
  return completed.credential;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

describe("ChatGptUpstreamSupplementService", () => {
  test("prefers DB overrides and falls back to env defaults when cleared", async () => {
    const { appDb } = await createTempDb();
    const service = new ChatGptUpstreamSupplementService(appDb, {
      env: {
        CHATGPT_UPSTREAM_BASE_URL: "https://env.example.test",
        CHATGPT_UPSTREAM_API_KEY: "env-secret-1234",
      } as NodeJS.ProcessEnv,
    });

    expect(service.serializeSettings()).toMatchObject({
      baseUrl: "https://env.example.test",
      hasApiKey: true,
      configured: true,
      baseUrlSource: "env",
      apiKeySource: "env",
    });

    const overridden = service.updateSettings({
      baseUrl: "https://db.example.test/",
      apiKey: "db-secret-9876",
      groupHistory: ["warm-pool", "warm-pool", "sync-ready"],
    });
    expect(overridden).toMatchObject({
      baseUrl: "https://db.example.test",
      hasApiKey: true,
      baseUrlSource: "db",
      apiKeySource: "db",
      groupHistory: ["warm-pool", "sync-ready"],
    });

    const cleared = service.updateSettings({
      clearBaseUrl: true,
      clearApiKey: true,
    });
    expect(cleared).toMatchObject({
      baseUrl: "https://env.example.test",
      hasApiKey: true,
      baseUrlSource: "env",
      apiKeySource: "env",
      groupHistory: ["warm-pool", "sync-ready"],
    });

    appDb.close();
  });

  test("normalizes env baseUrl and ignores invalid env overrides", async () => {
    const { appDb } = await createTempDb();
    const normalizedEnvService = new ChatGptUpstreamSupplementService(appDb, {
      env: {
        CHATGPT_UPSTREAM_BASE_URL: "https://env.example.test/base/?foo=1#frag",
        CHATGPT_UPSTREAM_API_KEY: "env-secret-1234",
      } as NodeJS.ProcessEnv,
    });

    expect(normalizedEnvService.serializeSettings()).toMatchObject({
      baseUrl: "https://env.example.test/base",
      configured: true,
      baseUrlSource: "env",
      apiKeySource: "env",
    });

    const invalidEnvService = new ChatGptUpstreamSupplementService(appDb, {
      env: {
        CHATGPT_UPSTREAM_BASE_URL: "env.example.test/no-scheme",
        CHATGPT_UPSTREAM_API_KEY: "env-secret-1234",
      } as NodeJS.ProcessEnv,
    });

    expect(invalidEnvService.serializeSettings()).toMatchObject({
      baseUrl: "",
      configured: false,
      baseUrlSource: "unset",
      apiKeySource: "env",
    });

    appDb.close();
  });

  test("supplements a credential with upstream oauth payload and remembers group history", async () => {
    const { appDb, tempDir } = await createTempDb();
    const credential = await seedCredential(appDb, tempDir, "alpha");
    const requests: Array<{ url: string; init?: RequestInit; body: any }> = [];
    const service = new ChatGptUpstreamSupplementService(appDb, {
      projectLabel: "tavreg-hikari",
      env: {
        CHATGPT_UPSTREAM_BASE_URL: "https://cvm.example.test/base",
        CHATGPT_UPSTREAM_API_KEY: "env-secret-1234",
      } as NodeJS.ProcessEnv,
      fetchImpl: createFetchMock(async (input: URL | RequestInfo, init?: RequestInit) => {
        requests.push({
          url: String(input),
          init,
          body: JSON.parse(String(init?.body || "{}")),
        });
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }),
    });

    const result = await service.supplementCredential(credential, "sync-ready");

    expect(result).toMatchObject({
      credentialId: credential.id,
      email: "alpha@mail.example.test",
      accountId: "acc-alpha",
      groupName: "sync-ready",
      success: true,
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe("https://cvm.example.test/base/api/external/v1/upstream-accounts/oauth/acc-alpha");
    expect(requests[0]?.init?.headers).toMatchObject({
      authorization: "Bearer env-secret-1234",
    });
    expect(requests[0]?.body).toMatchObject({
      displayName: "tavreg-hikari / alpha@mail.example.test / acc-alpha",
      groupName: "sync-ready",
      oauth: {
        email: "alpha@mail.example.test",
        accessToken: "access-alpha",
        refreshToken: "refresh-alpha",
        idToken: "id-alpha",
        tokenType: "Bearer",
        expired: "2026-04-18T10:00:00.000Z",
      },
    });
    expect(service.serializeSettings().groupHistory).toEqual(["sync-ready"]);

    appDb.close();
  });

  test("returns per-record failures for missing rows in batch supplement", async () => {
    const { appDb, tempDir } = await createTempDb();
    const credential = await seedCredential(appDb, tempDir, "beta");
    const service = new ChatGptUpstreamSupplementService(appDb, {
      env: {
        CHATGPT_UPSTREAM_BASE_URL: "https://cvm.example.test",
        CHATGPT_UPSTREAM_API_KEY: "env-secret-1234",
      } as NodeJS.ProcessEnv,
      fetchImpl: createFetchMock(async () => new Response(JSON.stringify({ ok: true }), { status: 200 })),
    });

    const result = await service.supplementCredentials([credential.id, 9999], "warm-pool");

    expect(result.requested).toBe(2);
    expect(result.succeeded).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.results.find((item) => item.credentialId === 9999)).toMatchObject({
      success: false,
      message: "credential #9999 not found",
    });

    appDb.close();
  });

  test("times out hung upstream supplement requests", async () => {
    const { appDb, tempDir } = await createTempDb();
    const credential = await seedCredential(appDb, tempDir, "gamma");
    const service = new ChatGptUpstreamSupplementService(appDb, {
      env: {
        CHATGPT_UPSTREAM_BASE_URL: "https://cvm.example.test",
        CHATGPT_UPSTREAM_API_KEY: "env-secret-1234",
      } as NodeJS.ProcessEnv,
      requestTimeoutMs: 10,
      fetchImpl: createFetchMock(async (_input: URL | RequestInfo, init?: RequestInit) => {
        const signal = init?.signal;
        return await new Promise<Response>((_resolve, reject) => {
          if (signal?.aborted) {
            reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
            return;
          }
          signal?.addEventListener(
            "abort",
            () => reject(signal.reason ?? new DOMException("Aborted", "AbortError")),
            { once: true },
          );
        });
      }),
    });

    const result = await service.supplementCredential(credential, "hung-pool");

    expect(result).toMatchObject({
      credentialId: credential.id,
      success: false,
      message: "upstream request timed out after 10ms",
    });

    appDb.close();
  });
});
