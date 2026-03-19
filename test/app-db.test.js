import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildNextSettings, validateBeforePersist } from "../src/server/app-settings.ts";
import { JobScheduler, buildAttemptRuntimeSpec } from "../src/server/scheduler.ts";
import { AppDatabase, computeLaunchCapacity, shouldEnterCompleting } from "../src/storage/app-db.ts";
import { resolveStaticAssetPath, shouldServeSpaFallback } from "../src/server/static-assets.ts";
import { TaskLedger } from "../src/storage/task-ledger.ts";

const tempDirs = [];

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { dbPath, appDb };
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

describe("AppDatabase account import", () => {
  test("dedupes by email and preserves skip marker after API key exists", async () => {
    const { appDb } = await createTempDb();
    appDb.importAccounts([
      { email: "demo@outlook.com", password: "first-pass" },
      { email: "demo@outlook.com", password: "second-pass" },
    ]);
    let accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts).toHaveLength(1);
    expect(accounts[0]?.passwordPlaintext).toBe("second-pass");

    const accountId = accounts[0].id;
    const apiKey = appDb.recordApiKey(accountId, "tvly-abcdef1234567890");
    expect(apiKey.apiKeyPrefix).toBe("tvly-abcdef1");

    appDb.importAccounts([{ email: "demo@outlook.com", password: "third-pass" }]);
    accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts[0]?.passwordPlaintext).toBe("third-pass");
    expect(accounts[0]?.hasApiKey).toBe(true);
    expect(accounts[0]?.skipReason).toBe("has_api_key");

    appDb.close();
  });

  test("stores groups and supports batch group updates and deletes", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts(
      [
        { email: "group-a@outlook.com", password: "pass-a" },
        { email: "group-b@outlook.com", password: "pass-b" },
      ],
      { groupName: "batch-a" },
    );

    expect(imported.affectedIds).toHaveLength(2);
    expect(appDb.listAccountGroups()).toEqual(["batch-a"]);

    let accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts.map((account) => account.groupName)).toEqual(["batch-a", "batch-a"]);

    const updated = appDb.updateAccountsGroup(imported.affectedIds, "batch-b");
    expect(updated.updated).toBe(2);
    expect(updated.groupName).toBe("batch-b");
    expect(appDb.listAccountGroups()).toEqual(["batch-b"]);

    accounts = appDb.listAccounts({ page: 1, pageSize: 10, groupName: "batch-b" }).rows;
    expect(accounts).toHaveLength(2);

    const deleted = appDb.deleteAccounts([imported.affectedIds[0]]);
    expect(deleted.deleted).toBe(1);
    expect(deleted.blockedIds).toEqual([]);
    expect(appDb.listAccounts({ page: 1, pageSize: 10 }).total).toBe(1);

    appDb.close();
  });

  test("blocks deleting accounts that already own extracted api keys", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "linked@outlook.com", password: "linked-pass" }]);
    const accountId = imported.affectedIds[0];
    appDb.recordApiKey(accountId, "tvly-abcdef1234567890");

    const deleted = appDb.deleteAccounts([accountId]);
    expect(deleted.deleted).toBe(0);
    expect(deleted.blockedIds).toEqual([accountId]);
    expect(appDb.listApiKeys({ page: 1, pageSize: 10 }).total).toBe(1);
    expect(appDb.getAccount(accountId)?.hasApiKey).toBe(true);

    appDb.close();
  });

  test("reassigning a duplicate api key clears the previous owner state", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "first@outlook.com", password: "first-pass" },
      { email: "second@outlook.com", password: "second-pass" },
    ]);
    const [firstId, secondId] = imported.affectedIds;
    appDb.recordApiKey(firstId, "tvly-shared-key");
    appDb.recordApiKey(secondId, "tvly-shared-key");

    const first = appDb.getAccount(firstId);
    const second = appDb.getAccount(secondId);
    const keys = appDb.listApiKeys({ page: 1, pageSize: 10 });

    expect(first).toMatchObject({
      hasApiKey: false,
      apiKeyId: null,
      skipReason: null,
      lastResultStatus: "ready",
    });
    expect(second).toMatchObject({
      hasApiKey: true,
      skipReason: "has_api_key",
    });
    expect(keys.total).toBe(1);
    expect(keys.rows[0]).toMatchObject({
      accountId: secondId,
      microsoftEmail: "second@outlook.com",
    });

    appDb.close();
  });

  test("searches accounts by email, password, and group", async () => {
    const { appDb } = await createTempDb();
    appDb.importAccounts(
      [
        { email: "search-a@outlook.com", password: "alpha-pass" },
        { email: "search-b@outlook.com", password: "bravo-pass" },
      ],
      { groupName: "team-bravo" },
    );
    appDb.importAccounts([{ email: "solo@outlook.com", password: "solo-pass" }], { groupName: "solo-group" });

    expect(appDb.listAccounts({ q: "search-a", page: 1, pageSize: 10 }).rows).toHaveLength(1);
    expect(appDb.listAccounts({ q: "bravo-pass", page: 1, pageSize: 10 }).rows).toHaveLength(1);
    expect(appDb.listAccounts({ q: "team-bravo", page: 1, pageSize: 10 }).rows).toHaveLength(2);

    appDb.close();
  });
});

describe("scheduler helpers", () => {
  test("computes launch capacity and completing state", () => {
    expect(
      computeLaunchCapacity(
        {
          status: "running",
          parallel: 3,
          need: 5,
          successCount: 1,
          maxAttempts: 7,
          launchedCount: 2,
        },
        1,
      ),
    ).toBe(2);
    expect(
      computeLaunchCapacity(
        {
          status: "paused",
          parallel: 3,
          need: 5,
          successCount: 1,
          maxAttempts: 7,
          launchedCount: 2,
        },
        1,
      ),
    ).toBe(0);
    expect(
      shouldEnterCompleting({
        need: 2,
        successCount: 2,
        maxAttempts: 6,
        launchedCount: 2,
      }),
    ).toBe(true);
  });

  test("rejects job starts before proxy subscription is configured", async () => {
    const { appDb, dbPath } = await createTempDb();
    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () => ({
        subscriptionUrl: "",
        groupName: "CODEX_AUTO",
        routeGroupName: "CODEX_ROUTE",
        checkUrl: "https://example.com/trace",
        timeoutMs: 1000,
        maxLatencyMs: 1000,
        apiPort: 39090,
        mixedPort: 49090,
        serverHost: "127.0.0.1",
        serverPort: 3717,
        defaultRunMode: "headed",
        defaultNeed: 1,
        defaultParallel: 1,
        defaultMaxAttempts: 1,
      }),
      () => undefined,
    );

    await expect(
      scheduler.startJob({
        runMode: "headed",
        need: 1,
        parallel: 1,
        maxAttempts: 1,
      }),
    ).rejects.toThrow("configure a Mihomo subscription before starting a job");

    await scheduler.shutdown();
    appDb.close();
  });

  test("rejects control actions for terminal jobs", async () => {
    const { appDb, dbPath } = await createTempDb();
    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () => ({
        subscriptionUrl: "https://example.com/sub.yaml",
        groupName: "CODEX_AUTO",
        routeGroupName: "CODEX_ROUTE",
        checkUrl: "https://example.com/trace",
        timeoutMs: 1000,
        maxLatencyMs: 1000,
        apiPort: 39090,
        mixedPort: 49090,
        serverHost: "127.0.0.1",
        serverPort: 3717,
        defaultRunMode: "headed",
        defaultNeed: 1,
        defaultParallel: 1,
        defaultMaxAttempts: 1,
      }),
      () => undefined,
    );

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    appDb.completeJob(job.id, true);

    expect(() => scheduler.pauseCurrentJob()).toThrow("current job is already completed");
    expect(() => scheduler.resumeCurrentJob()).toThrow("current job is already completed");
    expect(() => scheduler.updateCurrentJobLimits({ parallel: 2 })).toThrow("current job is already completed");

    await scheduler.shutdown();
    appDb.close();
  });

  test("marks attempts failed when launch setup throws before spawn", async () => {
    const { appDb, dbPath } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "broken@outlook.com", password: "broken-pass" }]);
    const accountId = imported.affectedIds[0];
    const events = [];
    const scheduler = new JobScheduler(
      appDb,
      "/dev/null",
      dbPath,
      () => ({
        subscriptionUrl: "https://example.com/sub.yaml",
        groupName: "CODEX_AUTO",
        routeGroupName: "CODEX_ROUTE",
        checkUrl: "https://example.com/trace",
        timeoutMs: 1000,
        maxLatencyMs: 1000,
        apiPort: 39090,
        mixedPort: 49090,
        serverHost: "127.0.0.1",
        serverPort: 3717,
        defaultRunMode: "headed",
        defaultNeed: 1,
        defaultParallel: 1,
        defaultMaxAttempts: 1,
      }),
      (event) => events.push(event),
    );

    const job = await scheduler.startJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });

    for (let attempt = 0; attempt < 20; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      const current = appDb.getJob(job.id);
      if (current?.status === "failed") break;
    }

    const currentJob = appDb.getJob(job.id);
    const attempts = appDb.listAttempts(job.id, false);
    const account = appDb.getAccount(accountId);

    expect(currentJob).toMatchObject({
      status: "failed",
      failureCount: 1,
      lastError: "eligible accounts exhausted or max attempts reached",
    });
    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({
      status: "failed",
      errorCode: "launch_setup_failed",
    });
    expect(account).toMatchObject({
      leaseJobId: null,
      lastResultStatus: "failed",
    });
    expect(events.some((event) => event.type === "attempt.updated")).toBe(true);

    await scheduler.shutdown();
    appDb.close();
  });
});

describe("proxy aggregation", () => {
  test("lists proxy nodes on a fresh database without signup_tasks", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["node-a"], "node-a");

    expect(appDb.listProxyNodes()).toEqual([
      expect.objectContaining({
        nodeName: "node-a",
        isSelected: true,
        success24h: 0,
      }),
    ]);

    appDb.close();
  });

  test("derives 24h success counts from signup_tasks", async () => {
    const { dbPath, appDb } = await createTempDb();
    appDb.importAccounts([{ email: "proxy@outlook.com", password: "proxy-pass" }]);
    const accountId = appDb.listAccounts({ page: 1, pageSize: 10 }).rows[0].id;
    appDb.upsertProxyInventory(["node-a"], "node-a");
    const ledger = await TaskLedger.open({
      enabled: true,
      dbPath,
      busyTimeoutMs: 5000,
      ipRateLimitCooldownMs: 60_000,
      ipRateLimitMax: 64,
      captchaMissingCooldownMs: 60_000,
      captchaMissingMax: 64,
      captchaMissingThreshold: 2,
      invalidCaptchaCooldownMs: 60_000,
      invalidCaptchaMax: 64,
      invalidCaptchaThreshold: 3,
      allowRateLimitedIpFallback: false,
    });

    ledger.upsertTask({
      runId: "run-success",
      jobId: 1,
      accountId,
      batchId: "batch-1",
      mode: "headed",
      attemptIndex: 1,
      modeRetryMax: 1,
      status: "succeeded",
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      proxyNode: "node-a",
      proxyIp: "1.1.1.1",
      apiKey: "tvly-abcdef1234567890",
      apiKeyPrefix: "tvly-abcdef1",
    });

    const nodes = appDb.listProxyNodes();
    expect(nodes[0]?.nodeName).toBe("node-a");
    expect(nodes[0]?.success24h).toBe(1);

    ledger.close();
    appDb.close();
  });

  test("drops stale proxy nodes when subscription inventory changes", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["node-a", "node-b"], "node-a");
    appDb.upsertProxyInventory(["node-b"], "node-b");

    expect(appDb.listProxyNodes()).toEqual([
      expect.objectContaining({
        nodeName: "node-b",
        isSelected: true,
      }),
    ]);

    appDb.close();
  });

  test("clears cached proxy nodes when inventory is disabled", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["node-a", "node-b"], "node-a");
    appDb.upsertProxyInventory([], null);

    expect(appDb.listProxyNodes()).toEqual([]);
    expect(appDb.getSelectedProxyName()).toBeNull();

    appDb.close();
  });
});

describe("static asset path resolution", () => {
  test("rejects path traversal while allowing normal routes", () => {
    expect(resolveStaticAssetPath("/repo/web/dist", "/")).toBe("/repo/web/dist/index.html");
    expect(resolveStaticAssetPath("/repo/web/dist", "/assets/index.js")).toBe("/repo/web/dist/assets/index.js");
    expect(resolveStaticAssetPath("/repo/web/dist", "/../../package.json")).toBeNull();
    expect(resolveStaticAssetPath("/repo/web/dist", "/..%2F..%2F.env.local")).toBeNull();
  });

  test("only falls back to the SPA shell for route-like paths", () => {
    expect(shouldServeSpaFallback("/")).toBe(true);
    expect(shouldServeSpaFallback("/accounts")).toBe(true);
    expect(shouldServeSpaFallback("/jobs/current")).toBe(true);
    expect(shouldServeSpaFallback("/assets/missing.js")).toBe(false);
    expect(shouldServeSpaFallback("/favicon.ico")).toBe(false);
    expect(shouldServeSpaFallback("/api/proxies")).toBe(false);
  });
});

describe("settings updates", () => {
  const currentSettings = {
    subscriptionUrl: "https://example.com/sub.yaml",
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: "https://example.com/trace",
    timeoutMs: 8000,
    maxLatencyMs: 3000,
    apiPort: 39090,
    mixedPort: 49090,
    serverHost: "127.0.0.1",
    serverPort: 3717,
    defaultRunMode: "headed",
    defaultNeed: 1,
    defaultParallel: 1,
    defaultMaxAttempts: 5,
  };

  test("normalizes incoming values before persisting", () => {
    expect(
      buildNextSettings(currentSettings, {
        subscriptionUrl: "  https://next.example/sub.yaml  ",
        groupName: "  WEB_AUTO  ",
        timeoutMs: 500,
      }),
    ).toMatchObject({
      subscriptionUrl: "https://next.example/sub.yaml",
      groupName: "WEB_AUTO",
      timeoutMs: 1000,
    });
  });

  test("persists only after sync succeeds", async () => {
    let persisted = null;

    await expect(
      validateBeforePersist({
        current: currentSettings,
        input: {
          subscriptionUrl: " https://broken.example/sub.yaml ",
        },
        sync: async () => {
          throw new Error("invalid proxy config");
        },
        persist: (settings) => {
          persisted = settings;
        },
      }),
    ).rejects.toThrow("invalid proxy config");

    expect(persisted).toBeNull();
  });
});

describe("api key queries", () => {
  test("supports pagination for api key listings", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts(
      Array.from({ length: 25 }, (_, index) => ({
        email: `key-${index}@outlook.com`,
        password: `pass-${index}`,
      })),
    );

    imported.affectedIds.forEach((accountId, index) => {
      appDb.recordApiKey(accountId, `tvly-key-${index.toString().padStart(4, "0")}`);
    });

    const firstPage = appDb.listApiKeys({ page: 1, pageSize: 20 });
    const secondPage = appDb.listApiKeys({ page: 2, pageSize: 20 });

    expect(firstPage.total).toBe(25);
    expect(firstPage.rows).toHaveLength(20);
    expect(secondPage.rows).toHaveLength(5);

    appDb.close();
  });
});

describe("scheduler runtime spec", () => {
  test("forwards proxy settings, selected node, and isolated mihomo ports to child attempts", () => {
    const runtime = buildAttemptRuntimeSpec({
      job: { id: 8, runMode: "headed" },
      account: {
        id: 21,
        microsoftEmail: "worker@outlook.com",
        passwordPlaintext: "worker-pass",
      },
      outputDir: "/tmp/tavreg/job-8/attempt-21",
      sharedLedgerPath: "/tmp/tavreg/app.sqlite",
      settings: {
        subscriptionUrl: "https://example.com/sub.yaml",
        groupName: "WEB_AUTO",
        routeGroupName: "WEB_ROUTE",
        checkUrl: "https://example.com/trace",
        timeoutMs: 4321,
        maxLatencyMs: 987,
      },
      reservedPorts: {
        apiPort: 40123,
        mixedPort: 40124,
      },
      selectedProxyNode: "Tokyo-01",
      baseEnv: {
        PATH: process.env.PATH,
        EXISTING_EMAIL: "legacy@example.com",
        EXISTING_PASSWORD: "legacy-pass",
        CHROME_REMOTE_DEBUGGING_PORT: "9222",
      },
    });

    expect(runtime.command).toBe(process.execPath);
    expect(runtime.args.slice(-8)).toEqual([
      "--mode",
      "headed",
      "--parallel",
      "1",
      "--need",
      "1",
      "--proxy-node",
      "Tokyo-01",
    ]);
    if (process.versions.bun) {
      expect(runtime.args.slice(0, 2)).toEqual(["run", "src/main.ts"]);
    } else {
      expect(runtime.args.slice(0, 3)).toEqual(["--import", "tsx", "src/main.ts"]);
    }
    expect(runtime.env).toMatchObject({
      MIHOMO_SUBSCRIPTION_URL: "https://example.com/sub.yaml",
      MIHOMO_GROUP_NAME: "WEB_AUTO",
      MIHOMO_ROUTE_GROUP_NAME: "WEB_ROUTE",
      MIHOMO_API_PORT: "40123",
      MIHOMO_MIXED_PORT: "40124",
      PROXY_CHECK_URL: "https://example.com/trace",
      PROXY_CHECK_TIMEOUT_MS: "4321",
      PROXY_LATENCY_MAX_MS: "987",
      MICROSOFT_ACCOUNT_EMAIL: "worker@outlook.com",
      MICROSOFT_ACCOUNT_PASSWORD: "worker-pass",
      TASK_LEDGER_JOB_ID: "8",
      TASK_LEDGER_ACCOUNT_ID: "21",
      TASK_LEDGER_DB_PATH: "/tmp/tavreg/app.sqlite",
      OUTPUT_ROOT_DIR: "/tmp/tavreg/job-8/attempt-21",
      CHROME_PROFILE_DIR: "/tmp/tavreg/job-8/attempt-21/chrome-profile",
      INSPECT_CHROME_PROFILE_DIR: "/tmp/tavreg/job-8/attempt-21/chrome-inspect-profile",
    });
    expect(runtime.env.EXISTING_EMAIL).toBeUndefined();
    expect(runtime.env.EXISTING_PASSWORD).toBeUndefined();
    expect(runtime.env.CHROME_REMOTE_DEBUGGING_PORT).toBeUndefined();
  });
});
