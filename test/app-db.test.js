import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fetchSingleExtractedAccount } from "../src/server/account-extractor.ts";
import { buildNextSettings, validateBeforePersist } from "../src/server/app-settings.ts";
import { JobScheduler, buildAttemptRuntimeSpec, resolveAttemptProxyNode } from "../src/server/scheduler.ts";
import { AppDatabase, computeLaunchCapacity, shouldEnterCompleting } from "../src/storage/app-db.ts";
import { resolveStaticAssetPath, shouldServeSpaFallback } from "../src/server/static-assets.ts";
import { TaskLedger } from "../src/storage/task-ledger.ts";

const tempDirs = [];
const originalFetch = globalThis.fetch;
const originalDateNow = Date.now;

function createSchedulerSettings(overrides = {}) {
  return {
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
    extractorZhanghaoyaKey: "",
    extractorShanyouxiangKey: "",
    defaultAutoExtractSources: [],
    defaultAutoExtractQuantity: 1,
    defaultAutoExtractMaxWaitSec: 60,
    defaultAutoExtractAccountType: "outlook",
    ...overrides,
  };
}

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { dbPath, appDb };
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  Date.now = originalDateNow;
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
    const firstKey = appDb.recordApiKey(firstId, "tvly-shared-key", "1.1.1.1");
    await new Promise((resolve) => setTimeout(resolve, 5));
    appDb.recordApiKey(secondId, "tvly-shared-key", "2.2.2.2");

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
      extractedIp: "2.2.2.2",
    });
    expect(new Date(keys.rows[0].extractedAt).getTime()).toBeGreaterThanOrEqual(new Date(firstKey.extractedAt).getTime());

    appDb.close();
  });

  test("recording the same api key for the same account preserves the original extracted time and ip", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "same@outlook.com", password: "same-pass" }]);
    const accountId = imported.affectedIds[0];
    const firstKey = appDb.recordApiKey(accountId, "tvly-stable-key", "3.3.3.3");
    await new Promise((resolve) => setTimeout(resolve, 5));
    const secondKey = appDb.recordApiKey(accountId, "tvly-stable-key", "4.4.4.4");

    expect(secondKey.accountId).toBe(accountId);
    expect(secondKey.extractedAt).toBe(firstKey.extractedAt);
    expect(secondKey.extractedIp).toBe("3.3.3.3");
    expect(new Date(secondKey.lastVerifiedAt).getTime()).toBeGreaterThanOrEqual(new Date(firstKey.lastVerifiedAt).getTime());

    appDb.close();
  });

  test("recording a legacy api key backfills missing extracted ip for the same account", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "legacy@outlook.com", password: "legacy-pass" }]);
    const accountId = imported.affectedIds[0];
    const firstKey = appDb.recordApiKey(accountId, "tvly-legacy-key");
    appDb.db.query("UPDATE api_keys SET extracted_ip = NULL WHERE id = ?").run(firstKey.id);

    const refreshed = appDb.recordApiKey(accountId, "tvly-legacy-key", "5.5.5.5");

    expect(refreshed.extractedAt).toBe(firstKey.extractedAt);
    expect(refreshed.extractedIp).toBe("5.5.5.5");

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
    const proofAccount = appDb.listAccounts({ q: "search-a", page: 1, pageSize: 10 }).rows[0];
    appDb.updateAccountProofMailbox(proofAccount.id, {
      provider: "moemail",
      address: "search-a-proof@mail-us.707079.xyz",
      mailboxId: "proof-search-a",
    });

    expect(appDb.listAccounts({ q: "search-a", page: 1, pageSize: 10 }).rows).toHaveLength(1);
    expect(appDb.listAccounts({ q: "bravo-pass", page: 1, pageSize: 10 }).rows).toHaveLength(1);
    expect(appDb.listAccounts({ q: "team-bravo", page: 1, pageSize: 10 }).rows).toHaveLength(2);
    expect(appDb.listAccounts({ q: "search-a-proof", page: 1, pageSize: 10 }).rows).toHaveLength(1);

    appDb.close();
  });

  test("returns account summary counts across the full filtered result set, not just one page", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "ready-a@outlook.com", password: "pass-a" },
      { email: "ready-b@outlook.com", password: "pass-b" },
      { email: "failed-c@outlook.com", password: "pass-c" },
    ]);
    appDb.recordApiKey(imported.affectedIds[0], "tvly-summary-0001");

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);
    expect(leased).not.toBeNull();
    const attempt = appDb.createAttempt(job.id, leased.id, "/tmp/tavreg-summary-attempt");
    appDb.completeAttemptFailure(job.id, attempt.id, leased.id, { errorCode: "summary-failed" });

    const firstPage = appDb.listAccounts({ page: 1, pageSize: 1 });

    expect(firstPage.rows).toHaveLength(1);
    expect(firstPage.summary).toEqual({
      ready: 1,
      linked: 1,
      failed: 1,
      disabled: 0,
    });

    appDb.close();
  });

  test("preserves the original imported_at when an existing account is re-imported", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "stable@outlook.com", password: "first-pass" }]);
    const before = appDb.getAccount(imported.affectedIds[0]);

    await new Promise((resolve) => setTimeout(resolve, 5));
    appDb.importAccounts([{ email: "stable@outlook.com", password: "second-pass" }], { groupName: "retry-pool" });

    const after = appDb.getAccount(imported.affectedIds[0]);
    expect(after?.passwordPlaintext).toBe("second-pass");
    expect(after?.groupName).toBe("retry-pool");
    expect(after?.importedAt).toBe(before?.importedAt);
    expect(after?.updatedAt).not.toBe(before?.updatedAt);

    appDb.close();
  });

  test("stores proof mailbox mapping and clears cached mailbox id when the address changes", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proof@outlook.com", password: "proof-pass" }]);
    const accountId = imported.affectedIds[0];

    let account = appDb.updateAccountProofMailbox(accountId, {
      provider: "moemail",
      address: "proof-a@mail-us.707079.xyz",
      mailboxId: "moe-proof-a",
    });
    expect(account).toMatchObject({
      proofMailboxProvider: "moemail",
      proofMailboxAddress: "proof-a@mail-us.707079.xyz",
      proofMailboxId: "moe-proof-a",
    });

    account = appDb.updateAccountProofMailbox(accountId, {
      address: "proof-b@mail-us.707079.xyz",
    });
    expect(account).toMatchObject({
      proofMailboxProvider: "moemail",
      proofMailboxAddress: "proof-b@mail-us.707079.xyz",
      proofMailboxId: null,
    });

    account = appDb.updateAccountProofMailbox(accountId, {
      address: null,
    });
    expect(account).toMatchObject({
      proofMailboxProvider: null,
      proofMailboxAddress: null,
      proofMailboxId: null,
    });

    appDb.close();
  });

  test("stores unavailable reason and keeps disabled status across failure updates", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "disabled@outlook.com", password: "disabled-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.markAccountUnavailable(accountId, "未知辅助邮箱：di*****@genq.top", "microsoft_unknown_recovery_email");
    let account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      lastErrorCode: "microsoft_unknown_recovery_email",
      disabledReason: "未知辅助邮箱：di*****@genq.top",
    });
    expect(account?.disabledAt).toBeTruthy();

    appDb.markAccountDirectFailure(accountId, "network_connection_closed");
    account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      lastErrorCode: "network_connection_closed",
      disabledReason: "未知辅助邮箱：di*****@genq.top",
    });

    appDb.updateAccountAvailability(accountId, { disabled: false, reason: null });
    account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "ready",
      disabledAt: null,
      disabledReason: null,
    });

    appDb.close();
  });

  test("preserves active leases when availability is edited mid-run", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "leased@outlook.com", password: "leased-pass" }]);
    const accountId = imported.affectedIds[0];
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);

    expect(leased?.id).toBe(accountId);

    const disabled = appDb.updateAccountAvailability(accountId, { disabled: true, reason: "manual hold" });
    expect(disabled.leaseJobId).toBe(job.id);

    const reenabled = appDb.updateAccountAvailability(accountId, { disabled: false, reason: null });
    expect(reenabled.leaseJobId).toBe(job.id);

    appDb.close();
  });

  test("can keep the active lease while syncing an in-flight worker failure", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "leased@outlook.com", password: "leased-pass" }]);
    const accountId = imported.affectedIds[0];
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);

    expect(leased?.leaseJobId).toBe(job.id);

    appDb.markAccountDirectFailure(accountId, "network_connection_closed", { releaseLease: false });
    let account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "failed",
      lastErrorCode: "network_connection_closed",
      leaseJobId: job.id,
    });

    appDb.markAccountUnavailable(accountId, "未知辅助邮箱", "microsoft_unknown_recovery_email", {
      releaseLease: false,
    });
    account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      disabledReason: "未知辅助邮箱",
      leaseJobId: job.id,
    });

    appDb.close();
  });

  test("ignores proof mailbox mappings when leasing the next account", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "plain-a@outlook.com", password: "pass-a" },
      { email: "proof-b@outlook.com", password: "pass-b" },
      { email: "plain-c@outlook.com", password: "pass-c" },
    ]);
    appDb.updateAccountProofMailbox(imported.affectedIds[1], {
      provider: "moemail",
      address: "proof-b@mail-us.707079.xyz",
      mailboxId: "proof-b-id",
    });

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);

    expect(leased?.microsoftEmail).toBe("plain-a@outlook.com");

    appDb.close();
  });

  test("fails paused jobs during stale-state recovery", async () => {
    const { dbPath, appDb } = await createTempDb();
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    appDb.updateJobState(job.id, { status: "paused", pausedAt: new Date().toISOString() });
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    expect(reopened.getJob(job.id)).toMatchObject({
      status: "failed",
      lastError: "server_restart",
    });

    reopened.close();
  });

  test("clears stale pinned proxy names when inventory drops them", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["JP1", "US1"], "JP1");
    appDb.setPinnedProxyName("JP1");

    expect(appDb.getPinnedProxyName()).toBe("JP1");

    appDb.upsertProxyInventory(["US1"], "US1");

    expect(appDb.getPinnedProxyName()).toBeNull();

    appDb.close();
  });

  test("stores extractor source fields and local extract history", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts(
      [{ email: "from-extractor@outlook.com", password: "extract-pass" }],
      {
        source: "extractor",
        accountSource: "zhanghaoya",
        rawPayloadByEmail: {
          "from-extractor@outlook.com": "from-extractor@outlook.com:extract-pass",
        },
      },
    );
    const account = appDb.getAccount(imported.affectedIds[0]);

    expect(account).toMatchObject({
      importSource: "extractor",
      accountSource: "zhanghaoya",
      sourceRawPayload: "from-extractor@outlook.com:extract-pass",
    });

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const batch = appDb.createAccountExtractBatch({
      jobId: job.id,
      provider: "zhanghaoya",
      requestedUsableCount: 1,
      attemptBudget: 4,
      acceptedCount: 1,
      status: "accepted",
      rawResponse: "{\"Code\":200,\"Data\":\"from-extractor@outlook.com:extract-pass\"}",
      maskedKey: "zhya********0001",
      completedAt: new Date().toISOString(),
    });
    appDb.createAccountExtractItem({
      batchId: batch.id,
      provider: "zhanghaoya",
      rawPayload: "from-extractor@outlook.com:extract-pass",
      email: "from-extractor@outlook.com",
      password: "extract-pass",
      parseStatus: "parsed",
      acceptStatus: "accepted",
      importedAccountId: account.id,
    });

    const history = appDb.listAccountExtractHistory({ q: "from-extractor@", page: 1, pageSize: 10 });
    expect(history.total).toBe(1);
    expect(history.rows[0]).toMatchObject({
      provider: "zhanghaoya",
      acceptedCount: 1,
      status: "accepted",
    });
    expect(history.rows[0]?.items[0]).toMatchObject({
      email: "from-extractor@outlook.com",
      acceptStatus: "accepted",
      importedAccountId: account.id,
    });

    appDb.close();
  });
});

describe("scheduler helpers", () => {
  test("normalizes extractor upstream responses", async () => {
    globalThis.fetch = async (url) => {
      const href = String(url);
      if (href.includes("zhanghaoya")) {
        return new Response(
          JSON.stringify({
            Code: 200,
            Message: "Success",
            Data: "mail-a@outlook.com:pass-a<br>mail-b@outlook.com:pass-b",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ status: -1, msg: "库存不足！" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const zhanghaoya = await fetchSingleExtractedAccount({
      provider: "zhanghaoya",
      config: {
        zhanghaoyaKey: "zhya-demo-key-001",
        shanyouxiangKey: "",
      },
    });
    expect(zhanghaoya.ok).toBe(true);
    expect(zhanghaoya.candidates[0]).toMatchObject({
      provider: "zhanghaoya",
      email: "mail-a@outlook.com",
      password: "pass-a",
      parseStatus: "parsed",
    });

    const shanyouxiang = await fetchSingleExtractedAccount({
      provider: "shanyouxiang",
      config: {
        zhanghaoyaKey: "",
        shanyouxiangKey: "shan-demo-key-001",
      },
    });
    expect(shanyouxiang.ok).toBe(false);
    expect(shanyouxiang.failureCode).toBe("insufficient_stock");
  });

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
      () => createSchedulerSettings({ subscriptionUrl: "" }),
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
      () => createSchedulerSettings(),
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

  test("rejects auto extract starts when provider keys are missing", async () => {
    const { appDb, dbPath } = await createTempDb();
    const scheduler = new JobScheduler(appDb, process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

    await expect(
      scheduler.startJob({
        runMode: "headed",
        need: 1,
        parallel: 1,
        maxAttempts: 1,
        autoExtractSources: ["zhanghaoya"],
        autoExtractQuantity: 1,
        autoExtractMaxWaitSec: 30,
        autoExtractAccountType: "outlook",
      }),
    ).rejects.toThrow("extractor key missing");

    await scheduler.shutdown();
    appDb.close();
  });

  test("caps auto extracted usable accounts to the current job need", async () => {
    const { appDb, dbPath } = await createTempDb();
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          Code: 200,
          Message: "Success",
          Data: "cap-a@outlook.com:pass-a<br>cap-b@outlook.com:pass-b",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );

    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
      () => undefined,
    );
    const job = appDb.createJob({
      runMode: "headed",
      need: 1,
      parallel: 1,
      maxAttempts: 3,
      autoExtractSources: ["zhanghaoya"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 30,
      autoExtractAccountType: "outlook",
    });
    scheduler["syncAutoExtractState"](job);

    const decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(appDb.countEligibleAccounts(job.id)).toBe(1);

    const accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts.map((account) => account.microsoftEmail)).toEqual(["cap-a@outlook.com"]);

    const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(history.rows[0]).toMatchObject({
      status: "accepted",
      acceptedCount: 1,
    });
    expect(history.rows[0]?.items).toHaveLength(2);
    expect(history.rows[0]?.items[1]).toMatchObject({
      email: "cap-b@outlook.com",
      acceptStatus: "rejected",
      rejectReason: "request_returned_multiple_accounts",
    });

    await scheduler.shutdown();
    appDb.close();
  });

  test("dispatches auto extract requests every 500ms per provider with up to 4 concurrent in flight", async () => {
    const { appDb, dbPath } = await createTempDb();
    let fakeNow = 0;
    Date.now = () => fakeNow;

    const pending = [];
    globalThis.fetch = () =>
      new Promise((resolve) => {
        pending.push(resolve);
      });

    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () =>
        createSchedulerSettings({
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "shan-demo-key-001",
        }),
      () => undefined,
    );
    const job = appDb.createJob({
      runMode: "headed",
      need: 6,
      parallel: 1,
      maxAttempts: 12,
      autoExtractSources: ["zhanghaoya", "shanyouxiang"],
      autoExtractQuantity: 6,
      autoExtractMaxWaitSec: 30,
      autoExtractAccountType: "outlook",
    });
    scheduler["syncAutoExtractState"](job);

    let decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 2,
      inFlightCount: 2,
      attemptBudget: 9,
    });

    decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 2,
      inFlightCount: 2,
    });

    fakeNow = 499;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 2,
      inFlightCount: 2,
    });

    fakeNow = 500;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 4,
      inFlightCount: 4,
    });

    fakeNow = 1000;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 4,
      inFlightCount: 4,
    });
    expect(pending).toHaveLength(4);

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
  test("inherits account groups for api key listings and follows later group updates", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts(
      [
        { email: "grouped-a@outlook.com", password: "pass-a" },
        { email: "grouped-b@outlook.com", password: "pass-b" },
      ],
      { groupName: "team-alpha" },
    );
    appDb.updateAccountsGroup([imported.affectedIds[1]], "team-bravo");

    appDb.recordApiKey(imported.affectedIds[0], "tvly-group-alpha", "10.10.10.10");
    appDb.recordApiKey(imported.affectedIds[1], "tvly-group-bravo", "20.20.20.20");

    const alphaKeys = appDb.listApiKeys({ groupName: "team-alpha", page: 1, pageSize: 10 });
    const bravoKeys = appDb.listApiKeys({ q: "team-bravo", page: 1, pageSize: 10 });

    expect(alphaKeys.rows).toHaveLength(1);
    expect(alphaKeys.rows[0]).toMatchObject({
      microsoftEmail: "grouped-a@outlook.com",
      groupName: "team-alpha",
    });
    expect(bravoKeys.rows).toHaveLength(1);
    expect(bravoKeys.rows[0]).toMatchObject({
      microsoftEmail: "grouped-b@outlook.com",
      groupName: "team-bravo",
    });

    appDb.updateAccountsGroup([imported.affectedIds[0]], "team-charlie");

    const refreshed = appDb.listApiKeys({ groupName: "team-charlie", page: 1, pageSize: 10 });
    expect(refreshed.rows).toHaveLength(1);
    expect(refreshed.rows[0]).toMatchObject({
      microsoftEmail: "grouped-a@outlook.com",
      groupName: "team-charlie",
    });

    appDb.close();
  });

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
    expect(firstPage.summary).toEqual({
      active: 25,
      revoked: 0,
    });

    appDb.close();
  });

  test("returns api key summary counts across the full filtered result set, not just one page", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "active-a@outlook.com", password: "pass-a" },
      { email: "active-b@outlook.com", password: "pass-b" },
      { email: "revoked-c@outlook.com", password: "pass-c" },
    ]);

    const [activeA, activeB, revokedC] = imported.affectedIds;
    appDb.recordApiKey(activeA, "tvly-summary-active-1");
    appDb.recordApiKey(activeB, "tvly-summary-active-2");
    const revoked = appDb.recordApiKey(revokedC, "tvly-summary-revoked-3");
    appDb.db
      .query("UPDATE api_keys SET status = 'revoked' WHERE id = ?")
      .run(revoked.id);

    const paged = appDb.listApiKeys({ page: 2, pageSize: 1 });

    expect(paged.rows).toHaveLength(1);
    expect(paged.summary).toEqual({
      active: 2,
      revoked: 1,
    });

    appDb.close();
  });

  test("returns selected api keys for export in request order", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "export-a@outlook.com", password: "pass-a" },
      { email: "export-b@outlook.com", password: "pass-b" },
      { email: "export-c@outlook.com", password: "pass-c" },
    ]);

    const keyA = appDb.recordApiKey(imported.affectedIds[0], "tvly-export-a", "11.11.11.11");
    const keyB = appDb.recordApiKey(imported.affectedIds[1], "tvly-export-b", null);
    const keyC = appDb.recordApiKey(imported.affectedIds[2], "tvly-export-c", "33.33.33.33");
    const exported = appDb.listApiKeysForExport([keyC.id, keyA.id, keyB.id]);

    expect(exported.map((row) => row.id)).toEqual([keyC.id, keyA.id, keyB.id]);
    expect(exported.map((row) => row.extractedIp)).toEqual(["33.33.33.33", "11.11.11.11", null]);

    appDb.close();
  });

  test("chunks large export selections to avoid SQLite bind limits", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts(
      Array.from({ length: 520 }, (_, index) => ({
        email: `bulk-export-${index}@outlook.com`,
        password: `pass-${index}`,
      })),
    );

    const keys = imported.affectedIds.map((accountId, index) => appDb.recordApiKey(accountId, `tvly-bulk-${index}`, `10.0.0.${index % 255}`));
    const selected = keys.slice().reverse().map((row) => row.id);
    const exported = appDb.listApiKeysForExport(selected);

    expect(exported).toHaveLength(520);
    expect(exported[0]?.id).toBe(selected[0]);
    expect(exported.at(-1)?.id).toBe(selected.at(-1));

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
        proofMailboxProvider: "moemail",
        proofMailboxAddress: "worker-proof@mail-us.707079.xyz",
        proofMailboxId: "worker-proof-001",
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

    const explicitNodeBinary = process.env.NODE_BINARY?.trim();
    expect(runtime.command).toBe(process.versions.bun && !explicitNodeBinary ? process.execPath : explicitNodeBinary || process.execPath);
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
    expect(runtime.args.slice(0, 3)).toEqual(process.versions.bun && !explicitNodeBinary ? ["run", "src/main.ts", "--mode"] : ["--import", "tsx", "src/main.ts"]);
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
      MICROSOFT_PROOF_MAILBOX_PROVIDER: "moemail",
      MICROSOFT_PROOF_MAILBOX_ADDRESS: "worker-proof@mail-us.707079.xyz",
      MICROSOFT_PROOF_MAILBOX_ID: "worker-proof-001",
      TASK_LEDGER_JOB_ID: "8",
      TASK_LEDGER_ACCOUNT_ID: "21",
      TASK_LEDGER_DB_PATH: "/tmp/tavreg/app.sqlite",
      OUTPUT_ROOT_DIR: "/tmp/tavreg/job-8/attempt-21",
      CHROME_PROFILE_DIR: "/tmp/tavreg/job-8/attempt-21/chrome-profile",
      INSPECT_CHROME_PROFILE_DIR: "/tmp/tavreg/job-8/attempt-21/chrome-inspect-profile",
    });
    expect(runtime.env.EXISTING_EMAIL).toBeUndefined();
    expect(runtime.env.EXISTING_PASSWORD).toBeUndefined();
    expect(runtime.env.MICROSOFT_PROOF_MAILBOX_PROVIDER).toBe("moemail");
    expect(runtime.env.MICROSOFT_PROOF_MAILBOX_ADDRESS).toBe("worker-proof@mail-us.707079.xyz");
    expect(runtime.env.MICROSOFT_PROOF_MAILBOX_ID).toBe("worker-proof-001");
    expect(runtime.env.CHROME_REMOTE_DEBUGGING_PORT).toBeUndefined();
  });

  test("only forwards pinned proxy nodes that still exist in inventory", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["Tokyo-01", "Tokyo-02"], "Tokyo-02");

    expect(resolveAttemptProxyNode(appDb)).toBe("Tokyo-02");

    appDb.setPinnedProxyName("Tokyo-01");
    expect(resolveAttemptProxyNode(appDb)).toBe("Tokyo-01");

    appDb.upsertProxyInventory(["Tokyo-02"], "Tokyo-02");
    expect(resolveAttemptProxyNode(appDb)).toBe("Tokyo-02");

    appDb.close();
  });

  test("falls back to the selected proxy node when no pinned override exists", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["Tokyo-01", "Tokyo-02"], "Tokyo-02");

    expect(resolveAttemptProxyNode(appDb)).toBe("Tokyo-02");

    appDb.close();
  });
});
