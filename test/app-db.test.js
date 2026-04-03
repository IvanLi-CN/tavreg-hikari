import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fetchSingleExtractedAccount } from "../src/server/account-extractor.ts";
import { buildNextSettings, validateBeforePersist } from "../src/server/app-settings.ts";
import {
  JobScheduler,
  PENDING_BROWSER_SESSION_WAIT_MS,
  buildAttemptRuntimeSpec,
  buildAttemptSpawnOptions,
  pickWorkerRuntime,
  resolvePendingBrowserSessionWait,
  resolveAttemptProxyNode,
  resolveReusableAttemptProxyNode,
  resolveWorkerRuntime,
} from "../src/server/scheduler.ts";
import { AppDatabase, computeLaunchCapacity, shouldEnterCompleting } from "../src/storage/app-db.ts";
import { resolveStaticAssetPath, shouldServeSpaFallback } from "../src/server/static-assets.ts";
import { TaskLedger } from "../src/storage/task-ledger.ts";

const tempDirs = [];
const originalFetch = globalThis.fetch;
const originalDateNow = Date.now;
const originalSetTimeout = globalThis.setTimeout;

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
    extractorShankeyunKey: "",
    extractorHotmail666Key: "",
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

function markBrowserSessionReady(appDb, accountId, overrides = {}) {
  return appDb.markBrowserSessionReady(accountId, {
    browserEngine: "chrome",
    proxyNode: "Tokyo-01",
    proxyIp: "1.1.1.1",
    proxyCountry: "JP",
    proxyRegion: "Tokyo",
    proxyCity: "Tokyo",
    proxyTimezone: "Asia/Tokyo",
    ...overrides,
  });
}

function markImportedAccountsReady(appDb, accountIds, overrides) {
  accountIds.forEach((accountId, index) => {
    const nextOverrides = typeof overrides === "function" ? overrides(accountId, index) : overrides;
    markBrowserSessionReady(appDb, accountId, nextOverrides);
  });
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  Date.now = originalDateNow;
  globalThis.setTimeout = originalSetTimeout;
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

  test("listAccounts summary only counts browser-ready accounts as ready", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "ready-count-a@outlook.com", password: "pass-a" },
      { email: "ready-count-b@outlook.com", password: "pass-b" },
    ]);

    appDb.markBrowserSessionReady(imported.affectedIds[0], {
      browserEngine: "chrome",
      proxyNode: "Tokyo-01",
    });

    const accounts = appDb.listAccounts({ page: 1, pageSize: 10 });
    expect(accounts.total).toBe(2);
    expect(accounts.summary.ready).toBe(1);

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
      provider: "cfmail",
      address: "search-a-proof@mail-us.707079.xyz",
      mailboxId: "proof-search-a",
    });

    expect(appDb.listAccounts({ q: "search-a", page: 1, pageSize: 10 }).rows).toHaveLength(1);
    expect(appDb.listAccounts({ q: "bravo-pass", page: 1, pageSize: 10 }).rows).toHaveLength(1);
    expect(appDb.listAccounts({ q: "team-bravo", page: 1, pageSize: 10 }).rows).toHaveLength(2);
    expect(appDb.listAccounts({ q: "search-a-proof", page: 1, pageSize: 10 }).rows).toHaveLength(1);

    appDb.close();
  });

  test("keeps newly imported accounts pending until browser bootstrap succeeds", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "pending-session@outlook.com", password: "pending-pass" }]);
    const accountId = imported.affectedIds[0];
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });

    expect(appDb.getAccount(accountId)?.browserSession).toMatchObject({
      status: "pending",
      profilePath: expect.stringContaining(`/accounts/${accountId}/chrome`),
    });
    expect(appDb.countEligibleAccounts(job.id)).toBe(0);
    expect(appDb.leaseNextAccount(job.id)).toBeNull();

    markBrowserSessionReady(appDb, accountId, { proxyIp: "7.7.7.7" });

    expect(appDb.countEligibleAccounts(job.id)).toBe(1);
    expect(appDb.leaseNextAccount(job.id)?.id).toBe(accountId);

    appDb.close();
  });

  test("preserves existing ready browser sessions across restart", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "restart-ready@outlook.com", password: "restart-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId, { proxyIp: "9.9.9.9" });
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    expect(reopened.getAccount(accountId)?.browserSession).toMatchObject({
      status: "ready",
      proxyIp: "9.9.9.9",
    });

    reopened.close();
  });

  test("reopen seeds missing browser sessions as pending for untouched legacy imports", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "legacy-usable@outlook.com", password: "legacy-pass" }]);
    const accountId = imported.affectedIds[0];
    const profilePath = appDb.accountBrowserProfilePath(accountId);

    await rm(profilePath, { recursive: true, force: true });
    appDb.db.exec("DROP TABLE account_browser_sessions;");
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    const job = reopened.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(reopened.getAccount(accountId)?.browserSession).toMatchObject({
      status: "pending",
      profilePath: expect.stringContaining(`/accounts/${accountId}/chrome`),
    });
    expect(reopened.countEligibleAccounts(job.id)).toBe(0);

    reopened.close();
  });

  test("reopen keeps legacy accounts ready only when a reusable browser profile already exists", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "legacy-used@outlook.com", password: "legacy-pass" }]);
    const accountId = imported.affectedIds[0];
    const profilePath = appDb.accountBrowserProfilePath(accountId);

    await mkdir(path.join(profilePath, "Default"), { recursive: true });
    await writeFile(path.join(profilePath, "Local State"), "{}");
    await writeFile(path.join(profilePath, "Default", "Preferences"), "{}");
    appDb.db.query("UPDATE microsoft_accounts SET last_used_at = ?, last_result_status = 'ready' WHERE id = ?").run("2026-04-03T01:23:45.000Z", accountId);
    appDb.db.exec("DROP TABLE account_browser_sessions;");
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    const job = reopened.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(reopened.getAccount(accountId)?.browserSession).toMatchObject({
      status: "ready",
      profilePath: expect.stringContaining(`/accounts/${accountId}/chrome`),
    });
    expect(reopened.countEligibleAccounts(job.id)).toBe(1);

    reopened.close();
  });

  test("reopen keeps attempted legacy accounts pending when no reusable browser profile exists", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "legacy-attempted@outlook.com", password: "legacy-pass" }]);
    const accountId = imported.affectedIds[0];
    const profilePath = appDb.accountBrowserProfilePath(accountId);

    await rm(profilePath, { recursive: true, force: true });
    appDb.db.query("UPDATE microsoft_accounts SET last_used_at = ?, last_result_status = 'running' WHERE id = ?").run("2026-04-03T01:23:45.000Z", accountId);
    appDb.db.exec("DROP TABLE account_browser_sessions;");
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    const job = reopened.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(reopened.getAccount(accountId)?.browserSession).toMatchObject({
      status: "pending",
      profilePath: expect.stringContaining(`/accounts/${accountId}/chrome`),
    });
    expect(reopened.countEligibleAccounts(job.id)).toBe(0);

    reopened.close();
  });

  test("returns account summary counts across the full filtered result set, not just one page", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "ready-a@outlook.com", password: "pass-a" },
      { email: "ready-b@outlook.com", password: "pass-b" },
      { email: "failed-c@outlook.com", password: "pass-c" },
    ]);
    markImportedAccountsReady(appDb, imported.affectedIds);
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

  test("supports importedAt sorting across the full filtered result set", async () => {
    const { appDb } = await createTempDb();
    appDb.importAccounts([{ email: "first@outlook.com", password: "pass-a" }]);
    await new Promise((resolve) => setTimeout(resolve, 5));
    appDb.importAccounts([{ email: "second@outlook.com", password: "pass-b" }]);
    await new Promise((resolve) => setTimeout(resolve, 5));
    appDb.importAccounts([{ email: "third@outlook.com", password: "pass-c" }]);

    expect(
      appDb.listAccounts({ page: 1, pageSize: 10, sortBy: "importedAt", sortDir: "desc" }).rows.map((account) => account.microsoftEmail),
    ).toEqual(["third@outlook.com", "second@outlook.com", "first@outlook.com"]);
    expect(
      appDb.listAccounts({ page: 1, pageSize: 10, sortBy: "importedAt", sortDir: "asc" }).rows.map((account) => account.microsoftEmail),
    ).toEqual(["first@outlook.com", "second@outlook.com", "third@outlook.com"]);

    appDb.close();
  });

  test("supports lastUsedAt sorting with nulls last in desc and first in asc", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "never-used@outlook.com", password: "pass-a" },
      { email: "older-used@outlook.com", password: "pass-b" },
      { email: "recent-used@outlook.com", password: "pass-c" },
    ]);

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 3 });
    const olderAccountId = imported.affectedIds[1];
    const recentAccountId = imported.affectedIds[2];
    const olderAttempt = appDb.createAttempt(job.id, olderAccountId, "/tmp/tavreg-sort-older");
    appDb.completeAttemptFailure(job.id, olderAttempt.id, olderAccountId, { errorCode: "older-sort-check" });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const recentAttempt = appDb.createAttempt(job.id, recentAccountId, "/tmp/tavreg-sort-recent");
    appDb.completeAttemptFailure(job.id, recentAttempt.id, recentAccountId, { errorCode: "recent-sort-check" });

    expect(
      appDb.listAccounts({ page: 1, pageSize: 10, sortBy: "lastUsedAt", sortDir: "desc" }).rows.map((account) => account.microsoftEmail),
    ).toEqual(["recent-used@outlook.com", "older-used@outlook.com", "never-used@outlook.com"]);
    expect(
      appDb.listAccounts({ page: 1, pageSize: 10, sortBy: "lastUsedAt", sortDir: "asc" }).rows.map((account) => account.microsoftEmail),
    ).toEqual(["never-used@outlook.com", "older-used@outlook.com", "recent-used@outlook.com"]);

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
      provider: "cfmail",
      address: "proof-a@mail-us.707079.xyz",
      mailboxId: "moe-proof-a",
    });
    expect(account).toMatchObject({
      proofMailboxProvider: "cfmail",
      proofMailboxAddress: "proof-a@mail-us.707079.xyz",
      proofMailboxId: "moe-proof-a",
    });

    account = appDb.updateAccountProofMailbox(accountId, {
      address: "proof-b@mail-us.707079.xyz",
    });
    expect(account).toMatchObject({
      proofMailboxProvider: "cfmail",
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

    appDb.markAccountUnavailable(accountId, "manual hold", "microsoft_unknown_recovery_email");
    let account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      lastErrorCode: "microsoft_unknown_recovery_email",
      disabledReason: "manual hold",
      skipReason: null,
    });
    expect(account?.disabledAt).toBeTruthy();

    appDb.markAccountDirectFailure(accountId, "network_connection_closed");
    account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      lastErrorCode: "network_connection_closed",
      disabledReason: "manual hold",
      skipReason: null,
    });

    appDb.updateAccountAvailability(accountId, { disabled: false, reason: null });
    account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "ready",
      disabledAt: null,
      disabledReason: null,
      skipReason: null,
    });

    appDb.close();
  });

  test("preserves active leases when availability is edited mid-run", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "leased@outlook.com", password: "leased-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
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
    markBrowserSessionReady(appDb, accountId);
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
      skipReason: null,
      leaseJobId: job.id,
    });

    appDb.close();
  });

  test("marks hard microsoft failures as reusable blockers instead of disabled accounts", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "blocked@outlook.com", password: "blocked-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.markAccountDirectFailure(accountId, "microsoft_account_locked");
    const account = appDb.getAccount(accountId);

    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      lastErrorCode: "microsoft_account_locked",
      skipReason: "microsoft_account_locked",
      disabledAt: null,
      disabledReason: null,
    });

    appDb.close();
  });

  test("marks locked accounts unavailable with an explicit disabled reason", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "locked-ui@outlook.com", password: "locked-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.markAccountLocked(accountId, "Microsoft 账户已锁定", "microsoft_account_locked");
    const account = appDb.getAccount(accountId);

    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      lastErrorCode: "microsoft_account_locked",
      skipReason: "microsoft_account_locked",
      disabledReason: "Microsoft 账户已锁定",
    });
    expect(account?.disabledAt).toBeTruthy();

    appDb.close();
  });

  test("can hide unconnected mailboxes from the inbox workspace listing", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "connected-mail@outlook.com", password: "connected-pass" },
      { email: "pending-mail@outlook.com", password: "pending-pass" },
    ]);
    const connectedAccountId = imported.affectedIds[0];
    const pendingAccountId = imported.affectedIds[1];
    const connectedMailbox = appDb.ensureMailboxForAccount(connectedAccountId);
    appDb.ensureMailboxForAccount(pendingAccountId);

    appDb.completeMailboxOAuth(connectedMailbox.id, {
      refreshToken: "refresh-token",
      accessToken: "access-token",
      accessTokenExpiresAt: "2026-03-30T08:00:00.000Z",
      authority: "common",
      graphDisplayName: "Connected",
    });

    expect(appDb.listMailboxes().map((row) => row.accountId).sort((a, b) => a - b)).toEqual(
      [connectedAccountId, pendingAccountId].sort((a, b) => a - b),
    );
    expect(appDb.listMailboxes({ connectedOnly: true }).map((row) => row.accountId)).toEqual([connectedAccountId]);

    appDb.close();
  });

  test("saveMailboxOauthStart clears stale authorization before a forced reconnect", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "oauth-reconnect@outlook.com", password: "oauth-pass" }]);
    const accountId = imported.affectedIds[0];
    const mailbox = appDb.ensureMailboxForAccount(accountId);

    appDb.completeMailboxOAuth(mailbox.id, {
      refreshToken: "refresh-token",
      accessToken: "access-token",
      accessTokenExpiresAt: "2026-03-30T08:00:00.000Z",
      authority: "common",
      graphDisplayName: "Reconnect",
    });

    const restarted = appDb.saveMailboxOauthStart(mailbox.id, {
      oauthState: "state-reconnect",
      oauthCodeVerifier: "verifier-reconnect",
      authority: "organizations",
    });

    expect(restarted).toMatchObject({
      status: "preparing",
      refreshToken: null,
      accessToken: null,
      oauthConnectedAt: null,
      oauthState: "state-reconnect",
      oauthCodeVerifier: "verifier-reconnect",
      authority: "organizations",
    });

    appDb.close();
  });

  test("clears the unknown recovery block after a proof mailbox is saved", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proof-blocked@outlook.com", password: "proof-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.markAccountDirectFailure(accountId, "microsoft_unknown_recovery_email:pr*****@mail.test");
    let account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      skipReason: "microsoft_unknown_recovery_email",
      lastErrorCode: "microsoft_unknown_recovery_email:pr*****@mail.test",
    });

    account = appDb.updateAccountProofMailbox(accountId, {
      provider: "cfmail",
      address: "proof@mail.test",
      mailboxId: "proof-box-001",
    });
    expect(account).toMatchObject({
      proofMailboxAddress: "proof@mail.test",
      proofMailboxId: "proof-box-001",
      lastResultStatus: "ready",
      skipReason: null,
      lastErrorCode: null,
    });

    appDb.close();
  });

  test("clears the password block only when a new password is imported", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "pw-blocked@outlook.com", password: "old-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.markAccountDirectFailure(accountId, "microsoft_password_incorrect");
    appDb.importAccounts([{ email: "pw-blocked@outlook.com", password: "old-pass" }]);
    let account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      lastResultStatus: "disabled",
      skipReason: "microsoft_password_incorrect",
      lastErrorCode: "microsoft_password_incorrect",
    });

    appDb.importAccounts([{ email: "pw-blocked@outlook.com", password: "new-pass" }]);
    account = appDb.getAccount(accountId);
    expect(account).toMatchObject({
      passwordPlaintext: "new-pass",
      lastResultStatus: "ready",
      skipReason: null,
      lastErrorCode: null,
    });

    appDb.close();
  });

  test("reuses transient failed accounts in the same job and in a new job", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "retryable@outlook.com", password: "retry-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
    const firstJob = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 3 });
    const leased = appDb.leaseNextAccount(firstJob.id);
    const attempt = appDb.createAttempt(firstJob.id, accountId, path.join(process.cwd(), "retryable-attempt"));

    expect(leased?.id).toBe(accountId);
    appDb.completeAttemptFailure(firstJob.id, attempt.id, accountId, { errorCode: "network_connection_closed" });
    expect(appDb.isAccountSchedulableForJob(firstJob.id, accountId)).toBe(true);
    expect(appDb.countEligibleAccounts(firstJob.id)).toBe(1);
    expect(appDb.leaseNextAccount(firstJob.id)?.id).toBe(accountId);
    const retryAttempt = appDb.createAttempt(firstJob.id, accountId, path.join(process.cwd(), "retryable-attempt-2"));
    appDb.completeAttemptFailure(firstJob.id, retryAttempt.id, accountId, { errorCode: "browser_proxy_ip_mismatch" });
    appDb.completeJob(firstJob.id, false, "transient failure exhausted the first job");

    const secondJob = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(appDb.countEligibleAccounts(secondJob.id)).toBe(1);
    expect(appDb.leaseNextAccount(secondJob.id)?.id).toBe(accountId);

    appDb.close();
  });

  test("keeps hard-blocked failed accounts out of future jobs until restored", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "hard-blocked@outlook.com", password: "hard-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
    const firstJob = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(firstJob.id);
    const attempt = appDb.createAttempt(firstJob.id, accountId, path.join(process.cwd(), "hard-blocked-attempt"));

    expect(leased?.id).toBe(accountId);
    appDb.completeAttemptFailure(firstJob.id, attempt.id, accountId, { errorCode: "microsoft_account_locked" });
    expect(appDb.isAccountSchedulableForJob(firstJob.id, accountId)).toBe(false);
    expect(appDb.countEligibleAccounts(firstJob.id)).toBe(0);
    appDb.completeJob(firstJob.id, false, "locked account exhausted the first job");

    const secondJob = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(appDb.countEligibleAccounts(secondJob.id)).toBe(0);

    appDb.updateAccountAvailability(accountId, { disabled: false, reason: null });
    expect(appDb.countEligibleAccounts(secondJob.id)).toBe(1);

    appDb.close();
  });

  test("startup bootstrap recovery skips accounts that are already hard-blocked", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "pending-hard-blocked@outlook.com", password: "hard-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);
    const attempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "pending-hard-blocked-attempt"));

    expect(leased?.id).toBe(accountId);
    appDb.completeAttemptFailure(job.id, attempt.id, accountId, { errorCode: "microsoft_password_incorrect" });
    expect(appDb.getAccount(accountId)?.skipReason).toBe("microsoft_password_incorrect");

    appDb.queueBrowserSessionBootstrap(accountId);

    expect(appDb.getAccount(accountId)?.browserSession?.status).toBe("pending");
    expect(appDb.listPendingBrowserSessionAccountIds()).not.toContain(accountId);

    appDb.close();
  });

  test("hard-failed accounts do not re-enter pending-session waits in the same job", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proof-same-job@outlook.com", password: "proof-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);
    const attempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "proof-same-job-attempt"));

    expect(leased?.id).toBe(accountId);
    appDb.completeAttemptFailure(job.id, attempt.id, accountId, {
      errorCode: "microsoft_unknown_recovery_email:pr*****@mail.test",
    });
    appDb.updateAccountProofMailbox(accountId, {
      provider: "cfmail",
      address: "proof-same-job@mail.test",
      mailboxId: "proof-same-job",
    });
    appDb.queueBrowserSessionBootstrap(accountId);

    expect(appDb.getAccount(accountId)).toMatchObject({
      skipReason: null,
      browserSession: { status: "pending" },
    });
    expect(appDb.isAccountSchedulableForJob(job.id, accountId)).toBe(false);
    expect(appDb.countEligibleAccounts(job.id)).toBe(0);
    expect(appDb.countPendingBrowserSessions(job.id)).toBe(0);

    appDb.close();
  });

  test("does not reschedule succeeded accounts within the same job", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "same-job-success@outlook.com", password: "success-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 3 });
    const leased = appDb.leaseNextAccount(job.id);
    const attempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "same-job-success-attempt"));

    expect(leased?.id).toBe(accountId);
    appDb.completeAttemptSuccess(job.id, attempt.id, accountId, "tvly-same-job-success");

    expect(appDb.isAccountSchedulableForJob(job.id, accountId)).toBe(false);
    expect(appDb.countEligibleAccounts(job.id)).toBe(0);
    expect(appDb.leaseNextAccount(job.id)).toBeNull();

    appDb.close();
  });

  test("normalizes legacy hard-blocked failed accounts to disabled on reopen", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "legacy-locked@outlook.com", password: "legacy-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.db
      .query(`
        UPDATE microsoft_accounts
        SET last_result_status = 'failed',
            skip_reason = 'microsoft_account_locked',
            last_error_code = 'microsoft_account_locked'
        WHERE id = ?
      `)
      .run(accountId);
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    expect(reopened.getAccount(accountId)).toMatchObject({
      lastResultStatus: "disabled",
      skipReason: "microsoft_account_locked",
      disabledAt: null,
      disabledReason: null,
    });

    reopened.close();
  });

  test("migrates legacy locked accounts out of manual disabled fields on reopen", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "legacy-disabled@outlook.com", password: "legacy-pass" }]);
    const accountId = imported.affectedIds[0];

    appDb.db
      .query(`
        UPDATE microsoft_accounts
        SET disabled_at = '2026-03-27T11:11:11.000Z',
            disabled_reason = '微软账户已锁定',
            skip_reason = NULL,
            last_result_status = 'disabled',
            last_error_code = NULL
        WHERE id = ?
      `)
      .run(accountId);
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    expect(reopened.getAccount(accountId)).toMatchObject({
      lastResultStatus: "disabled",
      skipReason: "microsoft_account_locked",
      disabledAt: null,
      disabledReason: null,
      lastErrorCode: "microsoft_account_locked",
    });

    reopened.close();
  });

  test("proof mailbox mappings do not make an account ineligible for leasing", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([
      { email: "plain-a@outlook.com", password: "pass-a" },
      { email: "proof-b@outlook.com", password: "pass-b" },
      { email: "plain-c@outlook.com", password: "pass-c" },
    ]);
    markImportedAccountsReady(appDb, imported.affectedIds);
    const proofAccountId = appDb.listAccounts({ page: 1, pageSize: 10 }).rows.find(
      (row) => row.microsoftEmail === "proof-b@outlook.com",
    )?.id;
    expect(proofAccountId).toBeDefined();
    appDb.updateAccountProofMailbox(proofAccountId, {
      provider: "cfmail",
      address: "proof-b@mail-us.707079.xyz",
      mailboxId: "proof-b-id",
    });
    for (const accountId of imported.affectedIds.filter((accountId) => accountId !== proofAccountId)) {
      appDb.recordApiKey(accountId, `tvly-proof-skip-${accountId}`);
    }

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const leased = appDb.leaseNextAccount(job.id);

    expect(leased?.microsoftEmail).toBe("proof-b@outlook.com");

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

  test("preserves manual-stop jobs and attempts across stale-state recovery", async () => {
    const { dbPath, appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "recover-stop@outlook.com", password: "pass-a" }]);
    const accountId = imported.affectedIds[0];
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const attempt = appDb.createAttempt(job.id, accountId, "/tmp/tavreg-recover-stop-attempt");
    appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });
    appDb.close();

    const reopened = await AppDatabase.open(dbPath);
    expect(reopened.getJob(job.id)).toMatchObject({
      status: "stopped",
      lastError: null,
    });
    expect(reopened.getAttempt(attempt.id)).toMatchObject({
      status: "stopped",
      stage: "stopped",
      errorCode: "force_stopped",
      errorMessage: "stopped by user",
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

    const secondBatch = appDb.createAccountExtractBatch({
      jobId: job.id,
      provider: "shankeyun",
      requestedUsableCount: 1,
      attemptBudget: 4,
      acceptedCount: 0,
      status: "insufficient_stock",
      errorMessage: "剩余次数不足",
      rawResponse: "{\"status\":0,\"msg\":\"剩余次数不足\"}",
      maskedKey: "shan********0002",
      completedAt: new Date().toISOString(),
    });
    appDb.createAccountExtractItem({
      batchId: secondBatch.id,
      provider: "shankeyun",
      rawPayload: "fresh-sk@outlook.com----pass-999--------refresh-token----client-id",
      email: "fresh-sk@outlook.com",
      password: "pass-999",
      parseStatus: "parsed",
      acceptStatus: "rejected",
      rejectReason: "already_attempted",
      importedAccountId: account.id,
    });

    const filtered = appDb.listAccountExtractHistory({ provider: "shankeyun", page: 1, pageSize: 10 });
    expect(filtered.total).toBe(1);
    expect(filtered.rows[0]).toMatchObject({
      provider: "shankeyun",
      status: "insufficient_stock",
    });

    appDb.close();
  });
});

describe("scheduler helpers", () => {
  test("pending browser session wait defaults to a multi-minute bootstrap window", () => {
    expect(PENDING_BROWSER_SESSION_WAIT_MS).toBeGreaterThanOrEqual(5 * 60_000);
  });

  test("pending browser session wait only blocks for a bounded window per pending-count change", () => {
    const first = resolvePendingBrowserSessionWait({
      state: null,
      pendingCount: 1,
      nowMs: 1_000,
      maxWaitMs: 5_000,
    });
    expect(first.wait).toBe(true);
    expect(first.state).toMatchObject({ count: 1, startedAtMs: 1_000, exhausted: false });

    const second = resolvePendingBrowserSessionWait({
      state: first.state,
      pendingCount: 1,
      nowMs: 4_000,
      maxWaitMs: 5_000,
    });
    expect(second.wait).toBe(true);

    const exhausted = resolvePendingBrowserSessionWait({
      state: second.state,
      pendingCount: 1,
      nowMs: 6_500,
      maxWaitMs: 5_000,
    });
    expect(exhausted.wait).toBe(false);
    expect(exhausted.state).toMatchObject({ count: 1, startedAtMs: 1_000, exhausted: true });

    const sameCountAfterExhausted = resolvePendingBrowserSessionWait({
      state: exhausted.state,
      pendingCount: 1,
      nowMs: 9_000,
      maxWaitMs: 5_000,
    });
    expect(sameCountAfterExhausted.wait).toBe(false);

    const changedCount = resolvePendingBrowserSessionWait({
      state: exhausted.state,
      pendingCount: 2,
      nowMs: 9_500,
      maxWaitMs: 5_000,
    });
    expect(changedCount.wait).toBe(true);
    expect(changedCount.state).toMatchObject({ count: 2, startedAtMs: 9_500, exhausted: false });
  });

  test("normalizes extractor upstream responses", async () => {
    const hotmailBodies = [];
    const hotmailUrls = [];
    const shankeyunUrls = [];
    globalThis.fetch = async (url, init) => {
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
      if (href.includes("shanyouxiang")) {
        return new Response(JSON.stringify({ status: -1, msg: "库存不足！" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (href.includes("/api/win/buy")) {
        shankeyunUrls.push(href);
        return new Response("mail-sk@outlook.com----pass-sk--------refresh-token----client-id", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }
      hotmailUrls.push(href);
      hotmailBodies.push(JSON.parse(String(init?.body || "{}")));
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            mails: ["mail-hm@outlook.com:pass-hm:refresh-token"],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const config = {
      zhanghaoyaKey: "zhya-demo-key-001",
      shanyouxiangKey: "shan-demo-key-001",
      shankeyunKey: "shanke-demo-key-001",
      hotmail666Key: "hotmail666-demo-key-001",
    };

    const zhanghaoya = await fetchSingleExtractedAccount({
      provider: "zhanghaoya",
      config,
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
      config,
    });
    expect(shanyouxiang.ok).toBe(false);
    expect(shanyouxiang.failureCode).toBe("insufficient_stock");

    const shankeyun = await fetchSingleExtractedAccount({
      provider: "shankeyun",
      config,
    });
    expect(shankeyun.ok).toBe(true);
    expect(shankeyun.candidates[0]).toMatchObject({
      provider: "shankeyun",
      email: "mail-sk@outlook.com",
      password: "pass-sk",
      parseStatus: "parsed",
    });
    expect(shankeyunUrls).toEqual([
      "https://fk.shankeyun.com/api/win/buy?card=shanke-demo-key-001&type=outlook&num=1",
    ]);

    const hotmail666 = await fetchSingleExtractedAccount({
      provider: "hotmail666",
      config,
    });
    expect(hotmail666.ok).toBe(true);
    expect(hotmail666.candidates[0]).toMatchObject({
      provider: "hotmail666",
      email: "mail-hm@outlook.com",
      password: "pass-hm",
      parseStatus: "parsed",
    });
    expect(hotmailBodies).toEqual([
      {
        cardKey: "hotmail666-demo-key-001",
        mailType: "outlook",
        quantity: 1,
      },
    ]);
    expect(hotmailUrls).toEqual([
      "https://api.hotmail666.com/api/extract-mail",
    ]);
  });

  test("rejects dashed extractor rows when the password field is empty", async () => {
    globalThis.fetch = async () =>
      new Response("mail-sk@outlook.com--------refresh-token----client-id", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });

    const result = await fetchSingleExtractedAccount({
      provider: "shankeyun",
      config: {
        zhanghaoyaKey: "",
        shanyouxiangKey: "",
        shankeyunKey: "shanke-demo-key-001",
        hotmail666Key: "",
      },
    });

    expect(result.ok).toBe(false);
    expect(result.failureCode).toBe("parse_failed");
    expect(result.candidates).toEqual([
      {
        provider: "shankeyun",
        rawPayload: "mail-sk@outlook.com--------refresh-token----client-id",
        email: null,
        password: null,
        parseStatus: "invalid",
      },
    ]);
  });

  test("maps new provider failure envelopes to canonical codes", async () => {
    globalThis.fetch = async (url) => {
      const href = String(url);
      if (href.includes("/api/win/buy")) {
        return new Response(JSON.stringify({ status: 0, msg: "卡密已过期" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ success: false, message: "剩余次数不足，当前剩余: 0" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const config = {
      zhanghaoyaKey: "",
      shanyouxiangKey: "",
      shankeyunKey: "shanke-demo-key-001",
      hotmail666Key: "hotmail666-demo-key-001",
    };

    const shankeyun = await fetchSingleExtractedAccount({
      provider: "shankeyun",
      config,
    });
    expect(shankeyun.ok).toBe(false);
    expect(shankeyun.failureCode).toBe("invalid_key");

    const hotmail666 = await fetchSingleExtractedAccount({
      provider: "hotmail666",
      config,
    });
    expect(hotmail666.ok).toBe(false);
    expect(hotmail666.failureCode).toBe("insufficient_stock");
  });

  test("preserves shankeyun upstream message for ambiguous stock failures", async () => {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ status: 0, msg: "余额不足或无此类型卡号" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const result = await fetchSingleExtractedAccount({
      provider: "shankeyun",
      config: {
        zhanghaoyaKey: "",
        shanyouxiangKey: "",
        shankeyunKey: "shanke-demo-key-001",
        hotmail666Key: "",
      },
    });

    expect(result.ok).toBe(false);
    expect(result.failureCode).toBe("insufficient_stock");
    expect(result.message).toBe("余额不足或无此类型卡号");
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

  test("preserves stopping status when the final successful attempt finishes after a graceful stop request", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "stop-success@outlook.com", password: "pass-a" }]);
    const accountId = imported.affectedIds[0];
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const attempt = appDb.createAttempt(job.id, accountId, "/tmp/tavreg-stop-success-attempt");
    appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });

    const { job: nextJob, attempt: nextAttempt } = appDb.completeAttemptSuccess(
      job.id,
      attempt.id,
      accountId,
      "tvly-stop-success-0001",
      null,
    );

    expect(nextAttempt.status).toBe("succeeded");
    expect(nextJob.status).toBe("stopping");

    appDb.close();
  });

  test("preserves force stopping status when a remaining attempt fails during manual shutdown", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "stop-failure@outlook.com", password: "pass-a" }]);
    const accountId = imported.affectedIds[0];
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const attempt = appDb.createAttempt(job.id, accountId, "/tmp/tavreg-stop-failure-attempt");
    appDb.updateJobState(job.id, { status: "force_stopping", pausedAt: null });

    const { job: nextJob, attempt: nextAttempt } = appDb.completeAttemptFailure(
      job.id,
      attempt.id,
      accountId,
      { errorCode: "network_connection_closed" },
      null,
    );

    expect(nextAttempt.status).toBe("failed");
    expect(nextJob.status).toBe("force_stopping");

    appDb.close();
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
    const seeded = appDb.importAccounts([{ email: "cap-a@outlook.com", password: "pass-a" }]);
    markImportedAccountsReady(appDb, seeded.affectedIds);
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

    const accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts.map((account) => account.microsoftEmail)).toEqual(["cap-a@outlook.com"]);
    expect(accounts[0]?.browserSession?.status).toBe("ready");
    expect(appDb.countEligibleAccounts(job.id)).toBe(1);

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

  test("does not count pending bootstrap imports as usable auto extracted accounts", async () => {
    const { appDb, dbPath } = await createTempDb();
    let fakeNow = 0;
    Date.now = () => fakeNow;
    const pending = [];
    globalThis.fetch = (url) =>
      new Promise((resolve) => {
        pending.push({ href: String(url), resolve });
      });

    const queuedImports = [];
    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
      () => undefined,
      {
        onImportedAccounts: (accountIds) => {
          queuedImports.push(accountIds);
        },
      },
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

    let decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      acceptedCount: 0,
      rawAttemptCount: 1,
      inFlightCount: 1,
    });

    pending[0].resolve(
      new Response(
        JSON.stringify({
          Code: 200,
          Message: "Success",
          Data: "pending-a@outlook.com:pass-a",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts.map((account) => account.microsoftEmail)).toEqual(["pending-a@outlook.com"]);
    expect(accounts[0]?.browserSession?.status).toBe("pending");
    expect(appDb.countEligibleAccounts(job.id)).toBe(0);
    expect(queuedImports).toEqual([[accounts[0].id]]);

    const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(history.rows[0]).toMatchObject({
      status: "pending_bootstrap",
      acceptedCount: 0,
      completedAt: null,
    });
    expect(history.rows[0]?.items).toHaveLength(0);

    fakeNow = 501;
    decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      acceptedCount: 0,
      rawAttemptCount: 1,
      inFlightCount: 0,
    });
    expect(pending).toHaveLength(1);

    markBrowserSessionReady(appDb, accounts[0].id);
    fakeNow = 601;
    decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "ready", reason: "accepted 1 usable account(s)" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      phase: "idle",
      acceptedCount: 0,
      rawAttemptCount: 0,
      inFlightCount: 0,
    });

    const reconciledHistory = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(reconciledHistory.rows[0]).toMatchObject({
      status: "accepted",
      acceptedCount: 1,
    });
    expect(reconciledHistory.rows[0]?.items[0]).toMatchObject({
      email: "pending-a@outlook.com",
      acceptStatus: "accepted",
      rejectReason: null,
    });

    await scheduler.shutdown();
    appDb.close();
  });

  test("dispatches auto extract requests every 500ms per provider with up to 3 workers per source", async () => {
    const { appDb, dbPath } = await createTempDb();
    let fakeNow = 0;
    Date.now = () => fakeNow;

    const pending = [];
    const buildResponseForUrl = (href) => {
      if (href.includes("zhanghaoya")) {
        return new Response(
          JSON.stringify({
            Code: 200,
            Message: "Success",
            Data: "cadence-zh@outlook.com:pass-zh",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (href.includes("shanyouxiang")) {
        return new Response("cadence-sy@outlook.com----pass-sy", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }
      if (href.includes("shankeyun")) {
        return new Response("cadence-sk@outlook.com----pass-sk--------refresh-token----client-id", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            mails: ["cadence-hm@outlook.com:pass-hm"],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };
    globalThis.fetch = (url) =>
      new Promise((resolve) => {
        pending.push({ href: String(url), resolve });
      });

    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () =>
        createSchedulerSettings({
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "shan-demo-key-001",
          extractorShankeyunKey: "shanke-demo-key-001",
          extractorHotmail666Key: "hotmail666-demo-key-001",
        }),
      () => undefined,
    );
    const job = appDb.createJob({
      runMode: "headed",
      need: 6,
      parallel: 1,
      maxAttempts: 12,
      autoExtractSources: ["zhanghaoya", "shanyouxiang", "shankeyun", "hotmail666"],
      autoExtractQuantity: 6,
      autoExtractMaxWaitSec: 30,
      autoExtractAccountType: "outlook",
    });
    scheduler["syncAutoExtractState"](job);

    let decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 4,
      inFlightCount: 4,
      attemptBudget: 0,
    });

    decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 4,
      inFlightCount: 4,
    });

    fakeNow = 499;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 4,
      inFlightCount: 4,
    });

    fakeNow = 500;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 8,
      inFlightCount: 8,
    });
    expect(pending).toHaveLength(8);

    fakeNow = 1000;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 12,
      inFlightCount: 12,
    });
    expect(pending).toHaveLength(12);

    fakeNow = 1500;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 12,
      inFlightCount: 12,
    });
    expect(pending).toHaveLength(12);

    pending[0].resolve(buildResponseForUrl(pending[0].href));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    fakeNow = 1501;
    await scheduler["maybeAutoExtract"](job);
    expect(scheduler.getAutoExtractSnapshot(job.id)).toMatchObject({
      rawAttemptCount: 13,
      inFlightCount: 12,
    });
    expect(pending).toHaveLength(13);

    await scheduler.shutdown();
    appDb.close();
  });

  test("rejects later in-flight extractor successes after the round target is already met", async () => {
    const { appDb, dbPath } = await createTempDb();
    const seeded = appDb.importAccounts([
      { email: "target-zh@outlook.com", password: "pass-zh" },
      { email: "target-sy@outlook.com", password: "pass-sy" },
      { email: "target-sk@outlook.com", password: "pass-sk" },
      { email: "target-hm@outlook.com", password: "pass-hm" },
    ]);
    markImportedAccountsReady(appDb, seeded.affectedIds);
    const buildResponseForUrl = (href) => {
      if (href.includes("zhanghaoya")) {
        return new Response(
          JSON.stringify({
            Code: 200,
            Message: "Success",
            Data: "target-zh@outlook.com:pass-zh",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (href.includes("shanyouxiang")) {
        return new Response("target-sy@outlook.com----pass-sy", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }
      if (href.includes("shankeyun")) {
        return new Response("target-sk@outlook.com----pass-sk--------refresh-token----client-id", {
          status: 200,
          headers: { "content-type": "text/plain" },
        });
      }
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            mails: ["target-hm@outlook.com:pass-hm"],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const pending = [];
    globalThis.fetch = (url) =>
      new Promise((resolve) => {
        pending.push({ href: String(url), resolve });
      });

    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () =>
        createSchedulerSettings({
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "shan-demo-key-001",
          extractorShankeyunKey: "shanke-demo-key-001",
          extractorHotmail666Key: "hotmail666-demo-key-001",
        }),
      () => undefined,
    );
    const job = appDb.createJob({
      runMode: "headed",
      need: 1,
      parallel: 1,
      maxAttempts: 8,
      autoExtractSources: ["zhanghaoya", "shanyouxiang", "shankeyun", "hotmail666"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 30,
      autoExtractAccountType: "outlook",
    });
    scheduler["syncAutoExtractState"](job);

    const decision = await scheduler["maybeAutoExtract"](job);
    expect(decision).toEqual({ status: "waiting" });
    expect(pending).toHaveLength(4);

    pending[0].resolve(buildResponseForUrl(pending[0].href));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    pending[1].resolve(buildResponseForUrl(pending[1].href));
    pending[2].resolve(buildResponseForUrl(pending[2].href));
    pending[3].resolve(buildResponseForUrl(pending[3].href));
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    const accounts = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(accounts.map((account) => account.microsoftEmail).sort()).toEqual([
      "target-hm@outlook.com",
      "target-sk@outlook.com",
      "target-sy@outlook.com",
      "target-zh@outlook.com",
    ]);
    expect(appDb.countEligibleAccounts(job.id)).toBe(4);

    const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(history.total).toBe(4);
    expect(history.rows.filter((row) => row.status === "accepted")).toHaveLength(1);
    expect(
      history.rows.flatMap((row) => row.items).filter((item) => item.rejectReason === "round_target_reached"),
    ).toHaveLength(3);

    await scheduler.shutdown();
    appDb.close();
  });

  test("auto extract requests use a 5 second timeout budget", async () => {
    const { appDb, dbPath } = await createTempDb();
    const observedTimeouts = [];
    globalThis.setTimeout = ((handler, timeout, ...args) => {
      observedTimeouts.push(Number(timeout));
      return originalSetTimeout(() => {
        if (typeof handler === "function") {
          handler(...args);
        }
      }, 0);
    });
    globalThis.fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted by timeout")));
      });

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
      maxAttempts: 1,
      autoExtractSources: ["zhanghaoya"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 30,
      autoExtractAccountType: "outlook",
    });
    scheduler["syncAutoExtractState"](job);

    await scheduler["maybeAutoExtract"](job);
    await new Promise((resolve) => originalSetTimeout(resolve, 0));
    await new Promise((resolve) => originalSetTimeout(resolve, 0));

    expect(observedTimeouts).toContain(5000);

    await scheduler.shutdown();
    appDb.close();
  });

  test("marks attempts failed when launch setup throws before spawn", async () => {
    const { appDb, dbPath } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "broken@outlook.com", password: "broken-pass" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
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

  test("prefers node workers over bun for fingerprint chromium CDP runs", () => {
    expect(
      pickWorkerRuntime({
        explicitNodeBinary: "/custom/node",
        explicitNodeTsxAvailable: true,
        runningUnderBun: true,
        processExecPath: "/custom/bun",
        nodeCommandAvailable: true,
        nodeTsxAvailable: true,
      }),
    ).toEqual({
      command: "/custom/node",
      bootstrapArgs: ["--import", "tsx", "src/main.ts"],
    });

    expect(
      pickWorkerRuntime({
        explicitNodeBinary: "/custom/node",
        explicitNodeTsxAvailable: false,
        runningUnderBun: true,
        processExecPath: "/custom/bun",
        nodeCommandAvailable: true,
        nodeTsxAvailable: false,
      }),
    ).toEqual({
      command: "/custom/bun",
      bootstrapArgs: ["run", "src/main.ts"],
    });

    expect(
      pickWorkerRuntime({
        explicitNodeBinary: "",
        runningUnderBun: true,
        processExecPath: "/custom/bun",
        nodeCommandAvailable: true,
        nodeTsxAvailable: true,
      }),
    ).toEqual({
      command: "node",
      bootstrapArgs: ["--import", "tsx", "src/main.ts"],
    });

    expect(
      pickWorkerRuntime({
        explicitNodeBinary: "",
        runningUnderBun: true,
        processExecPath: "/custom/bun",
        nodeCommandAvailable: true,
        nodeTsxAvailable: false,
      }),
    ).toEqual({
      command: "/custom/bun",
      bootstrapArgs: ["run", "src/main.ts"],
    });

    expect(
      pickWorkerRuntime({
        explicitNodeBinary: "",
        runningUnderBun: false,
        processExecPath: "/custom/node",
        nodeCommandAvailable: false,
        nodeTsxAvailable: false,
      }),
    ).toEqual({
      command: "/custom/node",
      bootstrapArgs: ["--import", "tsx", "src/main.ts"],
    });
  });

  test("syncs active attempt rows from signup task ledger into the job attempts table", async () => {
    const { appDb, dbPath } = await createTempDb();
    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () => createSchedulerSettings(),
      () => undefined,
    );
    const imported = appDb.importAccounts([{ email: "alpha@outlook.com", password: "pw123456" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
    const account = appDb.getAccount(accountId);
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const attempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "tmp-attempt"));
    const ledger = await TaskLedger.open({
      enabled: true,
      dbPath,
      busyTimeoutMs: 1000,
      ipRateLimitCooldownMs: 60_000,
      ipRateLimitMax: 3,
      captchaMissingCooldownMs: 60_000,
      captchaMissingMax: 3,
      captchaMissingThreshold: 1,
      invalidCaptchaCooldownMs: 60_000,
      invalidCaptchaMax: 3,
      invalidCaptchaThreshold: 1,
      allowRateLimitedIpFallback: false,
    });

    try {
      ledger.upsertTask({
        runId: "run-123",
        jobId: job.id,
        accountId,
        batchId: "batch-1",
        mode: "headed",
        attemptIndex: 1,
        modeRetryMax: 3,
        status: "running",
        startedAt: new Date().toISOString(),
        failureStage: "browser_launch",
        proxyNode: "Tokyo-1",
        proxyIp: "1.2.3.4",
        errorCode: "oauth_timeout",
        errorMessage: "waiting for callback",
      });

      scheduler.activeAttempts.set(attempt.id, {
        child: {},
        attempt,
        account,
        outputDir: path.join(process.cwd(), "tmp-attempt"),
        reservedPorts: { apiPort: 39090, mixedPort: 49090 },
        tail: [],
      });

      const rows = scheduler.activeAttemptRows();
      expect(rows[0]).toMatchObject({
        runId: "run-123",
        stage: "browser_launch",
        proxyNode: "Tokyo-1",
        proxyIp: "1.2.3.4",
        errorCode: "oauth_timeout",
        errorMessage: "waiting for callback",
      });
      expect(appDb.getAttempt(attempt.id)).toMatchObject({
        runId: "run-123",
        stage: "browser_launch",
        proxyNode: "Tokyo-1",
        proxyIp: "1.2.3.4",
        errorCode: "oauth_timeout",
        errorMessage: "waiting for callback",
      });
    } finally {
      scheduler.activeAttempts.clear();
      ledger?.close();
      await scheduler.shutdown();
      appDb.close();
    }
  });

  test("ignores stale signup task rows before a retried attempt writes its own run id", async () => {
    const { appDb, dbPath } = await createTempDb();
    const scheduler = new JobScheduler(
      appDb,
      process.cwd(),
      dbPath,
      () => createSchedulerSettings(),
      () => undefined,
    );
    const imported = appDb.importAccounts([{ email: "retry-sync@outlook.com", password: "pw123456" }]);
    const accountId = imported.affectedIds[0];
    markBrowserSessionReady(appDb, accountId);
    const account = appDb.getAccount(accountId);
    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 2 });
    const ledger = await TaskLedger.open({
      enabled: true,
      dbPath,
      busyTimeoutMs: 1000,
      ipRateLimitCooldownMs: 60_000,
      ipRateLimitMax: 3,
      captchaMissingCooldownMs: 60_000,
      captchaMissingMax: 3,
      captchaMissingThreshold: 1,
      invalidCaptchaCooldownMs: 60_000,
      invalidCaptchaMax: 3,
      invalidCaptchaThreshold: 1,
      allowRateLimitedIpFallback: false,
    });

    try {
      ledger.upsertTask({
        runId: "run-old",
        jobId: job.id,
        accountId,
        batchId: "batch-old",
        mode: "headed",
        attemptIndex: 1,
        modeRetryMax: 3,
        status: "failed",
        startedAt: "2026-03-27T00:00:00.000Z",
        completedAt: "2026-03-27T00:00:10.000Z",
        failureStage: "browser_launch",
        errorCode: "oauth_timeout",
        errorMessage: "old retry failed",
      });

      const retryAttempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "tmp-attempt-retry"));
      scheduler.activeAttempts.set(retryAttempt.id, {
        child: {},
        attempt: retryAttempt,
        account,
        outputDir: path.join(process.cwd(), "tmp-attempt-retry"),
        reservedPorts: { apiPort: 39090, mixedPort: 49090 },
        tail: [],
      });

      let rows = scheduler.activeAttemptRows();
      expect(rows[0]).toMatchObject({
        runId: null,
        stage: "spawned",
        errorCode: null,
        errorMessage: null,
      });
      expect(appDb.getAttempt(retryAttempt.id)).toMatchObject({
        runId: null,
        stage: "spawned",
        errorCode: null,
        errorMessage: null,
      });

      ledger.upsertTask({
        runId: "run-current",
        jobId: job.id,
        accountId,
        batchId: "batch-current",
        mode: "headed",
        attemptIndex: 2,
        modeRetryMax: 3,
        status: "running",
        startedAt: new Date(Date.parse(retryAttempt.startedAt) + 1000).toISOString(),
        failureStage: "login_home",
        errorCode: "login_waiting",
        errorMessage: "current retry active",
      });

      rows = scheduler.activeAttemptRows();
      expect(rows[0]).toMatchObject({
        runId: "run-current",
        stage: "login_home",
        errorCode: "login_waiting",
        errorMessage: "current retry active",
      });
      expect(appDb.getAttempt(retryAttempt.id)).toMatchObject({
        runId: "run-current",
        stage: "login_home",
        errorCode: "login_waiting",
        errorMessage: "current retry active",
      });
    } finally {
      scheduler.activeAttempts.clear();
      ledger?.close();
      await scheduler.shutdown();
      appDb.close();
    }
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

  test("reuses the same ip first, then same-region lru, then global lru", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proxy-reuse@outlook.com", password: "proxy-pass" }]);
    const accountId = imported.affectedIds[0];
    appDb.upsertProxyInventory(["Tokyo-01", "Tokyo-02", "Seoul-01"], "Tokyo-01");
    appDb.touchProxyLease("Seoul-01", {
      status: "ok",
      egressIp: "2.2.2.2",
      region: "Seoul",
      leasedAt: "2026-03-01T00:00:00.000Z",
    });
    appDb.touchProxyLease("Tokyo-01", {
      status: "ok",
      egressIp: "3.3.3.3",
      region: "Tokyo",
      leasedAt: "2026-03-02T00:00:00.000Z",
    });
    appDb.touchProxyLease("Tokyo-02", {
      status: "ok",
      egressIp: "4.4.4.4",
      region: "Tokyo",
      leasedAt: "2026-03-03T00:00:00.000Z",
    });

    markBrowserSessionReady(appDb, accountId, {
      proxyNode: "Old-Seoul",
      proxyIp: "2.2.2.2",
      proxyRegion: "Tokyo",
    });
    expect(appDb.selectReusableProxyNodeForAccount(accountId)?.nodeName).toBe("Seoul-01");

    markBrowserSessionReady(appDb, accountId, {
      proxyNode: "Old-Tokyo",
      proxyIp: "9.9.9.9",
      proxyRegion: "Tokyo",
    });
    expect(appDb.selectReusableProxyNodeForAccount(accountId)?.nodeName).toBe("Tokyo-01");

    markBrowserSessionReady(appDb, accountId, {
      proxyNode: "Old-Nowhere",
      proxyIp: "8.8.8.8",
      proxyRegion: "Osaka",
    });
    expect(appDb.selectReusableProxyNodeForAccount(accountId)?.nodeName).toBe("Seoul-01");

    appDb.close();
  });

  test("falls back to untested proxy nodes only when no verified healthy node exists", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proxy-unverified@outlook.com", password: "proxy-pass" }]);
    const accountId = imported.affectedIds[0];
    appDb.upsertProxyInventory(["Tokyo-01", "Tokyo-02"], "Tokyo-01");
    markBrowserSessionReady(appDb, accountId, {
      proxyIp: "3.3.3.3",
      proxyRegion: "Tokyo",
    });

    expect(appDb.selectReusableProxyNodeForAccount(accountId)?.nodeName).toBe("Tokyo-01");

    appDb.touchProxyLease("Tokyo-02", {
      status: "ok",
      egressIp: "4.4.4.4",
      region: "Tokyo",
      leasedAt: "2026-03-04T00:00:00.000Z",
    });

    expect(appDb.selectReusableProxyNodeForAccount(accountId)?.nodeName).toBe("Tokyo-02");

    appDb.close();
  });

  test("attempt completion refreshes stored proxy region for later reuse", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proxy-region@outlook.com", password: "proxy-pass" }]);
    const accountId = imported.affectedIds[0];
    appDb.upsertProxyInventory(["Osaka-01"], "Osaka-01");
    markBrowserSessionReady(appDb, accountId, {
      proxyNode: "Tokyo-01",
      proxyIp: "3.3.3.3",
      proxyRegion: "Tokyo",
    });

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(appDb.leaseNextAccount(job.id)?.id).toBe(accountId);
    const attempt = appDb.createAttempt(job.id, accountId, "/tmp/proxy-region-attempt");
    appDb.completeAttemptSuccess(job.id, attempt.id, accountId, "tvly-proxy-region-001", {
      proxy_node: "Osaka-01",
      proxy_ip: "5.5.5.5",
      proxy_country: "JP",
      proxy_region: "Osaka",
      proxy_city: "Osaka",
      proxy_timezone: "Asia/Tokyo",
      status: "succeeded",
    });

    expect(appDb.getAccount(accountId)?.browserSession).toMatchObject({
      proxyNode: "Osaka-01",
      proxyIp: "5.5.5.5",
      proxyRegion: "Osaka",
    });
    expect(appDb.getProxyNode("Osaka-01")).toMatchObject({
      lastEgressIp: "5.5.5.5",
      lastRegion: "Osaka",
    });

    appDb.close();
  });

  test("account-level failures do not blacklist an otherwise healthy proxy node", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proxy-health@outlook.com", password: "proxy-pass" }]);
    const accountId = imported.affectedIds[0];
    appDb.upsertProxyInventory(["Tokyo-01"], "Tokyo-01");
    appDb.touchProxyLease("Tokyo-01", {
      status: "ok",
      egressIp: "1.1.1.1",
      country: "JP",
      region: "Tokyo",
      city: "Tokyo",
    });
    markBrowserSessionReady(appDb, accountId);

    const job = appDb.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    expect(appDb.leaseNextAccount(job.id)?.id).toBe(accountId);
    const attempt = appDb.createAttempt(job.id, accountId, "/tmp/proxy-health-attempt");
    appDb.completeAttemptFailure(job.id, attempt.id, accountId, { errorCode: "microsoft_account_locked" }, {
      proxy_node: "Tokyo-01",
      proxy_ip: "1.1.1.1",
      proxy_country: "JP",
      proxy_region: "Tokyo",
      proxy_city: "Tokyo",
      proxy_timezone: "Asia/Tokyo",
      status: "failed",
    });

    expect(appDb.getProxyNode("Tokyo-01")?.lastStatus).toBe("ok");
    expect(resolveAttemptProxyNode(appDb)).toBe("Tokyo-01");

    appDb.close();
  });

  test("failed rebootstrap preserves the last known proxy geo when capture never starts", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "proxy-failed-bootstrap@outlook.com", password: "proxy-pass" }]);
    const accountId = imported.affectedIds[0];

    markBrowserSessionReady(appDb, accountId, {
      proxyNode: "Tokyo-01",
      proxyIp: "1.1.1.1",
      proxyRegion: "Tokyo",
      proxyCity: "Tokyo",
    });

    appDb.markBrowserSessionBootstrapping(accountId, { proxyNode: "Osaka-01" });
    appDb.markBrowserSessionFailure(accountId, {
      status: "failed",
      proxyNode: "Osaka-01",
      errorCode: "session_bootstrap_failed",
    });

    expect(appDb.getAccount(accountId)?.browserSession).toMatchObject({
      status: "failed",
      proxyNode: "Osaka-01",
      proxyIp: "1.1.1.1",
      proxyRegion: "Tokyo",
      proxyCity: "Tokyo",
    });

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
        extractorShankeyunKey: " shanke-demo-key-001 ",
        extractorHotmail666Key: " hotmail666-demo-key-001 ",
        defaultAutoExtractSources: ["zhanghaoya", "shankeyun", "hotmail666", "zhanghaoya"],
      }),
    ).toMatchObject({
      subscriptionUrl: "https://next.example/sub.yaml",
      groupName: "WEB_AUTO",
      timeoutMs: 1000,
      extractorShankeyunKey: "shanke-demo-key-001",
      extractorHotmail666Key: "hotmail666-demo-key-001",
      defaultAutoExtractSources: ["zhanghaoya", "shankeyun", "hotmail666"],
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
        proofMailboxProvider: "cfmail",
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

    const expectedRuntime = resolveWorkerRuntime();
    expect(runtime.command).toBe(expectedRuntime.command);
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
    expect(runtime.args.slice(0, expectedRuntime.bootstrapArgs.length)).toEqual(expectedRuntime.bootstrapArgs);
    expect(runtime.args[expectedRuntime.bootstrapArgs.length]).toBe("--mode");
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
      MICROSOFT_PROOF_MAILBOX_PROVIDER: "cfmail",
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
    expect(runtime.env.MICROSOFT_PROOF_MAILBOX_PROVIDER).toBe("cfmail");
    expect(runtime.env.MICROSOFT_PROOF_MAILBOX_ADDRESS).toBe("worker-proof@mail-us.707079.xyz");
    expect(runtime.env.MICROSOFT_PROOF_MAILBOX_ID).toBe("worker-proof-001");
    expect(runtime.env.CHROME_REMOTE_DEBUGGING_PORT).toBeUndefined();
  });

  test("launches child attempts in their own process group for force-stop cleanup", () => {
    const runtime = buildAttemptRuntimeSpec({
      job: { id: 9, runMode: "headless" },
      account: {
        id: 22,
        microsoftEmail: "grouped@outlook.com",
        passwordPlaintext: "worker-pass",
        proofMailboxProvider: null,
        proofMailboxAddress: null,
        proofMailboxId: null,
      },
      outputDir: "/tmp/tavreg/job-9/attempt-22",
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
        apiPort: 40125,
        mixedPort: 40126,
      },
    });

    expect(buildAttemptSpawnOptions("/tmp/tavreg", runtime)).toEqual({
      cwd: "/tmp/tavreg",
      env: runtime.env,
      detached: true,
    });
  });

  test("reuses exact persistent account profiles when a browser session already exists", () => {
    const runtime = buildAttemptRuntimeSpec({
      job: { id: 9, runMode: "headed" },
      account: {
        id: 22,
        microsoftEmail: "persistent@outlook.com",
        passwordPlaintext: "worker-pass",
        proofMailboxProvider: null,
        proofMailboxAddress: null,
        proofMailboxId: null,
        browserSession: {
          profilePath: "output/browser-profiles/accounts/22/chrome",
        },
      },
      outputDir: "/tmp/tavreg/job-9/attempt-22",
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
    });

    expect(runtime.env.CHROME_PROFILE_DIR).toBe(path.resolve("output/browser-profiles/accounts/22/chrome"));
    expect(runtime.env.CHROME_PROFILE_STRATEGY).toBe("exact");
    expect(runtime.env.INSPECT_CHROME_PROFILE_DIR).toBe("/tmp/tavreg/job-9/attempt-22/chrome-inspect-profile");
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

  test("stops forcing a selected proxy node after it is marked failed", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["Tokyo-01", "Tokyo-02"], "Tokyo-02");

    expect(resolveAttemptProxyNode(appDb)).toBe("Tokyo-02");

    appDb.recordProxyCheck({
      nodeName: "Tokyo-02",
      status: "failed",
      error: "net::ERR_CONNECTION_CLOSED",
    });

    expect(resolveAttemptProxyNode(appDb)).toBeNull();

    appDb.close();
  });

  test("launch proxy reuse only follows account-level reusable selection", () => {
    expect(
      resolveReusableAttemptProxyNode(
        {
          selectReusableProxyNodeForAccount: () => null,
        },
        21,
      ),
    ).toBeNull();
    expect(
      resolveReusableAttemptProxyNode(
        {
          selectReusableProxyNodeForAccount: () => ({ nodeName: "Tokyo-01" }),
        },
        21,
      ),
    ).toBe("Tokyo-01");
  });

  test("does not force a selected proxy node while it is still in a non-healthy running state", async () => {
    const { appDb } = await createTempDb();
    appDb.upsertProxyInventory(["Tokyo-01", "Tokyo-02"], "Tokyo-02");

    appDb.recordProxyCheck({
      nodeName: "Tokyo-02",
      status: "running",
    });

    expect(resolveAttemptProxyNode(appDb)).toBeNull();

    appDb.close();
  });
});
