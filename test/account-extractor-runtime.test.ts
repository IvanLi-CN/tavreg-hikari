import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  AccountExtractorRuntime,
  decideManualExtractorAcceptance,
  normalizeExtractorSources,
} from "../src/server/account-extractor-runtime.ts";
import { AppDatabase } from "../src/storage/app-db.ts";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-runtime-"));
  tempDirs.push(tempDir);
  const appDb = await AppDatabase.open(path.join(tempDir, "app.sqlite"));
  return { appDb };
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

function createExistingAccount(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    passwordPlaintext: "same-pass",
    disabledAt: null,
    skipReason: null,
    lastErrorCode: null,
    hasApiKey: false,
    leaseJobId: null,
    browserSession: null,
    ...overrides,
  };
}

describe("account extractor runtime helpers", () => {
  test("normalizeExtractorSources filters unknown items and deduplicates in order", () => {
    expect(
      normalizeExtractorSources([
        "zhanghaoya",
        "hotmail666",
        "zhanghaoya",
        "shankeyun",
        "invalid-provider" as never,
      ]),
    ).toEqual(["zhanghaoya", "hotmail666", "shankeyun"]);
  });

  test("accepts new accounts and imports them", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: null,
        candidatePassword: "fresh-pass",
      }),
    ).toEqual({
      accept: true,
      rejectReason: null,
      shouldImport: true,
      forceBootstrap: false,
    });
  });

  test("rejects ready sessions when the password is unchanged", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          browserSession: { status: "ready" },
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "session_ready",
      shouldImport: false,
      forceBootstrap: false,
    });
  });

  test("allows failed sessions to retry bootstrap without reimporting", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          browserSession: { status: "failed" },
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: true,
      rejectReason: null,
      shouldImport: false,
      forceBootstrap: true,
    });
  });

  test("reimports existing accounts when the password changes", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          browserSession: { status: "ready" },
        }),
        candidatePassword: "next-pass",
      }),
    ).toEqual({
      accept: true,
      rejectReason: null,
      shouldImport: true,
      forceBootstrap: true,
    });
  });

  test("rejects locked, disabled, leased, and linked accounts", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          skipReason: "microsoft_account_locked",
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "microsoft_account_locked",
      shouldImport: false,
      forceBootstrap: false,
    });

    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          disabledAt: "2026-04-01T00:00:00.000Z",
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "disabled",
      shouldImport: false,
      forceBootstrap: false,
    });

    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          leaseJobId: 42,
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "leased",
      shouldImport: false,
      forceBootstrap: false,
    });

    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          hasApiKey: true,
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "has_api_key",
      shouldImport: false,
      forceBootstrap: false,
    });
  });

  test("manual stop drains in-flight requests into the stopped terminal state", async () => {
    const { appDb } = await createTempDb();
    const runtime = new AccountExtractorRuntime(
      appDb,
      () =>
        ({
          microsoftGraphClientId: "client-id",
          microsoftGraphClientSecret: "client-secret",
          microsoftGraphRedirectUri: "https://example.com/callback",
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "",
          extractorShankeyunKey: "",
          extractorHotmail666Key: "",
        }) as never,
      () => undefined,
      () => false,
    );
    const controller = new AbortController();
    const now = "2026-04-03T03:20:00.000Z";
    runtime["state"] = {
      runId: 7,
      status: "running",
      enabledSources: ["zhanghaoya"],
      accountType: "outlook",
      requestedUsableCount: 1,
      acceptedCount: 0,
      rawAttemptCount: 1,
      attemptBudget: 0,
      inFlightCount: 1,
      remainingWaitMs: 60_000,
      maxWaitMs: 60_000,
      startedAt: now,
      lastProvider: "zhanghaoya",
      lastMessage: "账号鸭 请求已发出",
      updatedAt: now,
      errorMessage: null,
      lastBatchId: null,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerInFlightCount: { zhanghaoya: 1, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerAttemptCount: { zhanghaoya: 1, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      lastBudgetTickMs: Date.now(),
      lastPublishedAtMs: 0,
      requestControllers: new Map([["req-1", controller]]),
      pendingBootstrapCandidates: new Map(),
    };

    const stopping = await runtime.stop();
    expect(stopping.status).toBe("stopping");
    expect(stopping.lastMessage).toContain("等待 1 个在途请求收尾");
    expect(controller.signal.aborted).toBe(true);

    runtime["finishRequest"]({
      runId: 7,
      provider: "zhanghaoya",
      requestId: "req-1",
      dispatchStartedAt: now,
      result: null,
      rawResponse: null,
      maskedKey: "zhya****0001",
      errorMessage: "提号已取消",
      failureCode: "manual_stop",
    });

    const stopped = runtime.getSnapshot();
    expect(stopped.status).toBe("stopped");
    expect(stopped.inFlightCount).toBe(0);
    expect(stopped.lastMessage).toBe("提号已取消");
    appDb.close();
  });

  test("start preserves the requested hotmail extractor account type", async () => {
    const { appDb } = await createTempDb();
    const published: Array<{ type: string; payload: Record<string, unknown> }> = [];
    globalThis.fetch = (async (_input, init) =>
      await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(init.signal?.reason ?? new Error("aborted")),
          { once: true },
        );
      })) as typeof fetch;
    const runtime = new AccountExtractorRuntime(
      appDb,
      () =>
        ({
          microsoftGraphClientId: "client-id",
          microsoftGraphClientSecret: "client-secret",
          microsoftGraphRedirectUri: "https://example.com/callback",
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "",
          extractorShankeyunKey: "",
          extractorHotmail666Key: "",
        }) as never,
      (event) => published.push(event),
      () => false,
    );

    const snapshot = await runtime.start({
      sources: ["zhanghaoya"],
      quantity: 1,
      maxWaitSec: 60,
      accountType: "hotmail",
    });

    expect(snapshot.accountType).toBe("hotmail");
    expect(published.some((event) => event.type === "toast" && String(event.payload.message || "").includes("类型 Hotmail"))).toBe(true);

    await runtime.stop();
    await new Promise((resolve) => setTimeout(resolve, 20));
    appDb.close();
  });

  test("manual runtime alternates unlimited requests independently for each provider", async () => {
    const { appDb } = await createTempDb();
    const zhanghaoyaTypes: string[] = [];
    const shanyouxiangTypes: string[] = [];
    globalThis.fetch = (async (input: URL | RequestInfo) => {
      const url = new URL(String(input));
      if (url.hostname.includes("zhanghaoya")) {
        zhanghaoyaTypes.push(url.searchParams.get("type") || "");
        return new Response(JSON.stringify({ Code: 1, Message: "库存不足" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      shanyouxiangTypes.push(url.searchParams.get("leixing") || "");
      return new Response(JSON.stringify({ status: -1, msg: "库存不足" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    const runtime = new AccountExtractorRuntime(
      appDb,
      () =>
        ({
          microsoftGraphClientId: "client-id",
          microsoftGraphClientSecret: "client-secret",
          microsoftGraphRedirectUri: "https://example.com/callback",
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "shan-demo-key-001",
          extractorShankeyunKey: "",
          extractorHotmail666Key: "",
        }) as never,
      () => undefined,
      () => false,
    );
    const now = "2026-04-03T03:25:00.000Z";
    runtime["state"] = {
      runId: 8,
      status: "running",
      enabledSources: ["zhanghaoya", "shanyouxiang"],
      accountType: "unlimited",
      requestedUsableCount: 4,
      acceptedCount: 0,
      rawAttemptCount: 0,
      attemptBudget: 4,
      inFlightCount: 0,
      remainingWaitMs: 60_000,
      maxWaitMs: 60_000,
      startedAt: now,
      lastProvider: null,
      lastMessage: "准备提号",
      updatedAt: now,
      errorMessage: null,
      lastBatchId: null,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerInFlightCount: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerAttemptCount: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      lastBudgetTickMs: Date.now(),
      lastPublishedAtMs: 0,
      requestControllers: new Map(),
      pendingBootstrapCandidates: new Map(),
    };

    runtime["maybeDispatchRequests"](runtime["state"]!);
    await new Promise((resolve) => setTimeout(resolve, 0));
    runtime["state"]!.providerNextAttemptAtMs = { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 };
    runtime["maybeDispatchRequests"](runtime["state"]!);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(zhanghaoyaTypes).toEqual(["outlook", "hotmail"]);
    expect(shanyouxiangTypes).toEqual(["outlook", "hotmail"]);
    appDb.close();
  });

  test("only counts extractor accounts after bootstrap becomes ready", async () => {
    const { appDb } = await createTempDb();
    const runtime = new AccountExtractorRuntime(
      appDb,
      () =>
        ({
          microsoftGraphClientId: "client-id",
          microsoftGraphClientSecret: "client-secret",
          microsoftGraphRedirectUri: "https://example.com/callback",
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "",
          extractorShankeyunKey: "",
          extractorHotmail666Key: "",
        }) as never,
      () => undefined,
      (accountId) => {
        appDb.queueBrowserSessionBootstrap(accountId);
        return true;
      },
    );
    const now = "2026-04-03T03:30:00.000Z";
    runtime["state"] = {
      runId: 9,
      status: "running",
      enabledSources: ["zhanghaoya"],
      accountType: "outlook",
      requestedUsableCount: 1,
      acceptedCount: 0,
      rawAttemptCount: 1,
      attemptBudget: 0,
      inFlightCount: 1,
      remainingWaitMs: 60_000,
      maxWaitMs: 60_000,
      startedAt: now,
      lastProvider: "zhanghaoya",
      lastMessage: "账号鸭 请求已发出",
      updatedAt: now,
      errorMessage: null,
      lastBatchId: null,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerInFlightCount: { zhanghaoya: 1, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerAttemptCount: { zhanghaoya: 1, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      lastBudgetTickMs: Date.now(),
      lastPublishedAtMs: 0,
      requestControllers: new Map(),
      pendingBootstrapCandidates: new Map(),
    };

    runtime["finishRequest"]({
      runId: 9,
      provider: "zhanghaoya",
      requestId: "req-1",
      dispatchStartedAt: now,
      result: {
        provider: "zhanghaoya",
        accountType: "outlook",
        rawResponse: "{\"Code\":200}",
        candidates: [
          {
            provider: "zhanghaoya",
            rawPayload: "pending-a@outlook.com:pass-a",
            email: "pending-a@outlook.com",
            password: "pass-a",
            parseStatus: "parsed",
          },
        ],
        ok: true,
        failureCode: null,
        message: null,
        maskedKey: "zhya****0001",
      },
      rawResponse: "{\"Code\":200}",
      maskedKey: "zhya****0001",
      errorMessage: null,
      failureCode: null,
    });

    expect(runtime.getSnapshot()).toMatchObject({
      acceptedCount: 0,
      inFlightCount: 0,
    });
    expect(runtime["state"]?.pendingBootstrapCandidates.size).toBe(1);

    const [account] = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    expect(account?.browserSession?.status).toBe("pending");

    const pendingHistory = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(pendingHistory.rows[0]).toMatchObject({
      status: "pending_bootstrap",
      acceptedCount: 0,
      completedAt: null,
    });

    appDb.markBrowserSessionReady(account!.id, { browserEngine: "chrome", proxyNode: "Tokyo-01" });
    runtime["reconcilePendingBootstrapCandidates"](runtime["state"]);

    expect(runtime.getSnapshot().acceptedCount).toBe(1);

    const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(history.rows[0]).toMatchObject({
      status: "accepted",
      acceptedCount: 1,
    });
    expect(history.rows[0]?.items[0]).toMatchObject({
      email: "pending-a@outlook.com",
      acceptStatus: "accepted",
      rejectReason: null,
    });

    appDb.close();
  });

  test("manual stop keeps queued bootstrap candidates reconcilable until they settle", async () => {
    const { appDb } = await createTempDb();
    const runtime = new AccountExtractorRuntime(
      appDb,
      () =>
        ({
          microsoftGraphClientId: "client-id",
          microsoftGraphClientSecret: "client-secret",
          microsoftGraphRedirectUri: "https://example.com/callback",
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "",
          extractorShankeyunKey: "",
          extractorHotmail666Key: "",
        }) as never,
      () => undefined,
      (accountId) => {
        appDb.queueBrowserSessionBootstrap(accountId);
        return true;
      },
    );
    const now = "2026-04-03T03:40:00.000Z";
    runtime["state"] = {
      runId: 11,
      status: "running",
      enabledSources: ["zhanghaoya"],
      accountType: "outlook",
      requestedUsableCount: 1,
      acceptedCount: 0,
      rawAttemptCount: 1,
      attemptBudget: 0,
      inFlightCount: 1,
      remainingWaitMs: 60_000,
      maxWaitMs: 60_000,
      startedAt: now,
      lastProvider: "zhanghaoya",
      lastMessage: "账号鸭 请求已发出",
      updatedAt: now,
      errorMessage: null,
      lastBatchId: null,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerInFlightCount: { zhanghaoya: 1, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerAttemptCount: { zhanghaoya: 1, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      lastBudgetTickMs: Date.now(),
      lastPublishedAtMs: 0,
      requestControllers: new Map(),
      pendingBootstrapCandidates: new Map(),
    };

    runtime["finishRequest"]({
      runId: 11,
      provider: "zhanghaoya",
      requestId: "req-1",
      dispatchStartedAt: now,
      result: {
        provider: "zhanghaoya",
        accountType: "outlook",
        rawResponse: "{\"Code\":200}",
        candidates: [
          {
            provider: "zhanghaoya",
            rawPayload: "pending-stop@outlook.com:pass-a",
            email: "pending-stop@outlook.com",
            password: "pass-a",
            parseStatus: "parsed",
          },
        ],
        ok: true,
        failureCode: null,
        message: null,
        maskedKey: "zhya****0001",
      },
      rawResponse: "{\"Code\":200}",
      maskedKey: "zhya****0001",
      errorMessage: null,
      failureCode: null,
    });

    expect(runtime["state"]?.pendingBootstrapCandidates.size).toBe(1);

    const stopping = await runtime.stop();
    expect(stopping.status).toBe("stopping");
    expect(stopping.lastMessage).toContain("Bootstrap 结果");

    const [account] = appDb.listAccounts({ page: 1, pageSize: 10 }).rows;
    appDb.markBrowserSessionReady(account!.id, { browserEngine: "chrome", proxyNode: "Tokyo-01" });
    runtime["reconcilePendingBootstrapCandidates"](runtime["state"]);

    const stopped = runtime.getSnapshot();
    expect(stopped.status).toBe("stopped");
    expect(stopped.acceptedCount).toBe(1);
    expect(runtime["state"]?.pendingBootstrapCandidates.size).toBe(0);

    const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(history.rows[0]).toMatchObject({
      status: "accepted",
      acceptedCount: 1,
    });

    appDb.close();
  });

  test("run stays alive until pending bootstrap candidates settle", async () => {
    const { appDb } = await createTempDb();
    const runtime = new AccountExtractorRuntime(
      appDb,
      () =>
        ({
          microsoftGraphClientId: "client-id",
          microsoftGraphClientSecret: "client-secret",
          microsoftGraphRedirectUri: "https://example.com/callback",
          extractorZhanghaoyaKey: "zhya-demo-key-001",
          extractorShanyouxiangKey: "",
          extractorShankeyunKey: "",
          extractorHotmail666Key: "",
        }) as never,
      () => undefined,
      () => false,
    );
    const imported = appDb.importAccounts([{ email: "late-ready@outlook.com", password: "pass-a" }]);
    const accountId = imported.affectedIds[0]!;
    appDb.queueBrowserSessionBootstrap(accountId);
    const batch = appDb.createAccountExtractBatch({
      jobId: null,
      provider: "zhanghaoya",
      requestedUsableCount: 1,
      attemptBudget: 0,
      acceptedCount: 0,
      status: "rejected",
      errorMessage: "session_not_ready",
    });
    const item = appDb.createAccountExtractItem({
      batchId: batch.id,
      provider: "zhanghaoya",
      rawPayload: "late-ready@outlook.com:pass-a",
      email: "late-ready@outlook.com",
      password: "pass-a",
      parseStatus: "parsed",
      acceptStatus: "rejected",
      rejectReason: "session_not_ready",
      importedAccountId: accountId,
    });
    const now = "2026-04-03T04:00:00.000Z";
    runtime["state"] = {
      runId: 13,
      status: "running",
      enabledSources: ["zhanghaoya"],
      accountType: "outlook",
      requestedUsableCount: 1,
      acceptedCount: 0,
      rawAttemptCount: 1,
      attemptBudget: 0,
      inFlightCount: 0,
      remainingWaitMs: 0,
      maxWaitMs: 60_000,
      startedAt: now,
      lastProvider: "zhanghaoya",
      lastMessage: "等待时间已到，等待 1 个 Bootstrap 结果",
      updatedAt: now,
      errorMessage: null,
      lastBatchId: batch.id,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerInFlightCount: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      providerAttemptCount: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
      lastBudgetTickMs: Date.now(),
      lastPublishedAtMs: 0,
      requestControllers: new Map(),
      pendingBootstrapCandidates: new Map([[accountId, { accountId, batchId: batch.id, itemId: item.id, provider: "zhanghaoya" }]]),
    };

    const runPromise = runtime["runCurrentRound"](13);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(runtime.getSnapshot()).toMatchObject({
      status: "running",
      acceptedCount: 0,
      lastMessage: "等待时间已到，等待 1 个 Bootstrap 结果",
    });

    appDb.markBrowserSessionReady(accountId, { browserEngine: "chrome", proxyNode: "Tokyo-01" });
    await runPromise;

    expect(runtime.getSnapshot()).toMatchObject({
      status: "succeeded",
      acceptedCount: 1,
      lastMessage: "已接受 1 / 1 个账号",
    });
    expect(runtime["state"]?.pendingBootstrapCandidates.size).toBe(0);

    const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
    expect(history.rows[0]).toMatchObject({
      status: "accepted",
      acceptedCount: 1,
    });
    expect(history.rows[0]?.items[0]).toMatchObject({
      email: "late-ready@outlook.com",
      acceptStatus: "accepted",
      rejectReason: null,
      importedAccountId: accountId,
    });

    appDb.close();
  });
});
