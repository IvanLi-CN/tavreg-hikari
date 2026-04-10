import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { fetchSingleExtractedAccount } from "../src/server/account-extractor";
import { JobScheduler } from "../src/server/scheduler";
import { AppDatabase, type AppSettings } from "../src/storage/app-db";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;
const originalChromeExecutablePath = process.env.CHROME_EXECUTABLE_PATH;

function createSchedulerSettings(overrides: Partial<AppSettings> = {}): AppSettings {
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
    microsoftGraphClientId: "",
    microsoftGraphClientSecret: "",
    microsoftGraphRedirectUri: "",
    microsoftGraphAuthority: "common",
    ...overrides,
  };
}

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-stop-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { dbPath, appDb };
}

function markBrowserSessionReady(appDb: AppDatabase, accountId: number) {
  return appDb.markBrowserSessionReady(accountId, {
    browserEngine: "chrome",
    proxyNode: "Tokyo-01",
    proxyIp: "1.1.1.1",
    proxyCountry: "JP",
    proxyRegion: "Tokyo",
    proxyCity: "Tokyo",
    proxyTimezone: "Asia/Tokyo",
  });
}

async function createFakeFingerprintBrowser(rootDir: string): Promise<string> {
  const dir = path.join(rootDir, "fingerprint-browser");
  const executablePath = path.join(dir, "chrome");
  await mkdir(dir, { recursive: true });
  await writeFile(executablePath, "#!/bin/sh\nexit 0\n");
  await chmod(executablePath, 0o755);
  return executablePath;
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  if (originalChromeExecutablePath == null) {
    delete process.env.CHROME_EXECUTABLE_PATH;
  } else {
    process.env.CHROME_EXECUTABLE_PATH = originalChromeExecutablePath;
  }
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

test("paused jobs can stop immediately into the stopped terminal state", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  appDb.updateJobState(job.id, { status: "paused", pausedAt: new Date().toISOString() });
  const stopped = scheduler.stopCurrentJob();

  expect(stopped.status).toBe("stopped");
  expect(stopped.completedAt).not.toBeNull();

  await scheduler.shutdown();
  appDb.close();
});

test("scheduler preserves hotmail auto extract account type across start and updates", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(
    appDb,
    "tavily",
    process.cwd(),
    dbPath,
    () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
    () => undefined,
  );

  const started = await scheduler.startJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "hotmail",
  });
  expect(started.autoExtractAccountType).toBe("hotmail");
  expect(scheduler.getAutoExtractSnapshot(started.id)?.accountType).toBe("hotmail");

  const updated = scheduler.updateCurrentJobLimits({
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 2,
    autoExtractMaxWaitSec: 90,
    autoExtractAccountType: "outlook",
  });
  expect(updated.autoExtractAccountType).toBe("outlook");
  expect(scheduler.getAutoExtractSnapshot(started.id)?.accountType).toBe("outlook");

  await scheduler.shutdown();
  appDb.close();
});

test("scheduler preserves unlimited auto extract account type across start and updates", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(
    appDb,
    "tavily",
    process.cwd(),
    dbPath,
    () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
    () => undefined,
  );

  const started = await scheduler.startJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "unlimited",
  });
  expect(started.autoExtractAccountType).toBe("unlimited");
  expect(scheduler.getAutoExtractSnapshot(started.id)?.accountType).toBe("unlimited");

  const updated = scheduler.updateCurrentJobLimits({
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 2,
    autoExtractMaxWaitSec: 90,
    autoExtractAccountType: "unlimited",
  });
  expect(updated.autoExtractAccountType).toBe("unlimited");
  expect(scheduler.getAutoExtractSnapshot(started.id)?.accountType).toBe("unlimited");

  await scheduler.shutdown();
  appDb.close();
});

test("scheduler alternates unlimited requests independently for each provider", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(
    appDb,
    "tavily",
    process.cwd(),
    dbPath,
    () =>
      createSchedulerSettings({
        extractorZhanghaoyaKey: "zhya-demo-key-001",
        extractorShanyouxiangKey: "shan-demo-key-001",
      }),
    () => undefined,
  );
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

  const job = appDb.createJob({
    runMode: "headed",
    need: 4,
    parallel: 1,
    maxAttempts: 4,
    autoExtractSources: ["zhanghaoya", "shanyouxiang"],
    autoExtractQuantity: 4,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "unlimited",
  });
  const now = new Date().toISOString();
  scheduler["autoExtractStates"].set(job.id, {
    jobId: job.id,
    enabledSources: ["zhanghaoya", "shanyouxiang"],
    accountType: "unlimited",
    maxWaitMs: 60_000,
    remainingWaitMs: 60_000,
    currentRoundTarget: 4,
    attemptBudget: 4,
    acceptedCount: 0,
    rawAttemptCount: 0,
    inFlightCount: 0,
    nextProviderIndex: 0,
    providerNextAttemptAtMs: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
    providerInFlightCount: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
    providerAttemptCount: { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 },
    phase: "extracting",
    startedAt: now,
    lastProvider: null,
    lastMessage: "dispatching",
    updatedAt: now,
    lastBudgetTickMs: Date.now(),
    requestControllers: new Map(),
    pendingBootstrapCandidates: new Map(),
  });

  await scheduler["maybeAutoExtract"](job);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const state = scheduler["autoExtractStates"].get(job.id)!;
  state.providerNextAttemptAtMs = { zhanghaoya: 0, shanyouxiang: 0, shankeyun: 0, hotmail666: 0 };
  await scheduler["maybeAutoExtract"](job);
  await new Promise((resolve) => setTimeout(resolve, 0));

  expect(zhanghaoyaTypes).toEqual(["outlook", "hotmail"]);
  expect(shanyouxiangTypes).toEqual(["outlook", "hotmail"]);

  await scheduler.shutdown();
  appDb.close();
});

test("force stop requires explicit confirmation", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });

  expect(() => scheduler.forceStopCurrentJob()).toThrow("force stop requires confirmForceStop=true");

  await scheduler.shutdown();
  appDb.close();
});

test("force stop aborts tracked auto extract requests and terminates active attempts", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(
    appDb,
    "tavily",
    process.cwd(),
    dbPath,
    () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
    () => undefined,
  );

  const imported = appDb.importAccounts([{ email: "stop-force@example.test", password: "pw123456" }]);
  const accountId = imported.affectedIds[0]!;
  const account = appDb.getAccount(accountId)!;
  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "outlook",
  });
  const attempt = appDb.createAttempt(job.id, {
    accountId,
    accountEmail: account.microsoftEmail,
    outputDir: path.join(process.cwd(), "tmp-force-stop-attempt"),
  });
  const signals: string[] = [];
  const activeAttempt = {
    child: {
      pid: 0,
      kill: (signal: string) => {
        signals.push(signal);
        return true;
      },
    },
    attempt,
    account,
    outputDir: path.join(process.cwd(), "tmp-force-stop-attempt"),
    reservedPorts: { apiPort: 39090, mixedPort: 49090 },
    tail: [],
    stopRequested: null,
  } as any;
  scheduler["activeAttempts"].set(attempt.id, activeAttempt);

  const state = scheduler["createAutoExtractState"](job);
  state.inFlightCount = 1;
  const controller = new AbortController();
  state.requestControllers.set("req-1", controller);
  scheduler["autoExtractStates"].set(job.id, state);

  const next = scheduler.forceStopCurrentJob(true);

  expect(next.status).toBe("force_stopping");
  expect(controller.signal.aborted).toBe(true);
  expect(signals).toContain("SIGTERM");
  expect(activeAttempt.stopRequested).toBe("force_stop");

  scheduler["activeAttempts"].clear();
  state.inFlightCount = 0;
  state.requestControllers.clear();
  const stopped = scheduler["maybeFinalizeStoppedJob"](job.id);
  expect(stopped?.status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("force stop records aborted auto extract requests as manual stops", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(
    appDb,
    "tavily",
    process.cwd(),
    dbPath,
    () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
    () => undefined,
  );

  globalThis.fetch = (async (_input, init) =>
    await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        "abort",
        () => {
          reject(init.signal?.reason ?? new Error("aborted"));
        },
        { once: true },
      );
    })) as typeof fetch;

  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "outlook",
  });
  const state = scheduler["createAutoExtractState"](job);
  const roundStartedAt = new Date().toISOString();
  state.phase = "extracting";
  state.startedAt = roundStartedAt;
  state.currentRoundTarget = 1;
  state.inFlightCount = 1;
  scheduler["autoExtractStates"].set(job.id, state);

  scheduler["launchAutoExtractRequest"]({
    jobId: job.id,
    provider: "zhanghaoya",
    accountType: "outlook",
    alternationIndex: 0,
    requestedUsableCount: 1,
    attemptBudget: 1,
    dispatchStartedAt: roundStartedAt,
    roundStartedAt,
    requestId: "req-force-stop-batch",
  });
  await new Promise((resolve) => setTimeout(resolve, 0));

  scheduler.forceStopCurrentJob(true);
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));

  const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
  expect(history.rows[0]).toMatchObject({
    provider: "zhanghaoya",
    status: "rejected",
    errorMessage: "stopped by user",
  });
  expect(appDb.getJob(job.id)?.status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("graceful stop keeps extractor aborts out of manual-stop history", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(
    appDb,
    "tavily",
    process.cwd(),
    dbPath,
    () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
    () => undefined,
  );

  globalThis.fetch = (async () => {
    const error = new Error("request timed out");
    error.name = "AbortError";
    throw error;
  }) as unknown as typeof fetch;

  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    autoExtractSources: ["zhanghaoya"],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "outlook",
  });
  const state = scheduler["createAutoExtractState"](job);
  const roundStartedAt = new Date().toISOString();
  state.phase = "extracting";
  state.startedAt = roundStartedAt;
  state.currentRoundTarget = 1;
  state.inFlightCount = 1;
  scheduler["autoExtractStates"].set(job.id, state);

  expect(scheduler.stopCurrentJob().status).toBe("stopping");

  scheduler["launchAutoExtractRequest"]({
    jobId: job.id,
    provider: "zhanghaoya",
    accountType: "outlook",
    alternationIndex: 0,
    requestedUsableCount: 1,
    attemptBudget: 1,
    dispatchStartedAt: roundStartedAt,
    roundStartedAt,
    requestId: "req-graceful-stop-batch",
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));

  const history = appDb.listAccountExtractHistory({ page: 1, pageSize: 10 });
  expect(history.rows[0]).toMatchObject({
    provider: "zhanghaoya",
    status: "error",
    errorMessage: "request aborted",
  });
  expect(appDb.getJob(job.id)?.status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("control actions stay idempotent under duplicate UI submissions", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });

  expect(scheduler.pauseCurrentJob().status).toBe("paused");
  expect(scheduler.pauseCurrentJob().status).toBe("paused");
  expect(scheduler.resumeCurrentJob().status).toBe("running");
  expect(scheduler.resumeCurrentJob().status).toBe("running");
  expect(scheduler.stopCurrentJob().status).toBe("stopped");
  expect(scheduler.stopCurrentJob().status).toBe("stopped");
  expect(scheduler.forceStopCurrentJob(true).status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("runLoop rechecks stop state before launching more attempts", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const imported = appDb.importAccounts([
    { email: "loop-stop-1@example.test", password: "pw123456" },
    { email: "loop-stop-2@example.test", password: "pw123456" },
  ]);
  imported.affectedIds.forEach((accountId) => markBrowserSessionReady(appDb, accountId));

  let spawnCalls = 0;
  scheduler["spawnAttempt"] = async () => {
    spawnCalls += 1;
    if (spawnCalls === 1) {
      scheduler.stopCurrentJob();
    }
    return true;
  };

  const job = await scheduler.startJob({
    runMode: "headed",
    need: 2,
    parallel: 2,
    maxAttempts: 2,
  });

  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 150));

  expect(spawnCalls).toBe(1);
  expect(appDb.getJob(job.id)?.status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("force stop wins over a last-moment successful worker exit", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const imported = appDb.importAccounts([{ email: "force-stop-success@example.test", password: "pw123456" }]);
  const accountId = imported.affectedIds[0]!;
  const account = appDb.getAccount(accountId)!;
  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  appDb.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
  const outputDir = path.join(path.dirname(dbPath), "force-stop-success-exit");
  await mkdir(outputDir, { recursive: true });
  await writeFile(path.join(outputDir, "result.json"), JSON.stringify({ apiKey: "tvly-force-stop-win-001" }));
  const attempt = appDb.createAttempt(job.id, {
    accountId,
    accountEmail: account.microsoftEmail,
    outputDir,
  });

  await scheduler["handleAttemptExit"](
    job.id,
    attempt.id,
    accountId,
    outputDir,
    0,
    null,
    {
      child: { pid: 0, kill: () => true },
      attempt,
      account,
      outputDir,
      reservedPorts: { apiPort: 39090, mixedPort: 49090 },
      tail: [],
      stopRequested: "force_stop",
    } as any,
  );

  expect(appDb.getAttempt(attempt.id)).toMatchObject({
    status: "stopped",
    stage: "stopped",
  });
  expect(appDb.getAccount(accountId)?.hasApiKey).toBe(false);

  await scheduler.shutdown();
  appDb.close();
});

test("pending launches block stop finalization until setup drains", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const imported = appDb.importAccounts([{ email: "pending-stop@example.test", password: "pw123456" }]);
  const accountId = imported.affectedIds[0]!;
  const account = appDb.getAccount(accountId)!;
  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  const attempt = appDb.createAttempt(job.id, {
    accountId,
    accountEmail: account.microsoftEmail,
    outputDir: path.join(process.cwd(), "tmp-pending-stop-attempt"),
  });
  scheduler["pendingAttemptLaunches"].set(attempt.id, {
    jobId: job.id,
    attempt,
    account,
    stopRequested: null,
  });

  const stopping = scheduler.stopCurrentJob();
  expect(stopping.status).toBe("stopping");

  const forceStopping = scheduler.forceStopCurrentJob(true);
  expect(forceStopping.status).toBe("force_stopping");
  expect(scheduler["pendingAttemptLaunches"].get(attempt.id)?.stopRequested).toBe("force_stop");

  scheduler["pendingAttemptLaunches"].delete(attempt.id);
  const stopped = scheduler["maybeFinalizeStoppedJob"](job.id);
  expect(stopped?.status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("graceful stop rolls back pending launches before they start", async () => {
  const { appDb, dbPath } = await createTempDb();
  process.env.CHROME_EXECUTABLE_PATH = await createFakeFingerprintBrowser(path.dirname(dbPath));
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const imported = appDb.importAccounts([{ email: "pending-graceful-stop@example.test", password: "pw123456" }]);
  markBrowserSessionReady(appDb, imported.affectedIds[0]!);
  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  const leased = appDb.leaseNextAccount(job.id)!;
  const outputDir = path.join(path.dirname(dbPath), "pending-graceful-stop-attempt");
  const attempt = appDb.createAttempt(job.id, {
    accountId: leased.id,
    accountEmail: leased.microsoftEmail,
    outputDir,
  });
  const pendingLaunch = {
    jobId: job.id,
    attempt,
    account: leased,
    stopRequested: null,
  };

  appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });
  const started = await scheduler["spawnAttempt"](appDb.getJob(job.id)!, leased, attempt, outputDir, pendingLaunch);

  expect(started).toBe(false);
  expect(appDb.getAttempt(attempt.id)).toBeNull();
  expect(appDb.getJob(job.id)?.launchedCount).toBe(0);
  expect(appDb.getAccount(leased.id)).toMatchObject({
    lastResultStatus: "ready",
    leaseJobId: null,
  });

  await scheduler.shutdown();
  appDb.close();
});

test("shutdown preserves stopped semantics while a manual stop is still draining", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, "tavily", process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const imported = appDb.importAccounts([{ email: "stop-shutdown@example.test", password: "pw123456" }]);
  const accountId = imported.affectedIds[0]!;
  const account = appDb.getAccount(accountId)!;
  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });
  const attempt = appDb.createAttempt(job.id, {
    accountId,
    accountEmail: account.microsoftEmail,
    outputDir: path.join(process.cwd(), "tmp-stop-shutdown-attempt"),
  });
  const signals: string[] = [];
  const listeners = new Map<string, () => void>();
  const activeAttempt = {
    child: {
      pid: 0,
      kill: (signal: string) => {
        signals.push(signal);
        queueMicrotask(() => listeners.get("close")?.());
        return true;
      },
      once: (event: string, handler: () => void) => {
        listeners.set(event, handler);
      },
    },
    attempt,
    account,
    outputDir: path.join(process.cwd(), "tmp-stop-shutdown-attempt"),
    reservedPorts: { apiPort: 39090, mixedPort: 49090 },
    tail: [],
    stopRequested: null,
  } as any;
  scheduler["activeAttempts"].set(attempt.id, activeAttempt);

  await scheduler.shutdown();

  expect(signals).toContain("SIGTERM");
  expect(activeAttempt.stopRequested).toBe("force_stop");
  appDb.close();
});

test("external abort signal cancels account extractor requests", async () => {
  globalThis.fetch = (async (_input, init) =>
    await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        "abort",
        () => {
          reject(init.signal?.reason ?? new Error("aborted"));
        },
        { once: true },
      );
    })) as typeof fetch;

  const controller = new AbortController();
  const pending = fetchSingleExtractedAccount({
    provider: "zhanghaoya",
    config: {
      zhanghaoyaKey: "zhya-demo-key-001",
      shanyouxiangKey: "",
      shankeyunKey: "",
      hotmail666Key: "",
      timeoutMs: 10_000,
    },
    signal: controller.signal,
  });

  controller.abort(new Error("force stop requested by user"));

  await expect(pending).rejects.toThrow("force stop requested by user");
});
