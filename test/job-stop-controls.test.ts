import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { fetchSingleExtractedAccount } from "../src/server/account-extractor";
import { JobScheduler } from "../src/server/scheduler";
import { AppDatabase, type AppSettings } from "../src/storage/app-db";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;

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

afterEach(async () => {
  globalThis.fetch = originalFetch;
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

test("paused jobs can stop immediately into the stopped terminal state", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

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

test("force stop requires explicit confirmation", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

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
    process.cwd(),
    dbPath,
    () => createSchedulerSettings({ extractorZhanghaoyaKey: "zhya-demo-key-001" }),
    () => undefined,
  );

  const imported = appDb.importAccounts([{ email: "stop-force@outlook.com", password: "pw123456" }]);
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
  const attempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "tmp-force-stop-attempt"));
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

test("shutdown preserves stopped semantics while a manual stop is still draining", async () => {
  const { appDb, dbPath } = await createTempDb();
  const scheduler = new JobScheduler(appDb, process.cwd(), dbPath, () => createSchedulerSettings(), () => undefined);

  const imported = appDb.importAccounts([{ email: "stop-shutdown@outlook.com", password: "pw123456" }]);
  const accountId = imported.affectedIds[0]!;
  const account = appDb.getAccount(accountId)!;
  const job = appDb.createJob({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });
  const attempt = appDb.createAttempt(job.id, accountId, path.join(process.cwd(), "tmp-stop-shutdown-attempt"));
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
