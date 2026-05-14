import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { GrokJobScheduler } from "../src/server/grok-scheduler";
import { AppDatabase, type AppSettings } from "../src/storage/app-db";
import {
  resetMailboxProviderGuardStateForTests,
  resolveMailboxProviderIdentity,
  setMailboxProviderCooldownForTests,
} from "../src/server/mailbox-provider-guard";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;
const originalProxyBrokerApiKey = process.env.PROXY_BROKER_API_KEY;

function createSchedulerSettings(overrides: Partial<AppSettings> = {}): AppSettings {
  return {
    localInstanceId: "test-instance",
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
    microsoftAccountBootstrapConcurrency: 3,
    microsoftAccountBootstrapWorkerTimeoutMs: 300000,
    microsoftAccountBootstrapKillGraceMs: 10000,
    microsoftAccountBootstrapLoginMode: "microsoft_graph",
    upstreamTavregBaseUrl: "https://tavreg-hikari.ivanli.cc",
    upstreamTavregSyncEnabled: false,
    upstreamTavregApiKey: "",
    upstreamTavregWriteback: "off",
    ...overrides,
  };
}

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-grok-scheduler-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { tempDir, dbPath, appDb };
}

beforeEach(() => {
  process.env.PROXY_BROKER_API_KEY = "pbk_test";
});

afterEach(async () => {
  globalThis.fetch = originalFetch;
  if (originalProxyBrokerApiKey == null) {
    delete process.env.PROXY_BROKER_API_KEY;
  } else {
    process.env.PROXY_BROKER_API_KEY = originalProxyBrokerApiKey;
  }
  resetMailboxProviderGuardStateForTests();
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

test("grok scheduler supports pause resume update and stop on its own site", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;

  const started = await scheduler.startJob({
    runMode: "headed",
    need: 3,
    parallel: 2,
    maxAttempts: 1,
  });
  expect(started.site).toBe("grok");
  expect(started.status).toBe("running");
  expect(started.maxAttempts).toBeGreaterThanOrEqual(3);
  expect(appDb.getCurrentJob("tavily")).toBeNull();

  const paused = scheduler.pauseCurrentJob();
  expect(paused.status).toBe("paused");

  const resumed = scheduler.resumeCurrentJob();
  expect(resumed.status).toBe("running");

  const updated = scheduler.updateCurrentJobLimits({
    parallel: 4,
    need: 5,
    maxAttempts: 2,
  });
  expect(updated.parallel).toBe(4);
  expect(updated.need).toBe(5);
  expect(updated.maxAttempts).toBeGreaterThanOrEqual(5);

  const stopped = scheduler.stopCurrentJob();
  expect(stopped.site).toBe("grok");
  expect(stopped.status).toBe("stopped");

  await scheduler.shutdown();
  appDb.close();
});

test("grok scheduler state changes do not mutate other site jobs", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;

  const tavilyJob = appDb.createJob({
    site: "tavily",
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: {},
  });
  const grokJob = await scheduler.startJob({
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });

  expect(grokJob.site).toBe("grok");
  expect(appDb.getCurrentJob("tavily")?.id).toBe(tavilyJob.id);

  scheduler.forceStopCurrentJob(true);
  expect(appDb.getCurrentJob("grok")?.status).toBe("stopped");
  expect(appDb.getCurrentJob("tavily")?.status).toBe("running");

  await scheduler.shutdown();
  appDb.close();
});

test("grok scheduler marks attempts as allocating proxy before broker launch completes", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).spawnAttempt = async (_job: any, attempt: any) => {
    expect(appDb.getAttempt(attempt.id)?.stage).toBe("allocating_proxy");
    expect(appDb.getAttempt(attempt.id)?.proxyNode).toBeNull();
    const error = new Error("Proxy Broker request timed out after 30000ms") as Error & { code?: string };
    error.code = "proxy_broker_request_timeout";
    throw error;
  };
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });

  await (scheduler as any).runLoop(job.id);
  const attempt = appDb.listAttempts(job.id)[0];

  expect(attempt?.status).toBe("failed");
  expect(attempt?.stage).toBe("failed");
  expect(attempt?.errorCode).toBe("proxy_broker_request_timeout");
  expect(appDb.getJob(job.id)?.status).toBe("failed");

  await scheduler.shutdown();
  appDb.close();
});

test("grok running reaper syncs worker stage markers into the attempt ledger", async () => {
  const { appDb, tempDir } = await createTempDb();
  const events: any[] = [];
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), (event) => events.push(event));
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "stage@example.test", outputDir: tempDir, stage: "spawned" });
  await writeFile(path.join(tempDir, "stage.json"), JSON.stringify({ stage: "checkout_started" }), "utf8");
  scheduler["activeAttempts"].set(attempt.id, {
    child: { pid: undefined, exitCode: null, signalCode: null, kill: () => true },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39090, mixedPort: 49090 },
    brokerSession: null,
    stopRequested: null,
    stopRequestedAtMs: null,
  } as any);

  (scheduler as any).reapActiveAttempts(job);

  expect(appDb.getAttempt(attempt.id)?.stage).toBe("checkout_started");
  expect(events.some((event) => event.type === "attempt.updated" && event.payload?.attempt?.stage === "checkout_started")).toBe(true);
  expect(scheduler["activeAttempts"].has(attempt.id)).toBe(true);

  await scheduler.shutdown();
  appDb.close();
});

test("grok running reaper routes exited error artifacts through the spawn finalizer", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "finalizer@example.test", outputDir: tempDir, stage: "spawned" });
  await writeFile(path.join(tempDir, "error.json"), JSON.stringify({ error: "worker failed after writing artifact" }), "utf8");
  let finalizerCalls = 0;
  let resolveFinalizer!: () => void;
  const finalizerDone = new Promise<void>((resolve) => {
    resolveFinalizer = resolve;
  });
  scheduler["activeAttempts"].set(attempt.id, {
    child: { pid: undefined, exitCode: 1, signalCode: null, kill: () => true },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39090, mixedPort: 49090 },
    brokerSession: null,
    stopRequested: null,
    stopRequestedAtMs: null,
    finalize: (runner: () => Promise<void> | void) => {
      finalizerCalls += 1;
      void (async () => {
        await runner();
        scheduler["activeAttempts"].delete(attempt.id);
        resolveFinalizer();
      })();
    },
  } as any);

  (scheduler as any).reapActiveAttempts(job);
  await finalizerDone;

  expect(finalizerCalls).toBe(1);
  expect(appDb.getAttempt(attempt.id)?.status).toBe("failed");
  expect(appDb.getJob(job.id)?.failureCount).toBe(1);
  expect(scheduler["activeAttempts"].has(attempt.id)).toBe(false);

  await scheduler.shutdown();
  appDb.close();
});

test("grok run loop refreshes job state after active attempt reaping before launching", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 2 });
  let reaped = false;
  let spawnCalls = 0;

  (scheduler as any).reapActiveAttempts = () => {
    if (reaped) return false;
    reaped = true;
    appDb.updateJobState(job.id, { successCount: 1, status: "completing" });
    return true;
  };
  (scheduler as any).spawnAttempt = async () => {
    spawnCalls += 1;
  };

  await (scheduler as any).runLoop(job.id);

  expect(spawnCalls).toBe(0);
  expect(appDb.getJob(job.id)?.status).toBe("completed");

  await scheduler.shutdown();
  appDb.close();
});

test("grok successful attempt writes back upstream when enabled", async () => {
  const { appDb, tempDir } = await createTempDb();
  const calls: Array<{ url: string; body: Record<string, unknown>; authorization: string | null }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      body: JSON.parse(String(init?.body || "{}")),
      authorization: String(new Headers(init?.headers || {}).get("authorization") || ""),
    });
    return Response.json({ ok: true });
  }) as typeof fetch;
  const scheduler = new GrokJobScheduler(
    appDb,
    process.cwd(),
    () =>
      createSchedulerSettings({
        upstreamTavregSyncEnabled: true,
        upstreamTavregApiKey: "upstream-secret",
        upstreamTavregBaseUrl: "https://upstream.example.test",
        upstreamTavregWriteback: "success_only",
        localInstanceId: "grok-instance",
      }),
    () => undefined,
  );
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "grok@example.test", outputDir: tempDir });
  await writeFile(
    path.join(tempDir, "result.json"),
    JSON.stringify({
      email: "grok@example.test",
      password: "grok-pass",
      sso: "grok-sso-token",
      ssoRw: "grok-sso-rw",
      cfClearance: "cf-clearance",
      checkoutUrl: "https://grok.example.test/checkout",
      birthDate: "1999-01-02",
      proxy: { ip: "198.51.100.88" },
    }),
  );

  await (scheduler as any).handleAttemptExit(job.id, attempt.id, tempDir, 0, null, { stopRequested: null });

  expect(calls).toHaveLength(1);
  expect(calls[0]?.url).toBe("https://upstream.example.test/api/integration/v1/keys/grok/success");
  expect(calls[0]?.authorization).toBe("Bearer upstream-secret");
  expect(calls[0]?.body).toMatchObject({
    sourceOrigin: "local:grok:grok-instance",
    sourceKeyId: 1,
    email: "grok@example.test",
    password: "grok-pass",
    sso: "grok-sso-token",
    extractedIp: "198.51.100.88",
  });
  await scheduler.shutdown();
  appDb.close();
});

test("grok scheduler does not create a launch storm while mailbox cooldown is active", async () => {
  const { appDb } = await createTempDb();
  process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
  process.env.CFMAIL_API_KEY = "cf_key_test";
  const identity = resolveMailboxProviderIdentity({
    provider: "cfmail",
    baseUrl: process.env.CFMAIL_BASE_URL,
    credential: process.env.CFMAIL_API_KEY,
  });
  expect(identity).not.toBeNull();

  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).spawnAttempt = async () => {
    setMailboxProviderCooldownForTests(identity!, "mailbox_rate_limited", new Date(Date.now() + 800).toISOString());
    throw new Error("mailbox_rate_limited");
  };

  const job = await scheduler.startJob({
    runMode: "headless",
    need: 5,
    parallel: 5,
    maxAttempts: 5,
  });

  await Bun.sleep(250);

  const attempts = appDb.listAttempts(job.id, false);
  expect(attempts).toHaveLength(1);
  expect(attempts[0]?.errorCode).toBe("mailbox_rate_limited");
  expect(scheduler.getCooldownSnapshot()?.sourceErrorCode).toBe("mailbox_rate_limited");

  await scheduler.shutdown();
  appDb.close();
});

test("grok force stop is idempotent and reaps stale active attempts", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "stale@example.test", outputDir: tempDir });
  appDb.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
  let released = false;
  const signals: string[] = [];
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: null,
      signalCode: null,
      kill: (signal: string) => {
        signals.push(signal);
        return true;
      },
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39090, mixedPort: 49090 },
    stopRequested: "force_stop",
    stopRequestedAtMs: Date.now() - 31_000,
    releaseResources: async () => {
      released = true;
    },
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  const stopped = scheduler.forceStopCurrentJob(true);

  expect(stopped.status).toBe("stopped");
  expect(appDb.getAttempt(attempt.id)?.status).toBe("stopped");
  expect(appDb.getAttempt(attempt.id)?.errorCode).toBe("force_stopped");
  expect(scheduler["activeAttempts"].size).toBe(0);
  expect(released).toBe(true);
  expect(signals).toEqual([]);

  await scheduler.shutdown();
  appDb.close();
});

test("grok force stop reaps running attempts that already wrote an error artifact", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "artifact@example.test", outputDir: tempDir });
  appDb.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
  await writeFile(path.join(tempDir, "error.json"), JSON.stringify({ error: "native_turnstile_token_missing" }), "utf8");
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: null,
      signalCode: null,
      kill: () => true,
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39091, mixedPort: 49091 },
    stopRequested: "force_stop",
    stopRequestedAtMs: Date.now() - 31_000,
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  const stopped = scheduler.forceStopCurrentJob(true);
  const stoppedAttempt = appDb.getAttempt(attempt.id);

  expect(stopped.status).toBe("stopped");
  expect(stoppedAttempt?.status).toBe("stopped");
  expect(stoppedAttempt?.errorCode).toBe("force_stopped");
  expect(stoppedAttempt?.errorMessage).toBe("native_turnstile_token_missing");
  expect(scheduler["activeAttempts"].size).toBe(0);

  await scheduler.shutdown();
  appDb.close();
});

test("grok force stop keeps ownership of error-artifact attempts until exit or reap timeout", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "live-artifact@example.test", outputDir: tempDir });
  appDb.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
  await writeFile(path.join(tempDir, "error.json"), JSON.stringify({ error: "native_turnstile_token_missing" }), "utf8");
  let released = false;
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: null,
      signalCode: null,
      kill: () => true,
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39093, mixedPort: 49093 },
    stopRequested: "force_stop",
    stopRequestedAtMs: Date.now(),
    releaseResources: async () => {
      released = true;
    },
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  const stillStopping = scheduler.forceStopCurrentJob(true);

  expect(stillStopping.status).toBe("force_stopping");
  expect(appDb.getAttempt(attempt.id)?.status).toBe("running");
  expect(scheduler["activeAttempts"].has(attempt.id)).toBe(true);
  expect(released).toBe(false);

  scheduler["activeAttempts"].clear();
  await scheduler.shutdown();
  appDb.close();
});

test("grok running reaper force stops stale attempts and releases broker resources", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "stale-grok@example.test", outputDir: tempDir });
  let killCount = 0;
  let released = false;
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: null,
      signalCode: null,
      kill: () => {
        killCount += 1;
        return true;
      },
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39094, mixedPort: 49094 },
    brokerSession: { session: { session_id: "sess-stale-grok" } },
    stopRequested: null,
    lastProgressAtMs: Date.now() - 10 * 60_000 - 1,
    releaseResources: async () => {
      released = true;
    },
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  scheduler["reapActiveAttempts"](appDb.getJob(job.id)!);
  expect(killCount).toBe(1);
  expect(appDb.getAttempt(attempt.id)?.status).toBe("running");
  expect(released).toBe(false);

  (activeAttempt as any).stopRequested = "force_stop";
  (activeAttempt as any).stopRequestedAtMs = Date.now() - 30_000 - 1;
  scheduler["reapActiveAttempts"](appDb.getJob(job.id)!);

  expect(appDb.getAttempt(attempt.id)?.status).toBe("stopped");
  expect(scheduler["activeAttempts"].size).toBe(0);
  expect(released).toBe(true);

  await scheduler.shutdown();
  appDb.close();
});

test("grok running reaper keeps silent attempts with fresh heartbeat alive", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "heartbeat-grok@example.test", outputDir: tempDir });
  await writeFile(path.join(tempDir, "heartbeat.json"), JSON.stringify({ updatedAt: new Date().toISOString() }), "utf8");
  let killCount = 0;
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: null,
      signalCode: null,
      kill: () => {
        killCount += 1;
        return true;
      },
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39095, mixedPort: 49095 },
    brokerSession: { session: { session_id: "sess-heartbeat-grok" } },
    stopRequested: null,
    lastProgressAtMs: Date.now() - 10 * 60_000 - 1,
    releaseResources: async () => {},
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  scheduler["reapActiveAttempts"](appDb.getJob(job.id)!);

  expect(killCount).toBe(0);
  expect(appDb.getAttempt(attempt.id)?.status).toBe("running");
  expect(scheduler["activeAttempts"].size).toBe(1);

  scheduler["activeAttempts"].clear();
  await scheduler.shutdown();
  appDb.close();
});

test("grok running reaper uses worker registration progress instead of attempt creation time", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "fresh-worker-grok@example.test", outputDir: tempDir });
  (appDb as any).db
    .query("UPDATE job_attempts SET started_at = ? WHERE id = ?")
    .run(new Date(Date.now() - 10 * 60_000 - 5_000).toISOString(), attempt.id);
  let killCount = 0;
  scheduler["activeAttempts"].set(attempt.id, {
    child: {
      pid: undefined,
      exitCode: null,
      signalCode: null,
      kill: () => {
        killCount += 1;
        return true;
      },
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39096, mixedPort: 49096 },
    brokerSession: { session: { session_id: "sess-fresh-grok" } },
    stopRequested: null,
    lastProgressAtMs: Date.now(),
    releaseResources: async () => {},
  } as any);

  scheduler["reapActiveAttempts"](appDb.getJob(job.id)!);

  expect(killCount).toBe(0);
  expect(appDb.getAttempt(attempt.id)?.status).toBe("running");
  expect(scheduler["activeAttempts"].size).toBe(1);

  scheduler["activeAttempts"].clear();
  await scheduler.shutdown();
  appDb.close();
});

test("grok graceful stop reaps exited attempts even without an error artifact", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "exited@example.test", outputDir: tempDir });
  appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: 1,
      signalCode: null,
      kill: () => true,
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39092, mixedPort: 49092 },
    stopRequested: null,
    stopRequestedAtMs: null,
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  const stopped = scheduler.stopCurrentJob();
  const failedAttempt = appDb.getAttempt(attempt.id);

  expect(stopped.status).toBe("stopped");
  expect(failedAttempt?.status).toBe("failed");
  expect(failedAttempt?.errorCode).toBe("exit_1");
  expect(failedAttempt?.errorMessage).toBe("process exited with code 1");
  expect(scheduler["activeAttempts"].size).toBe(0);

  await scheduler.shutdown();
  appDb.close();
});

test("grok graceful stop lets exited successful attempts use the normal result finalizer", async () => {
  const { appDb, tempDir } = await createTempDb();
  const scheduler = new GrokJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;
  const job = appDb.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const attempt = appDb.createAttempt(job.id, { accountEmail: "success-exit@example.test", outputDir: tempDir });
  appDb.updateJobState(job.id, { status: "stopping", pausedAt: null });
  await writeFile(
    path.join(tempDir, "result.json"),
    JSON.stringify({
      email: "success-exit@example.test",
      password: "grok-pass",
      sso: "grok-sso-token",
    }),
    "utf8",
  );
  let resolveFinalizer!: () => void;
  const finalizerDone = new Promise<void>((resolve) => {
    resolveFinalizer = resolve;
  });
  const activeAttempt = {
    child: {
      pid: undefined,
      exitCode: 0,
      signalCode: null,
      kill: () => true,
    },
    attempt,
    outputDir: tempDir,
    reservedPorts: { apiPort: 39094, mixedPort: 49094 },
    stopRequested: null,
    stopRequestedAtMs: null,
    finalize: (runner: () => Promise<void> | void) => {
      void (async () => {
        await runner();
        scheduler["activeAttempts"].delete(attempt.id);
        scheduler["maybeFinalizeStoppedJob"](job.id);
        resolveFinalizer();
      })();
    },
  };
  scheduler["activeAttempts"].set(attempt.id, activeAttempt as any);

  const stopping = scheduler.stopCurrentJob();
  await finalizerDone;

  expect(stopping.status).toBe("stopping");
  expect(appDb.getAttempt(attempt.id)?.status).toBe("succeeded");
  expect(appDb.getGrokApiKey(1)?.sso).toBe("grok-sso-token");
  expect(appDb.getJob(job.id)?.status).toBe("stopped");
  expect(scheduler["activeAttempts"].size).toBe(0);

  await scheduler.shutdown();
  appDb.close();
});
