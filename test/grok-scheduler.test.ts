import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
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
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-grok-scheduler-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { tempDir, dbPath, appDb };
}

afterEach(async () => {
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
  expect(stopped.status).toBe("stopping");

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
  expect(appDb.getCurrentJob("grok")?.status).toBe("force_stopping");
  expect(appDb.getCurrentJob("tavily")?.status).toBe("running");

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
