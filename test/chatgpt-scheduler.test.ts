import { afterEach, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ChatGptJobScheduler } from "../src/server/chatgpt-scheduler";
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

function createDraft(index = 1) {
  return {
    email: `draft-${index}@example.com`,
    password: `Password${index}23!`,
    nickname: `Hana ${index}`,
    birthDate: "1995-04-02",
    mailboxId: `mbx_${index}`,
  };
}

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-chatgpt-scheduler-"));
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

test("chatgpt scheduler blocks fresh starts during auth challenge cooldown", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: {},
  });
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: "mailbox@example.com",
    outputDir: path.join(process.cwd(), "tmp-chatgpt-cooldown"),
  });
  appDb.updateAttempt(attempt.id, {
    status: "failed",
    stage: "email_submit",
    errorCode: "chatgpt_auth_challenge_detected",
    errorMessage: "chatgpt_auth_challenge_detected:https://auth.openai.com/oauth/authorize?__cf_chl_rt_tk=demo",
    completedAt: new Date().toISOString(),
    durationMs: 1234,
  });
  appDb.stopJob(job.id);

  const cooldown = scheduler.getCooldownSnapshot();
  expect(cooldown?.active).toBe(true);
  expect(cooldown?.sourceAttemptId).toBe(attempt.id);

  await expect(
    scheduler.startJob({
      runMode: "headed",
      need: 1,
      parallel: 1,
      maxAttempts: 1,
    }),
  ).rejects.toThrow(/retry after/i);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler allows starts after cooldown window expires", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(1),
  });
  (scheduler as any).ensureLoop = () => undefined;
  (scheduler as any).spawnAttempt = async () => undefined;

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: {},
  });
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: "mailbox@example.com",
    outputDir: path.join(process.cwd(), "tmp-chatgpt-cooldown-expired"),
  });
  appDb.updateAttempt(attempt.id, {
    status: "failed",
    stage: "email_submit",
    errorCode: "chatgpt_auth_challenge_detected",
    errorMessage: "chatgpt_auth_challenge_detected:https://auth.openai.com/oauth/authorize?__cf_chl_rt_tk=demo",
    completedAt: new Date(Date.now() - 31 * 60_000).toISOString(),
    durationMs: 1234,
  });
  appDb.stopJob(job.id);

  expect(scheduler.getCooldownSnapshot()).toBeNull();

  const next = await scheduler.startJob({
    runMode: "headed",
    need: 2,
    parallel: 2,
    maxAttempts: 3,
  });
  expect(next.site).toBe("chatgpt");
  expect(next.status).toBe("running");
  expect(next.need).toBe(2);
  expect(next.parallel).toBe(2);
  expect(next.maxAttempts).toBe(3);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler starts without pre-provisioned drafts in payload", async () => {
  const { appDb } = await createTempDb();
  let generatedDrafts = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(++generatedDrafts),
  });
  (scheduler as any).ensureLoop = () => undefined;
  (scheduler as any).spawnAttempt = async () => undefined;

  const next = await scheduler.startJob({
    runMode: "headless",
    need: 3,
    parallel: 2,
    maxAttempts: 5,
  });

  expect(next.runMode).toBe("headless");
  expect(next.need).toBe(3);
  expect(next.parallel).toBe(2);
  expect(next.maxAttempts).toBe(5);
  expect(next.payloadJson).toEqual({});
  expect(generatedDrafts).toBe(1);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler persists and updates upstream group selection in job payload", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(1),
  });
  (scheduler as any).ensureLoop = () => undefined;
  (scheduler as any).spawnAttempt = async () => undefined;

  const started = await scheduler.startJob({
    runMode: "headless",
    need: 2,
    parallel: 1,
    maxAttempts: 2,
    upstreamGroupName: "sync-ready",
  });
  expect(started.payloadJson).toEqual({ upstreamGroupName: "sync-ready" });

  const updated = scheduler.updateCurrentJobLimits({
    upstreamGroupName: "warm-pool",
  });
  expect(updated.payloadJson).toEqual({ upstreamGroupName: "warm-pool" });

  const cleared = scheduler.updateCurrentJobLimits({
    upstreamGroupName: "",
  });
  expect(cleared.payloadJson).toEqual({});

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler does not block attempt finalization on background supplement", async () => {
  const { appDb, tempDir } = await createTempDb();
  let releaseSupplement: () => void = () => {};
  const supplementStarted = new Promise<void>((resolve) => {
    releaseSupplement = resolve;
  });
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    supplementCredential: async () => supplementStarted,
  });

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: { upstreamGroupName: "sync-ready" },
  });
  const outputDir = path.join(tempDir, "attempt-success-nonblocking");
  await mkdir(outputDir, { recursive: true });
  await writeFile(
    path.join(outputDir, "result.json"),
    JSON.stringify({
      mode: "headless",
      email: "nonblocking@example.com",
      password: "Password123!",
      nickname: "Koha",
      birthDate: "1995-04-02",
      credentials: {
        access_token: "access-token-demo",
        refresh_token: "refresh-token-demo",
        id_token: "id-token-demo",
        account_id: "acc-nonblocking",
        expires_at: "2026-04-18T10:00:00.000Z",
        token_type: "Bearer",
      },
    }),
  );
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: "nonblocking@example.com",
    outputDir,
  });

  const finalizePromise = (scheduler as any).handleAttemptExit(job.id, attempt.id, outputDir, 0, null, {
    child: { pid: 0, kill: () => false },
    attempt,
    outputDir,
    reservedPorts: { apiPort: 39091, mixedPort: 49091 },
    stopRequested: null,
  });

  const finalizedQuickly = await Promise.race([
    finalizePromise.then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 50)),
  ]);

  expect(finalizedQuickly).toBe(true);
  expect(appDb.getChatGptCredential(1)?.email).toBe("nonblocking@example.com");

  releaseSupplement();
  await finalizePromise;
  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler waits for in-flight supplement work during shutdown", async () => {
  const { appDb, tempDir } = await createTempDb();
  let releaseSupplement: () => void = () => {};
  const supplementGate = new Promise<void>((resolve) => {
    releaseSupplement = resolve;
  });
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    supplementCredential: async () => supplementGate,
  });

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: { upstreamGroupName: "sync-ready" },
  });
  const outputDir = path.join(tempDir, "attempt-success-shutdown-wait");
  await mkdir(outputDir, { recursive: true });
  await writeFile(
    path.join(outputDir, "result.json"),
    JSON.stringify({
      mode: "headless",
      email: "shutdown-wait@example.com",
      password: "Password123!",
      nickname: "Koha",
      birthDate: "1995-04-02",
      credentials: {
        access_token: "access-token-demo",
        refresh_token: "refresh-token-demo",
        id_token: "id-token-demo",
        account_id: "acc-shutdown-wait",
        expires_at: "2026-04-18T10:00:00.000Z",
        token_type: "Bearer",
      },
    }),
  );
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: "shutdown-wait@example.com",
    outputDir,
  });

  await (scheduler as any).handleAttemptExit(job.id, attempt.id, outputDir, 0, null, {
    child: { pid: 0, kill: () => false },
    attempt,
    outputDir,
    reservedPorts: { apiPort: 39092, mixedPort: 49092 },
    stopRequested: null,
  });

  const shutdownPromise = scheduler.shutdown();
  const finishedEarly = await Promise.race([
    shutdownPromise.then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 50)),
  ]);

  expect(finishedEarly).toBe(false);

  releaseSupplement();
  await shutdownPromise;
  appDb.close();
});

test("chatgpt scheduler keeps local credential success when supplement fails", async () => {
  const { appDb, tempDir } = await createTempDb();
  const publishedEvents: Array<{ type: string; payload: Record<string, unknown> }> = [];
  const scheduler = new ChatGptJobScheduler(
    appDb,
    process.cwd(),
    () => createSchedulerSettings(),
    (event) => publishedEvents.push({ type: event.type, payload: event.payload }),
    {
      supplementCredential: async () => {
        throw new Error("upstream refused sync");
      },
    },
  );

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: { upstreamGroupName: "sync-ready" },
  });
  const outputDir = path.join(tempDir, "attempt-success");
  await mkdir(outputDir, { recursive: true });
  await writeFile(
    path.join(outputDir, "result.json"),
    JSON.stringify({
      mode: "headless",
      email: "supplement@example.com",
      password: "Password123!",
      nickname: "Koha",
      birthDate: "1995-04-02",
      credentials: {
        access_token: "access-token-demo",
        refresh_token: "refresh-token-demo",
        id_token: "id-token-demo",
        account_id: "acc-supplement",
        expires_at: "2026-04-18T10:00:00.000Z",
        token_type: "Bearer",
      },
    }),
  );
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: "supplement@example.com",
    outputDir,
  });

  await (scheduler as any).handleAttemptExit(job.id, attempt.id, outputDir, 0, null, {
    child: { pid: 0, kill: () => false },
    attempt,
    outputDir,
    reservedPorts: { apiPort: 39090, mixedPort: 49090 },
    stopRequested: null,
  });

  const credential = appDb.getChatGptCredential(1);
  expect(credential?.email).toBe("supplement@example.com");
  expect(appDb.getJob(job.id)?.successCount).toBe(1);

  await scheduler.shutdown();
  expect(
    publishedEvents.some(
      (event) => event.type === "toast" && event.payload.level === "warning" && String(event.payload.message || "").includes("supplement failed"),
    ),
  ).toBe(true);

  appDb.close();
});

test("chatgpt scheduler emits upstream settings refresh after successful supplement", async () => {
  const { appDb, tempDir } = await createTempDb();
  const publishedEvents: Array<{ type: string; payload: Record<string, unknown> }> = [];
  const scheduler = new ChatGptJobScheduler(
    appDb,
    process.cwd(),
    () => createSchedulerSettings(),
    (event) => publishedEvents.push({ type: event.type, payload: event.payload }),
    {
      supplementCredential: async () => undefined,
    },
  );

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: { upstreamGroupName: "sync-ready" },
  });
  const outputDir = path.join(tempDir, "attempt-success-refresh");
  await mkdir(outputDir, { recursive: true });
  await writeFile(
    path.join(outputDir, "result.json"),
    JSON.stringify({
      mode: "headless",
      email: "refresh@example.com",
      password: "Password123!",
      nickname: "Koha",
      birthDate: "1995-04-02",
      credentials: {
        access_token: "access-token-demo",
        refresh_token: "refresh-token-demo",
        id_token: "id-token-demo",
        account_id: "acc-refresh",
        expires_at: "2026-04-18T10:00:00.000Z",
        token_type: "Bearer",
      },
    }),
  );
  const attempt = appDb.createAttempt(job.id, {
    accountEmail: "refresh@example.com",
    outputDir,
  });

  await (scheduler as any).handleAttemptExit(job.id, attempt.id, outputDir, 0, null, {
    child: { pid: 0, kill: () => false },
    attempt,
    outputDir,
    reservedPorts: { apiPort: 39093, mixedPort: 49093 },
    stopRequested: null,
  });
  await scheduler.shutdown();

  expect(
    publishedEvents.some(
      (event) =>
        event.type === "chatgpt.upstream-settings.updated"
        && event.payload.groupName === "sync-ready"
        && event.payload.credentialId === 1,
    ),
  ).toBe(true);

  appDb.close();
});

test("chatgpt scheduler supports pause resume update and stop on its own site", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(1),
  });
  (scheduler as any).ensureLoop = () => undefined;
  (scheduler as any).spawnAttempt = async () => undefined;

  const started = await scheduler.startJob({
    runMode: "headed",
    need: 3,
    parallel: 2,
    maxAttempts: 1,
  });
  expect(started.site).toBe("chatgpt");
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
  expect(stopped.site).toBe("chatgpt");
  expect(["stopping", "stopped"]).toContain(stopped.status);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler lets paused jobs complete after in-flight attempts finish", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(1),
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any, draft: ReturnType<typeof createDraft>) => {
    (scheduler as any).activeAttempts.set(attempt.id, {
      attemptId: attempt.id,
      child: null,
      stopRequested: null,
    });
    setTimeout(() => {
      appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
        email: draft.email,
        accountId: `acc-${attempt.id}`,
        accessToken: `access-${attempt.id}`,
        refreshToken: `refresh-${attempt.id}`,
        idToken: `id-${attempt.id}`,
        expiresAt: null,
        credentialJson: JSON.stringify({ email: draft.email }),
      });
      (scheduler as any).activeAttempts.delete(attempt.id);
    }, 50);
  };

  const started = await scheduler.startJob({
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  expect(started.status).toBe("running");

  const paused = scheduler.pauseCurrentJob();
  expect(paused.status).toBe("paused");

  for (let index = 0; index < 80; index += 1) {
    const current = appDb.getJob(started.id);
    if (current?.status === "completed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const completed = appDb.getJob(started.id);
  expect(completed?.status).toBe("completed");
  expect(completed?.successCount).toBe(1);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler keeps exhausted paused jobs resumable for limit updates", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(++draftCalls),
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any) => {
    (scheduler as any).activeAttempts.set(attempt.id, {
      attemptId: attempt.id,
      child: null,
      stopRequested: null,
    });
    setTimeout(() => {
      (scheduler as any).failAttempt(job.id, attempt.id, {
        errorCode: "simulated_failure",
        errorMessage: `attempt-${attempt.id}-failed`,
      });
      (scheduler as any).activeAttempts.delete(attempt.id);
    }, 40);
  };

  const started = await scheduler.startJob({
    runMode: "headless",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
  });
  expect(started.status).toBe("running");

  const paused = scheduler.pauseCurrentJob();
  expect(paused.status).toBe("paused");

  for (let index = 0; index < 80; index += 1) {
    const current = appDb.getJob(started.id);
    if (current?.status === "paused" && current.launchedCount === 1 && current.successCount === 0) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const stillPaused = appDb.getJob(started.id);
  expect(stillPaused?.status).toBe("paused");
  expect(stillPaused?.launchedCount).toBe(1);
  expect(stillPaused?.successCount).toBe(0);

  const updated = scheduler.updateCurrentJobLimits({ maxAttempts: 2 });
  expect(updated.status).toBe("paused");
  expect(updated.maxAttempts).toBe(2);

  const resumed = scheduler.resumeCurrentJob();
  expect(resumed.status).toBe("running");

  for (let index = 0; index < 80; index += 1) {
    const current = appDb.getJob(started.id);
    if (current?.status === "failed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const failed = appDb.getJob(started.id);
  expect(failed?.status).toBe("failed");
  expect(failed?.maxAttempts).toBe(2);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler stops dispatching additional slots as soon as pause is requested", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(++draftCalls),
  });

  (scheduler as any).spawnAttempt = async (_job: any, attempt: any) => {
    (scheduler as any).activeAttempts.set(attempt.id, {
      attemptId: attempt.id,
      child: {
        pid: 0,
        kill: () => true,
      },
      stopRequested: null,
    });
    if (attempt.id === 2) {
      scheduler.pauseCurrentJob();
    }
  };

  const started = await scheduler.startJob({
    runMode: "headless",
    need: 3,
    parallel: 3,
    maxAttempts: 3,
  });
  expect(started.status).toBe("running");

  for (let index = 0; index < 40; index += 1) {
    const current = appDb.getJob(started.id);
    if (current?.status === "paused" && current.launchedCount >= 2) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const paused = appDb.getJob(started.id);
  expect(paused?.status).toBe("paused");
  expect(paused?.launchedCount).toBe(2);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler does not launch a draft that finishes after pause", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => {
      draftCalls += 1;
      if (draftCalls === 2) {
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
      return createDraft(draftCalls);
    },
  });

  (scheduler as any).spawnAttempt = async (_job: any, attempt: any) => {
    (scheduler as any).activeAttempts.set(attempt.id, {
      attemptId: attempt.id,
      child: {
        pid: 0,
        kill: () => true,
      },
      stopRequested: null,
    });
  };

  const started = await scheduler.startJob({
    runMode: "headless",
    need: 2,
    parallel: 2,
    maxAttempts: 2,
  });
  expect(started.status).toBe("running");

  for (let index = 0; index < 40; index += 1) {
    if (draftCalls >= 2) break;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  expect(draftCalls).toBeGreaterThanOrEqual(2);

  const paused = scheduler.pauseCurrentJob();
  expect(paused.status).toBe("paused");

  await new Promise((resolve) => setTimeout(resolve, 120));

  const current = appDb.getJob(started.id);
  expect(current?.status).toBe("paused");
  expect(current?.launchedCount).toBe(1);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler surfaces first-attempt draft provisioning failures during start", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => {
      throw new Error("cfmail_api_unavailable");
    },
  });
  (scheduler as any).ensureLoop = () => undefined;

  await expect(
    scheduler.startJob({
      runMode: "headless",
      need: 1,
      parallel: 1,
      maxAttempts: 1,
    }),
  ).rejects.toThrow("chatgpt attempt draft failed at attempt #1: cfmail_api_unavailable");

  const current = appDb.getCurrentJob("chatgpt");
  expect(current).toBeNull();

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler blocks fresh starts during mailbox provider cooldown", async () => {
  const { appDb } = await createTempDb();
  process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
  process.env.CFMAIL_API_KEY = "cf_key_test";
  const identity = resolveMailboxProviderIdentity({
    provider: "cfmail",
    baseUrl: process.env.CFMAIL_BASE_URL,
    credential: process.env.CFMAIL_API_KEY,
  });
  expect(identity).not.toBeNull();
  setMailboxProviderCooldownForTests(identity!, "mailbox_rate_limited", new Date(Date.now() + 60_000).toISOString());

  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(1),
  });

  await expect(
    scheduler.startJob({
      runMode: "headless",
      need: 1,
      parallel: 1,
      maxAttempts: 1,
    }),
  ).rejects.toThrow(/retry after/i);

  expect(scheduler.getCooldownSnapshot()?.sourceErrorCode).toBe("mailbox_rate_limited");

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler only provisions drafts for launched attempts", async () => {
  const { appDb } = await createTempDb();
  let generatedDrafts = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => createDraft(++generatedDrafts),
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any, draft: ReturnType<typeof createDraft>) => {
    appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
      email: draft.email,
      accountId: `acc-${attempt.id}`,
      accessToken: `access-${attempt.id}`,
      refreshToken: `refresh-${attempt.id}`,
      idToken: `id-${attempt.id}`,
      expiresAt: null,
      credentialJson: JSON.stringify({ email: draft.email }),
    });
  };

  const next = await scheduler.startJob({
    runMode: "headless",
    need: 3,
    parallel: 2,
    maxAttempts: 5,
  });

  for (let index = 0; index < 40; index += 1) {
    const current = appDb.getJob(next.id);
    if (current?.status === "completed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const completed = appDb.getJob(next.id);
  expect(completed?.status).toBe("completed");
  expect(completed?.successCount).toBe(3);
  expect(completed?.launchedCount).toBe(3);
  expect(generatedDrafts).toBe(3);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler retries draft generation after transient failures while attempts are still active", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => {
      draftCalls += 1;
      if (draftCalls === 2) {
        throw new Error("cfmail_temporarily_unavailable");
      }
      return createDraft(draftCalls);
    },
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any, draft: ReturnType<typeof createDraft>) => {
    (scheduler as any).activeAttempts.set(attempt.id, {
      attemptId: attempt.id,
      child: null,
      stopRequested: null,
    });
    setTimeout(() => {
      appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
        email: draft.email,
        accountId: `acc-${attempt.id}`,
        accessToken: `access-${attempt.id}`,
        refreshToken: `refresh-${attempt.id}`,
        idToken: `id-${attempt.id}`,
        expiresAt: null,
        credentialJson: JSON.stringify({ email: draft.email }),
      });
      (scheduler as any).activeAttempts.delete(attempt.id);
    }, 50);
  };

  const next = await scheduler.startJob({
    runMode: "headless",
    need: 2,
    parallel: 2,
    maxAttempts: 3,
  });

  for (let index = 0; index < 80; index += 1) {
    const current = appDb.getJob(next.id);
    if (current?.status === "completed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const completed = appDb.getJob(next.id);
  expect(completed?.status).toBe("completed");
  expect(completed?.successCount).toBe(2);
  expect(completed?.launchedCount).toBe(2);
  expect(completed?.maxAttempts).toBe(3);
  expect(draftCalls).toBe(3);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler keeps retry budget after transient draft failures between sequential attempts", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => {
      draftCalls += 1;
      if (draftCalls === 2) {
        throw new Error("cfmail_temporarily_unavailable");
      }
      return createDraft(draftCalls);
    },
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any, draft: ReturnType<typeof createDraft>) => {
    setTimeout(() => {
      appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
        email: draft.email,
        accountId: `acc-${attempt.id}`,
        accessToken: `access-${attempt.id}`,
        refreshToken: `refresh-${attempt.id}`,
        idToken: `id-${attempt.id}`,
        expiresAt: null,
        credentialJson: JSON.stringify({ email: draft.email }),
      });
    }, 20);
  };

  const next = await scheduler.startJob({
    runMode: "headless",
    need: 2,
    parallel: 1,
    maxAttempts: 3,
  });

  for (let index = 0; index < 120; index += 1) {
    const current = appDb.getJob(next.id);
    if (current?.status === "completed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const completed = appDb.getJob(next.id);
  expect(completed?.status).toBe("completed");
  expect(completed?.successCount).toBe(2);
  expect(completed?.launchedCount).toBe(2);
  expect(completed?.maxAttempts).toBe(3);
  expect(draftCalls).toBe(3);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler does not consume the last retry window while another attempt is still active", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => {
      draftCalls += 1;
      if (draftCalls === 3) {
        throw new Error("cfmail_temporarily_unavailable");
      }
      return createDraft(draftCalls);
    },
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any, draft: ReturnType<typeof createDraft>) => {
    (scheduler as any).activeAttempts.set(attempt.id, {
      attemptId: attempt.id,
      child: null,
      stopRequested: null,
    });
    const delay = attempt.id === 1 ? 20 : attempt.id === 2 ? 120 : 20;
    setTimeout(() => {
      appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
        email: draft.email,
        accountId: `acc-${attempt.id}`,
        accessToken: `access-${attempt.id}`,
        refreshToken: `refresh-${attempt.id}`,
        idToken: `id-${attempt.id}`,
        expiresAt: null,
        credentialJson: JSON.stringify({ email: draft.email }),
      });
      (scheduler as any).activeAttempts.delete(attempt.id);
    }, delay);
  };

  const next = await scheduler.startJob({
    runMode: "headless",
    need: 3,
    parallel: 2,
    maxAttempts: 3,
  });

  for (let index = 0; index < 200; index += 1) {
    const current = appDb.getJob(next.id);
    if (current?.status === "completed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const completed = appDb.getJob(next.id);
  expect(completed?.status).toBe("completed");
  expect(completed?.successCount).toBe(3);
  expect(completed?.launchedCount).toBe(3);
  expect(draftCalls).toBe(4);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler fails once draft-generation errors exhaust the remaining launch budget", async () => {
  const { appDb } = await createTempDb();
  let draftCalls = 0;
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined, {
    createAttemptDraft: async () => {
      draftCalls += 1;
      if (draftCalls >= 2) {
        throw new Error("cfmail_temporarily_unavailable");
      }
      return createDraft(draftCalls);
    },
  });

  (scheduler as any).spawnAttempt = async (job: any, attempt: any, draft: ReturnType<typeof createDraft>) => {
    setTimeout(() => {
      appDb.completeChatGptAttemptSuccess(job.id, attempt.id, {
        email: draft.email,
        accountId: `acc-${attempt.id}`,
        accessToken: `access-${attempt.id}`,
        refreshToken: `refresh-${attempt.id}`,
        idToken: `id-${attempt.id}`,
        expiresAt: null,
        credentialJson: JSON.stringify({ email: draft.email }),
      });
    }, 20);
  };

  const next = await scheduler.startJob({
    runMode: "headless",
    need: 2,
    parallel: 1,
    maxAttempts: 3,
  });

  for (let index = 0; index < 160; index += 1) {
    const current = appDb.getJob(next.id);
    if (current?.status === "failed") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const failed = appDb.getJob(next.id);
  expect(failed?.status).toBe("failed");
  expect(failed?.successCount).toBe(1);
  expect(failed?.launchedCount).toBe(1);
  expect(failed?.lastError).toBe("chatgpt attempt draft failed at attempt #2: cfmail_temporarily_unavailable");
  expect(draftCalls).toBe(4);

  await scheduler.shutdown();
  appDb.close();
});
