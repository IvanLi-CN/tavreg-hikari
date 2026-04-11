import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ChatGptJobScheduler } from "../src/server/chatgpt-scheduler";
import { AppDatabase, type AppSettings } from "../src/storage/app-db";

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
  expect(current?.status).toBe("failed");
  expect(current?.lastError).toBe("chatgpt attempt draft failed at attempt #1: cfmail_api_unavailable");

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
