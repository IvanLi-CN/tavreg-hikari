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
    payloadJson: {
      drafts: [createDraft(1)],
    },
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
      need: 1,
      parallel: 1,
      maxAttempts: 1,
      drafts: [createDraft(2)],
    }),
  ).rejects.toThrow(/retry after/i);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler allows starts after cooldown window expires", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;

  const job = appDb.createJob({
    site: "chatgpt",
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    payloadJson: {
      drafts: [createDraft(1)],
    },
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
    need: 2,
    parallel: 2,
    maxAttempts: 3,
    drafts: [createDraft(2), createDraft(3), createDraft(4)],
  });
  expect(next.site).toBe("chatgpt");
  expect(next.status).toBe("running");
  expect(next.need).toBe(2);
  expect(next.parallel).toBe(2);
  expect(next.maxAttempts).toBe(3);

  await scheduler.shutdown();
  appDb.close();
});

test("chatgpt scheduler stores batch drafts inside payload", async () => {
  const { appDb } = await createTempDb();
  const scheduler = new ChatGptJobScheduler(appDb, process.cwd(), () => createSchedulerSettings(), () => undefined);
  (scheduler as any).ensureLoop = () => undefined;

  const next = await scheduler.startJob({
    need: 3,
    parallel: 2,
    maxAttempts: 5,
    drafts: [createDraft(1), createDraft(2), createDraft(3), createDraft(4), createDraft(5)],
  });

  expect(next.need).toBe(3);
  expect(next.parallel).toBe(2);
  expect(next.maxAttempts).toBe(5);
  expect(Array.isArray(next.payloadJson.drafts)).toBe(true);
  expect((next.payloadJson.drafts as Array<Record<string, unknown>>).map((draft) => draft.email)).toEqual([
    "draft-1@example.com",
    "draft-2@example.com",
    "draft-3@example.com",
    "draft-4@example.com",
    "draft-5@example.com",
  ]);

  await scheduler.shutdown();
  appDb.close();
});
