import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ChatGptJobScheduler } from "../src/server/chatgpt-scheduler";
import { GrokJobScheduler } from "../src/server/grok-scheduler";
import {
  resetMailboxProviderGuardStateForTests,
  resolveMailboxProviderIdentity,
  setMailboxProviderCooldownForTests,
} from "../src/server/mailbox-provider-guard";
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

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-shared-mailbox-cooldown-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { appDb };
}

afterEach(async () => {
  resetMailboxProviderGuardStateForTests();
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

test("shared mailbox cooldown is visible to both grok and chatgpt schedulers", async () => {
  process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
  process.env.CFMAIL_API_KEY = "cf_key_test";
  const identity = resolveMailboxProviderIdentity({
    provider: "cfmail",
    baseUrl: process.env.CFMAIL_BASE_URL,
    credential: process.env.CFMAIL_API_KEY,
  });
  expect(identity).not.toBeNull();
  setMailboxProviderCooldownForTests(identity!, "mailbox_rate_limited", new Date(Date.now() + 60_000).toISOString());

  const { appDb } = await createTempDb();
  const getSettings = () => createSchedulerSettings();
  const publish = () => undefined;
  const grokScheduler = new GrokJobScheduler(appDb, process.cwd(), getSettings, publish);
  const chatgptScheduler = new ChatGptJobScheduler(appDb, process.cwd(), getSettings, publish);

  expect(grokScheduler.getCooldownSnapshot()?.sourceErrorCode).toBe("mailbox_rate_limited");
  expect(chatgptScheduler.getCooldownSnapshot()?.sourceErrorCode).toBe("mailbox_rate_limited");

  await expect(
    grokScheduler.startJob({
      runMode: "headless",
      need: 1,
      parallel: 1,
      maxAttempts: 1,
    }),
  ).rejects.toThrow(/retry after/i);
  await expect(
    chatgptScheduler.startJob({
      runMode: "headless",
      need: 1,
      parallel: 1,
      maxAttempts: 1,
    }),
  ).rejects.toThrow(/retry after/i);

  await Promise.all([grokScheduler.shutdown(), chatgptScheduler.shutdown()]);
  appDb.close();
});
