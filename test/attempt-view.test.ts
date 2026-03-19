import { expect, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { serializeAttemptForApi } from "../src/server/attempt-view.ts";
import { AppDatabase } from "../src/storage/app-db.ts";
import { TaskLedger } from "../src/storage/task-ledger.ts";

test("serializeAttemptForApi reflects the latest signup task details for active attempts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tavreg-attempt-view-"));
  const dbPath = path.join(root, "ledger.sqlite");
  const db = await AppDatabase.open(dbPath);
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
    const imported = db.importAccounts([{ email: "alpha@outlook.com", password: "pw123456" }]);
    const accountId = imported.affectedIds[0]!;
    const job = db.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const attempt = db.createAttempt(job.id, accountId, path.join(root, "attempt-output"));

    ledger!.upsertTask({
      runId: "run-1",
      jobId: job.id,
      accountId,
      batchId: "batch-1",
      mode: "headed",
      attemptIndex: 1,
      modeRetryMax: 1,
      status: "running",
      startedAt: new Date().toISOString(),
      failureStage: "login_home",
      proxyNode: "Tokyo-1",
      proxyIp: "1.2.3.4",
      errorCode: "oauth_timeout",
      errorMessage: "waiting for callback",
    });

    const serialized = serializeAttemptForApi(db, attempt);
    expect(serialized.runId).toBe("run-1");
    expect(serialized.stage).toBe("login_home");
    expect(serialized.proxyNode).toBe("Tokyo-1");
    expect(serialized.proxyIp).toBe("1.2.3.4");
    expect(serialized.errorCode).toBe("oauth_timeout");
    expect(serialized.errorMessage).toBe("waiting for callback");
  } finally {
    ledger?.close();
    db.close();
  }
});
