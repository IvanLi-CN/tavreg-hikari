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
    const attempt = db.createAttempt(job.id, {
      accountId,
      accountEmail: "alpha@outlook.com",
      outputDir: path.join(root, "attempt-output"),
    });

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

test("serializeAttemptForApi ignores stale signup task rows for a fresh retry attempt", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tavreg-attempt-view-stale-"));
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
    const imported = db.importAccounts([{ email: "retry@outlook.com", password: "pw123456" }]);
    const accountId = imported.affectedIds[0]!;
    const job = db.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 2 });

    ledger!.upsertTask({
      runId: "run-old",
      jobId: job.id,
      accountId,
      batchId: "batch-old",
      mode: "headed",
      attemptIndex: 1,
      modeRetryMax: 2,
      status: "failed",
      startedAt: "2026-03-27T00:00:00.000Z",
      completedAt: "2026-03-27T00:00:08.000Z",
      failureStage: "browser_launch",
      errorCode: "oauth_timeout",
      errorMessage: "old retry failed",
    });

    const retryAttempt = db.createAttempt(job.id, {
      accountId,
      accountEmail: "retry@outlook.com",
      outputDir: path.join(root, "attempt-output"),
    });
    const serialized = serializeAttemptForApi(db, retryAttempt);

    expect(serialized.runId).toBeNull();
    expect(serialized.status).toBe("running");
    expect(serialized.stage).toBe("spawned");
    expect(serialized.errorCode).toBeNull();
    expect(serialized.errorMessage).toBeNull();
  } finally {
    ledger?.close();
    db.close();
  }
});

test("serializeAttemptForApi keeps ledger diagnostics for failed attempts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tavreg-attempt-view-failed-"));
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
    const imported = db.importAccounts([{ email: "failed@outlook.com", password: "pw123456" }]);
    const accountId = imported.affectedIds[0]!;
    const job = db.createJob({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 1 });
    const attempt = db.createAttempt(job.id, {
      accountId,
      accountEmail: "failed@outlook.com",
      outputDir: path.join(root, "attempt-output"),
    });

    ledger!.upsertTask({
      runId: "run-failed-1",
      jobId: job.id,
      accountId,
      batchId: "batch-failed-1",
      mode: "headed",
      attemptIndex: 1,
      modeRetryMax: 1,
      status: "failed",
      startedAt: attempt.startedAt,
      completedAt: new Date().toISOString(),
      failureStage: "extract_api_key",
      proxyNode: "Tokyo-2",
      proxyIp: "5.6.7.8",
      errorCode: "extract_timeout",
      errorMessage: "API key extraction timed out",
    });
    db.updateAttempt(attempt.id, {
      status: "failed",
      stage: "failed",
      completedAt: new Date().toISOString(),
      errorCode: "exit_1",
      errorMessage: "process exited with code 1",
    });

    const serialized = serializeAttemptForApi(db, db.getAttempt(attempt.id)!);
    expect(serialized.status).toBe("failed");
    expect(serialized.stage).toBe("extract_api_key");
    expect(serialized.proxyNode).toBe("Tokyo-2");
    expect(serialized.proxyIp).toBe("5.6.7.8");
    expect(serialized.errorCode).toBe("extract_timeout");
    expect(serialized.errorMessage).toBe("API key extraction timed out");
  } finally {
    ledger?.close();
    db.close();
  }
});
