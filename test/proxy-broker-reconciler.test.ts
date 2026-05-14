import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { planProxyBrokerSessionReconciliation, reconcileProxyBrokerSessions } from "../src/server/proxy-broker-reconciler";
import { resolveProxyBrokerReconcileDbPath } from "../src/proxy-broker-reconcile-cli";
import { AppDatabase } from "../src/storage/app-db";
import type { ProxyBrokerSession } from "../src/proxy/broker";

function session(sessionId: string): ProxyBrokerSession {
  return {
    session_id: sessionId,
    listen: "0.0.0.0:20000",
    bind_host: "0.0.0.0",
    display_host: "proxy-broker",
    display_address: `proxy-broker:${sessionId.slice(-2)}`,
    port: 20000,
    selected_ip: `203.0.113.${sessionId.length}`,
    proxy_name: `node-${sessionId}`,
    node_id: `node-${sessionId}`,
  };
}

test("proxy broker reconciler plans orphan sessions without closing referenced sessions", () => {
  const plan = planProxyBrokerSessionReconciliation({
    sessions: [session("sess-live"), session("sess-orphan")],
    references: [{ sessionId: "sess-live", attemptId: 1, jobId: 1, jobStatus: "running" }],
  });

  expect(plan.activeSessionIds).toEqual(["sess-live", "sess-orphan"]);
  expect(plan.referencedSessionIds).toEqual(["sess-live"]);
  expect(plan.orphanSessions.map((item) => item.session_id)).toEqual(["sess-orphan"]);
});

test("proxy broker reconciler dry-run does not close orphan sessions", async () => {
  const closed: string[] = [];
  const result = await reconcileProxyBrokerSessions({
    settings: { proxyBrokerBaseUrl: "https://proxy.example.test", proxyBrokerProfileId: "Tavily", timeoutMs: 1000 },
    references: [{ sessionId: "sess-live" }],
    apply: false,
    listSessions: async () => ({ sessions: [session("sess-live"), session("sess-orphan")] }),
    closeSession: async (sessionId) => {
      closed.push(sessionId);
    },
  });

  expect(result.orphanSessions.map((item) => item.session_id)).toEqual(["sess-orphan"]);
  expect(result.closedSessionIds).toEqual([]);
  expect(closed).toEqual([]);
});

test("proxy broker reconciler apply closes only orphan sessions", async () => {
  const closed: string[] = [];
  const result = await reconcileProxyBrokerSessions({
    settings: { proxyBrokerBaseUrl: "https://proxy.example.test", proxyBrokerProfileId: "Tavily", timeoutMs: 1000 },
    references: [{ sessionId: "sess-live" }],
    apply: true,
    listSessions: async () => ({ sessions: [session("sess-live"), session("sess-orphan-a"), session("sess-orphan-b")] }),
    closeSession: async (sessionId) => {
      closed.push(sessionId);
    },
  });

  expect(result.closedSessionIds).toEqual(["sess-orphan-a", "sess-orphan-b"]);
  expect(closed).toEqual(["sess-orphan-a", "sess-orphan-b"]);
});

test("proxy broker reconciler rechecks references before closing orphan sessions", async () => {
  const closed: string[] = [];
  const result = await reconcileProxyBrokerSessions({
    settings: { proxyBrokerBaseUrl: "https://proxy.example.test", proxyBrokerProfileId: "Tavily", timeoutMs: 1000 },
    references: [],
    apply: true,
    listSessions: async () => ({ sessions: [session("sess-race")] }),
    refreshReferences: async () => [{ sessionId: "sess-race", attemptId: 1, jobId: 1, jobStatus: "running" }],
    closeSession: async (sessionId) => {
      closed.push(sessionId);
    },
  });

  expect(result.closedSessionIds).toEqual([]);
  expect(result.skippedReferencedSessionIds).toEqual(["sess-race"]);
  expect(closed).toEqual([]);
});

test("proxy broker reconciler skips closing when per-session close guard blocks apply", async () => {
  const closed: string[] = [];
  const result = await reconcileProxyBrokerSessions({
    settings: { proxyBrokerBaseUrl: "https://proxy.example.test", proxyBrokerProfileId: "Tavily", timeoutMs: 1000 },
    references: [],
    apply: true,
    listSessions: async () => ({ sessions: [session("sess-bootstrap-race")] }),
    shouldSkipClose: async (sessionId) => sessionId === "sess-bootstrap-race",
    closeSession: async (sessionId) => {
      closed.push(sessionId);
    },
  });

  expect(result.closedSessionIds).toEqual([]);
  expect(result.skippedReferencedSessionIds).toEqual(["sess-bootstrap-race"]);
  expect(closed).toEqual([]);
});

test("proxy broker reconciler records close failures for later compensation", async () => {
  const result = await reconcileProxyBrokerSessions({
    settings: { proxyBrokerBaseUrl: "https://proxy.example.test", proxyBrokerProfileId: "Tavily", timeoutMs: 1000 },
    references: [],
    apply: true,
    listSessions: async () => ({ sessions: [session("sess-orphan")] }),
    closeSession: async () => {
      throw new Error("broker close timed out");
    },
  });

  expect(result.closedSessionIds).toEqual([]);
  expect(result.closeErrors).toEqual([{ sessionId: "sess-orphan", message: "broker close timed out" }]);
});

test("proxy broker reconcile CLI resolves default database path through legacy compatibility helper", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-broker-reconciler-"));
  const legacyPath = path.join(tempDir, "registry", "signup-tasks.sqlite");
  const expectedPath = path.join(tempDir, "registry", "tavreg-hikari.sqlite");
  const db = await AppDatabase.open(legacyPath);
  db.close();
  try {
    const resolvedPath = resolveProxyBrokerReconcileDbPath("", tempDir);

    expect(resolvedPath).toBe(expectedPath);
    expect(existsSync(expectedPath)).toBe(true);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("database active broker references include only running attempts on active jobs", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-broker-reconciler-"));
  const db = await AppDatabase.open(path.join(tempDir, "app.sqlite"));
  try {
    const runningJob = db.createJob({ site: "chatgpt", runMode: "headless", need: 1, parallel: 1, maxAttempts: 2 });
    const activeAttempt = db.createAttempt(runningJob.id, { accountEmail: "active@example.test", outputDir: tempDir });
    db.updateAttempt(activeAttempt.id, { brokerSessionId: "sess-active" });

    const failedJob = db.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
    const inactiveAttempt = db.createAttempt(failedJob.id, { accountEmail: "inactive@example.test", outputDir: tempDir });
    db.updateAttempt(inactiveAttempt.id, { brokerSessionId: "sess-inactive" });
    db.completeJob(failedJob.id, false, "done");

    expect(db.listActiveBrokerSessionReferences().map((item) => item.sessionId)).toEqual(["sess-active"]);
  } finally {
    db.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("database non-recovering open preserves running broker references", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-broker-reconciler-"));
  const dbPath = path.join(tempDir, "app.sqlite");
  const db = await AppDatabase.open(dbPath);
  const runningJob = db.createJob({ site: "chatgpt", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
  const activeAttempt = db.createAttempt(runningJob.id, { accountEmail: "active@example.test", outputDir: tempDir });
  db.updateAttempt(activeAttempt.id, { brokerSessionId: "sess-active" });
  db.close();

  const reopened = await AppDatabase.openExistingWithoutRecovery(dbPath);
  try {
    expect(reopened.getJob(runningJob.id)?.status).toBe("running");
    expect(reopened.getAttempt(activeAttempt.id)?.status).toBe("running");
    expect(reopened.listActiveBrokerSessionReferences().map((item) => item.sessionId)).toEqual(["sess-active"]);
  } finally {
    reopened.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("database broker session launch guards include active attempts before broker binding", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-broker-reconciler-"));
  const db = await AppDatabase.open(path.join(tempDir, "app.sqlite"));
  try {
    const runningJob = db.createJob({ site: "chatgpt", runMode: "headless", need: 1, parallel: 1, maxAttempts: 2 });
    const unboundAttempt = db.createAttempt(runningJob.id, {
      accountEmail: "unbound@example.test",
      outputDir: tempDir,
      stage: "allocating_proxy",
    });
    const boundAttempt = db.createAttempt(runningJob.id, {
      accountEmail: "bound@example.test",
      outputDir: tempDir,
      stage: "proxy_bound",
    });
    db.updateAttempt(boundAttempt.id, { brokerSessionId: "sess-bound" });

    const completedJob = db.createJob({ site: "grok", runMode: "headless", need: 1, parallel: 1, maxAttempts: 1 });
    db.createAttempt(completedJob.id, { accountEmail: "inactive@example.test", outputDir: tempDir, stage: "allocating_proxy" });
    db.completeJob(completedJob.id, false, "done");

    expect(db.listBrokerSessionLaunchGuards().map((guard) => ({
      attemptId: guard.attemptId,
      jobId: guard.jobId,
      stage: guard.stage,
      site: guard.site,
    }))).toEqual([
      { attemptId: unboundAttempt.id, jobId: runningJob.id, stage: "allocating_proxy", site: "chatgpt" },
    ]);
  } finally {
    db.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});

test("database browser session bootstrap guards include active bootstrapping sessions only", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-broker-reconciler-"));
  const db = await AppDatabase.open(path.join(tempDir, "app.sqlite"));
  try {
    const imported = db.importAccounts([
      { email: "pending-bootstrap@example.test", password: "pass-a" },
      { email: "active-bootstrap@example.test", password: "pass-b" },
      { email: "ready-bootstrap@example.test", password: "pass-c" },
      { email: "failed-bootstrap@example.test", password: "pass-d" },
    ]);
    const [pendingId, bootstrappingId, readyId, failedId] = imported.affectedIds;
    expect(pendingId).toBeDefined();
    expect(bootstrappingId).toBeDefined();
    expect(readyId).toBeDefined();
    expect(failedId).toBeDefined();

    db.markBrowserSessionBootstrapping(bootstrappingId!, { proxyNode: "Tokyo-01" });
    db.markBrowserSessionReady(readyId!, { browserEngine: "chrome", proxyNode: "Osaka-01" });
    db.markBrowserSessionFailure(failedId!, {
      status: "failed",
      errorCode: "bootstrap_failed",
      errorMessage: "failed before broker cleanup",
    });

    const guards = db
      .listBrowserSessionBootstrapGuards()
      .map((guard) => ({ accountId: guard.accountId, status: guard.status, proxyNode: guard.proxyNode }))
      .sort((a, b) => a.accountId - b.accountId);

    expect(guards).toEqual([
      { accountId: bootstrappingId!, status: "bootstrapping", proxyNode: "Tokyo-01" },
    ]);
  } finally {
    db.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});
