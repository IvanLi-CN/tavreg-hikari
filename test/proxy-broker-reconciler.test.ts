import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { planProxyBrokerSessionReconciliation, reconcileProxyBrokerSessions } from "../src/server/proxy-broker-reconciler";
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
