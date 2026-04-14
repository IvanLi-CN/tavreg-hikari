import { expect, test } from "bun:test";
import { createProxyCheckCoordinator, type ProxyCheckState } from "../src/server/proxy-check-coordinator.ts";

function createSettings() {
  return {
    subscriptionUrl: "https://example.com/sub.yaml",
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: "https://www.gstatic.com/generate_204",
    timeoutMs: 1000,
    maxLatencyMs: 500,
    apiPort: 39090,
    mixedPort: 49090,
    serverHost: "127.0.0.1",
    serverPort: 3717,
    defaultRunMode: "headed" as const,
    defaultNeed: 1,
    defaultParallel: 1,
    defaultMaxAttempts: 5,
    extractorZhanghaoyaKey: "",
    extractorShanyouxiangKey: "",
    extractorShankeyunKey: "",
    extractorHotmail666Key: "",
    defaultAutoExtractSources: [],
    defaultAutoExtractQuantity: 1,
    defaultAutoExtractMaxWaitSec: 60,
    defaultAutoExtractAccountType: "outlook" as const,
    microsoftGraphClientId: "",
    microsoftGraphClientSecret: "",
    microsoftGraphRedirectUri: "",
    microsoftGraphAuthority: "common",
  };
}

async function waitForTerminal(getState: () => ProxyCheckState): Promise<ProxyCheckState> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const state = getState();
    if (state.status !== "running") return state;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("proxy check coordinator did not finish in time");
}

test("proxy check coordinator limits concurrency and publishes incremental progress", async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  let createdWorkers = 0;
  let closedWorkers = 0;
  const published: string[] = [];
  const recorded: string[] = [];
  const coordinator = createProxyCheckCoordinator({
    defaultConcurrency: 5,
    readSettings: createSettings,
    resolveNodeNames: async () => Array.from({ length: 12 }, (_, index) => `node-${index + 1}`),
    createWorker: async ({ workerSlot }) => {
      createdWorkers += 1;
      return {
        checkNode: async (nodeName) => {
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          await new Promise((resolve) => setTimeout(resolve, 10));
          inFlight -= 1;
          return { name: nodeName, ok: workerSlot > 0 };
        },
        close: async () => {
          closedWorkers += 1;
        },
      };
    },
    recordResult: (result) => {
      recorded.push(result.name);
    },
    listNodes: () => [],
    publish: (event) => {
      published.push(event.type);
    },
    createRunId: () => "run-001",
    nowIso: () => "2026-04-15T00:00:00.000Z",
  });

  const started = await coordinator.startCheck({ scope: "all" });
  expect(started.accepted).toBe(true);
  expect(started.checkState.status).toBe("running");

  const terminal = await waitForTerminal(() => coordinator.getState());
  expect(terminal.status).toBe("completed");
  expect(terminal.completed).toBe(12);
  expect(terminal.succeeded).toBe(12);
  expect(terminal.failed).toBe(0);
  expect(recorded).toHaveLength(12);
  expect(maxInFlight).toBe(5);
  expect(createdWorkers).toBe(5);
  expect(closedWorkers).toBe(5);
  expect(published[0]).toBe("proxy.check.started");
  expect(published).toContain("proxy.check.progress");
  expect(published[published.length - 1]).toBe("proxy.check.completed");
});

test("proxy check coordinator rejects overlapping starts while a run is active", async () => {
  let resolveNodeCheck!: () => void;
  const coordinator = createProxyCheckCoordinator({
    defaultConcurrency: 2,
    readSettings: createSettings,
    resolveNodeNames: async () => ["node-1"],
    createWorker: async () => ({
      checkNode: async (nodeName) => {
        await new Promise<void>((resolve) => {
          resolveNodeCheck = resolve;
        });
        return { name: nodeName, ok: true };
      },
      close: async () => {},
    }),
    recordResult: () => {},
    listNodes: () => [],
    publish: () => {},
    createRunId: () => "run-002",
    nowIso: () => "2026-04-15T00:00:00.000Z",
  });

  const first = await coordinator.startCheck({ scope: "all" });
  const second = await coordinator.startCheck({ scope: "all" });
  expect(first.accepted).toBe(true);
  expect(second.accepted).toBe(false);
  resolveNodeCheck();
  const terminal = await waitForTerminal(() => coordinator.getState());
  expect(terminal.status).toBe("completed");
});

test("proxy check coordinator marks orchestration failure as failed state", async () => {
  const published: string[] = [];
  const coordinator = createProxyCheckCoordinator({
    defaultConcurrency: 5,
    readSettings: createSettings,
    resolveNodeNames: async () => {
      throw new Error("inventory_sync_failed");
    },
    createWorker: async () => ({
      checkNode: async (nodeName) => ({ name: nodeName, ok: true }),
      close: async () => {},
    }),
    recordResult: () => {},
    listNodes: () => [],
    publish: (event) => {
      published.push(event.type);
    },
    createRunId: () => "run-003",
    nowIso: () => "2026-04-15T00:00:00.000Z",
  });

  const started = await coordinator.startCheck({ scope: "all" });
  expect(started.accepted).toBe(true);
  const terminal = await waitForTerminal(() => coordinator.getState());
  expect(terminal.status).toBe("failed");
  expect(terminal.error).toBe("inventory_sync_failed");
  expect(published[published.length - 1]).toBe("proxy.check.failed");
});

test("proxy check coordinator reuses each worker across multiple nodes", async () => {
  const workerNodeCounts = new Map<number, number>();
  const coordinator = createProxyCheckCoordinator({
    defaultConcurrency: 3,
    readSettings: createSettings,
    resolveNodeNames: async () => ["node-1", "node-2", "node-3", "node-4", "node-5", "node-6", "node-7"],
    createWorker: async ({ workerSlot }) => ({
      checkNode: async (nodeName) => {
        workerNodeCounts.set(workerSlot, (workerNodeCounts.get(workerSlot) || 0) + 1);
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { name: nodeName, ok: true };
      },
      close: async () => {},
    }),
    recordResult: () => {},
    listNodes: () => [],
    publish: () => {},
    createRunId: () => "run-004",
    nowIso: () => "2026-04-15T00:00:00.000Z",
  });

  const started = await coordinator.startCheck({ scope: "all" });
  expect(started.accepted).toBe(true);

  const terminal = await waitForTerminal(() => coordinator.getState());
  expect(terminal.status).toBe("completed");
  expect(workerNodeCounts.size).toBe(3);
  expect(Array.from(workerNodeCounts.values()).some((count) => count > 1)).toBe(true);
});
