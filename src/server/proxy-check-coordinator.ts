import { randomUUID } from "node:crypto";
import path from "node:path";
import { startMihomo } from "../proxy/mihomo.js";
import { checkNode, type NodeCheckResult } from "../proxy/check.js";
import type { AppSettings } from "../storage/app-db.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import type { ServerEvent } from "./scheduler.js";

export type ProxyCheckScope = "all" | "node";
export type ProxyCheckStatus = "idle" | "running" | "completed" | "failed";

export interface ProxyCheckState {
  runId: string | null;
  status: ProxyCheckStatus;
  scope: ProxyCheckScope | null;
  concurrency: number;
  total: number;
  completed: number;
  succeeded: number;
  failed: number;
  activeWorkers: number;
  currentNodeNames: string[];
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
}

export interface ProxyCheckStartResult {
  accepted: boolean;
  checkState: ProxyCheckState;
}

export interface ProxyCheckEventPayload<TNode = unknown> {
  checkState: ProxyCheckState;
  nodes: TNode[];
  result?: NodeCheckResult | null;
}

export interface ProxyCheckWorker {
  checkNode: (nodeName: string) => Promise<NodeCheckResult>;
  close?: () => Promise<void>;
}

interface ProxyCheckCoordinatorOptions<TNode> {
  defaultConcurrency: number;
  readSettings: () => AppSettings;
  resolveNodeNames: (input: { settings: AppSettings; scope: ProxyCheckScope; nodeName?: string | null }) => Promise<string[]>;
  createWorker: (input: { settings: AppSettings; runId: string; workerSlot: number }) => Promise<ProxyCheckWorker>;
  recordResult: (result: NodeCheckResult) => void;
  listNodes: () => TNode[];
  publish: (event: ServerEvent) => void;
  nowIso?: () => string;
  createRunId?: () => string;
}

function normalizeConcurrency(value: number | undefined, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return Math.max(1, fallback);
  return Math.max(1, Math.trunc(value));
}

function cloneState(state: ProxyCheckState): ProxyCheckState {
  return {
    ...state,
    currentNodeNames: [...state.currentNodeNames],
  };
}

function buildIdleState(defaultConcurrency: number): ProxyCheckState {
  return {
    runId: null,
    status: "idle",
    scope: null,
    concurrency: normalizeConcurrency(defaultConcurrency, 1),
    total: 0,
    completed: 0,
    succeeded: 0,
    failed: 0,
    activeWorkers: 0,
    currentNodeNames: [],
    startedAt: null,
    finishedAt: null,
    error: null,
  };
}

export function createProxyCheckCoordinator<TNode>(options: ProxyCheckCoordinatorOptions<TNode>) {
  const nowIso = options.nowIso || (() => new Date().toISOString());
  const createRunId = options.createRunId || (() => randomUUID());
  let latestState = buildIdleState(options.defaultConcurrency);
  let activeRunId: string | null = null;

  const publishSnapshot = (
    type: ServerEvent["type"],
    payload: Omit<ProxyCheckEventPayload<TNode>, "checkState" | "nodes"> & Partial<Pick<ProxyCheckEventPayload<TNode>, "nodes">> = {},
  ): void => {
    options.publish({
      type,
      payload: {
        checkState: cloneState(latestState),
        nodes: payload.nodes || options.listNodes(),
        ...(Object.prototype.hasOwnProperty.call(payload, "result") ? { result: payload.result ?? null } : {}),
      },
      timestamp: nowIso(),
    });
  };

  const refreshState = (mutator: (state: ProxyCheckState) => void): ProxyCheckState => {
    const next = cloneState(latestState);
    mutator(next);
    next.currentNodeNames = Array.from(new Set(next.currentNodeNames)).sort((left, right) => left.localeCompare(right, "zh-Hans-CN"));
    latestState = next;
    return cloneState(latestState);
  };

  const markTerminal = (status: Extract<ProxyCheckStatus, "completed" | "failed">, error: string | null = null): void => {
    refreshState((state) => {
      state.status = status;
      state.finishedAt = nowIso();
      state.activeWorkers = 0;
      state.currentNodeNames = [];
      state.error = error;
    });
    activeRunId = null;
  };

  const runCheck = async (input: {
    runId: string;
    scope: ProxyCheckScope;
    nodeName?: string | null;
    concurrency: number;
    settings: AppSettings;
  }): Promise<void> => {
    try {
      const names = await options.resolveNodeNames({ settings: input.settings, scope: input.scope, nodeName: input.nodeName });
      if (activeRunId !== input.runId) return;
      refreshState((state) => {
        state.total = names.length;
        state.error = null;
      });
      publishSnapshot("proxy.check.started");
      if (names.length === 0) {
        markTerminal("completed", null);
        publishSnapshot("proxy.check.completed");
        return;
      }

      let cursor = 0;
      const workerCount = Math.min(input.concurrency, names.length);
      const worker = async (workerSlot: number): Promise<void> => {
        const runner = await options.createWorker({
          settings: input.settings,
          runId: input.runId,
          workerSlot,
        });
        try {
          while (true) {
            if (activeRunId !== input.runId) return;
            const index = cursor;
            cursor += 1;
            const nodeName = names[index];
            if (!nodeName) return;
            refreshState((state) => {
              state.activeWorkers += 1;
              state.currentNodeNames.push(nodeName);
            });
            publishSnapshot("proxy.check.progress");
            const result = await runner.checkNode(nodeName);
            if (activeRunId !== input.runId) return;
            options.recordResult(result);
            refreshState((state) => {
              state.completed += 1;
              state.activeWorkers = Math.max(0, state.activeWorkers - 1);
              state.currentNodeNames = state.currentNodeNames.filter((name) => name !== nodeName);
              if (result.ok) state.succeeded += 1;
              else state.failed += 1;
            });
            publishSnapshot("proxy.check.progress", { result });
          }
        } finally {
          await runner.close?.().catch(() => {});
        }
      };

      await Promise.all(Array.from({ length: workerCount }, (_, index) => worker(index + 1)));
      if (activeRunId !== input.runId) return;
      markTerminal("completed", null);
      publishSnapshot("proxy.check.completed");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (activeRunId === input.runId) {
        markTerminal("failed", message);
        publishSnapshot("proxy.check.failed");
      }
    }
  };

  return {
    getState(): ProxyCheckState {
      return cloneState(latestState);
    },
    isRunning(): boolean {
      return latestState.status === "running" && Boolean(activeRunId);
    },
    async startCheck(input: { scope: ProxyCheckScope; nodeName?: string | null; concurrencyOverride?: number }): Promise<ProxyCheckStartResult> {
      if (this.isRunning()) {
        return { accepted: false, checkState: cloneState(latestState) };
      }
      const settings = options.readSettings();
      if (!settings.subscriptionUrl.trim()) {
        throw new Error("MIHOMO_SUBSCRIPTION_URL is not configured");
      }
      if (input.scope === "node" && !String(input.nodeName || "").trim()) {
        throw new Error("nodeName is required when scope=node");
      }
      const runId = createRunId();
      const concurrency = normalizeConcurrency(input.concurrencyOverride, options.defaultConcurrency);
      activeRunId = runId;
      latestState = {
        runId,
        status: "running",
        scope: input.scope,
        concurrency,
        total: 0,
        completed: 0,
        succeeded: 0,
        failed: 0,
        activeWorkers: 0,
        currentNodeNames: [],
        startedAt: nowIso(),
        finishedAt: null,
        error: null,
      };
      void runCheck({
        runId,
        scope: input.scope,
        nodeName: input.nodeName,
        concurrency,
        settings,
      });
      return { accepted: true, checkState: cloneState(latestState) };
    },
  };
}

export function resolveProxyCheckConcurrency(raw: string | undefined, fallback = 5): number {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return normalizeConcurrency(fallback, 1);
  const parsed = Number.parseInt(trimmed, 10);
  return normalizeConcurrency(parsed, fallback);
}

export function createMihomoNodeCheckRunner(input: { repoRoot: string; outputRoot: string; ipinfoToken?: string }) {
  return async (params: { settings: AppSettings; runId: string; workerSlot: number }): Promise<ProxyCheckWorker> => {
    const portLeases = await reserveMihomoPortLeases();
    let controller: Awaited<ReturnType<typeof startMihomo>> | null = null;
    let closed = false;
    const close = async () => {
      if (closed) return;
      closed = true;
      await controller?.stop().catch(() => {});
      await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]).catch(() => {});
    };
    try {
      await Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
      controller = await startMihomo({
        subscriptionUrl: params.settings.subscriptionUrl,
        groupName: params.settings.groupName,
        routeGroupName: params.settings.routeGroupName,
        checkUrl: params.settings.checkUrl,
        apiPort: portLeases.apiPort.port,
        mixedPort: portLeases.mixedPort.port,
        workDir: path.join(input.outputRoot, "mihomo", "proxy-checks", params.runId, `worker-${params.workerSlot}`),
        downloadDir: path.join(input.repoRoot, "downloads", "mihomo"),
      });
      const activeController = controller;
      return {
        checkNode: async (nodeName: string) =>
          await checkNode(activeController, nodeName, {
            checkUrl: params.settings.checkUrl,
            timeoutMs: params.settings.timeoutMs,
            maxLatencyMs: params.settings.maxLatencyMs,
            ipinfoToken: input.ipinfoToken,
          }),
        close,
      };
    } catch (error) {
      await close();
      throw error;
    }
  };
}
