import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import {
  AppDatabase,
  computeLaunchCapacity,
  normalizeJobMaxAttempts,
  type AppSettings,
  type JobAttemptRecord,
  type JobRecord,
  type JobSite,
  type ProxyNodeRecord,
} from "../storage/app-db.js";
import { buildAttemptSpawnOptions, resolveAttemptProxyNode, resolveWorkerRuntime, type ServerEvent } from "./scheduler.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import { createGrokMailbox, rememberGrokBlockedMailbox } from "./grok-mail-service.js";

interface ActiveAttempt {
  child: ChildProcessWithoutNullStreams;
  attempt: JobAttemptRecord;
  outputDir: string;
  reservedPorts: { apiPort: number; mixedPort: number };
  stopRequested: "force_stop" | null;
}

interface GrokWorkerResult {
  mode?: "headed" | "headless";
  email?: string;
  password?: string;
  sso?: string;
  ssoRw?: string | null;
  cfClearance?: string | null;
  checkoutUrl?: string | null;
  birthDate?: string | null;
  proxy?: {
    nodeName?: string | null;
    ip?: string | null;
  };
  runId?: string | null;
  notes?: string[];
}

interface StoredMailboxSession {
  address?: string | null;
}

function nowIso(): string {
  return new Date().toISOString();
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function isTerminalJobStatus(status: JobRecord["status"]): boolean {
  return status === "completed" || status === "failed" || status === "stopped";
}

function isStopInProgressStatus(status: JobRecord["status"]): boolean {
  return status === "stopping" || status === "force_stopping";
}

function signalChildProcess(child: Pick<ChildProcessWithoutNullStreams, "pid" | "kill">, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (pid) {
    try {
      process.kill(-pid, signal);
      return;
    } catch {
      // fall through
    }
  }
  try {
    child.kill(signal);
  } catch {
    // ignore shutdown races
  }
}

function randomSuffix(): string {
  return Math.random().toString(16).slice(2, 8);
}

function resolveProxyRecord(db: Pick<AppDatabase, "listProxyNodes">, nodeName: string | null | undefined): ProxyNodeRecord | null {
  const normalized = String(nodeName || "").trim();
  if (!normalized) return null;
  return db.listProxyNodes().find((node) => node.nodeName === normalized) || null;
}

export class GrokJobScheduler {
  private readonly activeAttempts = new Map<number, ActiveAttempt>();
  private readonly pendingAttemptFinalizers = new Set<Promise<void>>();
  private loopPromise: Promise<void> | null = null;
  private shuttingDown = false;

  constructor(
    private readonly db: AppDatabase,
    private readonly repoRoot: string,
    private readonly getSettings: () => AppSettings,
    private readonly publish: (event: ServerEvent) => void,
    private readonly site: JobSite = "grok",
  ) {}

  currentJob(): JobRecord | null {
    return this.db.getCurrentJob(this.site);
  }

  activeAttemptRows(): JobAttemptRecord[] {
    return Array.from(this.activeAttempts.values())
      .map((item) => this.db.getAttempt(item.attempt.id) || item.attempt)
      .filter(Boolean);
  }

  getAutoExtractSnapshot(_jobId: number): null {
    return null;
  }

  async startJob(input: {
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
  }): Promise<JobRecord> {
    const settings = this.getSettings();
    if (!settings.subscriptionUrl.trim()) {
      throw new Error("configure a Mihomo subscription before starting a Grok job");
    }
    const need = Math.max(1, Number.isFinite(input.need) ? Math.trunc(input.need) : 1);
    const parallel = Math.max(1, Number.isFinite(input.parallel) ? Math.trunc(input.parallel) : 1);
    const requestedMaxAttempts = Math.max(1, Number.isFinite(input.maxAttempts) ? Math.trunc(input.maxAttempts) : 1);
    const maxAttempts = normalizeJobMaxAttempts(need, requestedMaxAttempts);
    const job = this.db.createJob({
      site: this.site,
      runMode: input.runMode,
      need,
      parallel,
      maxAttempts,
      payloadJson: {},
    });
    this.emit("job.updated", { site: this.site, job });
    this.emit("toast", { level: "info", message: `grok job #${job.id} started` });
    if (maxAttempts !== requestedMaxAttempts) {
      this.emit("toast", {
        level: "info",
        message: `grok job #${job.id} max attempts auto-adjusted to ${maxAttempts} for need ${need}`,
      });
    }
    this.ensureLoop(job.id);
    return job;
  }

  pauseCurrentJob(): JobRecord {
    const job = this.requireCurrentJob();
    if (job.status === "paused") {
      return job;
    }
    if (job.status !== "running") {
      throw new Error(`current Grok job cannot be paused from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "paused", pausedAt: nowIso() });
    this.emit("job.updated", { site: this.site, job: next });
    this.emit("toast", { level: "info", message: `grok job #${job.id} paused` });
    return next;
  }

  resumeCurrentJob(): JobRecord {
    const job = this.requireCurrentJob();
    if (job.status === "running") {
      return job;
    }
    if (job.status !== "paused") {
      throw new Error(`current Grok job cannot be resumed from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "running", pausedAt: null });
    this.emit("job.updated", { site: this.site, job: next });
    this.emit("toast", { level: "info", message: `grok job #${job.id} resumed` });
    this.ensureLoop(job.id);
    return next;
  }

  stopCurrentJob(): JobRecord {
    const job = this.db.getCurrentJob(this.site);
    if (!job) throw new Error("no current Grok job");
    if (job.status === "stopped" || isStopInProgressStatus(job.status)) {
      return job;
    }
    if (!["running", "paused", "completing"].includes(job.status)) {
      throw new Error(`current Grok job cannot be stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "stopping", pausedAt: null });
    this.emit("job.updated", { site: this.site, job: next });
    this.emit("toast", { level: "info", message: `grok job #${job.id} stopping gracefully` });
    this.ensureLoop(job.id);
    return next;
  }

  forceStopCurrentJob(confirmForceStop = false): JobRecord {
    if (!confirmForceStop) {
      throw new Error("force stop requires confirmForceStop=true");
    }
    const job = this.db.getCurrentJob(this.site);
    if (!job) throw new Error("no current Grok job");
    if (job.status === "stopped" || job.status === "force_stopping") {
      return job;
    }
    if (!["running", "paused", "stopping", "completing"].includes(job.status)) {
      throw new Error(`current Grok job cannot be force stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
    for (const active of this.activeAttempts.values()) {
      active.stopRequested = "force_stop";
      signalChildProcess(active.child, "SIGTERM");
    }
    this.emit("job.updated", { site: this.site, job: next });
    this.emit("toast", { level: "warning", message: `grok job #${job.id} force stopping` });
    this.ensureLoop(job.id);
    return next;
  }

  updateCurrentJobLimits(input: Partial<Pick<JobRecord, "parallel" | "need" | "maxAttempts">>): JobRecord {
    const job = this.requireCurrentJob();
    if (!["running", "paused", "completing"].includes(job.status)) {
      throw new Error(`current Grok job cannot update limits from ${job.status}`);
    }
    const requestedNeed =
      typeof input.need === "number" ? Math.max(1, Number.isFinite(input.need) ? Math.trunc(input.need) : 1) : job.need;
    const requestedParallel =
      typeof input.parallel === "number" ? Math.max(1, Number.isFinite(input.parallel) ? Math.trunc(input.parallel) : 1) : job.parallel;
    const requestedMaxAttempts =
      typeof input.maxAttempts === "number"
        ? Math.max(1, Number.isFinite(input.maxAttempts) ? Math.trunc(input.maxAttempts) : 1)
        : job.maxAttempts;
    const maxAttempts = normalizeJobMaxAttempts(requestedNeed, requestedMaxAttempts);
    const next = this.db.updateJobState(job.id, {
      need: requestedNeed,
      parallel: requestedParallel,
      maxAttempts,
    });
    this.emit("job.updated", { site: this.site, job: next });
    this.emit("toast", { level: "info", message: `grok job #${job.id} limits updated` });
    this.ensureLoop(job.id);
    return next;
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    for (const active of this.activeAttempts.values()) {
      active.stopRequested = "force_stop";
      signalChildProcess(active.child, "SIGTERM");
    }
    await Promise.allSettled(Array.from(this.pendingAttemptFinalizers));
    await this.loopPromise;
  }

  private requireCurrentJob(): JobRecord {
    const job = this.db.getCurrentJob(this.site);
    if (!job) throw new Error("no current Grok job");
    if (isTerminalJobStatus(job.status)) {
      throw new Error(`current Grok job is already ${job.status}`);
    }
    return job;
  }

  private ensureLoop(jobId: number): void {
    if (this.loopPromise || this.shuttingDown) return;
    this.loopPromise = this.runLoop(jobId).finally(() => {
      this.loopPromise = null;
    });
  }

  private async runLoop(jobId: number): Promise<void> {
    while (!this.shuttingDown) {
      const job = this.db.getJob(jobId);
      if (!job || job.site !== this.site) return;
      if (isTerminalJobStatus(job.status)) return;

      if (isStopInProgressStatus(job.status)) {
        if (this.activeAttempts.size === 0) {
          const stopped = this.db.stopJob(job.id);
          this.emit("job.updated", { site: this.site, job: stopped });
          this.emit("toast", { level: "info", message: `grok job #${job.id} stopped` });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 150));
        continue;
      }

      if (job.status === "paused") {
        await new Promise((resolve) => setTimeout(resolve, 150));
        continue;
      }

      if (job.successCount >= job.need) {
        if (this.activeAttempts.size === 0) {
          const completed = this.db.completeJob(job.id, true);
          this.emit("job.updated", { site: this.site, job: completed });
          this.emit("toast", { level: "success", message: `grok job #${job.id} completed` });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 150));
        continue;
      }

      const launchCapacity = computeLaunchCapacity(job, this.activeAttempts.size);
      if (launchCapacity > 0) {
        for (let index = 0; index < launchCapacity; index += 1) {
          const outputDir = path.join(
            this.repoRoot,
            "output",
            "web-runs",
            `grok-job-${job.id}`,
            `attempt-${Date.now()}-${randomSuffix()}`,
          );
          const attempt = this.db.createAttempt(job.id, {
            accountEmail: null,
            outputDir,
          });
          try {
            await this.spawnAttempt(job, attempt, outputDir);
          } catch (error) {
            this.failAttempt(job.id, attempt.id, {
              errorCode: "launch_setup_failed",
              errorMessage: error instanceof Error ? error.message : String(error),
            });
          }
        }
        this.emit("job.updated", { site: this.site, job: this.db.getJob(job.id) });
      }

      const refreshed = this.db.getJob(jobId);
      if (!refreshed) return;
      if (this.activeAttempts.size === 0 && refreshed.launchedCount >= refreshed.maxAttempts && refreshed.successCount < refreshed.need) {
        const failed = this.db.completeJob(jobId, false, "grok attempts exhausted");
        this.emit("job.updated", { site: this.site, job: failed });
        this.emit("toast", { level: "error", message: `grok job #${job.id} failed: ${failed.lastError}` });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }

  private async spawnAttempt(job: JobRecord, attempt: JobAttemptRecord, outputDir: string): Promise<void> {
    await mkdir(outputDir, { recursive: true });
    const mailbox = await createGrokMailbox();
    await writeFile(
      path.join(outputDir, "mailbox-session.json"),
      `${JSON.stringify(
        {
          provider: mailbox.provider,
          address: mailbox.address,
          accountId: mailbox.accountId,
          baseUrl: mailbox.baseUrl,
          capturedAt: nowIso(),
        },
        null,
        2,
      )}
`,
      "utf8",
    ).catch(() => {});
    const settings = this.getSettings();
    const portLeases = await reserveMihomoPortLeases();
    const reservedPorts = {
      apiPort: portLeases.apiPort.port,
      mixedPort: portLeases.mixedPort.port,
    };
    const runtime = resolveWorkerRuntime();
    const selectedProxyNode = resolveAttemptProxyNode(this.db);
    this.db.updateAttempt(attempt.id, {
      accountEmail: mailbox.address.toLowerCase(),
    });
    const proxyRecord = resolveProxyRecord(this.db, selectedProxyNode);
    if (selectedProxyNode) {
      this.db.updateAttempt(attempt.id, {
        proxyNode: selectedProxyNode,
        proxyIp: proxyRecord?.lastEgressIp ?? null,
      });
      this.db.touchProxyLease(selectedProxyNode, {
        leasedAt: nowIso(),
        egressIp: proxyRecord?.lastEgressIp ?? null,
      });
    }
    const args =
      runtime.command === "bun"
        ? ["run", "src/server/grok-worker.ts"]
        : ["--import", "tsx", "src/server/grok-worker.ts"];
    if (selectedProxyNode?.trim()) {
      args.push("--proxy-node", selectedProxyNode.trim());
    }
    const child = spawn(runtime.command, args, {
      ...buildAttemptSpawnOptions(this.repoRoot, {
        env: {
          ...process.env,
          RUN_MODE: job.runMode,
          GROK_JOB_OUTPUT_DIR: outputDir,
          GROK_JOB_EMAIL: mailbox.address.toLowerCase(),
          GROK_JOB_MAILBOX_ID: mailbox.accountId,
          OUTPUT_ROOT_DIR: outputDir,
          MIHOMO_SUBSCRIPTION_URL: settings.subscriptionUrl,
          MIHOMO_GROUP_NAME: settings.groupName,
          MIHOMO_ROUTE_GROUP_NAME: settings.routeGroupName,
          MIHOMO_API_PORT: String(reservedPorts.apiPort),
          MIHOMO_MIXED_PORT: String(reservedPorts.mixedPort),
          PROXY_CHECK_URL: settings.checkUrl,
          PROXY_CHECK_TIMEOUT_MS: String(settings.timeoutMs),
          PROXY_LATENCY_MAX_MS: String(settings.maxLatencyMs),
          CHROME_PROFILE_DIR: path.join(outputDir, "chrome-profile"),
          INSPECT_CHROME_PROFILE_DIR: path.join(outputDir, "chrome-inspect-profile"),
          KEEP_BROWSER_OPEN_ON_FAILURE: process.env.KEEP_BROWSER_OPEN_ON_FAILURE || "false",
          KEEP_BROWSER_OPEN_MS: process.env.KEEP_BROWSER_OPEN_MS || "0",
          ...(process.env.GROK_KEY_NAME_PREFIX ? { GROK_KEY_NAME_PREFIX: process.env.GROK_KEY_NAME_PREFIX } : {}),
          ...(process.env.KEY_NAME ? { KEY_NAME: process.env.KEY_NAME } : {}),
        },
      }),
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stdin.end();
    const active: ActiveAttempt = {
      child,
      attempt,
      outputDir,
      reservedPorts,
      stopRequested: null,
    };
    this.activeAttempts.set(attempt.id, active);
    let stdout = "";
    let stderr = "";
    const workerLogPath = path.join(outputDir, "worker.log");
    const flushWorkerLog = async () => {
      const content = [stdout.trim(), stderr.trim()].filter(Boolean).join("\n");
      if (!content) return;
      await writeFile(workerLogPath, `${content}\n`, "utf8").catch(() => {});
    };
    let settled = false;
    const finalize = async (runner: () => Promise<void> | void) => {
      if (settled) return;
      settled = true;
      const finalizer = (async () => {
        try {
          await runner();
        } finally {
          await flushWorkerLog();
          this.activeAttempts.delete(attempt.id);
          await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
        }
      })();
      this.pendingAttemptFinalizers.add(finalizer);
      try {
        await finalizer;
      } finally {
        this.pendingAttemptFinalizers.delete(finalizer);
      }
    };

    child.once("spawn", () => {
      void Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
    });
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      void flushWorkerLog();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      void flushWorkerLog();
    });
    child.once("error", (error) => {
      void finalize(() =>
        this.failAttempt(job.id, attempt.id, {
          errorCode: "spawn_error",
          errorMessage: error.message || "failed to start grok worker process",
        }),
      );
    });
    child.once("close", (code, signal) => {
      void finalize(() => this.handleAttemptExit(job.id, attempt.id, outputDir, code, signal, active));
    });
  }

  private async handleAttemptExit(
    jobId: number,
    attemptId: number,
    outputDir: string,
    code: number | null,
    signal: NodeJS.Signals | null,
    active: ActiveAttempt,
  ): Promise<void> {
    const result = await readJsonFile<GrokWorkerResult>(path.join(outputDir, "result.json"));
    const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
    const mailboxSession = await readJsonFile<StoredMailboxSession>(path.join(outputDir, "mailbox-session.json"));
    const message =
      error?.error
      || (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
    if (active.stopRequested === "force_stop") {
      const { job, attempt } = this.db.completeAttemptStopped(jobId, attemptId, null, {
        errorCode: signal ? `force_stop_${String(signal).toLowerCase()}` : "force_stopped",
        errorMessage: message || "stopped by user",
      });
      this.emit("attempt.updated", { site: this.site, attempt });
      this.emit("job.updated", { site: this.site, job });
      return;
    }

    const email = String(result?.email || "").trim().toLowerCase();
    const password = String(result?.password || "").trim();
    const sso = String(result?.sso || "").trim();
    if (code === 0 && signal == null && email && password && sso) {
      const currentAttempt = this.db.getAttempt(attemptId);
      const proxyNode = String(result?.proxy?.nodeName || currentAttempt?.proxyNode || "").trim() || null;
      const proxyIp = String(result?.proxy?.ip || currentAttempt?.proxyIp || "").trim() || null;
      const { job, attempt, key } = this.db.completeGrokAttemptSuccess(jobId, attemptId, {
        email,
        password,
        sso,
        ssoRw: result?.ssoRw ?? null,
        cfClearance: result?.cfClearance ?? null,
        checkoutUrl: result?.checkoutUrl ?? null,
        birthDate: result?.birthDate ?? null,
        extractedIp: proxyIp,
        runId: result?.runId || null,
        proxyNode,
        proxyIp,
      });
      this.emit("attempt.updated", { site: this.site, attempt });
      this.emit("job.updated", { site: this.site, job });
      this.emit("toast", { level: "success", message: `grok sso saved #${key.id}` });
      return;
    }

    const errorCode = code == null ? "process_exit" : `exit_${code}`;
    if (/^grok_email_code_timeout:/i.test(message)) {
      const blockedDomain = rememberGrokBlockedMailbox(mailboxSession?.address);
      if (blockedDomain) {
        this.emit("toast", {
          level: "info",
          message: `grok mailbox domain blocked for future attempts: ${blockedDomain}`,
        });
      }
    }
    this.failAttempt(jobId, attemptId, {
      errorCode,
      errorMessage: message,
    });
  }

  private failAttempt(jobId: number, attemptId: number, input: { errorCode: string; errorMessage: string }): void {
    const { job, attempt } = this.db.completeAttemptFailure(jobId, attemptId, null, input, null);
    this.emit("attempt.updated", { site: this.site, attempt });
    this.emit("job.updated", { site: this.site, job });
    this.emit("toast", { level: "error", message: `grok attempt #${attempt.id} failed: ${input.errorMessage}` });
  }

  private emit(type: ServerEvent["type"], payload: Record<string, unknown>): void {
    this.publish({
      type,
      payload,
      timestamp: nowIso(),
    });
  }
}
