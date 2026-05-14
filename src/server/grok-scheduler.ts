import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync } from "node:fs";
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
import { buildAttemptSpawnOptions, resolveWorkerRuntime, type ServerEvent } from "./scheduler.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import { createGrokMailbox, rememberGrokBlockedMailbox } from "./grok-mail-service.js";
import { buildLocalWritebackSourceOrigin, buildUpstreamSyncConfig, writeBackUpstreamSuccess } from "./upstream-sync.js";
import {
  buildProxyBrokerEnv,
  closeProxyBrokerRuntimeSession,
  logProxyBrokerSessionCloseError,
  openDomainProbedProxyBrokerRuntimeSession,
  type ProxyBrokerRuntimeSession,
} from "./proxy-broker-runtime.js";
import {
  getMailboxProviderCooldownSnapshot,
  isMailboxProviderCooldownErrorCode,
  resolveMailboxProviderIdentity,
  type MailboxProviderCooldownSnapshot,
} from "./mailbox-provider-guard.js";

interface ActiveAttempt {
  child: ChildProcessWithoutNullStreams;
  attempt: JobAttemptRecord;
  outputDir: string;
  reservedPorts: { apiPort: number; mixedPort: number };
  brokerSession?: ProxyBrokerRuntimeSession | null;
  stopRequested: "force_stop" | null;
  stopRequestedAtMs?: number | null;
  lastProgressAtMs?: number | null;
  releaseResources?: () => Promise<void>;
  finalize?: (runner: () => Promise<void> | void) => void;
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

export interface GrokStartCooldownState {
  active: boolean;
  until: string;
  sourceAttemptId: number | null;
  sourceJobId: number | null;
  sourceErrorCode: string;
  reason: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function getLaunchSetupErrorCode(error: unknown): string {
  if (error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string") {
    const code = (error as { code: string }).code.trim();
    if (code && !/^[A-Z][A-Z0-9_]*$/.test(code)) return code;
    return "launch_setup_failed";
  }
  if (error instanceof Error && error.name && error.name !== "Error") {
    return error.name;
  }
  return "launch_setup_failed";
}

function parseIsoToMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function readJsonFileSync<T>(filePath: string): T | null {
  try {
    return JSON.parse(readFileSync(filePath, "utf8")) as T;
  } catch {
    return null;
  }
}

function readProgressMarkerMs(outputDir: string): number | null {
  let latest: number | null = null;
  for (const fileName of ["heartbeat.json", "stage.json"]) {
    const marker = readJsonFileSync<{ updatedAt?: string | null }>(path.join(outputDir, fileName));
    const updatedAtMs = parseIsoToMs(marker?.updatedAt);
    if (updatedAtMs != null) {
      latest = latest == null ? updatedAtMs : Math.max(latest, updatedAtMs);
    }
  }
  return latest;
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

function stageMarkerStage(outputDir: string): string | null {
  const marker = readJsonFileSync<{ stage?: unknown }>(path.join(outputDir, "stage.json"));
  const stage = String(marker?.stage || "").trim();
  return stage || null;
}

const FORCE_STOP_SIGKILL_AFTER_MS = 5_000;
const FORCE_STOP_REAP_AFTER_MS = 30_000;
const RUNNING_STALE_ATTEMPT_REAP_AFTER_MS = 10 * 60_000;

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

  getCooldownSnapshot(): GrokStartCooldownState | null {
    const identity = resolveMailboxProviderIdentity({
      provider: "cfmail",
      baseUrl: process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test",
      credential: process.env.CFMAIL_API_KEY || "",
    });
    if (!identity) return null;
    const snapshot = getMailboxProviderCooldownSnapshot(identity);
    if (!snapshot?.active) return null;
    return {
      active: true,
      until: snapshot.until,
      sourceAttemptId: null,
      sourceJobId: null,
      sourceErrorCode: snapshot.sourceErrorCode,
      reason: snapshot.reason,
    };
  }

  async startJob(input: {
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
  }): Promise<JobRecord> {
    const settings = this.getSettings();
    if (!process.env.PROXY_BROKER_API_KEY?.trim()) {
      throw new Error("configure PROXY_BROKER_API_KEY before starting a Grok job");
    }
    const cooldown = this.getCooldownSnapshot();
    if (cooldown?.active) {
      throw new Error(`${cooldown.reason}; retry after ${cooldown.until}`);
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
      this.reapActiveAttempts(job);
      return this.maybeFinalizeStoppedJob(job.id) || job;
    }
    if (!["running", "paused", "completing"].includes(job.status)) {
      throw new Error(`current Grok job cannot be stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "stopping", pausedAt: null });
    this.reapActiveAttempts(next);
    const finalized = this.maybeFinalizeStoppedJob(next.id) || next;
    this.emit("job.updated", { site: this.site, job: finalized });
    this.emit("toast", {
      level: "info",
      message:
        finalized.status === "stopped"
          ? `grok job #${job.id} stopped`
          : `grok job #${job.id} stopping gracefully`,
    });
    if (finalized.status !== "stopped") {
      this.ensureLoop(job.id);
    }
    return finalized;
  }

  forceStopCurrentJob(confirmForceStop = false): JobRecord {
    if (!confirmForceStop) {
      throw new Error("force stop requires confirmForceStop=true");
    }
    const job = this.db.getCurrentJob(this.site);
    if (!job) throw new Error("no current Grok job");
    if (job.status === "stopped" || job.status === "force_stopping") {
      this.reapActiveAttempts(job);
      return this.maybeFinalizeStoppedJob(job.id) || job;
    }
    if (!["running", "paused", "stopping", "completing"].includes(job.status)) {
      throw new Error(`current Grok job cannot be force stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
    for (const active of this.activeAttempts.values()) {
      if (active.attempt.jobId === job.id) {
        this.requestForceStop(active);
      }
    }
    this.reapActiveAttempts(next);
    const finalized = this.maybeFinalizeStoppedJob(next.id) || next;
    this.emit("job.updated", { site: this.site, job: finalized });
    this.emit("toast", {
      level: "warning",
      message: finalized.status === "stopped" ? `grok job #${job.id} force stopped` : `grok job #${job.id} force stopping`,
    });
    if (finalized.status !== "stopped") {
      this.ensureLoop(job.id);
    }
    return finalized;
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
      this.requestForceStop(active);
    }
    await Promise.allSettled(Array.from(this.activeAttempts.values()).map((active) => active.releaseResources?.()));
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

  private requestForceStop(active: ActiveAttempt): void {
    active.stopRequested = "force_stop";
    active.stopRequestedAtMs ??= Date.now();
    if (active.child) {
      signalChildProcess(active.child, "SIGTERM");
    }
    const attemptId = this.activeAttemptId(active);
    setTimeout(() => {
      const current = attemptId == null ? null : this.activeAttempts.get(attemptId);
      if (current?.stopRequested === "force_stop" && current.child) {
        signalChildProcess(current.child, "SIGKILL");
      }
    }, FORCE_STOP_SIGKILL_AFTER_MS).unref?.();
  }

  private activeAttemptId(active: ActiveAttempt): number | null {
    const id = active.attempt?.id ?? (active as unknown as { attemptId?: unknown }).attemptId;
    const numericId = Number(id);
    return Number.isFinite(numericId) && numericId > 0 ? numericId : null;
  }

  private cleanupActiveAttempt(active: ActiveAttempt): void {
    const attemptId = this.activeAttemptId(active);
    if (attemptId != null) {
      this.activeAttempts.delete(attemptId);
    }
    void active.releaseResources?.().catch(() => {});
  }

  private syncActiveAttemptStage(active: ActiveAttempt): void {
    const attemptId = this.activeAttemptId(active);
    if (attemptId == null) return;
    if (!active.outputDir) return;
    const markerStage = stageMarkerStage(active.outputDir);
    if (!markerStage) return;
    const latest = this.db.getAttempt(attemptId);
    if (!latest || latest.status !== "running" || latest.stage === markerStage) return;
    const updated = this.db.updateAttempt(attemptId, { stage: markerStage });
    active.attempt = updated;
    this.emit("attempt.updated", { site: this.site, attempt: updated });
  }

  private maybeFinalizeStoppedJob(jobId: number): JobRecord | null {
    const job = this.db.getJob(jobId);
    if (!job || !isStopInProgressStatus(job.status)) return null;
    for (const active of this.activeAttempts.values()) {
      if (active.attempt.jobId === jobId) return null;
    }
    return this.db.stopJob(jobId);
  }

  private reapActiveAttempts(job: JobRecord): boolean {
    let changed = false;
    const nowMs = Date.now();
    for (const active of Array.from(this.activeAttempts.values())) {
      const attemptId = this.activeAttemptId(active);
      if (attemptId == null) continue;
      const latestAttempt = this.db.getAttempt(attemptId);
      if ((latestAttempt?.jobId ?? active.attempt?.jobId) !== job.id) continue;
      if (!latestAttempt || latestAttempt.status !== "running") {
        this.cleanupActiveAttempt(active);
        changed = true;
        continue;
      }
      this.syncActiveAttemptStage(active);

      const child = active.child as ChildProcessWithoutNullStreams & {
        exitCode?: number | null;
        signalCode?: NodeJS.Signals | null;
      };
      if (!child) continue;
      const errorArtifact = readJsonFileSync<{ error?: string; failureStage?: string }>(path.join(active.outputDir, "error.json"));
      const resultArtifact = readJsonFileSync<GrokWorkerResult>(path.join(active.outputDir, "result.json"));
      const exited = child.exitCode != null || child.signalCode != null;
      const stopRequestedAtMs = active.stopRequestedAtMs ?? null;
      const forceStopTimedOut =
        (job.status === "force_stopping" || active.stopRequested === "force_stop")
        && stopRequestedAtMs != null
        && nowMs - stopRequestedAtMs >= FORCE_STOP_REAP_AFTER_MS;
      const markerProgressAtMs = readProgressMarkerMs(active.outputDir);
      const explicitProgressAtMs = Math.max(active.lastProgressAtMs ?? 0, markerProgressAtMs ?? 0) || null;
      const lastProgressAtMs = explicitProgressAtMs ?? parseIsoToMs(latestAttempt.startedAt) ?? null;
      const runningStaleTimedOut =
        (job.status === "running" || job.status === "completing")
        && lastProgressAtMs != null
        && nowMs - lastProgressAtMs >= RUNNING_STALE_ATTEMPT_REAP_AFTER_MS;
      if (runningStaleTimedOut && !exited && active.stopRequested !== "force_stop") {
        this.requestForceStop(active);
        changed = true;
        continue;
      }

      if (!exited && !forceStopTimedOut) continue;

      if (active.finalize && exited) {
        active.finalize(() =>
          this.handleAttemptExit(job.id, attemptId, active.outputDir, child.exitCode ?? null, child.signalCode ?? null, active),
        );
        changed = true;
        continue;
      }

      if (job.status === "force_stopping" || active.stopRequested === "force_stop" || forceStopTimedOut) {
        const signal = child.signalCode ?? null;
        this.db.completeAttemptStopped(job.id, attemptId, null, {
          errorCode: signal ? `force_stop_${String(signal).toLowerCase()}` : "force_stopped",
          errorMessage:
            errorArtifact?.error
            || (signal ? `terminated by ${signal}` : child.exitCode != null ? `process exited with code ${child.exitCode}` : "stopped by user"),
        });
        this.cleanupActiveAttempt(active);
        changed = true;
        continue;
      }

      if (errorArtifact?.error) {
        this.failAttempt(job.id, attemptId, {
          errorCode: child.exitCode == null ? "process_exit" : `exit_${child.exitCode}`,
          errorMessage: errorArtifact.error,
        });
        this.cleanupActiveAttempt(active);
        changed = true;
        continue;
      }

      if (exited) {
        const email = String(resultArtifact?.email || "").trim().toLowerCase();
        const password = String(resultArtifact?.password || "").trim();
        const sso = String(resultArtifact?.sso || "").trim();
        if (child.exitCode === 0 && child.signalCode == null && email && password && sso) {
          continue;
        }
        const signal = child.signalCode ?? null;
        this.failAttempt(job.id, attemptId, {
          errorCode: signal ? `signal_${String(signal).toLowerCase()}` : child.exitCode == null ? "process_exit" : `exit_${child.exitCode}`,
          errorMessage:
            signal ? `terminated by ${signal}` : child.exitCode == null ? "process exited without code" : `process exited with code ${child.exitCode}`,
        });
        this.cleanupActiveAttempt(active);
        changed = true;
      }
    }
    return changed;
  }

  private async runLoop(jobId: number): Promise<void> {
    while (!this.shuttingDown) {
      const job = this.db.getJob(jobId);
      if (!job || job.site !== this.site) return;
      if (isTerminalJobStatus(job.status)) return;
      if (this.reapActiveAttempts(job)) {
        await new Promise((resolve) => setTimeout(resolve, 150));
        continue;
      }

      if (isStopInProgressStatus(job.status)) {
        const stopped = this.maybeFinalizeStoppedJob(job.id);
        if (stopped) {
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

      const cooldown = this.getCooldownSnapshot();
      if (cooldown?.active) {
        const untilMs = parseIsoToMs(cooldown.until);
        const waitMs = untilMs == null ? 1000 : Math.max(250, Math.min(5000, untilMs - Date.now()));
        await new Promise((resolve) => setTimeout(resolve, waitMs));
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
            stage: "allocating_proxy",
          });
          try {
            await this.spawnAttempt(job, attempt, outputDir);
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            this.failAttempt(job.id, attempt.id, {
              errorCode: isMailboxProviderCooldownErrorCode(errorMessage) ? errorMessage : getLaunchSetupErrorCode(error),
              errorMessage,
            });
            if (isMailboxProviderCooldownErrorCode(errorMessage)) {
              break;
            }
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
    const brokerSession = await openDomainProbedProxyBrokerRuntimeSession({
      settings,
      businessSite: "grok",
      excludedIps: this.activeAttemptRows().map((item) => item.proxyIp).filter((item): item is string => Boolean(item)),
    }).catch(async (error) => {
      await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
      throw error;
    });
    this.db.updateAttempt(attempt.id, {
      accountEmail: mailbox.address.toLowerCase(),
      stage: "proxy_bound",
      proxyNode: brokerSession.session.proxy_name,
      proxyIp: brokerSession.session.selected_ip,
      brokerSessionId: brokerSession.session.session_id,
      proxyDisplayAddress: brokerSession.session.display_address,
      proxyNodeId: brokerSession.session.node_id,
    });
    this.db.touchProxyLease(brokerSession.session.proxy_name, {
      leasedAt: nowIso(),
      egressIp: brokerSession.session.selected_ip || null,
    });
    const refreshedJob = this.db.getJob(job.id);
    if (refreshedJob && (isStopInProgressStatus(refreshedJob.status) || refreshedJob.status === "stopped")) {
      await closeProxyBrokerRuntimeSession(settings, brokerSession.session.session_id).catch((closeError) => {
        logProxyBrokerSessionCloseError(brokerSession.session.session_id, closeError, "grok-stopped-before-launch");
      });
      await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
      const { job: stoppedJob, attempt: stoppedAttempt } = this.db.completeAttemptStopped(job.id, attempt.id, null, {
        errorCode: refreshedJob.status === "force_stopping" ? "force_stopped" : "stopped_before_launch",
        errorMessage: "stopped before launch",
      });
      this.emit("attempt.updated", { site: this.site, attempt: stoppedAttempt });
      this.emit("job.updated", { site: this.site, job: this.maybeFinalizeStoppedJob(job.id) || stoppedJob });
      return;
    }
    const args =
      runtime.command === "bun"
        ? ["run", "src/server/grok-worker.ts"]
        : ["--import", "tsx", "src/server/grok-worker.ts"];
    args.push("--proxy-node", brokerSession.session.proxy_name);
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(runtime.command, args, {
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
            ...buildProxyBrokerEnv(brokerSession),
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
    } catch (error) {
      await closeProxyBrokerRuntimeSession(settings, brokerSession.session.session_id).catch((closeError) => {
        logProxyBrokerSessionCloseError(brokerSession.session.session_id, closeError, "grok-spawn-failure");
      });
      await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
      throw error;
    }
    child.stdin.end();
    let resourcesReleased = false;
    const releaseResources = async () => {
      if (resourcesReleased) return;
      resourcesReleased = true;
      await closeProxyBrokerRuntimeSession(settings, brokerSession.session.session_id).catch((error) => {
        logProxyBrokerSessionCloseError(brokerSession.session.session_id, error, "grok-attempt-finalize");
      });
      await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
    };
    const active: ActiveAttempt = {
      child,
      attempt,
      outputDir,
      reservedPorts,
      brokerSession,
      stopRequested: null,
      stopRequestedAtMs: null,
      releaseResources,
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
          await active.releaseResources?.();
          const stopped = this.maybeFinalizeStoppedJob(job.id);
          if (stopped) {
            this.emit("job.updated", { site: this.site, job: stopped });
          }
        }
      })();
      this.pendingAttemptFinalizers.add(finalizer);
      try {
        await finalizer;
      } finally {
        this.pendingAttemptFinalizers.delete(finalizer);
      }
    };
    active.finalize = (runner) => {
      void finalize(runner);
    };

    child.once("spawn", () => {
      this.db.updateAttempt(attempt.id, { stage: "spawned" });
      void Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
    });
    child.stdout.on("data", (chunk) => {
      active.lastProgressAtMs = Date.now();
      stdout += chunk.toString();
      void flushWorkerLog();
    });
    child.stderr.on("data", (chunk) => {
      active.lastProgressAtMs = Date.now();
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
      try {
        const config = buildUpstreamSyncConfig(this.getSettings());
        await writeBackUpstreamSuccess({
          site: "grok",
          key,
        }, {
          config,
          sourceOrigin: buildLocalWritebackSourceOrigin("grok", config.localInstanceId),
        });
      } catch (writebackError) {
        const message = writebackError instanceof Error ? writebackError.message : String(writebackError);
        this.emit("toast", {
          level: "warning",
          message: `grok sso #${key.id} saved locally, but upstream writeback failed: ${message}`,
        });
      }
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
