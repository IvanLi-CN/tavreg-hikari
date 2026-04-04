import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { mkdir, readFile } from "node:fs/promises";
import {
  AppDatabase,
  type AppSettings,
  type ChatGptCredentialRecord,
  type JobAttemptRecord,
  type JobRecord,
  type JobSite,
} from "../storage/app-db.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import { buildAttemptSpawnOptions, resolveAttemptProxyNode, resolveWorkerRuntime, type ServerEvent } from "./scheduler.js";

interface ActiveAttempt {
  child: ChildProcessWithoutNullStreams;
  attempt: JobAttemptRecord;
  outputDir: string;
  reservedPorts: { apiPort: number; mixedPort: number };
  stopRequested: "force_stop" | null;
}

interface ChatGptJobPayload {
  email: string;
  password: string;
  nickname: string;
  birthDate: string;
  mailboxId: string;
}

interface ChatGptWorkerResult {
  mode: "headed" | "headless";
  email: string;
  password: string;
  nickname: string;
  birthDate: string;
  credentials?: {
    access_token?: string;
    refresh_token?: string;
    id_token?: string;
    account_id?: string;
    expires_at?: string | null;
    exp?: number | null;
  };
  notes?: string[];
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

function parsePayload(job: Pick<JobRecord, "payloadJson">): ChatGptJobPayload {
  const payload = job.payloadJson || {};
  const email = String(payload.email || "").trim().toLowerCase();
  const password = String(payload.password || "");
  const nickname = String(payload.nickname || "").trim();
  const birthDate = String(payload.birthDate || "").trim();
  const mailboxId = String(payload.mailboxId || "").trim();
  if (!email || !password || !nickname || !birthDate || !mailboxId) {
    throw new Error("chatgpt_job_payload_invalid");
  }
  return { email, password, nickname, birthDate, mailboxId };
}

function resolveCredentialExpiry(result: NonNullable<ChatGptWorkerResult["credentials"]>): string | null {
  if (typeof result.expires_at === "string" && result.expires_at.trim()) {
    return result.expires_at.trim();
  }
  if (typeof result.exp === "number" && Number.isFinite(result.exp) && result.exp > 0) {
    return new Date(result.exp * 1000).toISOString();
  }
  return null;
}

export class ChatGptJobScheduler {
  private readonly activeAttempts = new Map<number, ActiveAttempt>();
  private readonly pendingAttemptFinalizers = new Set<Promise<void>>();
  private loopPromise: Promise<void> | null = null;
  private shuttingDown = false;

  constructor(
    private readonly db: AppDatabase,
    private readonly repoRoot: string,
    private readonly getSettings: () => AppSettings,
    private readonly publish: (event: ServerEvent) => void,
    private readonly site: JobSite = "chatgpt",
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

  getRecentCredentials(limit = 20): ChatGptCredentialRecord[] {
    return this.db.listChatGptCredentials(limit);
  }

  async startJob(input: ChatGptJobPayload): Promise<JobRecord> {
    const settings = this.getSettings();
    if (!settings.subscriptionUrl.trim()) {
      throw new Error("configure a Mihomo subscription before starting a ChatGPT job");
    }
    const job = this.db.createJob({
      site: this.site,
      runMode: "headed",
      need: 1,
      parallel: 1,
      maxAttempts: 1,
      payloadJson: {
        email: input.email,
        password: input.password,
        nickname: input.nickname,
        birthDate: input.birthDate,
        mailboxId: input.mailboxId,
      },
    });
    this.emit("job.updated", { site: this.site, job });
    this.emit("toast", { level: "info", message: `chatgpt job #${job.id} started` });
    this.ensureLoop(job.id);
    return job;
  }

  stopCurrentJob(): JobRecord {
    const job = this.requireCurrentJob();
    if (job.status === "stopped" || isStopInProgressStatus(job.status)) {
      return job;
    }
    if (job.status !== "running") {
      throw new Error(`current ChatGPT job cannot be stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "stopping", pausedAt: null });
    this.emit("job.updated", { site: this.site, job: next });
    this.ensureLoop(job.id);
    return next;
  }

  forceStopCurrentJob(confirmForceStop = false): JobRecord {
    if (!confirmForceStop) {
      throw new Error("force stop requires confirmForceStop=true");
    }
    const job = this.requireCurrentJob();
    if (job.status === "stopped" || job.status === "force_stopping") {
      return job;
    }
    const next = this.db.updateJobState(job.id, { status: "force_stopping", pausedAt: null });
    for (const active of this.activeAttempts.values()) {
      active.stopRequested = "force_stop";
      signalChildProcess(active.child, "SIGTERM");
    }
    this.emit("job.updated", { site: this.site, job: next });
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
    if (!job) throw new Error("no current ChatGPT job");
    if (isTerminalJobStatus(job.status)) {
      throw new Error(`current ChatGPT job is already ${job.status}`);
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
          this.emit("toast", { level: "info", message: `chatgpt job #${job.id} stopped` });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
        continue;
      }

      if (job.successCount >= job.need) {
        if (this.activeAttempts.size === 0) {
          const completed = this.db.completeJob(job.id, true);
          this.emit("job.updated", { site: this.site, job: completed });
          this.emit("toast", { level: "success", message: `chatgpt job #${job.id} completed` });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
        continue;
      }

      if (this.activeAttempts.size === 0 && job.launchedCount < job.maxAttempts) {
        const payload = parsePayload(job);
        const outputDir = path.join(this.repoRoot, "output", "web-runs", `chatgpt-job-${job.id}`, `attempt-${Date.now()}`);
        const attempt = this.db.createAttempt(job.id, {
          accountEmail: payload.email,
          outputDir,
        });
        try {
          await this.spawnAttempt(job, attempt, payload, outputDir);
          this.emit("attempt.updated", { site: this.site, attempt: this.db.getAttempt(attempt.id) });
          this.emit("job.updated", { site: this.site, job: this.db.getJob(job.id) });
        } catch (error) {
          this.failAttempt(job.id, attempt.id, {
            errorCode: "launch_setup_failed",
            errorMessage: error instanceof Error ? error.message : String(error),
          });
        }
      }

      const refreshed = this.db.getJob(jobId);
      if (!refreshed) return;
      if (this.activeAttempts.size === 0 && refreshed.launchedCount >= refreshed.maxAttempts && refreshed.successCount < refreshed.need) {
        const failed = this.db.completeJob(jobId, false, "chatgpt attempts exhausted");
        this.emit("job.updated", { site: this.site, job: failed });
        this.emit("toast", { level: "error", message: `chatgpt job #${job.id} failed: ${failed.lastError}` });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  private async spawnAttempt(job: JobRecord, attempt: JobAttemptRecord, payload: ChatGptJobPayload, outputDir: string): Promise<void> {
    await mkdir(outputDir, { recursive: true });
    const settings = this.getSettings();
    const portLeases = await reserveMihomoPortLeases();
    const reservedPorts = {
      apiPort: portLeases.apiPort.port,
      mixedPort: portLeases.mixedPort.port,
    };
    const runtime = resolveWorkerRuntime();
    const selectedProxyNode = resolveAttemptProxyNode(this.db);
    if (selectedProxyNode) {
      this.db.touchProxyLease(selectedProxyNode);
    }
    const args =
      runtime.command === "bun"
        ? ["run", "src/server/chatgpt-worker.ts"]
        : ["--import", "tsx", "src/server/chatgpt-worker.ts"];
    if (selectedProxyNode?.trim()) {
      args.push("--proxy-node", selectedProxyNode.trim());
    }
    const child = spawn(runtime.command, args, {
      ...buildAttemptSpawnOptions(this.repoRoot, {
        env: {
          ...process.env,
          RUN_MODE: "headed",
          CHATGPT_JOB_EMAIL: payload.email,
          CHATGPT_JOB_PASSWORD: payload.password,
          CHATGPT_JOB_NICKNAME: payload.nickname,
          CHATGPT_JOB_BIRTH_DATE: payload.birthDate,
          CHATGPT_JOB_MAILBOX_ID: payload.mailboxId,
          CHATGPT_JOB_OUTPUT_DIR: outputDir,
          MIHOMO_SUBSCRIPTION_URL: settings.subscriptionUrl,
          MIHOMO_GROUP_NAME: settings.groupName,
          MIHOMO_ROUTE_GROUP_NAME: settings.routeGroupName,
          MIHOMO_API_PORT: String(reservedPorts.apiPort),
          MIHOMO_MIXED_PORT: String(reservedPorts.mixedPort),
          PROXY_CHECK_URL: settings.checkUrl,
          PROXY_CHECK_TIMEOUT_MS: String(settings.timeoutMs),
          PROXY_LATENCY_MAX_MS: String(settings.maxLatencyMs),
          OUTPUT_ROOT_DIR: outputDir,
          KEEP_BROWSER_OPEN_ON_FAILURE: process.env.KEEP_BROWSER_OPEN_ON_FAILURE || "true",
          KEEP_BROWSER_OPEN_MS: process.env.KEEP_BROWSER_OPEN_MS || "0",
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
    let settled = false;
    const finalize = async (runner: () => Promise<void> | void) => {
      if (settled) return;
      settled = true;
      const finalizer = (async () => {
        try {
          await runner();
        } finally {
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

    child.once("error", (error) => {
      void finalize(() =>
        this.failAttempt(job.id, attempt.id, {
          errorCode: "spawn_error",
          errorMessage: error.message || "failed to start chatgpt worker process",
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
    const result = await readJsonFile<ChatGptWorkerResult>(path.join(outputDir, "result.json"));
    const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
    const credentials = result?.credentials;
    const accessToken = String(credentials?.access_token || "").trim();
    const refreshToken = String(credentials?.refresh_token || "").trim();
    const idToken = String(credentials?.id_token || "").trim();
    const accountId = String(credentials?.account_id || "").trim();
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

    if (code === 0 && signal == null && accessToken && refreshToken && idToken) {
      const payloadJson = JSON.stringify({
        ...credentials,
        email: result?.email || "",
        nickname: result?.nickname || "",
        birthDate: result?.birthDate || "",
        notes: result?.notes || [],
      });
      const { job, attempt, credential } = this.db.completeChatGptAttemptSuccess(jobId, attemptId, {
        email: result?.email || "",
        accountId,
        accessToken,
        refreshToken,
        idToken,
        expiresAt: credentials ? resolveCredentialExpiry(credentials) : null,
        credentialJson: payloadJson,
      });
      this.emit("attempt.updated", { site: this.site, attempt });
      this.emit("job.updated", { site: this.site, job });
      this.emit("toast", { level: "success", message: `chatgpt credential saved #${credential.id}` });
      return;
    }

    const errorCode =
      code === 0 && signal == null && accessToken && !refreshToken
        ? "chatgpt_refresh_token_missing"
        : code == null
          ? "process_exit"
          : `exit_${code}`;
    this.failAttempt(jobId, attemptId, {
      errorCode,
      errorMessage: message,
    });
  }

  private failAttempt(jobId: number, attemptId: number, input: { errorCode: string; errorMessage: string }): void {
    const { job, attempt } = this.db.completeAttemptFailure(jobId, attemptId, null, input, null);
    this.emit("attempt.updated", { site: this.site, attempt });
    this.emit("job.updated", { site: this.site, job });
    this.emit("toast", { level: "error", message: `chatgpt attempt #${attempt.id} failed: ${input.errorMessage}` });
  }

  private emit(type: ServerEvent["type"], payload: Record<string, unknown>): void {
    this.publish({
      type,
      payload,
      timestamp: nowIso(),
    });
  }
}
