import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import {
  AppDatabase,
  computeLaunchCapacity,
  normalizeJobMaxAttempts,
  type AppSettings,
  type ChatGptCredentialRecord,
  type JobAttemptRecord,
  type JobRecord,
  type JobSite,
  type ProxyNodeRecord,
} from "../storage/app-db.js";
import { buildCodexVibeMonitorCredentialJson } from "./chatgpt-credential-format.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import { buildAttemptSpawnOptions, resolveWorkerRuntime, type ServerEvent } from "./scheduler.js";
import { pickAutoProxyNode } from "./proxy-node-allocation.js";
import {
  formatMailboxProviderCooldownReason,
  getMailboxProviderCooldownSnapshot,
  resolveMailboxProviderIdentity,
  type MailboxProviderCooldownSnapshot,
} from "./mailbox-provider-guard.js";

interface ActiveAttempt {
  child: ChildProcessWithoutNullStreams;
  attempt: JobAttemptRecord;
  outputDir: string;
  reservedPorts: { apiPort: number; mixedPort: number };
  stopRequested: "force_stop" | null;
}

interface ChatGptAttemptDraft {
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
    token_type?: string | null;
    exp?: number | null;
  };
  notes?: string[];
}

export interface ChatGptStartCooldownState {
  active: boolean;
  until: string;
  sourceAttemptId: number | null;
  sourceJobId: number | null;
  sourceErrorCode: string;
  reason: string;
}

const CHATGPT_START_COOLDOWN_MS = 5 * 60_000;
const CHATGPT_START_COOLDOWN_ERROR_CODES = new Set([
  "chatgpt_auth_challenge_detected",
  "chatgpt_captcha_manual_required",
]);

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

function normalizeDraft(input: unknown): ChatGptAttemptDraft | null {
  if (!input || typeof input !== "object") return null;
  const record = input as Record<string, unknown>;
  const email = String(record.email || "").trim().toLowerCase();
  const password = String(record.password || "");
  const nickname = String(record.nickname || "").trim();
  const birthDate = String(record.birthDate || "").trim();
  const mailboxId = String(record.mailboxId || "").trim();
  if (!email || !password || !nickname || !birthDate || !mailboxId) {
    return null;
  }
  return {
    email,
    password,
    nickname,
    birthDate,
    mailboxId,
  };
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

function deriveWorkerErrorCode(rawMessage: string): string | null {
  const message = String(rawMessage || "").trim();
  if (!message) return null;
  const normalized = message.match(/^(chatgpt_[a-z0-9_]+)/i);
  const value = normalized?.[1];
  return value ? value.toLowerCase() : null;
}

function formatChatGptCooldownReason(errorCode: string): string {
  switch (String(errorCode || "").trim().toLowerCase()) {
    case "chatgpt_auth_challenge_detected":
      return "recent auth challenge detected";
    case "chatgpt_captcha_manual_required":
      return "recent captcha/manual verification detected";
    default:
      return "recent auth risk detected";
  }
}

function parseIsoToMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function attemptOutputShowsAuthChallenge(attempt: Pick<JobAttemptRecord, "outputDir">): boolean {
  const outputDir = String(attempt.outputDir || "").trim();
  if (!outputDir) return false;
  try {
    const workerLog = readFileSync(path.join(outputDir, "worker.log"), "utf8");
    return /__cf_chl_rt_tk=|just a moment|checking your browser|cloudflare|security check|enable javascript and cookies/i.test(
      workerLog,
    );
  } catch {
    return false;
  }
}

function isBlockedChatGptProxyNode(nodeName: string): boolean {
  return /香港|hong\s*kong|\bhk\b/i.test(String(nodeName || "").trim());
}

function isHealthyChatGptProxyNode(node: Pick<ProxyNodeRecord, "lastStatus">): boolean {
  const status = String(node.lastStatus || "").trim().toLowerCase();
  return !status || status === "ok" || status === "succeeded" || status === "running";
}

function shouldBlockChatGptProxyAfterFailure(input: { errorCode: string; errorMessage: string }): boolean {
  const errorCode = String(input.errorCode || "").trim().toLowerCase();
  const errorMessage = String(input.errorMessage || "").trim().toLowerCase();
  if (errorCode === "chatgpt_auth_challenge_detected") return true;
  if (errorCode === "chatgpt_phone_verification_required") return true;
  if (errorCode === "exit_1") {
    return /__cf_chl_rt_tk=|just a moment|checking your browser|cloudflare|security verification/.test(errorMessage);
  }
  return false;
}

function resolveChatGptProxyNode(
  db: Pick<AppDatabase, "listProxyNodes">,
  activeAttempts: JobAttemptRecord[],
): ProxyNodeRecord | null {
  return pickAutoProxyNode({
    nodes: db.listProxyNodes().filter((node) => isHealthyChatGptProxyNode(node)),
    activeAttempts,
    policy: {
      allowNode: (node) => !isBlockedChatGptProxyNode(node.nodeName),
    },
  });
}

export class ChatGptJobScheduler {
  private readonly activeAttempts = new Map<number, ActiveAttempt>();
  private readonly pendingAttemptFinalizers = new Set<Promise<void>>();
  private readonly draftFailureCounts = new Map<number, number>();
  private loopPromise: Promise<void> | null = null;
  private shuttingDown = false;
  private readonly site: JobSite;
  private readonly createAttemptDraft: () => Promise<ChatGptAttemptDraft>;

  constructor(
    private readonly db: AppDatabase,
    private readonly repoRoot: string,
    private readonly getSettings: () => AppSettings,
    private readonly publish: (event: ServerEvent) => void,
    options?: {
      site?: JobSite;
      createAttemptDraft?: () => Promise<ChatGptAttemptDraft>;
    },
  ) {
    this.site = options?.site || "chatgpt";
    this.createAttemptDraft =
      options?.createAttemptDraft
      || (async (): Promise<ChatGptAttemptDraft> => {
        throw new Error("chatgpt_attempt_draft_factory_missing");
      });
  }

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

  getRecentCredentials(filters?: {
    limit?: number;
    sortBy?: "createdAt" | "expiresAt";
    sortDir?: "desc" | "asc";
    q?: string;
    expiryStatus?: "valid" | "expired" | "noExpiry";
  }): ChatGptCredentialRecord[] {
    return this.db.listChatGptCredentials(filters);
  }

  getCooldownSnapshot(): ChatGptStartCooldownState | null {
    const mailboxCooldown = this.getMailboxProviderCooldownSnapshot();
    const job = this.db.getCurrentJob(this.site);
    let authCooldown: ChatGptStartCooldownState | null = null;
    if (job) {
      const attempt = this.db.listAttempts(job.id, false).find((item) => {
        const errorCode = String(item.errorCode || "").trim().toLowerCase();
        return CHATGPT_START_COOLDOWN_ERROR_CODES.has(errorCode) || attemptOutputShowsAuthChallenge(item);
      });
      if (attempt?.completedAt) {
        const completedAtMs = Date.parse(attempt.completedAt);
        if (Number.isFinite(completedAtMs)) {
          const untilMs = completedAtMs + CHATGPT_START_COOLDOWN_MS;
          if (untilMs > Date.now()) {
            const sourceErrorCode = String(attempt.errorCode || "").trim().toLowerCase() || "chatgpt_auth_challenge_detected";
            authCooldown = {
              active: true,
              until: new Date(untilMs).toISOString(),
              sourceAttemptId: attempt.id,
              sourceJobId: job.id,
              sourceErrorCode,
              reason: formatChatGptCooldownReason(sourceErrorCode),
            };
          }
        }
      }
    }
    const authUntilMs = parseIsoToMs(authCooldown?.until);
    const mailboxUntilMs = parseIsoToMs(mailboxCooldown?.until);
    if (authUntilMs != null && mailboxUntilMs != null) {
      return mailboxUntilMs > authUntilMs ? mailboxCooldown : authCooldown;
    }
    return authCooldown || mailboxCooldown;
  }

  private getMailboxProviderCooldownSnapshot(): MailboxProviderCooldownSnapshot | null {
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
      reason: snapshot.reason || formatMailboxProviderCooldownReason(snapshot.sourceErrorCode),
    };
  }

  async startJob(input: {
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
  }): Promise<JobRecord> {
    const settings = this.getSettings();
    if (!settings.subscriptionUrl.trim()) {
      throw new Error("configure a Mihomo subscription before starting a ChatGPT job");
    }
    const cooldown = this.getCooldownSnapshot();
    if (cooldown?.active) {
      throw new Error(`${cooldown.reason}; retry after ${cooldown.until}`);
    }
    const normalizedNeed = Math.max(1, Math.trunc(input.need));
    const normalizedParallel = Math.max(1, Math.trunc(input.parallel));
    const normalizedMaxAttempts = normalizeJobMaxAttempts(normalizedNeed, input.maxAttempts);
    const runMode = input.runMode === "headless" ? "headless" : "headed";
    const job = this.db.createJob({
      site: this.site,
      runMode,
      need: normalizedNeed,
      parallel: normalizedParallel,
      maxAttempts: normalizedMaxAttempts,
      payloadJson: {},
    });
    const startupLaunch = await this.dispatchAttempt(job, { persistFailureOnDraftError: false });
    if (!startupLaunch.launched && startupLaunch.fatal) {
      this.db.deleteJob(job.id);
      throw new Error(startupLaunch.error || "chatgpt attempt draft failed at attempt #1");
    }
    const current = this.db.getJob(job.id) || job;
    this.emit("job.updated", { site: this.site, job: current });
    this.emit("toast", { level: "info", message: `chatgpt job #${job.id} started` });
    this.ensureLoop(job.id);
    return current;
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

  private clearJobRuntimeState(jobId: number): void {
    this.draftFailureCounts.delete(jobId);
  }

  private async dispatchAttempt(
    job: JobRecord,
    options?: { persistFailureOnDraftError?: boolean },
  ): Promise<{ launched: boolean; fatal: boolean; error?: string }> {
    const currentJob = this.db.getJob(job.id) || job;
    const launchIndex = currentJob.launchedCount;
    let draft: ChatGptAttemptDraft;
    try {
      const generatedDraft = await this.createAttemptDraft();
      const normalizedDraft = normalizeDraft(generatedDraft);
      if (!normalizedDraft) {
        throw new Error("chatgpt_attempt_draft_invalid");
      }
      draft = normalizedDraft;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      const lastError = `chatgpt attempt draft failed at attempt #${launchIndex + 1}: ${reason}`;
      if (options?.persistFailureOnDraftError === false) {
        return { launched: false, fatal: true, error: lastError };
      }
      if (currentJob.launchedCount > 0 && this.activeAttempts.size === 0) {
        this.draftFailureCounts.set(job.id, (this.draftFailureCounts.get(job.id) || 0) + 1);
      }
      if (this.activeAttempts.size > 0 || currentJob.launchedCount > 0) {
        const next = this.db.updateJobState(job.id, { lastError });
        this.emit("job.updated", { site: this.site, job: next });
        return { launched: false, fatal: false, error: lastError };
      }
      const failed = this.db.completeJob(job.id, false, lastError);
      this.emit("job.updated", { site: this.site, job: failed });
      this.emit("toast", { level: "error", message: `chatgpt job #${job.id} failed: ${failed.lastError}` });
      return { launched: false, fatal: true, error: failed.lastError || lastError };
    }

    this.draftFailureCounts.delete(job.id);

    const outputDir = path.join(this.repoRoot, "output", "web-runs", `chatgpt-job-${job.id}`, `attempt-${Date.now()}-${launchIndex + 1}`);
    const attempt = this.db.createAttempt(job.id, {
      accountEmail: draft.email,
      outputDir,
    });
    try {
      await this.spawnAttempt(currentJob, attempt, draft, outputDir);
      this.emit("attempt.updated", { site: this.site, attempt: this.db.getAttempt(attempt.id) });
      this.emit("job.updated", { site: this.site, job: this.db.getJob(job.id) });
    } catch (error) {
      this.failAttempt(job.id, attempt.id, {
        errorCode: "launch_setup_failed",
        errorMessage: error instanceof Error ? error.message : String(error),
      });
    }
    return { launched: true, fatal: false };
  }

  private async runLoop(jobId: number): Promise<void> {
    while (!this.shuttingDown) {
      const job = this.db.getJob(jobId);
      if (!job || job.site !== this.site) return;
      if (isTerminalJobStatus(job.status)) return;

      if (isStopInProgressStatus(job.status)) {
        if (this.activeAttempts.size === 0) {
          const stopped = this.db.stopJob(job.id);
          this.clearJobRuntimeState(job.id);
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
          this.clearJobRuntimeState(job.id);
          this.emit("job.updated", { site: this.site, job: completed });
          this.emit("toast", { level: "success", message: `chatgpt job #${job.id} completed` });
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
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
        for (let slot = 0; slot < launchCapacity; slot += 1) {
          const launch = await this.dispatchAttempt(job);
          if (!launch.launched) {
            if (launch.fatal) {
              return;
            }
            break;
          }
        }
      }

      const refreshed = this.db.getJob(jobId);
      if (!refreshed) return;
      const remainingLaunchBudget = Math.max(0, refreshed.maxAttempts - refreshed.launchedCount);
      const draftFailureCount = this.draftFailureCounts.get(jobId) || 0;
      const draftBudgetExhausted = remainingLaunchBudget >= 0 && draftFailureCount > remainingLaunchBudget;
      if (
        this.activeAttempts.size === 0
        && refreshed.successCount < refreshed.need
        && (refreshed.launchedCount >= refreshed.maxAttempts || draftBudgetExhausted)
      ) {
        const failed = this.db.completeJob(jobId, false, refreshed.lastError || "chatgpt attempts exhausted");
        this.clearJobRuntimeState(job.id);
        this.emit("job.updated", { site: this.site, job: failed });
        this.emit("toast", { level: "error", message: `chatgpt job #${job.id} failed: ${failed.lastError}` });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  private async spawnAttempt(job: JobRecord, attempt: JobAttemptRecord, payload: ChatGptAttemptDraft, outputDir: string): Promise<void> {
    await mkdir(outputDir, { recursive: true });
    const settings = this.getSettings();
    const portLeases = await reserveMihomoPortLeases();
    const reservedPorts = {
      apiPort: portLeases.apiPort.port,
      mixedPort: portLeases.mixedPort.port,
    };
    const runtime = resolveWorkerRuntime();
    const selectedProxy = resolveChatGptProxyNode(this.db, this.activeAttemptRows());
    if (selectedProxy) {
      this.db.updateAttempt(attempt.id, { proxyNode: selectedProxy.nodeName, proxyIp: selectedProxy.lastEgressIp });
      this.db.touchProxyLease(selectedProxy.nodeName, {
        egressIp: selectedProxy.lastEgressIp,
        leasedAt: nowIso(),
      });
    }
    const args =
      runtime.command === "bun"
        ? ["run", "src/server/chatgpt-worker.ts"]
        : ["--import", "tsx", "src/server/chatgpt-worker.ts"];
    if (selectedProxy?.nodeName.trim()) {
      args.push("--proxy-node", selectedProxy.nodeName.trim());
    }
    const child = spawn(runtime.command, args, {
      ...buildAttemptSpawnOptions(this.repoRoot, {
        env: {
          ...process.env,
          RUN_MODE: job.runMode,
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
          CHROME_PROFILE_DIR: path.join(outputDir, "chrome-profile"),
          INSPECT_CHROME_PROFILE_DIR: path.join(outputDir, "chrome-inspect-profile"),
          KEEP_BROWSER_OPEN_ON_FAILURE: process.env.KEEP_BROWSER_OPEN_ON_FAILURE || "false",
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
    const workerErrorCode = deriveWorkerErrorCode(message);

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
      const expiresAt = credentials ? resolveCredentialExpiry(credentials) : null;
      const payloadJson = buildCodexVibeMonitorCredentialJson({
        email: result?.email || "",
        accountId,
        accessToken,
        refreshToken,
        idToken,
        expiresAt,
        createdAt: new Date().toISOString(),
        tokenType: typeof credentials?.token_type === "string" ? credentials.token_type : null,
      });
      const { job, attempt, credential } = this.db.completeChatGptAttemptSuccess(jobId, attemptId, {
        email: result?.email || "",
        accountId,
        accessToken,
        refreshToken,
        idToken,
        expiresAt,
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
        : workerErrorCode
          ? workerErrorCode
          : code == null
            ? "process_exit"
            : `exit_${code}`;
    this.failAttempt(jobId, attemptId, {
      errorCode,
      errorMessage: message,
    });
  }

  private failAttempt(jobId: number, attemptId: number, input: { errorCode: string; errorMessage: string }): void {
    const priorAttempt = this.db.getAttempt(attemptId);
    const { job, attempt } = this.db.completeAttemptFailure(jobId, attemptId, null, input, null);
    const failedProxyNode = priorAttempt?.proxyNode || attempt.proxyNode;
    if (failedProxyNode && shouldBlockChatGptProxyAfterFailure(input)) {
      this.db.touchProxyLease(failedProxyNode, {
        status: "failed",
      });
    }
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
