import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { mkdir, readFile } from "node:fs/promises";
import {
  AppDatabase,
  computeLaunchCapacity,
  normalizeJobMaxAttempts,
  type AccountExtractorAccountType,
  type AccountExtractorProvider,
  type AppSettings,
  type JobAttemptRecord,
  type JobRecord,
  type MicrosoftAccountRecord,
} from "../storage/app-db.js";
import { fetchSingleExtractedAccount, keyConfiguredForProvider } from "./account-extractor.js";
import { reserveMihomoPortLeases, type PortLease } from "./port-lease.js";

export interface ServerEvent {
  type: "job.updated" | "attempt.updated" | "account.updated" | "proxy.updated" | "proxy.check.completed" | "toast";
  payload: Record<string, unknown>;
  timestamp: string;
}

interface ActiveAttempt {
  child: ChildProcessWithoutNullStreams;
  attempt: JobAttemptRecord;
  account: MicrosoftAccountRecord;
  outputDir: string;
  reservedPorts: { apiPort: number; mixedPort: number };
  tail: string[];
}

type AutoExtractPhase = "idle" | "waiting" | "extracting";

interface AutoExtractState {
  jobId: number;
  enabledSources: AccountExtractorProvider[];
  accountType: AccountExtractorAccountType;
  maxWaitMs: number;
  remainingWaitMs: number;
  currentRoundTarget: number;
  attemptBudget: number;
  acceptedCount: number;
  rawAttemptCount: number;
  inFlightCount: number;
  nextProviderIndex: number;
  providerNextAttemptAtMs: Record<AccountExtractorProvider, number>;
  phase: AutoExtractPhase;
  startedAt: string | null;
  lastProvider: AccountExtractorProvider | null;
  lastMessage: string | null;
  updatedAt: string;
  lastBudgetTickMs: number | null;
}

interface AutoExtractRequestContext {
  jobId: number;
  provider: AccountExtractorProvider;
  accountType: AccountExtractorAccountType;
  requestedUsableCount: number;
  attemptBudget: number;
  dispatchStartedAt: string;
  roundStartedAt: string | null;
}

export interface AutoExtractSnapshot {
  phase: AutoExtractPhase;
  enabledSources: AccountExtractorProvider[];
  accountType: AccountExtractorAccountType;
  currentRoundTarget: number;
  acceptedCount: number;
  rawAttemptCount: number;
  attemptBudget: number;
  inFlightCount: number;
  remainingWaitSec: number;
  maxWaitSec: number;
  startedAt: string | null;
  lastProvider: AccountExtractorProvider | null;
  lastMessage: string | null;
  updatedAt: string | null;
}

type AutoExtractDecision =
  | { status: "ready" }
  | { status: "waiting" }
  | { status: "unavailable"; reason: string };

const AUTO_EXTRACT_REQUEST_INTERVAL_MS = 500;
const AUTO_EXTRACT_MAX_CONCURRENT_REQUESTS = 4;
const AUTO_EXTRACT_OVERFETCH_ALLOWANCE = AUTO_EXTRACT_MAX_CONCURRENT_REQUESTS - 1;
const AUTO_EXTRACT_REQUEST_TIMEOUT_MS = 5000;

const STRIPPED_ATTEMPT_ENV_KEYS = [
  "EXISTING_EMAIL",
  "EXISTING_PASSWORD",
  "MICROSOFT_ACCOUNT_EMAIL",
  "MICROSOFT_ACCOUNT_PASSWORD",
  "MICROSOFT_PROOF_MAILBOX_PROVIDER",
  "MICROSOFT_PROOF_MAILBOX_ADDRESS",
  "MICROSOFT_PROOF_MAILBOX_ID",
  "CHROME_REMOTE_DEBUGGING_PORT",
] as const;

function buildAttemptBaseEnv(baseEnv: NodeJS.ProcessEnv | undefined): NodeJS.ProcessEnv {
  const next: NodeJS.ProcessEnv = { ...(baseEnv || process.env) };
  for (const key of STRIPPED_ATTEMPT_ENV_KEYS) {
    delete next[key];
  }
  return next;
}

function resolveWorkerRuntime(): { command: string; bootstrapArgs: string[] } {
  const explicitNodeBinary = process.env.NODE_BINARY?.trim();
  if (process.versions.bun && !explicitNodeBinary) {
    return {
      command: process.execPath,
      bootstrapArgs: ["run", "src/main.ts"],
    };
  }
  return {
    // Prefer Node.js when it is explicitly configured, but keep the Bun-hosted
    // scheduler deployable on environments that only ship Bun.
    command: explicitNodeBinary || process.execPath || "node",
    bootstrapArgs: ["--import", "tsx", "src/main.ts"],
  };
}

function isTerminalJobStatus(status: JobRecord["status"]): boolean {
  return status === "completed" || status === "failed";
}

function normalizeExtractorSources(sources: AccountExtractorProvider[] | undefined): AccountExtractorProvider[] {
  return Array.from(
    new Set((sources || []).filter((item): item is AccountExtractorProvider => item === "zhanghaoya" || item === "shanyouxiang")),
  );
}

function providerLabel(provider: AccountExtractorProvider): string {
  return provider === "zhanghaoya" ? "账号鸭" : "闪邮箱";
}

function mapFailureCodeToBatchStatus(
  code: "invalid_key" | "insufficient_stock" | "parse_failed" | "upstream_error" | null,
): "invalid_key" | "insufficient_stock" | "parse_failed" | "error" {
  if (code === "invalid_key") return "invalid_key";
  if (code === "insufficient_stock") return "insufficient_stock";
  if (code === "parse_failed") return "parse_failed";
  return "error";
}

function maskLocalSecret(secret: string): string | null {
  const value = secret.trim();
  if (!value) return null;
  if (value.length <= 8) return `${"*".repeat(Math.max(0, value.length - 2))}${value.slice(-2)}`;
  return `${value.slice(0, 4)}${"*".repeat(Math.max(4, value.length - 8))}${value.slice(-4)}`;
}

export function resolveAttemptProxyNode(
  db: Pick<AppDatabase, "getPinnedProxyName" | "getSelectedProxyName" | "hasProxyNode">,
): string | null {
  const pinnedProxyNode = db.getPinnedProxyName();
  if (pinnedProxyNode) {
    return db.hasProxyNode(pinnedProxyNode) ? pinnedProxyNode : null;
  }
  const selectedProxyNode = db.getSelectedProxyName();
  if (!selectedProxyNode) {
    return null;
  }
  return db.hasProxyNode(selectedProxyNode) ? selectedProxyNode : null;
}

export function buildAttemptRuntimeSpec(input: {
  job: Pick<JobRecord, "id" | "runMode">;
  account: Pick<
    MicrosoftAccountRecord,
    "id" | "microsoftEmail" | "passwordPlaintext" | "proofMailboxProvider" | "proofMailboxAddress" | "proofMailboxId"
  >;
  outputDir: string;
  sharedLedgerPath: string;
  settings: Pick<AppSettings, "subscriptionUrl" | "groupName" | "routeGroupName" | "checkUrl" | "timeoutMs" | "maxLatencyMs">;
  reservedPorts: { apiPort: number; mixedPort: number };
  selectedProxyNode?: string | null;
  baseEnv?: NodeJS.ProcessEnv;
}): { command: string; args: string[]; env: NodeJS.ProcessEnv } {
  const runtime = resolveWorkerRuntime();
  const args = [...runtime.bootstrapArgs, "--mode", input.job.runMode, "--parallel", "1", "--need", "1"];
  if (input.selectedProxyNode?.trim()) {
    args.push("--proxy-node", input.selectedProxyNode.trim());
  }
  const inheritedEnv = buildAttemptBaseEnv(input.baseEnv);
  return {
    command: runtime.command,
    args,
    env: {
      ...inheritedEnv,
      RUN_MODE: input.job.runMode,
      MICROSOFT_ACCOUNT_EMAIL: input.account.microsoftEmail,
      MICROSOFT_ACCOUNT_PASSWORD: input.account.passwordPlaintext,
      ...(input.account.proofMailboxProvider ? { MICROSOFT_PROOF_MAILBOX_PROVIDER: input.account.proofMailboxProvider } : {}),
      ...(input.account.proofMailboxAddress ? { MICROSOFT_PROOF_MAILBOX_ADDRESS: input.account.proofMailboxAddress } : {}),
      ...(input.account.proofMailboxId ? { MICROSOFT_PROOF_MAILBOX_ID: input.account.proofMailboxId } : {}),
      MIHOMO_SUBSCRIPTION_URL: input.settings.subscriptionUrl,
      MIHOMO_GROUP_NAME: input.settings.groupName,
      MIHOMO_ROUTE_GROUP_NAME: input.settings.routeGroupName,
      MIHOMO_API_PORT: String(input.reservedPorts.apiPort),
      MIHOMO_MIXED_PORT: String(input.reservedPorts.mixedPort),
      PROXY_CHECK_URL: input.settings.checkUrl,
      PROXY_CHECK_TIMEOUT_MS: String(input.settings.timeoutMs),
      PROXY_LATENCY_MAX_MS: String(input.settings.maxLatencyMs),
      TASK_LEDGER_JOB_ID: String(input.job.id),
      TASK_LEDGER_ACCOUNT_ID: String(input.account.id),
      TASK_LEDGER_DB_PATH: input.sharedLedgerPath,
      OUTPUT_ROOT_DIR: input.outputDir,
      CHROME_PROFILE_DIR: path.join(input.outputDir, "chrome-profile"),
      INSPECT_CHROME_PROFILE_DIR: path.join(input.outputDir, "chrome-inspect-profile"),
      ...(input.job.runMode === "headed"
        ? {
            KEEP_BROWSER_OPEN_ON_FAILURE: inheritedEnv.KEEP_BROWSER_OPEN_ON_FAILURE || "false",
            KEEP_BROWSER_OPEN_MS: inheritedEnv.KEEP_BROWSER_OPEN_MS || "0",
          }
        : {}),
    },
  };
}

function nowIso(): string {
  return new Date().toISOString();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createProviderAttemptClock(): Record<AccountExtractorProvider, number> {
  return {
    zhanghaoya: 0,
    shanyouxiang: 0,
  };
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export class JobScheduler {
  private readonly activeAttempts = new Map<number, ActiveAttempt>();
  private readonly autoExtractStates = new Map<number, AutoExtractState>();
  private loopPromise: Promise<void> | null = null;

  constructor(
    private readonly db: AppDatabase,
    private readonly repoRoot: string,
    private readonly sharedLedgerPath: string,
    private readonly getSettings: () => AppSettings,
    private readonly publish: (event: ServerEvent) => void,
  ) {}

  currentJob(): JobRecord | null {
    return this.db.getCurrentJob();
  }

  activeAttemptRows(): JobAttemptRecord[] {
    return Array.from(this.activeAttempts.values())
      .map((item) => this.db.getAttempt(item.attempt.id) || item.attempt)
      .filter(Boolean);
  }

  getAutoExtractSnapshot(jobId: number): AutoExtractSnapshot | null {
    const job = this.db.getJob(jobId);
    if (!job || job.autoExtractSources.length === 0) return null;
    const state = this.autoExtractStates.get(jobId) || this.createAutoExtractState(job);
    return {
      phase: state.phase,
      enabledSources: [...state.enabledSources],
      accountType: state.accountType,
      currentRoundTarget: state.currentRoundTarget,
      acceptedCount: state.acceptedCount,
      rawAttemptCount: state.rawAttemptCount,
      attemptBudget: state.attemptBudget,
      inFlightCount: state.inFlightCount,
      remainingWaitSec: Math.max(0, Math.ceil(state.remainingWaitMs / 1000)),
      maxWaitSec: Math.max(0, Math.ceil(state.maxWaitMs / 1000)),
      startedAt: state.startedAt,
      lastProvider: state.lastProvider,
      lastMessage: state.lastMessage,
      updatedAt: state.updatedAt || null,
    };
  }

  async startJob(params: {
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
    autoExtractSources?: AccountExtractorProvider[];
    autoExtractQuantity?: number;
    autoExtractMaxWaitSec?: number;
    autoExtractAccountType?: AccountExtractorAccountType;
  }): Promise<JobRecord> {
    const settings = this.getSettings();
    if (!settings.subscriptionUrl.trim()) {
      throw new Error("configure a Mihomo subscription before starting a job");
    }
    const autoExtract = this.normalizeAutoExtractConfig(params, settings);
    const requestedNeed = Math.max(1, Number.isFinite(params.need) ? Math.trunc(params.need) : 1);
    const normalizedMaxAttempts = normalizeJobMaxAttempts(requestedNeed, params.maxAttempts);
    const job = this.db.createJob({
      ...params,
      maxAttempts: normalizedMaxAttempts,
      ...autoExtract,
    });
    this.syncAutoExtractState(job);
    this.emit("job.updated", { job });
    this.emit("toast", { level: "info", message: `job #${job.id} started` });
    const requestedMaxAttempts = Math.max(1, Number.isFinite(params.maxAttempts) ? Math.trunc(params.maxAttempts) : 1);
    if (normalizedMaxAttempts !== requestedMaxAttempts) {
      this.emit("toast", {
        level: "info",
        message: `job #${job.id} max attempts auto-adjusted to ${normalizedMaxAttempts} for need ${requestedNeed}`,
      });
    }
    this.ensureLoop(job.id);
    return job;
  }

  pauseCurrentJob(): JobRecord {
    const job = this.requireCurrentJob();
    const next = this.db.updateJobState(job.id, { status: "paused", pausedAt: nowIso() });
    this.emit("job.updated", { job: next });
    this.emit("toast", { level: "info", message: `job #${job.id} paused` });
    return next;
  }

  resumeCurrentJob(): JobRecord {
    const job = this.requireCurrentJob();
    const next = this.db.updateJobState(job.id, { status: "running", pausedAt: null });
    this.syncAutoExtractState(next);
    this.emit("job.updated", { job: next });
    this.emit("toast", { level: "info", message: `job #${job.id} resumed` });
    this.ensureLoop(job.id);
    return next;
  }

  updateCurrentJobLimits(
    input: Partial<
      Pick<
        JobRecord,
        | "parallel"
        | "need"
        | "maxAttempts"
        | "autoExtractSources"
        | "autoExtractQuantity"
        | "autoExtractMaxWaitSec"
        | "autoExtractAccountType"
      >
    >,
  ): JobRecord {
    const job = this.requireCurrentJob();
    const settings = this.getSettings();
    const patch: Partial<JobRecord> = {};
    const requestedParallel =
      typeof input.parallel === "number" ? Math.max(1, Number.isFinite(input.parallel) ? Math.trunc(input.parallel) : 1) : job.parallel;
    const requestedNeed =
      typeof input.need === "number" ? Math.max(1, Number.isFinite(input.need) ? Math.trunc(input.need) : 1) : job.need;
    const requestedMaxAttempts =
      typeof input.maxAttempts === "number"
        ? Math.max(1, Number.isFinite(input.maxAttempts) ? Math.trunc(input.maxAttempts) : 1)
        : job.maxAttempts;
    const normalizedMaxAttempts = normalizeJobMaxAttempts(requestedNeed, requestedMaxAttempts);
    if (typeof input.parallel === "number") patch.parallel = requestedParallel;
    if (typeof input.need === "number") patch.need = requestedNeed;
    if (input.maxAttempts !== undefined || input.need !== undefined) {
      patch.maxAttempts = normalizedMaxAttempts;
    }
    if (
      input.autoExtractSources !== undefined
      || input.autoExtractQuantity !== undefined
      || input.autoExtractMaxWaitSec !== undefined
      || input.autoExtractAccountType !== undefined
    ) {
      const autoExtract = this.normalizeAutoExtractConfig(
        {
          autoExtractSources: input.autoExtractSources,
          autoExtractQuantity: input.autoExtractQuantity,
          autoExtractMaxWaitSec: input.autoExtractMaxWaitSec,
          autoExtractAccountType: input.autoExtractAccountType,
        },
        settings,
        job,
      );
      patch.autoExtractSources = autoExtract.autoExtractSources;
      patch.autoExtractQuantity = autoExtract.autoExtractQuantity;
      patch.autoExtractMaxWaitSec = autoExtract.autoExtractMaxWaitSec;
      patch.autoExtractAccountType = autoExtract.autoExtractAccountType;
    }
    const next = this.db.updateJobState(job.id, patch);
    this.syncAutoExtractState(next);
    if (next.successCount >= next.need && next.status === "running") {
      this.db.updateJobState(next.id, { status: "completing" });
    }
    this.emit("job.updated", { job: this.db.getJob(job.id) });
    this.emit("toast", { level: "info", message: `job #${job.id} limits updated` });
    if (normalizedMaxAttempts !== requestedMaxAttempts) {
      this.emit("toast", {
        level: "info",
        message: `job #${job.id} max attempts auto-adjusted to ${normalizedMaxAttempts} for need ${requestedNeed}`,
      });
    }
    this.ensureLoop(job.id);
    return this.db.getJob(job.id)!;
  }

  async shutdown(): Promise<void> {
    const waits: Promise<void>[] = [];
    for (const active of this.activeAttempts.values()) {
      active.child.kill("SIGTERM");
      waits.push(
        new Promise((resolve) => {
          active.child.once("close", () => resolve());
        }),
      );
    }
    await Promise.allSettled(waits);
  }

  private requireCurrentJob(): JobRecord {
    const job = this.db.getCurrentJob();
    if (!job) throw new Error("no current job");
    if (isTerminalJobStatus(job.status)) {
      throw new Error(`current job is already ${job.status}`);
    }
    return job;
  }

  private ensureLoop(jobId: number): void {
    if (this.loopPromise) return;
    this.loopPromise = this.runLoop(jobId).finally(() => {
      this.loopPromise = null;
    });
  }

  private async runLoop(jobId: number): Promise<void> {
    while (true) {
      const job = this.db.getJob(jobId);
      if (!job) return;

      const activeCount = this.activeAttempts.size;

      if (job.status === "paused") {
        await delay(100);
        continue;
      }

      if (job.successCount >= job.need) {
        if (job.status !== "completing" && activeCount > 0) {
          const next = this.db.updateJobState(jobId, { status: "completing" });
          this.emit("job.updated", { job: next });
        }
        if (activeCount === 0) {
          const completed = this.db.completeJob(jobId, true);
          this.deleteAutoExtractStateIfIdle(jobId);
          this.emit("job.updated", { job: completed });
          this.emit("toast", { level: "success", message: `job #${job.id} completed` });
          return;
        }
        await delay(100);
        continue;
      }

      const capacity = computeLaunchCapacity(job, activeCount);
      for (let i = 0; i < capacity; i += 1) {
        const account = this.db.leaseNextAccount(jobId);
        if (!account) break;
        const attemptOutputDir = path.join(this.repoRoot, "output", "web-runs", `job-${job.id}`, `attempt-${Date.now()}-${account.id}`);
        const attempt = this.db.createAttempt(job.id, account.id, attemptOutputDir);
        try {
          await this.spawnAttempt(job, account, attempt, attemptOutputDir);
          this.emit("attempt.updated", { attempt: this.db.getAttempt(attempt.id) });
          this.emit("account.updated", { account: this.db.getAccount(account.id) });
          this.emit("job.updated", { job: this.db.getJob(job.id) });
        } catch (error) {
          this.failAttempt(job.id, attempt.id, account.id, {
            errorCode: "launch_setup_failed",
            errorMessage: error instanceof Error ? error.message : String(error),
          });
        }
      }

      const refreshed = this.db.getJob(jobId);
      if (!refreshed) return;
      const eligible = this.db.countEligibleAccounts(jobId);
      const hasAutoExtractState = this.autoExtractStates.has(jobId);
      if (eligible === 0 && refreshed.successCount < refreshed.need && refreshed.launchedCount < refreshed.maxAttempts) {
        const extraction = await this.maybeAutoExtract(refreshed);
        if (extraction.status === "ready" || extraction.status === "waiting") {
          await delay(100);
          continue;
        }
        if (this.activeAttempts.size === 0) {
          const failed = this.db.completeJob(jobId, false, extraction.reason);
          this.deleteAutoExtractStateIfIdle(jobId);
          this.emit("job.updated", { job: failed });
          this.emit("toast", { level: "error", message: `job #${job.id} failed: ${failed.lastError}` });
          return;
        }
      }
      if (this.activeAttempts.size === 0) {
        if (refreshed.successCount >= refreshed.need) {
          const completed = this.db.completeJob(jobId, true);
          this.deleteAutoExtractStateIfIdle(jobId);
          this.emit("job.updated", { job: completed });
          this.emit("toast", { level: "success", message: `job #${job.id} completed` });
          return;
        }
        if ((eligible === 0 && !hasAutoExtractState) || refreshed.launchedCount >= refreshed.maxAttempts) {
          const failed = this.db.completeJob(jobId, false, "eligible accounts exhausted or max attempts reached");
          this.deleteAutoExtractStateIfIdle(jobId);
          this.emit("job.updated", { job: failed });
          this.emit("toast", { level: "error", message: `job #${job.id} failed: ${failed.lastError}` });
          return;
        }
      }

      await delay(100);
    }
  }

  private async spawnAttempt(job: JobRecord, account: MicrosoftAccountRecord, attempt: JobAttemptRecord, outputDir: string): Promise<void> {
    let reservedPorts: { apiPort: number; mixedPort: number } | null = null;
    let portLeases: { apiPort: PortLease; mixedPort: PortLease } | null = null;
    try {
      await mkdir(outputDir, { recursive: true });
      const settings = this.getSettings();
      portLeases = await reserveMihomoPortLeases();
      reservedPorts = {
        apiPort: portLeases.apiPort.port,
        mixedPort: portLeases.mixedPort.port,
      };
      const selectedProxyNode = resolveAttemptProxyNode(this.db);
      const runtimeSpec = buildAttemptRuntimeSpec({
        job,
        account,
        outputDir,
        sharedLedgerPath: this.sharedLedgerPath,
        settings,
        reservedPorts,
        selectedProxyNode,
      });
      const child = spawn(runtimeSpec.command, runtimeSpec.args, {
        cwd: this.repoRoot,
        env: runtimeSpec.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin.end();
      const active: ActiveAttempt = {
        child,
        attempt,
        account,
        outputDir,
        reservedPorts,
        tail: [],
      };
      let leasesReleased = false;
      const releasePortLeases = async () => {
        if (leasesReleased) return;
        leasesReleased = true;
        await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
      };
      let listenersReleased = false;
      const releasePortListeners = async () => {
        if (listenersReleased) return;
        listenersReleased = true;
        await Promise.all([portLeases?.apiPort.releaseListener(), portLeases?.mixedPort.releaseListener()]);
      };
      this.activeAttempts.set(attempt.id, active);
      this.emit("toast", { level: "info", message: `attempt #${attempt.id} started for ${account.microsoftEmail}` });

      const pushTail = (chunk: Buffer): void => {
        const lines = chunk
          .toString("utf8")
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);
        if (lines.length === 0) return;
        active.tail.push(...lines);
        if (active.tail.length > 40) {
          active.tail.splice(0, active.tail.length - 40);
        }
      };

      child.stdout.on("data", pushTail);
      child.stderr.on("data", pushTail);

      let settled = false;
      const finalize = async (runner: () => Promise<void> | void) => {
        if (settled) return;
        settled = true;
        try {
          await runner();
        } finally {
          this.activeAttempts.delete(attempt.id);
          await releasePortLeases();
        }
      };

      child.once("spawn", () => {
        void releasePortListeners();
      });

      child.once("error", (error) => {
        void finalize(() =>
          this.failAttempt(job.id, attempt.id, account.id, {
            errorCode: "spawn_error",
            errorMessage: error.message || "failed to start worker process",
          }),
        );
      });

      child.once("close", (code, signal) => {
        void finalize(() => this.handleAttemptExit(job.id, attempt.id, account.id, outputDir, code, signal));
      });
    } catch (error) {
      if (portLeases) {
        await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
      }
      throw error;
    }
  }

  private async handleAttemptExit(
    jobId: number,
    attemptId: number,
    accountId: number,
    outputDir: string,
    code: number | null,
    signal: NodeJS.Signals | null,
  ): Promise<void> {
    const result = await readJsonFile<{ apiKey?: string | null; email?: string; password?: string }>(path.join(outputDir, "result.json"));
    const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
    const signupTask = this.db.getLatestSignupTask(jobId, accountId);
    const apiKey =
      (typeof result?.apiKey === "string" && result.apiKey.trim() ? result.apiKey.trim() : null) ||
      (signupTask?.api_key ? String(signupTask.api_key) : null);

    if (signupTask?.proxy_node) {
      this.db.recordProxyCheck({
        nodeName: String(signupTask.proxy_node),
        status: signupTask.status ? String(signupTask.status) : "unknown",
        egressIp: signupTask.proxy_ip ? String(signupTask.proxy_ip) : null,
        country: signupTask.proxy_country ? String(signupTask.proxy_country) : null,
        city: signupTask.proxy_city ? String(signupTask.proxy_city) : null,
        org: null,
        error: signupTask.error_code ? String(signupTask.error_code) : null,
      });
      this.emit("proxy.updated", { nodes: this.db.listProxyNodes() });
    }

    if (code === 0 && signal == null && apiKey) {
      const { job, attempt } = this.db.completeAttemptSuccess(jobId, attemptId, accountId, apiKey, signupTask);
      this.emit("attempt.updated", { attempt });
      this.emit("account.updated", { account: this.db.getAccount(accountId) });
      this.emit("job.updated", { job });
      this.emit("toast", { level: "success", message: `attempt #${attempt.id} succeeded for account #${accountId}` });
      return;
    }

    const message =
      error?.error ||
      (signupTask?.error_message ? String(signupTask.error_message) : "") ||
      (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
    const errorCode = signupTask?.error_code ? String(signupTask.error_code) : code == null ? "process_exit" : `exit_${code}`;
    const { job, attempt } = this.db.completeAttemptFailure(
      jobId,
      attemptId,
      accountId,
      { errorCode, errorMessage: message },
      signupTask,
    );
    this.emit("attempt.updated", { attempt });
    this.emit("account.updated", { account: this.db.getAccount(accountId) });
    this.emit("job.updated", { job });
    this.emit("toast", { level: "error", message: `attempt #${attempt.id} failed for account #${accountId}: ${message}` });
  }

  private failAttempt(
    jobId: number,
    attemptId: number,
    accountId: number,
    input: { errorCode: string; errorMessage: string },
  ): void {
    const { job, attempt } = this.db.completeAttemptFailure(jobId, attemptId, accountId, input, null);
    this.emit("attempt.updated", { attempt });
    this.emit("account.updated", { account: this.db.getAccount(accountId) });
    this.emit("job.updated", { job });
    this.emit("toast", { level: "error", message: `attempt #${attempt.id} failed for account #${accountId}: ${input.errorMessage}` });
  }

  private emit(type: ServerEvent["type"], payload: Record<string, unknown>): void {
    this.publish({
      type,
      payload,
      timestamp: nowIso(),
    });
  }

  private normalizeAutoExtractConfig(
    input: {
      autoExtractSources?: AccountExtractorProvider[];
      autoExtractQuantity?: number;
      autoExtractMaxWaitSec?: number;
      autoExtractAccountType?: AccountExtractorAccountType;
    },
    settings: AppSettings,
    fallback?: Pick<JobRecord, "autoExtractSources" | "autoExtractQuantity" | "autoExtractMaxWaitSec" | "autoExtractAccountType">,
  ): Pick<JobRecord, "autoExtractSources" | "autoExtractQuantity" | "autoExtractMaxWaitSec" | "autoExtractAccountType"> {
    const autoExtractSources = normalizeExtractorSources(input.autoExtractSources ?? fallback?.autoExtractSources);
    if (autoExtractSources.length === 0) {
      return {
        autoExtractSources: [],
        autoExtractQuantity: 0,
        autoExtractMaxWaitSec: 0,
        autoExtractAccountType: "outlook",
      };
    }
    const autoExtractQuantity = Math.max(1, Math.trunc(input.autoExtractQuantity ?? fallback?.autoExtractQuantity ?? 0));
    const autoExtractMaxWaitSec = Math.max(1, Math.trunc(input.autoExtractMaxWaitSec ?? fallback?.autoExtractMaxWaitSec ?? 0));
    if (!autoExtractQuantity) {
      throw new Error("auto extract quantity must be greater than 0 when sources are enabled");
    }
    if (!autoExtractMaxWaitSec) {
      throw new Error("auto extract max wait must be greater than 0 when sources are enabled");
    }
    const runtimeConfig = {
      zhanghaoyaKey: settings.extractorZhanghaoyaKey,
      shanyouxiangKey: settings.extractorShanyouxiangKey,
    };
    const missingProviders = autoExtractSources.filter((provider) => !keyConfiguredForProvider(provider, runtimeConfig));
    if (missingProviders.length > 0) {
      throw new Error(`extractor key missing for ${missingProviders.map(providerLabel).join(", ")}`);
    }
    return {
      autoExtractSources,
      autoExtractQuantity,
      autoExtractMaxWaitSec,
      autoExtractAccountType: "outlook",
    };
  }

  private createAutoExtractState(
    job: Pick<JobRecord, "id" | "autoExtractSources" | "autoExtractMaxWaitSec" | "autoExtractAccountType">,
  ): AutoExtractState {
    const now = nowIso();
    const waitMs = Math.max(0, job.autoExtractMaxWaitSec * 1000);
    return {
      jobId: job.id,
      enabledSources: [...job.autoExtractSources],
      accountType: job.autoExtractAccountType,
      maxWaitMs: waitMs,
      remainingWaitMs: waitMs,
      currentRoundTarget: 0,
      attemptBudget: 0,
      acceptedCount: 0,
      rawAttemptCount: 0,
      inFlightCount: 0,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: createProviderAttemptClock(),
      phase: "idle",
      startedAt: null,
      lastProvider: null,
      lastMessage: null,
      updatedAt: now,
      lastBudgetTickMs: null,
    };
  }

  private syncAutoExtractState(job: JobRecord): void {
    const current = this.autoExtractStates.get(job.id);
    if (job.autoExtractSources.length === 0) {
      if (current?.inFlightCount) {
        current.enabledSources = [];
        current.phase = current.inFlightCount > 0 ? "waiting" : "idle";
        current.lastMessage = "auto extract disabled, waiting for in-flight requests to finish";
        current.updatedAt = nowIso();
      } else {
        this.autoExtractStates.delete(job.id);
      }
      return;
    }
    const nextMaxWaitMs = Math.max(0, job.autoExtractMaxWaitSec * 1000);
    if (!current) {
      this.autoExtractStates.set(job.id, this.createAutoExtractState(job));
      return;
    }
    const bonusWaitMs = Math.max(0, nextMaxWaitMs - current.maxWaitMs);
    current.enabledSources = [...job.autoExtractSources];
    current.accountType = job.autoExtractAccountType;
    current.maxWaitMs = nextMaxWaitMs;
    current.remainingWaitMs = Math.min(nextMaxWaitMs, Math.max(0, current.remainingWaitMs + bonusWaitMs));
    current.nextProviderIndex = current.enabledSources.length > 0 ? current.nextProviderIndex % current.enabledSources.length : 0;
    current.updatedAt = nowIso();
    if (current.phase === "idle") {
      current.currentRoundTarget = 0;
      current.attemptBudget = 0;
      current.acceptedCount = 0;
      current.rawAttemptCount = 0;
      current.inFlightCount = 0;
      current.startedAt = null;
      current.lastBudgetTickMs = null;
      current.providerNextAttemptAtMs = createProviderAttemptClock();
    }
  }

  private updateAutoExtractBudget(state: AutoExtractState): void {
    if (state.phase !== "waiting" && state.phase !== "extracting") {
      state.lastBudgetTickMs = null;
      state.updatedAt = nowIso();
      return;
    }
    const nowMs = Date.now();
    if (state.lastBudgetTickMs != null) {
      state.remainingWaitMs = Math.max(0, state.remainingWaitMs - (nowMs - state.lastBudgetTickMs));
    }
    state.lastBudgetTickMs = nowMs;
    state.updatedAt = nowIso();
  }

  private resetAutoExtractRound(state: AutoExtractState, message: string | null): void {
    state.phase = "idle";
    state.currentRoundTarget = 0;
    state.attemptBudget = 0;
    state.acceptedCount = 0;
    state.rawAttemptCount = 0;
    state.inFlightCount = 0;
    state.startedAt = null;
    state.providerNextAttemptAtMs = createProviderAttemptClock();
    state.lastBudgetTickMs = null;
    state.lastMessage = message;
    state.updatedAt = nowIso();
  }

  private startAutoExtractRound(job: JobRecord, state: AutoExtractState): string | null {
    const remainingNeed = Math.max(0, job.need - job.successCount);
    const attemptsLeft = Math.max(0, job.maxAttempts - job.launchedCount);
    const currentRoundTarget = Math.min(remainingNeed, Math.max(0, job.autoExtractQuantity), attemptsLeft);
    if (currentRoundTarget <= 0) {
      return "auto extract has no remaining demand";
    }
    state.phase = "waiting";
    state.currentRoundTarget = currentRoundTarget;
    state.attemptBudget = currentRoundTarget + AUTO_EXTRACT_OVERFETCH_ALLOWANCE;
    state.acceptedCount = 0;
    state.rawAttemptCount = 0;
    state.inFlightCount = 0;
    state.startedAt = nowIso();
    state.providerNextAttemptAtMs = createProviderAttemptClock();
    state.lastProvider = null;
    state.lastMessage = `waiting to extract ${currentRoundTarget} usable account(s)`;
    state.lastBudgetTickMs = Date.now();
    state.updatedAt = nowIso();
    this.emit("toast", {
      level: "info",
      message: `job #${job.id} waiting for auto extraction (${currentRoundTarget} usable target)`,
    });
    this.emit("job.updated", { job: this.db.getJob(job.id), autoExtractState: this.getAutoExtractSnapshot(job.id) });
    return null;
  }

  private describeExtractRejectReason(jobId: number, account: MicrosoftAccountRecord | null): string {
    if (!account) return "import_missing";
    if (account.disabledAt != null) return "disabled";
    if (account.hasApiKey || account.skipReason === "has_api_key") return "has_api_key";
    if (account.leaseJobId != null) return "leased";
    return this.db.isAccountSchedulableForJob(jobId, account.id) ? "unknown" : "already_attempted";
  }

  private deleteAutoExtractStateIfIdle(jobId: number): void {
    const state = this.autoExtractStates.get(jobId);
    if (!state || state.inFlightCount === 0) {
      this.autoExtractStates.delete(jobId);
    }
  }

  private finalizeAutoExtractRound(
    state: AutoExtractState,
    outcome: { status: "ready" | "unavailable"; reason: string },
  ): AutoExtractDecision {
    this.resetAutoExtractRound(state, outcome.reason);
    this.emit("job.updated", { job: this.db.getJob(state.jobId), autoExtractState: this.getAutoExtractSnapshot(state.jobId) });
    return outcome;
  }

  private evaluateAutoExtractState(job: JobRecord, state: AutoExtractState): AutoExtractDecision | null {
    const targetReached = state.currentRoundTarget > 0 && state.acceptedCount >= state.currentRoundTarget;
    const waitExhausted = state.remainingWaitMs <= 0;
    const rawBudgetExhausted = state.rawAttemptCount >= state.attemptBudget && state.attemptBudget > 0;
    if (state.inFlightCount > 0 && (targetReached || waitExhausted || rawBudgetExhausted)) {
      state.phase = "waiting";
      state.lastMessage = targetReached
        ? `target reached, waiting for ${state.inFlightCount} in-flight request(s)`
        : waitExhausted
          ? `wait budget exhausted, waiting for ${state.inFlightCount} in-flight request(s)`
          : `raw request budget exhausted, waiting for ${state.inFlightCount} in-flight request(s)`;
      state.updatedAt = nowIso();
      return { status: "waiting" };
    }
    if (targetReached) {
      return this.finalizeAutoExtractRound(state, {
        status: "ready",
        reason: `accepted ${state.acceptedCount} usable account(s)`,
      });
    }
    if (waitExhausted) {
      return this.finalizeAutoExtractRound(state, {
        status: state.acceptedCount > 0 ? "ready" : "unavailable",
        reason: `auto extract timed out after ${Math.ceil(state.maxWaitMs / 1000)}s`,
      });
    }
    if (rawBudgetExhausted) {
      return this.finalizeAutoExtractRound(state, {
        status: state.acceptedCount > 0 ? "ready" : "unavailable",
        reason: `auto extract stopped after ${state.attemptBudget} raw request(s)`,
      });
    }
    if (job.autoExtractSources.length === 0) {
      return this.finalizeAutoExtractRound(state, {
        status: state.acceptedCount > 0 ? "ready" : "unavailable",
        reason: "auto extract disabled",
      });
    }
    return null;
  }

  private pickDueProvider(state: AutoExtractState, nowMs: number): AccountExtractorProvider | null {
    if (state.enabledSources.length === 0) {
      return null;
    }
    const total = state.enabledSources.length;
    for (let offset = 0; offset < total; offset += 1) {
      const index = (state.nextProviderIndex + offset) % total;
      const provider = state.enabledSources[index];
      if (!provider) {
        continue;
      }
      if (state.providerNextAttemptAtMs[provider] <= nowMs) {
        state.nextProviderIndex = (index + 1) % total;
        return provider;
      }
    }
    return null;
  }

  private launchAutoExtractRequest(context: AutoExtractRequestContext): void {
    const settings = this.getSettings();
    const runtimeConfig = {
      zhanghaoyaKey: settings.extractorZhanghaoyaKey,
      shanyouxiangKey: settings.extractorShanyouxiangKey,
      timeoutMs: AUTO_EXTRACT_REQUEST_TIMEOUT_MS,
    };

    const finish = (input: {
      ok: boolean;
      result?: Awaited<ReturnType<typeof fetchSingleExtractedAccount>>;
      errorMessage?: string;
      failureCode?: "invalid_key" | "insufficient_stock" | "parse_failed" | "upstream_error" | null;
      rawResponse?: string | null;
      maskedKey?: string | null;
    }) => {
      const state = this.autoExtractStates.get(context.jobId);
      const startedAt = context.dispatchStartedAt;
      const completedAt = nowIso();

      let acceptedInBatch = 0;
      const affectedIds = new Set<number>();
      const rejectReasons = new Set<string>();

      let batchStatus: "accepted" | "rejected" | "invalid_key" | "insufficient_stock" | "parse_failed" | "error" =
        input.ok && input.result ? "rejected" : mapFailureCodeToBatchStatus(input.failureCode ?? null);
      let batchErrorMessage = input.errorMessage ?? null;
      const batch = this.db.createAccountExtractBatch({
        jobId: context.jobId,
        provider: context.provider,
        accountType: context.accountType,
        requestedUsableCount: context.requestedUsableCount,
        attemptBudget: context.attemptBudget,
        acceptedCount: 0,
        status: batchStatus,
        errorMessage: batchErrorMessage,
        rawResponse: input.rawResponse ?? null,
        maskedKey: input.maskedKey ?? null,
        startedAt,
        completedAt: null,
      });

      if (input.ok && input.result) {
        let acceptedRequestCandidate = false;
        for (const candidate of input.result.candidates) {
          if (candidate.parseStatus !== "parsed" || !candidate.email || !candidate.password) {
            rejectReasons.add("parse_failed");
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: candidate.parseStatus,
              acceptStatus: "rejected",
              rejectReason: "parse_failed",
            });
            continue;
          }

          if (acceptedRequestCandidate) {
            rejectReasons.add("request_returned_multiple_accounts");
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: "parsed",
              acceptStatus: "rejected",
              rejectReason: "request_returned_multiple_accounts",
            });
            continue;
          }

          const importResult = this.db.importAccounts(
            [{ email: candidate.email, password: candidate.password }],
            {
              source: "extractor",
              accountSource: context.provider,
              rawPayloadByEmail: {
                [candidate.email]: candidate.rawPayload,
              },
            },
          );
          for (const accountId of importResult.affectedIds) {
            affectedIds.add(accountId);
          }
          const importedAccount = this.db.getAccountsByEmails([candidate.email])[0] || null;
          const rejectReason = this.describeExtractRejectReason(context.jobId, importedAccount);
          if (rejectReason !== "unknown") {
            rejectReasons.add(rejectReason);
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: "parsed",
              acceptStatus: "rejected",
              rejectReason,
              importedAccountId: importedAccount?.id ?? null,
            });
            continue;
          }

          acceptedRequestCandidate = true;
          acceptedInBatch = 1;
          if (importedAccount) {
            affectedIds.add(importedAccount.id);
          }
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: context.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: "parsed",
            acceptStatus: "accepted",
            rejectReason: null,
            importedAccountId: importedAccount?.id ?? null,
          });
        }

        batchStatus =
          acceptedInBatch > 0 ? "accepted" : input.result.ok ? "rejected" : mapFailureCodeToBatchStatus(input.result.failureCode);
        batchErrorMessage = acceptedInBatch > 0 ? null : input.result.message || Array.from(rejectReasons).join(", ") || null;
      }

      this.db.updateAccountExtractBatch(batch.id, {
        acceptedCount: acceptedInBatch,
        status: batchStatus,
        errorMessage: batchErrorMessage,
        rawResponse: input.rawResponse ?? null,
        maskedKey: input.maskedKey ?? null,
        completedAt,
      });

      if (state && state.startedAt === context.roundStartedAt) {
        state.inFlightCount = Math.max(0, state.inFlightCount - 1);
        state.lastProvider = context.provider;
        state.acceptedCount += acceptedInBatch;
        state.phase = state.inFlightCount > 0 ? "waiting" : state.acceptedCount >= state.currentRoundTarget ? "waiting" : "extracting";
        state.lastMessage =
          acceptedInBatch > 0
            ? `${providerLabel(context.provider)} accepted ${acceptedInBatch} usable account`
            : batchErrorMessage || "no usable account accepted";
        state.updatedAt = completedAt;
      }

      if (affectedIds.size > 0) {
        this.emit("account.updated", { affectedIds: Array.from(affectedIds), action: "extractor_import" });
      }
      if (acceptedInBatch > 0) {
        this.emit("toast", {
          level: "success",
          message: `job #${context.jobId} accepted ${acceptedInBatch} extracted account(s) from ${providerLabel(context.provider)}`,
        });
      }

      const currentJob = this.db.getJob(context.jobId);
      if (state && currentJob) {
        const decision = this.evaluateAutoExtractState(currentJob, state);
        if (decision == null) {
          this.emit("job.updated", { job: currentJob, autoExtractState: this.getAutoExtractSnapshot(context.jobId) });
        }
      } else {
        this.emit("job.updated", { job: currentJob, autoExtractState: this.getAutoExtractSnapshot(context.jobId) });
      }
    };

    if (!keyConfiguredForProvider(context.provider, runtimeConfig)) {
      finish({
        ok: false,
        errorMessage: `${providerLabel(context.provider)} key missing`,
        failureCode: "invalid_key",
        rawResponse: null,
        maskedKey: null,
      });
      return;
    }

    void fetchSingleExtractedAccount({
      provider: context.provider,
      accountType: context.accountType,
      config: runtimeConfig,
    })
      .then((result) => {
        finish({
          ok: true,
          result,
          errorMessage: result.message ?? undefined,
          failureCode: result.failureCode,
          rawResponse: result.rawResponse,
          maskedKey: result.maskedKey,
        });
      })
      .catch((error) => {
        finish({
          ok: false,
          errorMessage: error instanceof Error ? error.message : String(error),
          failureCode: "upstream_error",
          rawResponse: null,
          maskedKey: maskLocalSecret(context.provider === "zhanghaoya" ? runtimeConfig.zhanghaoyaKey : runtimeConfig.shanyouxiangKey),
        });
      });
  }

  private async maybeAutoExtract(job: JobRecord): Promise<AutoExtractDecision> {
    const existingState = this.autoExtractStates.get(job.id);
    if (job.autoExtractSources.length === 0 && (!existingState || existingState.inFlightCount === 0)) {
      return { status: "unavailable", reason: "eligible accounts exhausted or max attempts reached" };
    }
    let state = existingState;
    if (!state) {
      state = this.createAutoExtractState(job);
      this.autoExtractStates.set(job.id, state);
    } else {
      this.syncAutoExtractState(job);
      state = this.autoExtractStates.get(job.id) || state;
    }

    if (state.phase === "idle") {
      const startError = this.startAutoExtractRound(job, state);
      if (startError) {
        return { status: "unavailable", reason: startError };
      }
    }

    this.updateAutoExtractBudget(state);
    const preDispatchDecision = this.evaluateAutoExtractState(job, state);
    if (preDispatchDecision) {
      return preDispatchDecision;
    }

    while (
      state.enabledSources.length > 0
      && state.remainingWaitMs > 0
      && state.acceptedCount < state.currentRoundTarget
      && state.rawAttemptCount < state.attemptBudget
      && state.inFlightCount < AUTO_EXTRACT_MAX_CONCURRENT_REQUESTS
    ) {
      const nowMs = Date.now();
      const provider = this.pickDueProvider(state, nowMs);
      if (!provider) {
        break;
      }
      const dispatchStartedAt = nowIso();
      state.phase = "extracting";
      state.lastProvider = provider;
      state.lastMessage = `${providerLabel(provider)} request dispatched`;
      state.rawAttemptCount += 1;
      state.inFlightCount += 1;
      state.providerNextAttemptAtMs[provider] = nowMs + AUTO_EXTRACT_REQUEST_INTERVAL_MS;
      state.updatedAt = dispatchStartedAt;
      this.launchAutoExtractRequest({
        jobId: job.id,
        provider,
        accountType: state.accountType,
        requestedUsableCount: state.currentRoundTarget,
        attemptBudget: state.attemptBudget,
        dispatchStartedAt,
        roundStartedAt: state.startedAt,
      });
    }

    if (state.acceptedCount < state.currentRoundTarget && state.inFlightCount === 0) {
      const nextProviderReadyAt = state.enabledSources
        .map((provider) => state.providerNextAttemptAtMs[provider])
        .filter((readyAt) => readyAt > Date.now())
        .sort((left, right) => left - right)[0];
      if (nextProviderReadyAt) {
        state.phase = "waiting";
        state.lastMessage = `next extractor slot in ${Math.max(1, Math.ceil((nextProviderReadyAt - Date.now()) / 1000))}s`;
        state.updatedAt = nowIso();
      }
    }

    this.emit("job.updated", { job: this.db.getJob(job.id), autoExtractState: this.getAutoExtractSnapshot(job.id) });
    return this.evaluateAutoExtractState(job, state) || { status: "waiting" };
  }
}
