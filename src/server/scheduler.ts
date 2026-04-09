import { spawn, spawnSync, type ChildProcessWithoutNullStreams, type SpawnOptionsWithoutStdio } from "node:child_process";
import path from "node:path";
import { mkdir, readFile } from "node:fs/promises";
import {
  AppDatabase,
  computeLaunchCapacity,
  normalizeAccountExtractorAccountType,
  normalizeJobMaxAttempts,
  type AccountExtractorAccountType,
  type AccountExtractorProvider,
  type AppSettings,
  type JobAttemptRecord,
  type JobRecord,
  type JobSite,
  type MicrosoftAccountRecord,
} from "../storage/app-db.js";
import {
  fetchSingleExtractedAccount,
  getAccountExtractorProviderLabel,
  getConfiguredExtractorKey,
  keyConfiguredForProvider,
} from "./account-extractor.js";
import { isLockedAccountRecord } from "./account-session-bootstrap.js";
import {
  assertUsableFingerprintChromiumExecutablePath,
  resolveExplicitChromeExecutablePath,
} from "../fingerprint-browser.js";
import { reserveMihomoPortLeases, type PortLease } from "./port-lease.js";

export interface ServerEvent {
  type: "job.updated" | "attempt.updated" | "account.updated" | "mailbox.updated" | "proxy.updated" | "proxy.check.completed" | "extractor.updated" | "toast";
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
  stopRequested: "force_stop" | null;
}

interface PendingAttemptLaunch {
  jobId: number;
  attempt: JobAttemptRecord;
  account: MicrosoftAccountRecord;
  stopRequested: "force_stop" | null;
}

type AutoExtractPhase = "idle" | "waiting" | "extracting";

interface PendingAutoExtractCandidate {
  accountId: number;
  batchId: number;
  provider: AccountExtractorProvider;
  rawPayload: string;
  email: string;
  password: string;
}

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
  providerInFlightCount: Record<AccountExtractorProvider, number>;
  providerAttemptCount: Record<AccountExtractorProvider, number>;
  phase: AutoExtractPhase;
  startedAt: string | null;
  lastProvider: AccountExtractorProvider | null;
  lastMessage: string | null;
  updatedAt: string;
  lastBudgetTickMs: number | null;
  requestControllers: Map<string, AbortController>;
  pendingBootstrapCandidates: Map<number, PendingAutoExtractCandidate>;
}

interface AutoExtractRequestContext {
  jobId: number;
  provider: AccountExtractorProvider;
  accountType: AccountExtractorAccountType;
  alternationIndex: number;
  requestedUsableCount: number;
  attemptBudget: number;
  dispatchStartedAt: string;
  roundStartedAt: string | null;
  requestId: string;
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

export function resolveReusableAttemptProxyNode(
  db: Pick<AppDatabase, "selectReusableProxyNodeForAccount">,
  accountId: number,
): string | null {
  return db.selectReusableProxyNodeForAccount(accountId)?.nodeName || null;
}

type AutoExtractDecision =
  | { status: "ready" }
  | { status: "waiting" }
  | { status: "unavailable"; reason: string };

const AUTO_EXTRACT_REQUEST_INTERVAL_MS = 500;
const AUTO_EXTRACT_WORKERS_PER_PROVIDER = 3;
const AUTO_EXTRACT_REQUEST_TIMEOUT_MS = 5000;
// Fresh Tavily + Graph bootstrap runs are serialized and can take several minutes
// per account. Keep jobs waiting long enough for pending session prep to finish
// before falling back to auto-extract/failure paths.
export const PENDING_BROWSER_SESSION_WAIT_MS = 10 * 60_000;

export interface PendingBrowserSessionWaitState {
  count: number;
  startedAtMs: number;
  exhausted: boolean;
}

const STRIPPED_ATTEMPT_ENV_KEYS = [
  "EXISTING_EMAIL",
  "EXISTING_PASSWORD",
  "MICROSOFT_ACCOUNT_EMAIL",
  "MICROSOFT_ACCOUNT_PASSWORD",
  "MICROSOFT_PROOF_MAILBOX_PROVIDER",
  "MICROSOFT_PROOF_MAILBOX_ADDRESS",
  "MICROSOFT_PROOF_MAILBOX_ID",
  "CHROME_EXECUTABLE_PATH",
  "CHROME_REMOTE_DEBUGGING_PORT",
] as const;

function buildAttemptBaseEnv(baseEnv: NodeJS.ProcessEnv | undefined): NodeJS.ProcessEnv {
  const next: NodeJS.ProcessEnv = { ...(baseEnv || process.env) };
  for (const key of STRIPPED_ATTEMPT_ENV_KEYS) {
    delete next[key];
  }
  return next;
}

export function resolvePendingBrowserSessionWait(input: {
  state: PendingBrowserSessionWaitState | null;
  pendingCount: number;
  nowMs: number;
  maxWaitMs?: number;
}): { wait: boolean; state: PendingBrowserSessionWaitState | null } {
  const maxWaitMs = Math.max(0, input.maxWaitMs ?? PENDING_BROWSER_SESSION_WAIT_MS);
  if (input.pendingCount <= 0) {
    return { wait: false, state: null };
  }
  if (!input.state || input.state.count !== input.pendingCount) {
    return {
      wait: true,
      state: {
        count: input.pendingCount,
        startedAtMs: input.nowMs,
        exhausted: false,
      },
    };
  }
  if (input.state.exhausted) {
    return { wait: false, state: input.state };
  }
  if (input.nowMs - input.state.startedAtMs < maxWaitMs) {
    return { wait: true, state: input.state };
  }
  return {
    wait: false,
    state: {
      ...input.state,
      exhausted: true,
    },
  };
}

let cachedNodeCommandAvailability: boolean | null = null;
let cachedNodeTsxAvailability: boolean | null = null;

function isNodeCommandAvailable(): boolean {
  if (cachedNodeCommandAvailability != null) {
    return cachedNodeCommandAvailability;
  }
  try {
    const result = spawnSync("node", ["-v"], {
      stdio: "ignore",
      env: process.env,
    });
    cachedNodeCommandAvailability = !result.error && result.status === 0;
  } catch {
    cachedNodeCommandAvailability = false;
  }
  return cachedNodeCommandAvailability;
}

function isNodeTsxAvailable(nodeBinary = "node"): boolean {
  if (nodeBinary === "node" && cachedNodeTsxAvailability != null) {
    return cachedNodeTsxAvailability;
  }
  try {
    const result = spawnSync(nodeBinary, ["--import", "tsx", "--eval", ""], {
      stdio: "ignore",
      env: process.env,
    });
    const available = !result.error && result.status === 0;
    if (nodeBinary === "node") {
      cachedNodeTsxAvailability = available;
    }
    return available;
  } catch {
    if (nodeBinary === "node") {
      cachedNodeTsxAvailability = false;
    }
    return false;
  }
}

export function pickWorkerRuntime(input: {
  explicitNodeBinary?: string | null;
  explicitNodeTsxAvailable?: boolean;
  runningUnderBun: boolean;
  processExecPath?: string | null;
  nodeCommandAvailable: boolean;
  nodeTsxAvailable: boolean;
}): { command: string; bootstrapArgs: string[] } {
  const nodeArgs = ["--import", "tsx", "src/main.ts"];
  const explicitNodeBinary = input.explicitNodeBinary?.trim();
  const explicitNodeRuntimeAvailable = explicitNodeBinary
    ? (input.explicitNodeTsxAvailable ?? isNodeTsxAvailable(explicitNodeBinary))
    : false;
  if (explicitNodeBinary && explicitNodeRuntimeAvailable) {
    return {
      command: explicitNodeBinary,
      bootstrapArgs: nodeArgs,
    };
  }
  if (!input.runningUnderBun) {
    return {
      command: input.processExecPath || "node",
      bootstrapArgs: nodeArgs,
    };
  }
  if (input.nodeCommandAvailable && input.nodeTsxAvailable) {
    // Bun-hosted playwright-core can hang on connectOverCDP against
    // fingerprint-chromium. Keep the worker on CDP, but run it under Node.
    return {
      command: "node",
      bootstrapArgs: nodeArgs,
    };
  }
  return {
    command: input.processExecPath || "bun",
    bootstrapArgs: ["run", "src/main.ts"],
  };
}

export function resolveWorkerRuntime(baseEnv: NodeJS.ProcessEnv | undefined = process.env): { command: string; bootstrapArgs: string[] } {
  const explicitNodeBinary = baseEnv?.NODE_BINARY;
  return pickWorkerRuntime({
    explicitNodeBinary,
    explicitNodeTsxAvailable: explicitNodeBinary?.trim() ? isNodeTsxAvailable(explicitNodeBinary.trim()) : undefined,
    runningUnderBun: Boolean(process.versions.bun),
    processExecPath: process.execPath,
    nodeCommandAvailable: isNodeCommandAvailable(),
    nodeTsxAvailable: isNodeTsxAvailable(),
  });
}

function isTerminalJobStatus(status: JobRecord["status"]): boolean {
  return status === "completed" || status === "failed" || status === "stopped";
}

function isStopInProgressStatus(status: JobRecord["status"]): boolean {
  return status === "stopping" || status === "force_stopping";
}

function normalizeExtractorSources(sources: AccountExtractorProvider[] | undefined): AccountExtractorProvider[] {
  return Array.from(
    new Set(
      (sources || []).filter(
        (item): item is AccountExtractorProvider =>
          item === "zhanghaoya" || item === "shanyouxiang" || item === "shankeyun" || item === "hotmail666",
      ),
    ),
  );
}

function providerLabel(provider: AccountExtractorProvider): string {
  return getAccountExtractorProviderLabel(provider);
}

function mapFailureCodeToBatchStatus(
  code: "invalid_key" | "insufficient_stock" | "parse_failed" | "upstream_error" | "job_force_stopping" | null,
): "rejected" | "invalid_key" | "insufficient_stock" | "parse_failed" | "error" {
  if (code === "invalid_key") return "invalid_key";
  if (code === "insufficient_stock") return "insufficient_stock";
  if (code === "parse_failed") return "parse_failed";
  if (code === "job_force_stopping") return "rejected";
  return "error";
}

function maskLocalSecret(secret: string): string | null {
  const value = secret.trim();
  if (!value) return null;
  if (value.length <= 8) return `${"*".repeat(Math.max(0, value.length - 2))}${value.slice(-2)}`;
  return `${value.slice(0, 4)}${"*".repeat(Math.max(4, value.length - 8))}${value.slice(-4)}`;
}

export function resolveAttemptProxyNode(
  db: Pick<AppDatabase, "getPinnedProxyName" | "getSelectedProxyName" | "getProxyNodeLastStatus" | "hasProxyNode">,
): string | null {
  const pinnedProxyNode = db.getPinnedProxyName();
  if (pinnedProxyNode) {
    return db.hasProxyNode(pinnedProxyNode) ? pinnedProxyNode : null;
  }
  const selectedProxyNode = db.getSelectedProxyName();
  if (!selectedProxyNode) {
    return null;
  }
  const selectedProxyStatus = db.getProxyNodeLastStatus(selectedProxyNode)?.trim().toLowerCase();
  if (selectedProxyStatus && selectedProxyStatus !== "ok" && selectedProxyStatus !== "succeeded") {
    return null;
  }
  return db.hasProxyNode(selectedProxyNode) ? selectedProxyNode : null;
}

export function buildAttemptRuntimeSpec(input: {
  job: Pick<JobRecord, "id" | "runMode">;
  account: Pick<
    MicrosoftAccountRecord,
    "id" | "microsoftEmail" | "passwordPlaintext" | "proofMailboxProvider" | "proofMailboxAddress" | "proofMailboxId"
  > & {
    browserSession?: Pick<NonNullable<MicrosoftAccountRecord["browserSession"]>, "profilePath"> | null;
  };
  outputDir: string;
  sharedLedgerPath: string;
  settings: Pick<AppSettings, "subscriptionUrl" | "groupName" | "routeGroupName" | "checkUrl" | "timeoutMs" | "maxLatencyMs">;
  reservedPorts: { apiPort: number; mixedPort: number };
  chromeExecutablePath: string;
  selectedProxyNode?: string | null;
  baseEnv?: NodeJS.ProcessEnv;
}): { command: string; args: string[]; env: NodeJS.ProcessEnv } {
  const runtime = resolveWorkerRuntime();
  const args = [...runtime.bootstrapArgs, "--mode", input.job.runMode, "--parallel", "1", "--need", "1"];
  if (input.selectedProxyNode?.trim()) {
    args.push("--proxy-node", input.selectedProxyNode.trim());
  }
  const inheritedEnv = buildAttemptBaseEnv(input.baseEnv);
  const persistentProfilePath = input.account.browserSession?.profilePath?.trim()
    ? path.resolve(input.account.browserSession.profilePath.trim())
    : null;
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
      CHROME_EXECUTABLE_PATH: input.chromeExecutablePath,
      CHROME_PROFILE_DIR: persistentProfilePath || path.join(input.outputDir, "chrome-profile"),
      ...(persistentProfilePath
        ? {
            CHROME_PROFILE_STRATEGY: "exact",
          }
        : {}),
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

export function buildAttemptSpawnOptions(repoRoot: string, runtimeSpec: { env: NodeJS.ProcessEnv }): SpawnOptionsWithoutStdio {
  return {
    cwd: repoRoot,
    env: runtimeSpec.env,
    detached: true,
  };
}

function nowIso(): string {
  return new Date().toISOString();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function signalChildProcess(child: Pick<ChildProcessWithoutNullStreams, "pid" | "kill">, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (pid) {
    try {
      process.kill(-pid, signal);
      return;
    } catch {
      // Fall through to direct child signalling when no process group exists.
    }
  }
  try {
    child.kill(signal);
  } catch {
    // Ignore races during shutdown or force stop.
  }
}

function isAbortError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  const name = error instanceof Error ? error.name : "";
  return name === "AbortError" || /abort/i.test(message);
}

function parseMillis(value: unknown): number | null {
  if (typeof value !== "string" || !value.trim()) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function shouldIgnoreSignupTaskForAttempt(
  attempt: Pick<JobAttemptRecord, "runId" | "startedAt">,
  latest: Record<string, unknown>,
): boolean {
  const latestRunId = latest.run_id == null ? null : String(latest.run_id);
  if (attempt.runId) {
    return latestRunId == null || latestRunId !== attempt.runId;
  }

  const attemptStartedAtMs = parseMillis(attempt.startedAt);
  const latestStartedAtMs = parseMillis(latest.started_at);
  const latestCompletedAtMs = parseMillis(latest.completed_at);
  if (attemptStartedAtMs == null) {
    return false;
  }
  if (latestStartedAtMs != null && latestStartedAtMs < attemptStartedAtMs) {
    return true;
  }
  if (latestCompletedAtMs != null && latestCompletedAtMs < attemptStartedAtMs) {
    return true;
  }
  return false;
}

function createProviderAttemptClock(): Record<AccountExtractorProvider, number> {
  return {
    zhanghaoya: 0,
    shanyouxiang: 0,
    shankeyun: 0,
    hotmail666: 0,
  };
}

function createProviderInFlightCounter(): Record<AccountExtractorProvider, number> {
  return {
    zhanghaoya: 0,
    shanyouxiang: 0,
    shankeyun: 0,
    hotmail666: 0,
  };
}

function createProviderAttemptCounter(): Record<AccountExtractorProvider, number> {
  return {
    zhanghaoya: 0,
    shanyouxiang: 0,
    shankeyun: 0,
    hotmail666: 0,
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
  private readonly pendingAttemptLaunches = new Map<number, PendingAttemptLaunch>();
  private readonly autoExtractStates = new Map<number, AutoExtractState>();
  private readonly pendingBrowserSessionWaits = new Map<number, PendingBrowserSessionWaitState>();
  private readonly pendingAttemptFinalizers = new Set<Promise<void>>();
  private loopPromise: Promise<void> | null = null;
  private shuttingDown = false;

  constructor(
    private readonly db: AppDatabase,
    private readonly site: JobSite,
    private readonly repoRoot: string,
    private readonly sharedLedgerPath: string,
    private readonly getSettings: () => AppSettings,
    private readonly publish: (event: ServerEvent) => void,
    private readonly hooks?: {
      onImportedAccounts?: (accountIds: number[]) => void | Promise<void>;
    },
  ) {}

  currentJob(): JobRecord | null {
    return this.db.getCurrentJob(this.site);
  }

  activeAttemptRows(): JobAttemptRecord[] {
    return Array.from(this.activeAttempts.values())
      .map((item) => this.syncActiveAttemptFromLedger(item))
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
      site: this.site,
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
    if (job.status === "paused") {
      return job;
    }
    if (job.status !== "running") {
      throw new Error(`current job cannot be paused from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "paused", pausedAt: nowIso() });
    this.emit("job.updated", { job: next });
    this.emit("toast", { level: "info", message: `job #${job.id} paused` });
    return next;
  }

  resumeCurrentJob(): JobRecord {
    const job = this.requireCurrentJob();
    if (job.status === "running") {
      return job;
    }
    if (job.status !== "paused") {
      throw new Error(`current job cannot be resumed from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, { status: "running", pausedAt: null });
    this.syncAutoExtractState(next);
    this.emit("job.updated", { job: next });
    this.emit("toast", { level: "info", message: `job #${job.id} resumed` });
    this.ensureLoop(job.id);
    return next;
  }

  stopCurrentJob(): JobRecord {
    const job = this.db.getCurrentJob(this.site);
    if (!job) throw new Error("no current job");
    if (job.status === "stopped" || isStopInProgressStatus(job.status)) {
      return this.maybeFinalizeStoppedJob(job.id) || job;
    }
    if (!["running", "paused"].includes(job.status)) {
      throw new Error(`current job cannot be stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, {
      status: "stopping",
      pausedAt: null,
    });
    this.syncAutoExtractState(next);
    const finalized = this.maybeFinalizeStoppedJob(next.id) || next;
    this.emit("job.updated", { job: finalized, autoExtractState: this.getAutoExtractSnapshot(next.id) });
    this.emit("toast", {
      level: "info",
      message:
        finalized.status === "stopped"
          ? `job #${job.id} stopped`
          : `job #${job.id} stopping gracefully; waiting for active work to finish`,
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
    if (!job) throw new Error("no current job");
    if (job.status === "stopped" || job.status === "force_stopping") {
      return this.maybeFinalizeStoppedJob(job.id) || job;
    }
    if (!["running", "paused", "stopping"].includes(job.status)) {
      throw new Error(`current job cannot be force stopped from ${job.status}`);
    }
    const next = this.db.updateJobState(job.id, {
      status: "force_stopping",
      pausedAt: null,
    });
    this.abortAutoExtractRequests(job.id, "force stop requested by user");
    this.terminateActiveAttempts(job.id);
    const finalized = this.maybeFinalizeStoppedJob(next.id) || next;
    this.emit("job.updated", { job: finalized, autoExtractState: this.getAutoExtractSnapshot(next.id) });
    this.emit("toast", {
      level: "warning",
      message:
        finalized.status === "stopped"
          ? `job #${job.id} force stopped`
          : `job #${job.id} force stopping; terminating active work`,
    });
    if (finalized.status !== "stopped") {
      this.ensureLoop(job.id);
    }
    return finalized;
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
    if (!["running", "paused", "completing"].includes(job.status)) {
      throw new Error(`current job cannot update limits from ${job.status}`);
    }
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

  private terminateActiveAttempts(jobId: number): void {
    for (const active of this.activeAttempts.values()) {
      if (active.attempt.jobId !== jobId) continue;
      active.stopRequested = "force_stop";
      signalChildProcess(active.child, "SIGTERM");
      void delay(5_000).then(() => {
        const current = this.activeAttempts.get(active.attempt.id);
        if (current?.stopRequested === "force_stop") {
          signalChildProcess(current.child, "SIGKILL");
        }
      });
    }
    for (const pending of this.pendingAttemptLaunches.values()) {
      if (pending.jobId !== jobId) continue;
      pending.stopRequested = "force_stop";
    }
  }

  private abortAutoExtractRequests(jobId: number, reason: string): void {
    const state = this.autoExtractStates.get(jobId);
    if (!state) return;
    for (const controller of state.requestControllers.values()) {
      controller.abort(new Error(reason));
    }
    state.lastMessage = reason;
    state.updatedAt = nowIso();
  }

  private hasInFlightAutoExtract(jobId: number): boolean {
    const state = this.autoExtractStates.get(jobId);
    return Boolean(state && state.inFlightCount > 0);
  }

  private hasPendingAttemptLaunch(jobId: number): boolean {
    for (const pending of this.pendingAttemptLaunches.values()) {
      if (pending.jobId === jobId) return true;
    }
    return false;
  }

  private maybeFinalizeStoppedJob(jobId: number): JobRecord | null {
    const job = this.db.getJob(jobId);
    if (!job || !isStopInProgressStatus(job.status)) return null;
    if (this.activeAttempts.size > 0 || this.hasPendingAttemptLaunch(jobId) || this.hasInFlightAutoExtract(jobId)) {
      return null;
    }
    const stopped = this.db.stopJob(jobId);
    this.deleteAutoExtractStateIfIdle(jobId);
    return stopped;
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    const currentJob = this.db.getCurrentJob(this.site);
    for (const job of [currentJob].filter(Boolean) as JobRecord[]) {
      this.abortAutoExtractRequests(job.id, "server shutdown");
    }
    const preserveManualStopSemantics = currentJob ? isStopInProgressStatus(currentJob.status) : false;
    const waits: Promise<void>[] = [];
    for (const active of this.activeAttempts.values()) {
      if (preserveManualStopSemantics) {
        active.stopRequested = "force_stop";
      }
      signalChildProcess(active.child, "SIGTERM");
      waits.push(
        new Promise((resolve) => {
          active.child.once("close", () => resolve());
        }),
      );
    }
    await Promise.allSettled(waits);
    await Promise.allSettled(Array.from(this.pendingAttemptFinalizers));
    const job = this.db.getCurrentJob(this.site);
    if (job && isStopInProgressStatus(job.status)) {
      this.maybeFinalizeStoppedJob(job.id);
    }
    await this.loopPromise;
  }

  private requireCurrentJob(): JobRecord {
    const job = this.db.getCurrentJob(this.site);
    if (!job) throw new Error("no current job");
    if (isTerminalJobStatus(job.status)) {
      throw new Error(`current job is already ${job.status}`);
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
    while (true) {
      if (this.shuttingDown) return;
      for (const active of this.activeAttempts.values()) {
        this.syncActiveAttemptFromLedger(active);
      }
      const job = this.db.getJob(jobId);
      if (!job) return;
      const autoExtractState = this.autoExtractStates.get(jobId);
      if (autoExtractState && this.reconcileAutoExtractPendingCandidates(job, autoExtractState)) {
        this.emit("job.updated", { job: this.db.getJob(jobId), autoExtractState: this.getAutoExtractSnapshot(jobId) });
      }

      const activeCount = this.activeAttempts.size;

      if (job.status === "paused") {
        await delay(100);
        continue;
      }

      if (isStopInProgressStatus(job.status)) {
        const stopped = this.maybeFinalizeStoppedJob(jobId);
        if (stopped) {
          this.emit("job.updated", { job: stopped, autoExtractState: this.getAutoExtractSnapshot(jobId) });
          this.emit("toast", {
            level: "info",
            message: job.status === "force_stopping" ? `job #${job.id} force stopped` : `job #${job.id} stopped`,
          });
          return;
        }
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
        const dispatchJob = this.db.getJob(jobId);
        if (!dispatchJob || dispatchJob.status !== "running") {
          break;
        }
        const account = this.db.leaseNextAccount(jobId);
        if (!account) break;
        const attemptOutputDir = path.join(this.repoRoot, "output", "web-runs", `job-${dispatchJob.id}`, `attempt-${Date.now()}-${account.id}`);
        const attempt = this.db.createAttempt(dispatchJob.id, {
          accountId: account.id,
          accountEmail: account.microsoftEmail,
          outputDir: attemptOutputDir,
        });
        const pendingLaunch: PendingAttemptLaunch = {
          jobId: dispatchJob.id,
          attempt,
          account,
          stopRequested: null,
        };
        this.pendingAttemptLaunches.set(attempt.id, pendingLaunch);
        try {
          const started = await this.spawnAttempt(dispatchJob, account, attempt, attemptOutputDir, pendingLaunch);
          if (!started) {
            continue;
          }
          this.emit("attempt.updated", { attempt: this.db.getAttempt(attempt.id) });
          this.emit("account.updated", { account: this.db.getAccount(account.id) });
          this.emit("job.updated", { job: this.db.getJob(dispatchJob.id) });
        } catch (error) {
          this.failAttempt(dispatchJob.id, attempt.id, account.id, {
            errorCode: "launch_setup_failed",
            errorMessage: error instanceof Error ? error.message : String(error),
          });
        } finally {
          this.pendingAttemptLaunches.delete(attempt.id);
        }
      }

      const refreshed = this.db.getJob(jobId);
      if (!refreshed) return;
      if (refreshed.status === "paused") {
        await delay(100);
        continue;
      }
      if (isStopInProgressStatus(refreshed.status)) {
        const stopped = this.maybeFinalizeStoppedJob(jobId);
        if (stopped) {
          this.emit("job.updated", { job: stopped, autoExtractState: this.getAutoExtractSnapshot(jobId) });
          this.emit("toast", {
            level: "info",
            message: refreshed.status === "force_stopping" ? `job #${refreshed.id} force stopped` : `job #${refreshed.id} stopped`,
          });
          return;
        }
        await delay(100);
        continue;
      }
      if (isTerminalJobStatus(refreshed.status)) {
        return;
      }
      const eligible = this.db.countEligibleAccounts(jobId);
      const pendingBrowserSessions = this.db.countPendingBrowserSessions(jobId);
      const hasAutoExtractState = this.autoExtractStates.has(jobId);
      const pendingWait = resolvePendingBrowserSessionWait({
        state: this.pendingBrowserSessionWaits.get(jobId) || null,
        pendingCount: eligible === 0 ? pendingBrowserSessions : 0,
        nowMs: Date.now(),
      });
      if (pendingWait.state) {
        this.pendingBrowserSessionWaits.set(jobId, pendingWait.state);
      } else {
        this.pendingBrowserSessionWaits.delete(jobId);
      }
      if (eligible === 0 && pendingWait.wait) {
        await delay(100);
        continue;
      }
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
        if ((eligible === 0 && pendingBrowserSessions === 0 && !hasAutoExtractState) || refreshed.launchedCount >= refreshed.maxAttempts) {
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

  private async spawnAttempt(
    job: JobRecord,
    account: MicrosoftAccountRecord,
    attempt: JobAttemptRecord,
    outputDir: string,
    pendingLaunch: PendingAttemptLaunch,
  ): Promise<boolean> {
    let reservedPorts: { apiPort: number; mixedPort: number } | null = null;
    let portLeases: { apiPort: PortLease; mixedPort: PortLease } | null = null;
    try {
      const latestJob = this.db.getJob(job.id);
      const launchBlockedByStop =
        pendingLaunch.stopRequested === "force_stop"
        || Boolean(latestJob && (latestJob.status === "stopped" || isStopInProgressStatus(latestJob.status)));
      if (launchBlockedByStop) {
        if (pendingLaunch.stopRequested === "force_stop") {
          const { job: stoppedJob, attempt: stoppedAttempt } = this.db.completeAttemptStopped(
            job.id,
            attempt.id,
            account.id,
            {
              errorCode: "force_stopped",
              errorMessage: "stopped by user",
            },
            null,
          );
          this.emit("attempt.updated", { attempt: stoppedAttempt });
          this.emit("account.updated", { account: this.db.getAccount(account.id) });
          this.emit("job.updated", { job: stoppedJob, autoExtractState: this.getAutoExtractSnapshot(job.id) });
          this.emit("toast", { level: "warning", message: `attempt #${attempt.id} stopped before launch for account #${account.id}` });
        } else {
          const { job: releasedJob, account: releasedAccount } = this.db.rollbackAttemptBeforeLaunch(job.id, attempt.id, account.id);
          this.emit("account.updated", { account: releasedAccount });
          this.emit("job.updated", { job: releasedJob, autoExtractState: this.getAutoExtractSnapshot(job.id) });
        }
        return false;
      }
      const attemptBaseEnv = buildAttemptBaseEnv(undefined);
      const chromeExecutablePath = assertUsableFingerprintChromiumExecutablePath(
        resolveExplicitChromeExecutablePath(process.env.CHROME_EXECUTABLE_PATH),
      );
      await mkdir(outputDir, { recursive: true });
      const settings = this.getSettings();
      portLeases = await reserveMihomoPortLeases();
      reservedPorts = {
        apiPort: portLeases.apiPort.port,
        mixedPort: portLeases.mixedPort.port,
      };
      const selectedProxyNode = resolveReusableAttemptProxyNode(this.db, account.id);
      if (selectedProxyNode) {
        this.db.touchProxyLease(selectedProxyNode);
      }
      const runtimeSpec = buildAttemptRuntimeSpec({
        job,
        account,
        outputDir,
        sharedLedgerPath: this.sharedLedgerPath,
        settings,
        reservedPorts,
        chromeExecutablePath,
        selectedProxyNode,
        baseEnv: attemptBaseEnv,
      });
      const refreshedJob = this.db.getJob(job.id);
      const launchBlockedAfterSetup =
        pendingLaunch.stopRequested === "force_stop"
        || Boolean(refreshedJob && (refreshedJob.status === "stopped" || isStopInProgressStatus(refreshedJob.status)));
      if (launchBlockedAfterSetup) {
        await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
        if (pendingLaunch.stopRequested === "force_stop") {
          const { job: stoppedJob, attempt: stoppedAttempt } = this.db.completeAttemptStopped(
            job.id,
            attempt.id,
            account.id,
            {
              errorCode: "force_stopped",
              errorMessage: "stopped by user",
            },
            null,
          );
          this.emit("attempt.updated", { attempt: stoppedAttempt });
          this.emit("account.updated", { account: this.db.getAccount(account.id) });
          this.emit("job.updated", { job: stoppedJob, autoExtractState: this.getAutoExtractSnapshot(job.id) });
          this.emit("toast", { level: "warning", message: `attempt #${attempt.id} stopped before launch for account #${account.id}` });
        } else {
          const { job: releasedJob, account: releasedAccount } = this.db.rollbackAttemptBeforeLaunch(job.id, attempt.id, account.id);
          this.emit("account.updated", { account: releasedAccount });
          this.emit("job.updated", { job: releasedJob, autoExtractState: this.getAutoExtractSnapshot(job.id) });
          this.emit("toast", {
            level: "info",
            message: `attempt #${attempt.id} skipped before launch because job #${job.id} is stopping`,
          });
        }
        return false;
      }
      const child = spawn(runtimeSpec.command, runtimeSpec.args, {
        ...buildAttemptSpawnOptions(this.repoRoot, runtimeSpec),
        stdio: ["pipe", "pipe", "pipe"],
      });
      const active: ActiveAttempt = {
        child,
        attempt,
        account,
        outputDir,
        reservedPorts,
        tail: [],
        stopRequested: null,
      };
      if (pendingLaunch.stopRequested === "force_stop") {
        active.stopRequested = "force_stop";
      }
      child.stdin.end();
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
        const finalizer = (async () => {
          try {
            await runner();
          } finally {
            this.activeAttempts.delete(attempt.id);
            await releasePortLeases();
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
        void finalize(() => this.handleAttemptExit(job.id, attempt.id, account.id, outputDir, code, signal, active));
      });
      return true;
    } catch (error) {
      if (portLeases) {
        await Promise.all([portLeases.apiPort.release(), portLeases.mixedPort.release()]);
      }
      throw error;
    }
  }

  private syncActiveAttemptFromLedger(active: ActiveAttempt): JobAttemptRecord {
    const latest = this.db.getLatestSignupTask(active.attempt.jobId, active.account.id);
    if (!latest || shouldIgnoreSignupTaskForAttempt(active.attempt, latest)) {
      const current = this.db.getAttempt(active.attempt.id) || active.attempt;
      active.attempt = current;
      return current;
    }

    const patch: Partial<
      Pick<JobAttemptRecord, "runId" | "stage" | "proxyNode" | "proxyIp" | "errorCode" | "errorMessage" | "status">
    > = {};
    const nextRunId = latest.run_id == null ? active.attempt.runId : String(latest.run_id);
    const nextStage = latest.failure_stage == null ? active.attempt.stage : String(latest.failure_stage);
    const nextProxyNode = latest.proxy_node == null ? active.attempt.proxyNode : String(latest.proxy_node);
    const nextProxyIp = latest.proxy_ip == null ? active.attempt.proxyIp : String(latest.proxy_ip);
    const nextErrorCode = latest.error_code == null ? active.attempt.errorCode : String(latest.error_code);
    const nextErrorMessage = latest.error_message == null ? active.attempt.errorMessage : String(latest.error_message);
    const nextStatus = latest.status === "running" ? "running" : active.attempt.status;

    if (nextRunId !== active.attempt.runId) patch.runId = nextRunId;
    if (nextStage !== active.attempt.stage) patch.stage = nextStage;
    if (nextProxyNode !== active.attempt.proxyNode) patch.proxyNode = nextProxyNode;
    if (nextProxyIp !== active.attempt.proxyIp) patch.proxyIp = nextProxyIp;
    if (nextErrorCode !== active.attempt.errorCode) patch.errorCode = nextErrorCode;
    if (nextErrorMessage !== active.attempt.errorMessage) patch.errorMessage = nextErrorMessage;
    if (nextStatus !== active.attempt.status) patch.status = nextStatus;

    if (Object.keys(patch).length === 0) {
      const current = this.db.getAttempt(active.attempt.id) || active.attempt;
      active.attempt = current;
      return current;
    }

    const updated = this.db.updateAttempt(active.attempt.id, patch);
    active.attempt = updated;
    this.emit("attempt.updated", { attempt: updated });
    return updated;
  }

  private async handleAttemptExit(
    jobId: number,
    attemptId: number,
    accountId: number,
    outputDir: string,
    code: number | null,
    signal: NodeJS.Signals | null,
    active: ActiveAttempt,
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

    const message =
      error?.error ||
      (signupTask?.error_message ? String(signupTask.error_message) : "") ||
      (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
    if (active.stopRequested === "force_stop") {
      const { job, attempt } = this.db.completeAttemptStopped(
        jobId,
        attemptId,
        accountId,
        {
          errorCode: signal ? `force_stop_${String(signal).toLowerCase()}` : "force_stopped",
          errorMessage: message || "stopped by user",
        },
        signupTask,
      );
      this.emit("attempt.updated", { attempt });
      this.emit("account.updated", { account: this.db.getAccount(accountId) });
      this.emit("job.updated", { job });
      this.emit("toast", { level: "warning", message: `attempt #${attempt.id} stopped for account #${accountId}` });
      return;
    }
    if (code === 0 && signal == null && apiKey) {
      const { job, attempt } = this.db.completeAttemptSuccess(jobId, attemptId, accountId, apiKey, signupTask);
      this.emit("attempt.updated", { attempt });
      this.emit("account.updated", { account: this.db.getAccount(accountId) });
      this.emit("job.updated", { job });
      this.emit("toast", { level: "success", message: `attempt #${attempt.id} succeeded for account #${accountId}` });
      return;
    }
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
        autoExtractAccountType: normalizeAccountExtractorAccountType(
          input.autoExtractAccountType ?? fallback?.autoExtractAccountType,
        ),
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
      shankeyunKey: settings.extractorShankeyunKey,
      hotmail666Key: settings.extractorHotmail666Key,
    };
    const missingProviders = autoExtractSources.filter((provider) => !keyConfiguredForProvider(provider, runtimeConfig));
    if (missingProviders.length > 0) {
      throw new Error(`extractor key missing for ${missingProviders.map(providerLabel).join(", ")}`);
    }
    return {
      autoExtractSources,
      autoExtractQuantity,
      autoExtractMaxWaitSec,
      autoExtractAccountType: normalizeAccountExtractorAccountType(
        input.autoExtractAccountType ?? fallback?.autoExtractAccountType,
      ),
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
      providerInFlightCount: createProviderInFlightCounter(),
      providerAttemptCount: createProviderAttemptCounter(),
      phase: "idle",
      startedAt: null,
      lastProvider: null,
      lastMessage: null,
      updatedAt: now,
      lastBudgetTickMs: null,
      requestControllers: new Map<string, AbortController>(),
      pendingBootstrapCandidates: new Map<number, PendingAutoExtractCandidate>(),
    };
  }

  private syncAutoExtractState(job: JobRecord): void {
    const current = this.autoExtractStates.get(job.id);
    if (job.autoExtractSources.length === 0) {
      if (current?.inFlightCount || current?.pendingBootstrapCandidates.size) {
        current.enabledSources = [];
        current.phase = current.inFlightCount > 0 ? "waiting" : "idle";
        current.lastMessage = current.inFlightCount > 0
          ? "auto extract disabled, waiting for in-flight requests to finish"
          : `auto extract disabled, waiting for ${current.pendingBootstrapCandidates.size} pending bootstrap result(s)`;
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
      current.providerInFlightCount = createProviderInFlightCounter();
      current.requestControllers.clear();
      current.pendingBootstrapCandidates.clear();
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
    state.providerInFlightCount = createProviderInFlightCounter();
    state.lastBudgetTickMs = null;
    state.lastMessage = message;
    state.updatedAt = nowIso();
    state.requestControllers.clear();
    state.pendingBootstrapCandidates.clear();
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
    state.attemptBudget = 0;
    state.acceptedCount = 0;
    state.rawAttemptCount = 0;
    state.inFlightCount = 0;
    state.startedAt = nowIso();
    state.providerNextAttemptAtMs = createProviderAttemptClock();
    state.providerInFlightCount = createProviderInFlightCounter();
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
    if (isLockedAccountRecord(account)) return "microsoft_account_locked";
    if (account.skipReason) return account.skipReason;
    if (account.leaseJobId != null) return "leased";
    if (account.browserSession && account.browserSession.status !== "ready") return "session_not_ready";
    return this.db.isAccountSchedulableForJob(jobId, account.id) ? "unknown" : "already_attempted";
  }

  private countReservedAutoExtractAccounts(state: AutoExtractState): number {
    return state.acceptedCount + state.pendingBootstrapCandidates.size;
  }

  private resolvePendingAutoExtractRejectReason(jobId: number, account: MicrosoftAccountRecord | null): string | null {
    if (!account) return "import_missing";
    if (account.disabledAt != null) return "disabled";
    if (account.hasApiKey || account.skipReason === "has_api_key") return "has_api_key";
    if (isLockedAccountRecord(account)) return "microsoft_account_locked";
    if (account.skipReason) return account.skipReason;
    if (account.leaseJobId != null) return "leased";
    if (account.browserSession?.status === "ready") {
      return this.db.isAccountSchedulableForJob(jobId, account.id) ? null : "already_attempted";
    }
    if (account.browserSession?.status === "failed" || account.browserSession?.status === "blocked") {
      return (
        account.browserSession.lastErrorCode?.trim()
        || account.lastErrorCode?.trim()
        || (account.browserSession.status === "blocked" ? "session_blocked" : "session_bootstrap_failed")
      );
    }
    return "session_not_ready";
  }

  private trackPendingAutoExtractCandidate(
    state: AutoExtractState,
    input: {
      accountId: number;
      batchId: number;
      provider: AccountExtractorProvider;
      rawPayload: string;
      email: string;
      password: string;
    },
  ): void {
    state.pendingBootstrapCandidates.set(input.accountId, {
      accountId: input.accountId,
      batchId: input.batchId,
      provider: input.provider,
      rawPayload: input.rawPayload,
      email: input.email,
      password: input.password,
    });
  }

  private reconcileAutoExtractPendingCandidates(job: JobRecord, state: AutoExtractState): boolean {
    if (state.pendingBootstrapCandidates.size === 0) {
      return false;
    }
    const completedAt = nowIso();
    let acceptedNow = 0;
    let failedNow = 0;
    for (const [accountId, pending] of state.pendingBootstrapCandidates.entries()) {
      const latestAccount = this.db.getAccount(accountId);
      const rejectReason = this.resolvePendingAutoExtractRejectReason(job.id, latestAccount);
      if (rejectReason === "session_not_ready") {
        continue;
      }
      state.pendingBootstrapCandidates.delete(accountId);
      if (!rejectReason) {
        acceptedNow += 1;
        this.db.createAccountExtractItem({
          batchId: pending.batchId,
          provider: pending.provider,
          rawPayload: pending.rawPayload,
          email: pending.email,
          password: pending.password,
          parseStatus: "parsed",
          acceptStatus: "accepted",
          rejectReason: null,
          importedAccountId: latestAccount?.id ?? accountId,
          createdAt: completedAt,
        });
        this.db.updateAccountExtractBatch(pending.batchId, {
          acceptedCount: 1,
          status: "accepted",
          errorMessage: null,
          completedAt,
        });
        continue;
      }
      failedNow += 1;
      this.db.createAccountExtractItem({
        batchId: pending.batchId,
        provider: pending.provider,
        rawPayload: pending.rawPayload,
        email: pending.email,
        password: pending.password,
        parseStatus: "parsed",
        acceptStatus: "rejected",
        rejectReason,
        importedAccountId: latestAccount?.id ?? accountId,
        createdAt: completedAt,
      });
      this.db.updateAccountExtractBatch(pending.batchId, {
        acceptedCount: 0,
        status: "rejected",
        errorMessage: rejectReason,
        completedAt,
      });
    }
    if (acceptedNow > 0) {
      state.acceptedCount += acceptedNow;
      state.lastMessage = `bootstrap completed for ${acceptedNow} extracted account(s)`;
      state.updatedAt = completedAt;
    } else if (failedNow > 0) {
      state.lastMessage = `bootstrap failed for ${failedNow} extracted account(s), continuing auto extract`;
      state.updatedAt = completedAt;
    }
    return acceptedNow > 0 || failedNow > 0;
  }

  private deleteAutoExtractStateIfIdle(jobId: number): void {
    const state = this.autoExtractStates.get(jobId);
    if (!state || (state.inFlightCount === 0 && state.pendingBootstrapCandidates.size === 0)) {
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
    const reservedCount = this.countReservedAutoExtractAccounts(state);
    const targetReached = state.currentRoundTarget > 0 && reservedCount >= state.currentRoundTarget;
    const waitExhausted = state.remainingWaitMs <= 0;
    const rawBudgetExhausted = state.rawAttemptCount >= state.attemptBudget && state.attemptBudget > 0;
    const pendingBootstrapCount = state.pendingBootstrapCandidates.size;
    if (state.inFlightCount > 0 && (targetReached || waitExhausted || rawBudgetExhausted)) {
      state.phase = "waiting";
      state.lastMessage = targetReached
        ? `target reached, waiting for ${state.inFlightCount} in-flight request(s)`
        : waitExhausted || rawBudgetExhausted
          ? `wait budget exhausted, waiting for ${state.inFlightCount} in-flight request(s)`
          : `waiting for ${state.inFlightCount} in-flight request(s)`;
      state.updatedAt = nowIso();
      return { status: "waiting" };
    }
    if (pendingBootstrapCount > 0 && (targetReached || waitExhausted || rawBudgetExhausted)) {
      state.phase = "waiting";
      state.lastMessage = targetReached
        ? `target reached, waiting for ${pendingBootstrapCount} bootstrap result(s)`
        : waitExhausted || rawBudgetExhausted
          ? `wait budget exhausted, waiting for ${pendingBootstrapCount} bootstrap result(s)`
          : `waiting for ${pendingBootstrapCount} bootstrap result(s)`;
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
        reason: `auto extract timed out after ${Math.ceil(state.maxWaitMs / 1000)}s`,
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
      if (
        state.providerNextAttemptAtMs[provider] <= nowMs
        && state.providerInFlightCount[provider] < AUTO_EXTRACT_WORKERS_PER_PROVIDER
      ) {
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
      shankeyunKey: settings.extractorShankeyunKey,
      hotmail666Key: settings.extractorHotmail666Key,
      timeoutMs: AUTO_EXTRACT_REQUEST_TIMEOUT_MS,
    };

    const finish = (input: {
      ok: boolean;
      result?: Awaited<ReturnType<typeof fetchSingleExtractedAccount>>;
      errorMessage?: string;
      failureCode?: "invalid_key" | "insufficient_stock" | "parse_failed" | "upstream_error" | "job_force_stopping" | null;
      rawResponse?: string | null;
      maskedKey?: string | null;
    }) => {
      const state = this.autoExtractStates.get(context.jobId);
      state?.requestControllers.delete(context.requestId);
      const startedAt = context.dispatchStartedAt;
      const completedAt = nowIso();
      const currentJobAtFinish = this.db.getJob(context.jobId);
      const forceStopping = currentJobAtFinish?.status === "force_stopping";

      let acceptedInBatch = 0;
      const affectedIds = new Set<number>();
      const rejectReasons = new Set<string>();

      let batchStatus: "accepted" | "rejected" | "pending_bootstrap" | "invalid_key" | "insufficient_stock" | "parse_failed" | "error" =
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
        let pendingBootstrapTrackedInBatch = false;
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

          const roundTargetReached =
            state != null
            && state.startedAt === context.roundStartedAt
            && this.countReservedAutoExtractAccounts(state) + acceptedInBatch >= state.currentRoundTarget;
          if (roundTargetReached) {
            rejectReasons.add("round_target_reached");
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: "parsed",
              acceptStatus: "rejected",
              rejectReason: "round_target_reached",
            });
            continue;
          }

          if (forceStopping) {
            rejectReasons.add("job_force_stopping");
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: "parsed",
              acceptStatus: "rejected",
              rejectReason: "job_force_stopping",
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
          const rejectReason = this.resolvePendingAutoExtractRejectReason(context.jobId, importedAccount);
          if (rejectReason && rejectReason !== "session_not_ready") {
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
          if (!importedAccount) {
            const missingReason = this.describeExtractRejectReason(context.jobId, importedAccount);
            rejectReasons.add(missingReason);
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: "parsed",
              acceptStatus: "rejected",
              rejectReason: missingReason,
              importedAccountId: null,
            });
            continue;
          }

          acceptedRequestCandidate = true;
          affectedIds.add(importedAccount.id);
          if (!rejectReason) {
            acceptedInBatch = 1;
            this.db.createAccountExtractItem({
              batchId: batch.id,
              provider: context.provider,
              rawPayload: candidate.rawPayload,
              email: candidate.email,
              password: candidate.password,
              parseStatus: "parsed",
              acceptStatus: "accepted",
              rejectReason: null,
              importedAccountId: importedAccount.id,
            });
          } else {
            rejectReasons.add("session_not_ready");
            if (state) {
              pendingBootstrapTrackedInBatch = true;
              this.trackPendingAutoExtractCandidate(state, {
                accountId: importedAccount.id,
                batchId: batch.id,
                provider: context.provider,
                rawPayload: candidate.rawPayload,
                email: candidate.email,
                password: candidate.password,
              });
            } else {
              this.db.createAccountExtractItem({
                batchId: batch.id,
                provider: context.provider,
                rawPayload: candidate.rawPayload,
                email: candidate.email,
                password: candidate.password,
                parseStatus: "parsed",
                acceptStatus: "rejected",
                rejectReason: "session_not_ready",
                importedAccountId: importedAccount.id,
              });
            }
          }
        }

        batchStatus =
          acceptedInBatch > 0
            ? "accepted"
            : pendingBootstrapTrackedInBatch
              ? "pending_bootstrap"
              : input.result.ok
                ? "rejected"
                : mapFailureCodeToBatchStatus(input.result.failureCode);
        batchErrorMessage = acceptedInBatch > 0 ? null : input.result.message || Array.from(rejectReasons).join(", ") || null;
      }

      this.db.updateAccountExtractBatch(batch.id, {
        acceptedCount: acceptedInBatch,
        status: batchStatus,
        errorMessage: batchErrorMessage,
        rawResponse: input.rawResponse ?? null,
        maskedKey: input.maskedKey ?? null,
        completedAt: batchStatus === "pending_bootstrap" ? null : completedAt,
      });

      if (state && state.startedAt === context.roundStartedAt) {
        state.inFlightCount = Math.max(0, state.inFlightCount - 1);
        state.providerInFlightCount[context.provider] = Math.max(0, state.providerInFlightCount[context.provider] - 1);
        state.lastProvider = context.provider;
        state.acceptedCount += acceptedInBatch;
        state.phase = state.inFlightCount > 0
          ? "waiting"
          : this.countReservedAutoExtractAccounts(state) >= state.currentRoundTarget
            ? "waiting"
            : "extracting";
        state.lastMessage =
          acceptedInBatch > 0
            ? `${providerLabel(context.provider)} accepted ${acceptedInBatch} usable account`
            : batchStatus === "pending_bootstrap"
              ? `${providerLabel(context.provider)} imported account, waiting for bootstrap`
            : batchErrorMessage || "no usable account accepted";
        state.updatedAt = completedAt;
      }

      if (affectedIds.size > 0) {
        this.emit("account.updated", { affectedIds: Array.from(affectedIds), action: "extractor_import" });
        void this.hooks?.onImportedAccounts?.(Array.from(affectedIds));
      }
      if (acceptedInBatch > 0) {
        this.emit("toast", {
          level: "success",
          message: `job #${context.jobId} accepted ${acceptedInBatch} extracted account(s) from ${providerLabel(context.provider)}`,
        });
      }

      const currentJob = this.db.getJob(context.jobId);
      const stopped = this.maybeFinalizeStoppedJob(context.jobId);
      if (stopped) {
        this.emit("job.updated", { job: stopped, autoExtractState: this.getAutoExtractSnapshot(context.jobId) });
        return;
      }
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

    const state = this.autoExtractStates.get(context.jobId);
    const controller = new AbortController();
    state?.requestControllers.set(context.requestId, controller);

    void fetchSingleExtractedAccount({
      provider: context.provider,
      accountType: context.accountType,
      alternationIndex: context.alternationIndex,
      config: runtimeConfig,
      signal: controller.signal,
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
        const requestAborted = controller.signal.aborted || isAbortError(error);
        const abortedByManualStop =
          controller.signal.aborted
          && this.db.getJob(context.jobId)?.status === "force_stopping";
        finish({
          ok: false,
          errorMessage: abortedByManualStop ? "stopped by user" : requestAborted ? "request aborted" : error instanceof Error ? error.message : String(error),
          failureCode: abortedByManualStop ? "job_force_stopping" : "upstream_error",
          rawResponse: null,
          maskedKey: maskLocalSecret(getConfiguredExtractorKey(context.provider, runtimeConfig)),
        });
      });
  }

  private async maybeAutoExtract(job: JobRecord): Promise<AutoExtractDecision> {
    const existingState = this.autoExtractStates.get(job.id);
    if (
      job.autoExtractSources.length === 0
      && (!existingState || (existingState.inFlightCount === 0 && existingState.pendingBootstrapCandidates.size === 0))
    ) {
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
    this.reconcileAutoExtractPendingCandidates(job, state);

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
      && this.countReservedAutoExtractAccounts(state) < state.currentRoundTarget
      && (state.attemptBudget <= 0 || state.rawAttemptCount < state.attemptBudget)
    ) {
      const nowMs = Date.now();
      const provider = this.pickDueProvider(state, nowMs);
      if (!provider) {
        break;
      }
      const dispatchStartedAt = nowIso();
      const alternationIndex = state.providerAttemptCount[provider];
      state.phase = "extracting";
      state.lastProvider = provider;
      state.lastMessage = `${providerLabel(provider)} request dispatched`;
      state.rawAttemptCount += 1;
      state.inFlightCount += 1;
      state.providerInFlightCount[provider] += 1;
      state.providerAttemptCount[provider] += 1;
      state.providerNextAttemptAtMs[provider] = nowMs + AUTO_EXTRACT_REQUEST_INTERVAL_MS;
      state.updatedAt = dispatchStartedAt;
      this.launchAutoExtractRequest({
        jobId: job.id,
        provider,
        accountType: state.accountType,
        alternationIndex,
        requestedUsableCount: state.currentRoundTarget,
        attemptBudget: state.attemptBudget,
        dispatchStartedAt,
        roundStartedAt: state.startedAt,
        requestId: `${job.id}:${provider}:${state.rawAttemptCount}:${dispatchStartedAt}`,
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
