import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";
import { mkdir, readFile } from "node:fs/promises";
import { AppDatabase, computeLaunchCapacity, type AppSettings, type JobAttemptRecord, type JobRecord, type MicrosoftAccountRecord } from "../storage/app-db.js";

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

const RESERVED_LOCAL_PORTS = new Set<number>();
const STRIPPED_ATTEMPT_ENV_KEYS = [
  "EXISTING_EMAIL",
  "EXISTING_PASSWORD",
  "MICROSOFT_ACCOUNT_EMAIL",
  "MICROSOFT_ACCOUNT_PASSWORD",
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
  if (process.versions.bun) {
    return {
      command: process.execPath,
      bootstrapArgs: ["run", "src/main.ts"],
    };
  }
  return {
    command: process.execPath || "node",
    bootstrapArgs: ["--import", "tsx", "src/main.ts"],
  };
}

function isTerminalJobStatus(status: JobRecord["status"]): boolean {
  return status === "completed" || status === "failed";
}

export function buildAttemptRuntimeSpec(input: {
  job: Pick<JobRecord, "id" | "runMode">;
  account: Pick<MicrosoftAccountRecord, "id" | "microsoftEmail" | "passwordPlaintext">;
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
    },
  };
}

function nowIso(): string {
  return new Date().toISOString();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function reserveLocalPort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        if (!port || port <= 0) {
          reject(new Error("failed to reserve local port"));
          return;
        }
        resolve(port);
      });
    });
  });
}

async function reserveUniqueLocalPort(): Promise<number> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const port = await reserveLocalPort();
    if (RESERVED_LOCAL_PORTS.has(port)) continue;
    RESERVED_LOCAL_PORTS.add(port);
    return port;
  }
  throw new Error("failed to reserve a unique local port");
}

async function reserveMihomoPorts(): Promise<{ apiPort: number; mixedPort: number }> {
  const apiPort = await reserveUniqueLocalPort();
  let mixedPort = await reserveUniqueLocalPort();
  while (mixedPort === apiPort) {
    RESERVED_LOCAL_PORTS.delete(mixedPort);
    mixedPort = await reserveUniqueLocalPort();
  }
  return { apiPort, mixedPort };
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
    return Array.from(this.activeAttempts.values()).map((item) => item.attempt);
  }

  async startJob(params: {
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
  }): Promise<JobRecord> {
    const settings = this.getSettings();
    if (!settings.subscriptionUrl.trim()) {
      throw new Error("configure a Mihomo subscription before starting a job");
    }
    const job = this.db.createJob(params);
    this.emit("job.updated", { job });
    this.emit("toast", { level: "info", message: `job #${job.id} started` });
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
    this.emit("job.updated", { job: next });
    this.emit("toast", { level: "info", message: `job #${job.id} resumed` });
    this.ensureLoop(job.id);
    return next;
  }

  updateCurrentJobLimits(input: Partial<Pick<JobRecord, "parallel" | "need" | "maxAttempts">>): JobRecord {
    const job = this.requireCurrentJob();
    const patch: Partial<JobRecord> = {};
    if (typeof input.parallel === "number") patch.parallel = Math.max(1, input.parallel);
    if (typeof input.need === "number") patch.need = Math.max(1, input.need);
    if (typeof input.maxAttempts === "number") patch.maxAttempts = Math.max(1, input.maxAttempts);
    const next = this.db.updateJobState(job.id, patch);
    if (next.successCount >= next.need && next.status === "running") {
      this.db.updateJobState(next.id, { status: "completing" });
    }
    this.emit("job.updated", { job: this.db.getJob(job.id) });
    this.emit("toast", { level: "info", message: `job #${job.id} limits updated` });
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
        await delay(300);
        continue;
      }

      if (job.successCount >= job.need) {
        if (job.status !== "completing" && activeCount > 0) {
          const next = this.db.updateJobState(jobId, { status: "completing" });
          this.emit("job.updated", { job: next });
        }
        if (activeCount === 0) {
          const completed = this.db.completeJob(jobId, true);
          this.emit("job.updated", { job: completed });
          this.emit("toast", { level: "success", message: `job #${job.id} completed` });
          return;
        }
        await delay(300);
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
      if (this.activeAttempts.size === 0) {
        if (refreshed.successCount >= refreshed.need) {
          const completed = this.db.completeJob(jobId, true);
          this.emit("job.updated", { job: completed });
          this.emit("toast", { level: "success", message: `job #${job.id} completed` });
          return;
        }
        if (eligible === 0 || refreshed.launchedCount >= refreshed.maxAttempts) {
          const failed = this.db.completeJob(jobId, false, "eligible accounts exhausted or max attempts reached");
          this.emit("job.updated", { job: failed });
          this.emit("toast", { level: "error", message: `job #${job.id} failed: ${failed.lastError}` });
          return;
        }
      }

      await delay(300);
    }
  }

  private async spawnAttempt(job: JobRecord, account: MicrosoftAccountRecord, attempt: JobAttemptRecord, outputDir: string): Promise<void> {
    let reservedPorts: { apiPort: number; mixedPort: number } | null = null;
    try {
      await mkdir(outputDir, { recursive: true });
      const settings = this.getSettings();
      reservedPorts = await reserveMihomoPorts();
      const selectedProxyNode = this.db.getSelectedProxyName();
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
      const activeReservedPorts = reservedPorts;
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
          RESERVED_LOCAL_PORTS.delete(activeReservedPorts.apiPort);
          RESERVED_LOCAL_PORTS.delete(activeReservedPorts.mixedPort);
        }
      };

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
      if (reservedPorts) {
        RESERVED_LOCAL_PORTS.delete(reservedPorts.apiPort);
        RESERVED_LOCAL_PORTS.delete(reservedPorts.mixedPort);
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
}
