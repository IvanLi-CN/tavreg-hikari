import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
  AppDatabase,
  type AppSettings,
  type JobRecord,
  type JobSite,
  type MicrosoftAccountRecord,
  type MicrosoftMailboxRecord,
} from "../storage/app-db.js";
import {
  assertUsableFingerprintChromiumExecutablePath,
  resolveExplicitChromeExecutablePath,
} from "../fingerprint-browser.js";
import {
  BrowserAvailabilityService,
  type AccountBusinessFlowAvailability,
} from "./browser-availability.js";
import { buildChatGptDraft } from "./chatgpt-draft.js";
import { buildCodexVibeMonitorCredentialJson } from "./chatgpt-credential-format.js";
import { reserveMihomoPortLeases } from "./port-lease.js";
import {
  buildAttemptRuntimeSpec,
  buildAttemptSpawnOptions,
  resolveReusableAttemptProxyNode,
  resolveWorkerRuntime,
  type ServerEvent,
} from "./scheduler.js";
import type { CfMailHttpJson } from "../cfmail-api.js";

export type AccountBusinessFlowSite = "none" | "tavily" | "grok" | "chatgpt";
export type AccountBusinessFlowMode = "headless" | "headed" | "fingerprint";
export type AccountBusinessFlowStatus = "starting" | "running" | "succeeded" | "failed";

export interface AccountBusinessFlowStateSnapshot {
  site: AccountBusinessFlowSite;
  mode: AccountBusinessFlowMode;
  status: AccountBusinessFlowStatus;
  browserRetained: boolean;
  lastError: string | null;
  startedAt: string;
  updatedAt: string;
  retainedAt: string | null;
}

interface ActiveBusinessFlow {
  key: string;
  accountId: number;
  site: AccountBusinessFlowSite;
  mode: AccountBusinessFlowMode;
  outputDir: string;
  retainPath: string;
  child: ChildProcessWithoutNullStreams;
  retainPollTimer: ReturnType<typeof setInterval> | null;
  jobId: number | null;
  attemptId: number | null;
  retainedAt: string | null;
  browserRetained: boolean;
}

interface RetainedBrowserSnapshot {
  retainedAt?: string | null;
  success?: boolean | null;
  error?: string | null;
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
      // fall through
    }
  }
  try {
    child.kill(signal);
  } catch {
    // ignore
  }
}

async function waitForChildClose(
  child: Pick<ChildProcessWithoutNullStreams, "exitCode" | "signalCode" | "once">,
  timeoutMs: number,
): Promise<boolean> {
  if (child.exitCode != null || child.signalCode != null) {
    return true;
  }
  return await Promise.race([
    new Promise<boolean>((resolve) => {
      child.once("close", () => resolve(true));
    }),
    delay(timeoutMs).then(() => false),
  ]);
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

function randomPassword(length = 18): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
  let output = "";
  for (let index = 0; index < length; index += 1) {
    output += alphabet[Math.floor(Math.random() * alphabet.length)] || "A";
  }
  return output;
}

function randomNickname(): string {
  const values = ["Mika", "Luna", "Rin", "Sora", "Aiko", "Nora", "Yuna", "Hana"];
  return values[Math.floor(Math.random() * values.length)] || "Mika";
}

function randomBirthDate(): string {
  const start = new Date("1988-01-01T00:00:00.000Z").getTime();
  const end = new Date("2004-12-31T00:00:00.000Z").getTime();
  const date = new Date(start + Math.floor(Math.random() * (end - start)));
  return date.toISOString().slice(0, 10);
}

function normalizeBusinessFlowRunMode(mode: AccountBusinessFlowMode): "headed" | "headless" {
  return mode === "headless" ? "headless" : "headed";
}

function buildFlowKey(accountId: number, site: AccountBusinessFlowSite): string {
  return `${accountId}:${site}`;
}

function getBusinessFlowDisplayLabel(site: AccountBusinessFlowSite): string {
  if (site === "none") return "微软账号页";
  if (site === "chatgpt") return "ChatGPT";
  if (site === "grok") return "Grok";
  return "Tavily";
}

function getRetainStateMessage(site: AccountBusinessFlowSite): string {
  if (site === "none") return "微软账号页已打开，浏览器保持可接管状态。";
  if (site === "chatgpt") return "ChatGPT 已完成登录，浏览器保持可接管状态。";
  if (site === "grok") return "Grok 已完成登录，浏览器保持可接管状态。";
  return "Tavily 已完成登录，浏览器保持可接管状态。";
}

function isSuccessfulRetainedBrowserSnapshot(retained: RetainedBrowserSnapshot | null): boolean {
  return Boolean(retained) && retained?.success !== false;
}

async function writeWorkerLog(outputDir: string, stdout: string, stderr: string): Promise<void> {
  const content = [stdout.trim(), stderr.trim()].filter(Boolean).join("\n");
  if (!content) return;
  await writeFile(path.join(outputDir, "worker.log"), `${content}\n`, "utf8").catch(() => {});
}

function buildHiddenJobPayload(accountId: number, site: AccountBusinessFlowSite, mode: AccountBusinessFlowMode): Record<string, unknown> {
  return {
    hidden: true,
    purpose: "account_business_flow",
    accountId,
    site,
    mode,
  };
}

export class AccountBusinessFlowManager {
  private readonly states = new Map<string, AccountBusinessFlowStateSnapshot>();
  private readonly active = new Map<string, ActiveBusinessFlow>();

  constructor(
    private readonly db: AppDatabase,
    private readonly repoRoot: string,
    private readonly taskLedgerDbPath: string,
    private readonly getSettings: () => AppSettings,
    private readonly broadcast: (event: ServerEvent) => void,
    private readonly httpJson: CfMailHttpJson,
    private readonly browserAvailability: BrowserAvailabilityService,
  ) {}

  getAvailability(): AccountBusinessFlowAvailability {
    return this.browserAvailability.getAccountBusinessFlowAvailability();
  }

  async ensureAvailability(): Promise<void> {
    await this.browserAvailability.ensureFresh();
  }

  getAccountState(accountId: number): AccountBusinessFlowStateSnapshot | null {
    const snapshots = Array.from(this.states.entries())
      .filter(([key]) => key.startsWith(`${accountId}:`))
      .map(([, snapshot]) => snapshot)
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
    return snapshots[0] || null;
  }

  serializeAccount(account: MicrosoftAccountRecord): { businessFlowAvailability: AccountBusinessFlowAvailability; businessFlowState: AccountBusinessFlowStateSnapshot | null } {
    return {
      businessFlowAvailability: this.getAvailability(),
      businessFlowState: this.getAccountState(account.id),
    };
  }

  async start(input: { accountId: number; site: AccountBusinessFlowSite; mode: AccountBusinessFlowMode }): Promise<void> {
    await this.ensureAvailability();
    const availability = this.getAvailability();
    if (input.mode === "headed" && !availability.headed) {
      throw new Error(availability.headedReason || "当前环境不支持 headed 模式");
    }
    if (input.mode === "fingerprint" && !availability.fingerprint) {
      throw new Error(availability.fingerprintReason || "当前环境不支持 fingerprint 模式");
    }
    const account = this.db.getAccount(input.accountId);
    if (!account) {
      throw new Error(`account not found: ${input.accountId}`);
    }
    if (account.leaseJobId != null) {
      throw new Error(`当前账号正被批量作业 #${account.leaseJobId} 占用，请等待该作业释放后再启动单账号业务流`);
    }
    if (!account.passwordPlaintext?.trim()) {
      throw new Error("账号缺少明文密码，暂时无法启动单账号业务流");
    }
    if (input.site !== "tavily" && input.site !== "none") {
      const mailbox = this.db.getMailboxByAccountId(account.id);
      if (!mailbox?.refreshToken?.trim()) {
        throw new Error("当前账号还没有完成 Microsoft 邮箱授权，暂时无法自动提取验证码");
      }
    }
    const key = buildFlowKey(account.id, input.site);
    const existing = Array.from(this.active.values()).find((activeFlow) => activeFlow.accountId === account.id) || null;
    if (existing) {
      if (existing.key === key && (existing.mode === "fingerprint" || input.mode === "fingerprint")) {
        await this.stopActiveFlow(existing, "superseded_by_new_launch");
      } else {
        throw new Error("该账号已有业务流正在运行中，请等待当前站点完成后再启动新的业务流");
      }
    }
    const startedAt = nowIso();
    this.setState(key, {
      site: input.site,
      mode: input.mode,
      status: "starting",
      browserRetained: false,
      lastError: null,
      startedAt,
      updatedAt: startedAt,
      retainedAt: null,
    });
    this.broadcastToast("info", `${account.microsoftEmail}：${getBusinessFlowDisplayLabel(input.site)} 单账号业务流已启动`);
    try {
      if (input.site === "none") {
        await this.startMicrosoftAccountFlow(account, input.mode, key);
        return;
      }
      if (input.site === "tavily") {
        await this.startTavilyFlow(account, input.site, input.mode, key);
        return;
      }
      const mailbox = this.db.getMailboxByAccountId(account.id);
      if (!mailbox) {
        throw new Error("当前账号还没有可用的 Microsoft 邮箱记录");
      }
      if (input.site === "chatgpt") {
        await this.startChatGptFlow(account, mailbox, input.mode, key);
        return;
      }
      await this.startGrokFlow(account, mailbox, input.mode, key);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error || "单账号业务流启动失败");
      this.updateState(key, {
        status: "failed",
        browserRetained: false,
        retainedAt: null,
        lastError: message,
      });
      this.broadcastToast("error", `${account.microsoftEmail}：${getBusinessFlowDisplayLabel(input.site)} 单账号业务流启动失败：${message}`);
      throw error;
    }
  }

  private setState(key: string, snapshot: AccountBusinessFlowStateSnapshot): void {
    this.states.set(key, snapshot);
    const accountId = Number.parseInt(key.split(":")[0] || "", 10);
    if (Number.isInteger(accountId) && accountId > 0) {
      this.broadcast({
        type: "account.updated",
        payload: { affectedIds: [accountId], action: "business_flow" },
        timestamp: nowIso(),
      });
    }
  }

  private updateState(key: string, patch: Partial<AccountBusinessFlowStateSnapshot>): void {
    const current = this.states.get(key);
    if (!current) return;
    this.setState(key, {
      ...current,
      ...patch,
      updatedAt: patch.updatedAt || nowIso(),
    });
  }

  private broadcastToast(level: "info" | "success" | "warning" | "error", message: string): void {
    this.broadcast({
      type: "toast",
      payload: { level, message },
      timestamp: nowIso(),
    });
  }

  private buildCommonFlowEnv(input: {
    account: MicrosoftAccountRecord;
    mailbox?: MicrosoftMailboxRecord | null;
    mode: AccountBusinessFlowMode;
    site: AccountBusinessFlowSite;
    outputDir: string;
    retainPath: string;
  }): NodeJS.ProcessEnv {
    const settings = this.getSettings();
    return {
      ...process.env,
      RUN_MODE: normalizeBusinessFlowRunMode(input.mode),
      ACCOUNT_BUSINESS_FLOW_MODE: input.mode,
      ACCOUNT_BUSINESS_FLOW_SITE: input.site,
      ACCOUNT_BUSINESS_FLOW_RETAIN_PATH: input.retainPath,
      MICROSOFT_ACCOUNT_EMAIL: input.account.microsoftEmail,
      MICROSOFT_ACCOUNT_PASSWORD: input.account.passwordPlaintext || "",
      ...(input.account.proofMailboxProvider ? { MICROSOFT_PROOF_MAILBOX_PROVIDER: input.account.proofMailboxProvider } : {}),
      ...(input.account.proofMailboxAddress ? { MICROSOFT_PROOF_MAILBOX_ADDRESS: input.account.proofMailboxAddress } : {}),
      ...(input.account.proofMailboxId ? { MICROSOFT_PROOF_MAILBOX_ID: input.account.proofMailboxId } : {}),
      MICROSOFT_GRAPH_CLIENT_ID: settings.microsoftGraphClientId,
      MICROSOFT_GRAPH_CLIENT_SECRET: settings.microsoftGraphClientSecret,
      MICROSOFT_GRAPH_REDIRECT_URI: settings.microsoftGraphRedirectUri,
      MICROSOFT_GRAPH_AUTHORITY: settings.microsoftGraphAuthority || "common",
      ...(input.mailbox?.id ? { MICROSOFT_MAILBOX_ID: String(input.mailbox.id) } : {}),
      ...(input.mailbox?.refreshToken ? { MICROSOFT_MAILBOX_REFRESH_TOKEN: input.mailbox.refreshToken } : {}),
      ...(input.mailbox?.accessToken ? { MICROSOFT_MAILBOX_ACCESS_TOKEN: input.mailbox.accessToken } : {}),
      ...(input.mailbox?.accessTokenExpiresAt ? { MICROSOFT_MAILBOX_ACCESS_TOKEN_EXPIRES_AT: input.mailbox.accessTokenExpiresAt } : {}),
      ...(input.mailbox?.authority ? { MICROSOFT_MAILBOX_AUTHORITY: input.mailbox.authority } : {}),
      ...(input.mode === "fingerprint"
        ? {
            KEEP_BROWSER_OPEN_ON_EXIT: "true",
            KEEP_BROWSER_OPEN_MS: "0",
            KEEP_BROWSER_OPEN_ON_FAILURE: "true",
          }
        : {}),
      OUTPUT_ROOT_DIR: input.outputDir,
    };
  }

  private async startTavilyFlow(
    account: MicrosoftAccountRecord,
    site: "tavily",
    mode: AccountBusinessFlowMode,
    key: string,
  ): Promise<void> {
    const outputDir = path.join(this.repoRoot, "output", "web-runs", "account-business-flow", site, `${account.id}-${Date.now()}`);
    const retainPath = path.join(outputDir, "retained-browser.json");
    const { hiddenJob, attemptId } = this.createLeasedHiddenJob({
      account,
      site,
      businessSite: site,
      mode,
      outputDir,
    });
    let portLeases: Awaited<ReturnType<typeof reserveMihomoPortLeases>> | null = null;
    try {
      const chromeExecutablePath = assertUsableFingerprintChromiumExecutablePath(
        resolveExplicitChromeExecutablePath(process.env.CHROME_EXECUTABLE_PATH),
      );
      const settings = this.getSettings();
      portLeases = await reserveMihomoPortLeases();
      const selectedProxyNode = resolveReusableAttemptProxyNode(this.db, account.id);
      if (selectedProxyNode) {
        this.db.touchProxyLease(selectedProxyNode);
      }
      const runtimeSpec = buildAttemptRuntimeSpec({
        job: hiddenJob,
        account,
        outputDir,
        sharedLedgerPath: this.taskLedgerDbPath,
        settings,
        reservedPorts: {
          apiPort: portLeases.apiPort.port,
          mixedPort: portLeases.mixedPort.port,
        },
        chromeExecutablePath,
        selectedProxyNode,
        baseEnv: this.buildCommonFlowEnv({ account, mode, site, outputDir, retainPath }),
      });
      const child = spawn(runtimeSpec.command, runtimeSpec.args, {
        ...buildAttemptSpawnOptions(this.repoRoot, runtimeSpec),
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin.end();
      child.once("spawn", () => {
        if (!portLeases) return;
        void Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
      });
      this.attachFlowProcess({
        key,
        accountId: account.id,
        site,
        mode,
        outputDir,
        retainPath,
        child,
        jobId: hiddenJob.id,
        attemptId,
        onClose: async (code, signal) => {
          await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
          const result = await readJsonFile<{ apiKey?: string | null }>(path.join(outputDir, "result.json"));
          const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
          const retained = await readJsonFile<RetainedBrowserSnapshot>(retainPath);
          if (code === 0 && signal == null && typeof result?.apiKey === "string" && result.apiKey.trim()) {
            this.db.completeAttemptSuccess(hiddenJob.id, attemptId, account.id, result.apiKey.trim(), null);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: Boolean(retained),
              retainedAt: retained?.retainedAt || null,
              lastError: null,
            });
            this.broadcastToast("success", `${account.microsoftEmail}：Tavily 单账号业务流完成`);
            return;
          }
          if (retained && isSuccessfulRetainedBrowserSnapshot(retained)) {
            this.finalizeDirectAttempt(attemptId, {
              status: "succeeded",
              stage: "retained",
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: true,
              retainedAt: retained.retainedAt || nowIso(),
              lastError: null,
            });
            this.broadcastToast("info", `${account.microsoftEmail}：${getRetainStateMessage(site)}`);
            return;
          }
          const message =
            error?.error ||
            retained?.error ||
            (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
          this.db.completeAttemptFailure(hiddenJob.id, attemptId, account.id, {
            errorCode: code == null ? "process_exit" : `exit_${code}`,
            errorMessage: message,
          }, null);
          this.db.completeJob(hiddenJob.id, false, message);
          this.updateState(key, {
            status: "failed",
            browserRetained: Boolean(retained),
            retainedAt: retained?.retainedAt || null,
            lastError: message,
          });
          this.broadcastToast("error", `${account.microsoftEmail}：Tavily 单账号业务流失败：${message}`);
        },
      });
    } catch (error) {
      await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
      this.rollbackHiddenLaunchSetup({
        hiddenJobId: hiddenJob.id,
        attemptId,
        accountId: account.id,
        error,
      });
      throw error;
    }
  }

  private async startMicrosoftAccountFlow(
    account: MicrosoftAccountRecord,
    mode: AccountBusinessFlowMode,
    key: string,
  ): Promise<void> {
    const outputDir = path.join(this.repoRoot, "output", "web-runs", "account-business-flow", "microsoft", `${account.id}-${Date.now()}`);
    const retainPath = path.join(outputDir, "retained-browser.json");
    const { hiddenJob, attemptId } = this.createLeasedHiddenJob({
      account,
      site: "microsoft",
      businessSite: "none",
      mode,
      outputDir,
    });
    let portLeases: Awaited<ReturnType<typeof reserveMihomoPortLeases>> | null = null;
    try {
      portLeases = await reserveMihomoPortLeases();
      const runtime = process.versions.bun
        ? { command: process.execPath || "bun", workerArgs: ["run", "src/server/microsoft-account-worker.ts"] }
        : { command: resolveWorkerRuntime().command, workerArgs: ["--import", "tsx", "src/server/microsoft-account-worker.ts"] };
      const selectedProxyNode = resolveReusableAttemptProxyNode(this.db, account.id) || account.browserSession?.proxyNode?.trim() || null;
      if (!selectedProxyNode) {
        throw new Error("当前账号还没有可复用的代理节点，暂时无法打开微软账号页");
      }
      this.db.touchProxyLease(selectedProxyNode);
      await mkdir(outputDir, { recursive: true });
      const args = [...runtime.workerArgs, "--proxy-node", selectedProxyNode];
      const child = spawn(runtime.command, args, {
        ...buildAttemptSpawnOptions(this.repoRoot, {
          env: {
            ...this.buildCommonFlowEnv({
              account,
              mode,
              site: "none",
              outputDir,
              retainPath,
            }),
            MICROSOFT_ACCOUNT_JOB_OUTPUT_DIR: outputDir,
            MIHOMO_SUBSCRIPTION_URL: this.getSettings().subscriptionUrl,
            MIHOMO_GROUP_NAME: this.getSettings().groupName,
            MIHOMO_ROUTE_GROUP_NAME: this.getSettings().routeGroupName,
            MIHOMO_API_PORT: String(portLeases.apiPort.port),
            MIHOMO_MIXED_PORT: String(portLeases.mixedPort.port),
            PROXY_CHECK_URL: this.getSettings().checkUrl,
            PROXY_CHECK_TIMEOUT_MS: String(this.getSettings().timeoutMs),
            PROXY_LATENCY_MAX_MS: String(this.getSettings().maxLatencyMs),
            CHROME_PROFILE_DIR: account.browserSession?.profilePath?.trim()
              ? path.resolve(account.browserSession.profilePath.trim())
              : path.join(outputDir, "chrome-profile"),
            ...(account.browserSession?.profilePath?.trim() ? { CHROME_PROFILE_STRATEGY: "exact" } : {}),
            INSPECT_CHROME_PROFILE_DIR: path.join(outputDir, "chrome-inspect-profile"),
          },
        }),
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin.end();
      child.once("spawn", () => {
        if (!portLeases) return;
        void Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
      });
      this.attachFlowProcess({
        key,
        accountId: account.id,
        site: "none",
        mode,
        outputDir,
        retainPath,
        child,
        jobId: hiddenJob.id,
        attemptId,
        onClose: async (code, signal) => {
          await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
          const result = await readJsonFile<{ ok?: boolean; finalUrl?: string | null }>(path.join(outputDir, "result.json"));
          const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
          const retained = await readJsonFile<RetainedBrowserSnapshot>(retainPath);
          if (code === 0 && signal == null && result?.ok) {
            this.finalizeDirectAttempt(attemptId, {
              status: "succeeded",
              stage: "completed",
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: Boolean(retained),
              retainedAt: retained?.retainedAt || null,
              lastError: null,
            });
            this.broadcastToast("success", `${account.microsoftEmail}：微软账号页已打开`);
            return;
          }
          if (retained && isSuccessfulRetainedBrowserSnapshot(retained)) {
            this.finalizeDirectAttempt(attemptId, {
              status: "succeeded",
              stage: "retained",
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: true,
              retainedAt: retained.retainedAt || nowIso(),
              lastError: null,
            });
            this.broadcastToast("info", `${account.microsoftEmail}：${getRetainStateMessage("none")}`);
            return;
          }
          const message =
            error?.error ||
            retained?.error ||
            (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
          this.db.completeAttemptFailure(hiddenJob.id, attemptId, null, {
            errorCode: code == null ? "process_exit" : `exit_${code}`,
            errorMessage: message,
          }, null);
          this.db.releaseAccountLease(account.id, hiddenJob.id);
          this.db.completeJob(hiddenJob.id, false, message);
          this.updateState(key, {
            status: "failed",
            browserRetained: Boolean(retained),
            retainedAt: retained?.retainedAt || null,
            lastError: message,
          });
          this.broadcastToast("error", `${account.microsoftEmail}：微软账号页打开失败：${message}`);
        },
      });
    } catch (error) {
      await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
      this.rollbackHiddenLaunchSetup({
        hiddenJobId: hiddenJob.id,
        attemptId,
        accountId: account.id,
        error,
      });
      throw error;
    }
  }

  private async createChatGptDraft(): Promise<{ nickname: string; birthDate: string }> {
    try {
      const draft = await buildChatGptDraft({
        apiKey: (process.env.CFMAIL_API_KEY || "").trim(),
        baseUrl: process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test",
        httpJson: this.httpJson,
        rootDomain: String(process.env.CHATGPT_CFMAIL_ROOT_DOMAIN || "").trim() || undefined,
        createPassword: randomPassword,
        createNickname: randomNickname,
        createBirthDate: randomBirthDate,
        nowIso,
      });
      return {
        nickname: draft.nickname,
        birthDate: draft.birthDate,
      };
    } catch {
      return {
        nickname: randomNickname(),
        birthDate: randomBirthDate(),
      };
    }
  }

  private createLeasedHiddenJob(input: {
    account: MicrosoftAccountRecord;
    site: JobSite;
    businessSite: AccountBusinessFlowSite;
    mode: AccountBusinessFlowMode;
    outputDir: string;
  }): { hiddenJob: JobRecord; attemptId: number } {
    const hiddenJob = this.db.createJob({
      site: input.site,
      runMode: normalizeBusinessFlowRunMode(input.mode),
      need: 1,
      parallel: 1,
      maxAttempts: 1,
      payloadJson: buildHiddenJobPayload(input.account.id, input.businessSite, input.mode),
    });
    const leased = this.db.leaseAccountForJob(hiddenJob.id, input.account.id);
    if (!leased) {
      this.db.completeJob(hiddenJob.id, false, "account became unavailable before single-account flow launch");
      throw new Error("当前账号在启动前被其他任务占用，请稍后重试");
    }
    const attempt = this.db.createAttempt(hiddenJob.id, {
      accountId: input.account.id,
      accountEmail: input.account.microsoftEmail,
      outputDir: input.outputDir,
    });
    return { hiddenJob, attemptId: attempt.id };
  }

  private rollbackHiddenLaunchSetup(input: {
    hiddenJobId: number;
    attemptId: number | null;
    accountId: number;
    error: unknown;
  }): void {
    const message = input.error instanceof Error ? input.error.message : String(input.error || "single-account flow setup failed");
    if (input.attemptId != null) {
      this.db.rollbackAttemptBeforeLaunch(input.hiddenJobId, input.attemptId, input.accountId);
    } else {
      this.db.releaseAccountLease(input.accountId, input.hiddenJobId);
    }
    this.db.completeJob(input.hiddenJobId, false, message);
  }

  private finalizeDirectAttempt(
    attemptId: number,
    patch: Partial<
      Pick<
        ReturnType<AppDatabase["getAttempt"]> extends infer T
          ? T extends null
            ? never
            : NonNullable<T>
          : never,
        "status" | "stage" | "completedAt" | "durationMs" | "errorCode" | "errorMessage" | "accountEmail" | "runId" | "proxyNode" | "proxyIp"
      >
    >,
  ): void {
    const currentAttempt = this.db.getAttempt(attemptId);
    if (!currentAttempt) return;
    const now = nowIso();
    const durationMs = Math.max(0, Date.parse(now) - Date.parse(currentAttempt.startedAt));
    this.db.updateAttempt(attemptId, {
      completedAt: now,
      durationMs,
      ...patch,
    });
  }

  private async startChatGptFlow(
    account: MicrosoftAccountRecord,
    mailbox: MicrosoftMailboxRecord,
    mode: AccountBusinessFlowMode,
    key: string,
  ): Promise<void> {
    const outputDir = path.join(this.repoRoot, "output", "web-runs", "account-business-flow", "chatgpt", `${account.id}-${Date.now()}`);
    const retainPath = path.join(outputDir, "retained-browser.json");
    const { hiddenJob, attemptId } = this.createLeasedHiddenJob({
      account,
      site: "chatgpt",
      businessSite: "chatgpt",
      mode,
      outputDir,
    });
    let portLeases: Awaited<ReturnType<typeof reserveMihomoPortLeases>> | null = null;
    try {
      const draft = await this.createChatGptDraft();
      portLeases = await reserveMihomoPortLeases();
      const runtime = resolveWorkerRuntime();
      const selectedProxyNode = resolveReusableAttemptProxyNode(this.db, account.id);
      const args = runtime.command === "bun" ? ["run", "src/server/chatgpt-worker.ts"] : ["--import", "tsx", "src/server/chatgpt-worker.ts"];
      if (selectedProxyNode?.trim()) {
        args.push("--proxy-node", selectedProxyNode.trim());
        this.db.touchProxyLease(selectedProxyNode.trim());
      }
      await mkdir(outputDir, { recursive: true });
      const child = spawn(runtime.command, args, {
        ...buildAttemptSpawnOptions(this.repoRoot, {
          env: {
            ...this.buildCommonFlowEnv({
              account,
              mailbox,
              mode,
              site: "chatgpt",
              outputDir,
              retainPath,
            }),
            CHATGPT_AUTH_PROVIDER: "microsoft",
            CHATGPT_JOB_EMAIL: account.microsoftEmail,
            CHATGPT_JOB_PASSWORD: account.passwordPlaintext || "",
            CHATGPT_JOB_NICKNAME: draft.nickname,
            CHATGPT_JOB_BIRTH_DATE: draft.birthDate,
            CHATGPT_JOB_MAILBOX_ID: String(mailbox.id),
            CHATGPT_JOB_OUTPUT_DIR: outputDir,
            MIHOMO_SUBSCRIPTION_URL: this.getSettings().subscriptionUrl,
            MIHOMO_GROUP_NAME: this.getSettings().groupName,
            MIHOMO_ROUTE_GROUP_NAME: this.getSettings().routeGroupName,
            MIHOMO_API_PORT: String(portLeases.apiPort.port),
            MIHOMO_MIXED_PORT: String(portLeases.mixedPort.port),
            PROXY_CHECK_URL: this.getSettings().checkUrl,
            PROXY_CHECK_TIMEOUT_MS: String(this.getSettings().timeoutMs),
            PROXY_LATENCY_MAX_MS: String(this.getSettings().maxLatencyMs),
            CHROME_PROFILE_DIR: account.browserSession?.profilePath?.trim()
              ? path.resolve(account.browserSession.profilePath.trim())
              : path.join(outputDir, "chrome-profile"),
            ...(account.browserSession?.profilePath?.trim() ? { CHROME_PROFILE_STRATEGY: "exact" } : {}),
            INSPECT_CHROME_PROFILE_DIR: path.join(outputDir, "chrome-inspect-profile"),
          },
        }),
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin.end();
      child.once("spawn", () => {
        if (!portLeases) return;
        void Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
      });
      this.attachFlowProcess({
        key,
        accountId: account.id,
        site: "chatgpt",
        mode,
        outputDir,
        retainPath,
        child,
        jobId: hiddenJob.id,
        attemptId,
        onClose: async (code, signal) => {
          await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
          const result = await readJsonFile<{
            email?: string;
            credentials?: {
              account_id?: string;
              access_token?: string;
              refresh_token?: string;
              id_token?: string;
              expires_at?: string | null;
              token_type?: string | null;
            };
          }>(path.join(outputDir, "result.json"));
          const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
          const retained = await readJsonFile<RetainedBrowserSnapshot>(retainPath);
          const accessToken = String(result?.credentials?.access_token || "").trim();
          const refreshToken = String(result?.credentials?.refresh_token || "").trim();
          const idToken = String(result?.credentials?.id_token || "").trim();
          const accountId = String(result?.credentials?.account_id || "").trim();
          if (code === 0 && signal == null && accessToken && refreshToken && idToken) {
            this.db.completeChatGptAttemptSuccess(hiddenJob.id, attemptId, {
              email: String(result?.email || account.microsoftEmail).trim().toLowerCase(),
              accountId,
              accessToken,
              refreshToken,
              idToken,
              expiresAt: result?.credentials?.expires_at || null,
              credentialJson: buildCodexVibeMonitorCredentialJson({
                email: String(result?.email || account.microsoftEmail).trim().toLowerCase(),
                accountId,
                accessToken,
                refreshToken,
                idToken,
                expiresAt: result?.credentials?.expires_at || null,
                createdAt: nowIso(),
                tokenType: result?.credentials?.token_type || null,
              }),
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: Boolean(retained),
              retainedAt: retained?.retainedAt || null,
              lastError: null,
            });
            this.broadcastToast("success", `${account.microsoftEmail}：ChatGPT 单账号业务流完成`);
            return;
          }
          if (retained && isSuccessfulRetainedBrowserSnapshot(retained)) {
            this.finalizeDirectAttempt(attemptId, {
              status: "succeeded",
              stage: "retained",
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: true,
              retainedAt: retained.retainedAt || nowIso(),
              lastError: null,
            });
            this.broadcastToast("info", `${account.microsoftEmail}：${getRetainStateMessage("chatgpt")}`);
            return;
          }
          const message =
            error?.error ||
            retained?.error ||
            (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
          this.db.completeAttemptFailure(hiddenJob.id, attemptId, null, {
            errorCode: code == null ? "process_exit" : `exit_${code}`,
            errorMessage: message,
          }, null);
          this.db.releaseAccountLease(account.id, hiddenJob.id);
          this.db.completeJob(hiddenJob.id, false, message);
          this.updateState(key, {
            status: "failed",
            browserRetained: Boolean(retained),
            retainedAt: retained?.retainedAt || null,
            lastError: message,
          });
          this.broadcastToast("error", `${account.microsoftEmail}：ChatGPT 单账号业务流失败：${message}`);
        },
      });
    } catch (error) {
      await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
      this.rollbackHiddenLaunchSetup({
        hiddenJobId: hiddenJob.id,
        attemptId,
        accountId: account.id,
        error,
      });
      throw error;
    }
  }

  private async startGrokFlow(
    account: MicrosoftAccountRecord,
    mailbox: MicrosoftMailboxRecord,
    mode: AccountBusinessFlowMode,
    key: string,
  ): Promise<void> {
    const outputDir = path.join(this.repoRoot, "output", "web-runs", "account-business-flow", "grok", `${account.id}-${Date.now()}`);
    const retainPath = path.join(outputDir, "retained-browser.json");
    const { hiddenJob, attemptId } = this.createLeasedHiddenJob({
      account,
      site: "grok",
      businessSite: "grok",
      mode,
      outputDir,
    });
    let portLeases: Awaited<ReturnType<typeof reserveMihomoPortLeases>> | null = null;
    try {
      portLeases = await reserveMihomoPortLeases();
      const runtime = resolveWorkerRuntime();
      const selectedProxyNode = resolveReusableAttemptProxyNode(this.db, account.id);
      const args = runtime.command === "bun" ? ["run", "src/server/grok-worker.ts"] : ["--import", "tsx", "src/server/grok-worker.ts"];
      if (selectedProxyNode?.trim()) {
        args.push("--proxy-node", selectedProxyNode.trim());
        this.db.touchProxyLease(selectedProxyNode.trim());
      }
      await mkdir(outputDir, { recursive: true });
      const child = spawn(runtime.command, args, {
        ...buildAttemptSpawnOptions(this.repoRoot, {
          env: {
            ...this.buildCommonFlowEnv({
              account,
              mailbox,
              mode,
              site: "grok",
              outputDir,
              retainPath,
            }),
            GROK_AUTH_PROVIDER: "microsoft",
            GROK_JOB_OUTPUT_DIR: outputDir,
            GROK_JOB_EMAIL: account.microsoftEmail,
            GROK_JOB_MAILBOX_ID: String(mailbox.id),
            MIHOMO_SUBSCRIPTION_URL: this.getSettings().subscriptionUrl,
            MIHOMO_GROUP_NAME: this.getSettings().groupName,
            MIHOMO_ROUTE_GROUP_NAME: this.getSettings().routeGroupName,
            MIHOMO_API_PORT: String(portLeases.apiPort.port),
            MIHOMO_MIXED_PORT: String(portLeases.mixedPort.port),
            PROXY_CHECK_URL: this.getSettings().checkUrl,
            PROXY_CHECK_TIMEOUT_MS: String(this.getSettings().timeoutMs),
            PROXY_LATENCY_MAX_MS: String(this.getSettings().maxLatencyMs),
            CHROME_PROFILE_DIR: account.browserSession?.profilePath?.trim()
              ? path.resolve(account.browserSession.profilePath.trim())
              : path.join(outputDir, "chrome-profile"),
            ...(account.browserSession?.profilePath?.trim() ? { CHROME_PROFILE_STRATEGY: "exact" } : {}),
            INSPECT_CHROME_PROFILE_DIR: path.join(outputDir, "chrome-inspect-profile"),
          },
        }),
        stdio: ["pipe", "pipe", "pipe"],
      });
      child.stdin.end();
      child.once("spawn", () => {
        if (!portLeases) return;
        void Promise.all([portLeases.apiPort.releaseListener(), portLeases.mixedPort.releaseListener()]);
      });
      this.attachFlowProcess({
        key,
        accountId: account.id,
        site: "grok",
        mode,
        outputDir,
        retainPath,
        child,
        jobId: hiddenJob.id,
        attemptId,
        onClose: async (code, signal) => {
          await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
          const result = await readJsonFile<{
            email?: string;
            password?: string;
            sso?: string;
            ssoRw?: string | null;
            cfClearance?: string | null;
            checkoutUrl?: string | null;
            birthDate?: string | null;
            proxy?: { nodeName?: string | null; ip?: string | null };
            runId?: string | null;
          }>(path.join(outputDir, "result.json"));
          const error = await readJsonFile<{ error?: string }>(path.join(outputDir, "error.json"));
          const retained = await readJsonFile<RetainedBrowserSnapshot>(retainPath);
          const email = String(result?.email || "").trim().toLowerCase();
          const password = String(result?.password || "").trim();
          const sso = String(result?.sso || "").trim();
          if (code === 0 && signal == null && email && password && sso) {
            this.db.completeGrokAttemptSuccess(hiddenJob.id, attemptId, {
              email,
              password,
              sso,
              ssoRw: result?.ssoRw || null,
              cfClearance: result?.cfClearance || null,
              checkoutUrl: result?.checkoutUrl || null,
              birthDate: result?.birthDate || null,
              extractedIp: result?.proxy?.ip || null,
              runId: result?.runId || null,
              proxyNode: result?.proxy?.nodeName || null,
              proxyIp: result?.proxy?.ip || null,
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: Boolean(retained),
              retainedAt: retained?.retainedAt || null,
              lastError: null,
            });
            this.broadcastToast("success", `${account.microsoftEmail}：Grok 单账号业务流完成`);
            return;
          }
          if (retained && isSuccessfulRetainedBrowserSnapshot(retained)) {
            this.finalizeDirectAttempt(attemptId, {
              status: "succeeded",
              stage: "retained",
            });
            this.db.releaseAccountLease(account.id, hiddenJob.id);
            this.db.completeJob(hiddenJob.id, true);
            this.updateState(key, {
              status: "succeeded",
              browserRetained: true,
              retainedAt: retained.retainedAt || nowIso(),
              lastError: null,
            });
            this.broadcastToast("info", `${account.microsoftEmail}：${getRetainStateMessage("grok")}`);
            return;
          }
          const message =
            error?.error ||
            retained?.error ||
            (signal ? `terminated by ${signal}` : code == null ? "process exited without code" : `process exited with code ${code}`);
          this.db.completeAttemptFailure(hiddenJob.id, attemptId, null, {
            errorCode: code == null ? "process_exit" : `exit_${code}`,
            errorMessage: message,
          }, null);
          this.db.releaseAccountLease(account.id, hiddenJob.id);
          this.db.completeJob(hiddenJob.id, false, message);
          this.updateState(key, {
            status: "failed",
            browserRetained: Boolean(retained),
            retainedAt: retained?.retainedAt || null,
            lastError: message,
          });
          this.broadcastToast("error", `${account.microsoftEmail}：Grok 单账号业务流失败：${message}`);
        },
      });
    } catch (error) {
      await Promise.all([portLeases?.apiPort.release(), portLeases?.mixedPort.release()]);
      this.rollbackHiddenLaunchSetup({
        hiddenJobId: hiddenJob.id,
        attemptId,
        accountId: account.id,
        error,
      });
      throw error;
    }
  }

  private attachFlowProcess(input: {
    key: string;
    accountId: number;
    site: AccountBusinessFlowSite;
    mode: AccountBusinessFlowMode;
    outputDir: string;
    retainPath: string;
    child: ChildProcessWithoutNullStreams;
    jobId: number | null;
    attemptId: number | null;
    onClose: (code: number | null, signal: NodeJS.Signals | null) => Promise<void>;
  }): void {
    let stdout = "";
    let stderr = "";
    const active: ActiveBusinessFlow = {
      key: input.key,
      accountId: input.accountId,
      site: input.site,
      mode: input.mode,
      outputDir: input.outputDir,
      retainPath: input.retainPath,
      child: input.child,
      retainPollTimer: null,
      jobId: input.jobId,
      attemptId: input.attemptId,
      retainedAt: null,
      browserRetained: false,
    };
    this.active.set(input.key, active);
    this.updateState(input.key, {
      status: "running",
      browserRetained: false,
      lastError: null,
    });

    const pollRetained = async () => {
      if (active.browserRetained) return;
      const retained = await readJsonFile<RetainedBrowserSnapshot>(input.retainPath);
      if (!retained) return;
      active.browserRetained = true;
      active.retainedAt = retained.retainedAt || nowIso();
      this.updateState(input.key, {
        status: retained.success === false ? "failed" : "succeeded",
        browserRetained: true,
        retainedAt: active.retainedAt,
        lastError: retained.success === false ? retained.error || "浏览器已保留，请手动接管当前页面。" : null,
      });
      this.broadcastToast(
        retained.success === false ? "warning" : "info",
        retained.success === false
          ? `${input.accountId}：浏览器已保留，请手动接管 ${getBusinessFlowDisplayLabel(input.site)}`
          : `${input.accountId}：${getRetainStateMessage(input.site)}`,
      );
    };
    active.retainPollTimer = setInterval(() => {
      void pollRetained();
    }, 1500);

    input.child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      void writeWorkerLog(input.outputDir, stdout, stderr);
    });
    input.child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      void writeWorkerLog(input.outputDir, stdout, stderr);
    });
    input.child.once("error", async (error) => {
      this.updateState(input.key, {
        status: "failed",
        browserRetained: false,
        lastError: error.message || "failed to start business-flow worker",
      });
      if (this.active.get(input.key) === active) {
        this.active.delete(input.key);
      }
    });
    input.child.once("close", async (code, signal) => {
      if (active.retainPollTimer) {
        clearInterval(active.retainPollTimer);
      }
      await writeWorkerLog(input.outputDir, stdout, stderr);
      try {
        await input.onClose(code, signal);
      } finally {
        if (this.active.get(input.key) === active) {
          this.active.delete(input.key);
        }
      }
    });
  }

  private async stopActiveFlow(active: ActiveBusinessFlow, reason: string): Promise<void> {
    if (active.retainPollTimer) {
      clearInterval(active.retainPollTimer);
      active.retainPollTimer = null;
    }
    signalChildProcess(active.child, "SIGTERM");
    const closedAfterTerm = await waitForChildClose(active.child, 5_000).catch(() => false);
    if (!closedAfterTerm) {
      signalChildProcess(active.child, "SIGKILL");
      await waitForChildClose(active.child, 5_000).catch(() => false);
    }
    this.updateState(active.key, {
      browserRetained: false,
      lastError: reason,
      updatedAt: nowIso(),
    });
  }
}
