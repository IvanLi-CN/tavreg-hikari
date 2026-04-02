import {
  fetchSingleExtractedAccount,
  getAccountExtractorProviderLabel,
  getConfiguredExtractorKey,
  keyConfiguredForProvider,
  type AccountExtractorFailureCode,
} from "./account-extractor.js";
import { isLockedAccountRecord } from "./account-session-bootstrap.js";
import type { ServerEvent } from "./scheduler.js";
import type {
  AccountExtractorAccountType,
  AccountExtractorProvider,
  AppDatabase,
  AppSettings,
  MicrosoftAccountRecord,
} from "../storage/app-db.js";

const REQUEST_INTERVAL_MS = 500;
const REQUEST_WORKERS_PER_PROVIDER = 3;
const REQUEST_TIMEOUT_MS = 5000;
const SNAPSHOT_HEARTBEAT_MS = 1000;

export type AccountExtractorRuntimeStatus = "idle" | "running" | "stopping" | "stopped" | "succeeded" | "failed";

export interface AccountExtractorRuntimeSnapshot {
  status: AccountExtractorRuntimeStatus;
  enabledSources: AccountExtractorProvider[];
  accountType: AccountExtractorAccountType;
  requestedUsableCount: number;
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
  errorMessage: string | null;
  lastBatchId: number | null;
}

export interface AccountExtractorRunInput {
  sources: AccountExtractorProvider[];
  quantity: number;
  maxWaitSec: number;
  accountType?: AccountExtractorAccountType;
}

type ExtractBatchStatus = "accepted" | "rejected" | "invalid_key" | "insufficient_stock" | "parse_failed" | "error";

type RuntimeAccountRecord = Pick<
  MicrosoftAccountRecord,
  "id" | "passwordPlaintext" | "disabledAt" | "skipReason" | "lastErrorCode" | "hasApiKey" | "leaseJobId" | "browserSession"
>;

interface RuntimeState {
  runId: number;
  status: Exclude<AccountExtractorRuntimeStatus, "idle">;
  enabledSources: AccountExtractorProvider[];
  accountType: AccountExtractorAccountType;
  requestedUsableCount: number;
  acceptedCount: number;
  rawAttemptCount: number;
  attemptBudget: number;
  inFlightCount: number;
  remainingWaitMs: number;
  maxWaitMs: number;
  startedAt: string;
  lastProvider: AccountExtractorProvider | null;
  lastMessage: string | null;
  updatedAt: string;
  errorMessage: string | null;
  lastBatchId: number | null;
  nextProviderIndex: number;
  providerNextAttemptAtMs: Record<AccountExtractorProvider, number>;
  providerInFlightCount: Record<AccountExtractorProvider, number>;
  lastBudgetTickMs: number;
  lastPublishedAtMs: number;
  requestControllers: Map<string, AbortController>;
}

export function createIdleAccountExtractorRuntimeSnapshot(): AccountExtractorRuntimeSnapshot {
  return {
    status: "idle",
    enabledSources: [],
    accountType: "outlook",
    requestedUsableCount: 0,
    acceptedCount: 0,
    rawAttemptCount: 0,
    attemptBudget: 0,
    inFlightCount: 0,
    remainingWaitSec: 0,
    maxWaitSec: 0,
    startedAt: null,
    lastProvider: null,
    lastMessage: null,
    updatedAt: null,
    errorMessage: null,
    lastBatchId: null,
  };
}

export function normalizeExtractorSources(sources: AccountExtractorProvider[] | undefined): AccountExtractorProvider[] {
  return Array.from(
    new Set(
      (sources || []).filter(
        (item): item is AccountExtractorProvider =>
          item === "zhanghaoya" || item === "shanyouxiang" || item === "shankeyun" || item === "hotmail666",
      ),
    ),
  );
}

function nowIso(): string {
  return new Date().toISOString();
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isAbortError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  const name = error instanceof Error ? error.name : "";
  return name === "AbortError" || /abort/i.test(message);
}

function isManualStopReason(reason: unknown): boolean {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  return /manual_stop/i.test(message);
}

function formatManualStopMessage(acceptedCount: number): string {
  return acceptedCount > 0 ? `提号已取消，本轮已接受 ${acceptedCount} 个账号` : "提号已取消";
}

function formatManualStopDrainMessage(inFlightCount: number): string {
  return `提号取消中，等待 ${inFlightCount} 个在途请求收尾`;
}

function providerLabel(provider: AccountExtractorProvider): string {
  return getAccountExtractorProviderLabel(provider);
}

function maskConfiguredKey(value: string | null | undefined): string | null {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  if (normalized.length <= 8) {
    return `${"*".repeat(Math.max(0, normalized.length - 2))}${normalized.slice(-2)}`;
  }
  return `${normalized.slice(0, 4)}${"*".repeat(Math.max(4, normalized.length - 8))}${normalized.slice(-4)}`;
}

function mapFailureCodeToBatchStatus(code: AccountExtractorFailureCode | "manual_stop" | null): ExtractBatchStatus {
  if (code === "invalid_key") return "invalid_key";
  if (code === "insufficient_stock") return "insufficient_stock";
  if (code === "parse_failed") return "parse_failed";
  return code === "manual_stop" ? "rejected" : "error";
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

export function decideManualExtractorAcceptance(input: {
  existingAccount: RuntimeAccountRecord | null;
  candidatePassword: string;
}): { accept: boolean; rejectReason: string | null; shouldImport: boolean; forceBootstrap: boolean } {
  const existing = input.existingAccount;
  if (!existing) {
    return { accept: true, rejectReason: null, shouldImport: true, forceBootstrap: false };
  }
  if (existing.disabledAt) {
    return { accept: false, rejectReason: "disabled", shouldImport: false, forceBootstrap: false };
  }
  if (existing.hasApiKey || existing.skipReason === "has_api_key") {
    return { accept: false, rejectReason: "has_api_key", shouldImport: false, forceBootstrap: false };
  }
  if (isLockedAccountRecord(existing)) {
    return { accept: false, rejectReason: "microsoft_account_locked", shouldImport: false, forceBootstrap: false };
  }
  if (existing.leaseJobId != null) {
    return { accept: false, rejectReason: "leased", shouldImport: false, forceBootstrap: false };
  }

  const priorPassword = String(existing.passwordPlaintext || "").trim();
  const nextPassword = String(input.candidatePassword || "").trim();
  const passwordChanged = priorPassword !== nextPassword;
  if (passwordChanged) {
    return { accept: true, rejectReason: null, shouldImport: true, forceBootstrap: true };
  }

  const priorSessionStatus = existing.browserSession?.status || null;
  if (priorSessionStatus === "failed" || priorSessionStatus === "blocked") {
    return { accept: true, rejectReason: null, shouldImport: false, forceBootstrap: true };
  }
  if (priorSessionStatus === "pending" || priorSessionStatus === "bootstrapping") {
    return { accept: false, rejectReason: "bootstrap_in_progress", shouldImport: false, forceBootstrap: false };
  }
  if (priorSessionStatus === "ready") {
    return { accept: false, rejectReason: "session_ready", shouldImport: false, forceBootstrap: false };
  }
  return { accept: true, rejectReason: null, shouldImport: false, forceBootstrap: false };
}

export class AccountExtractorRuntime {
  private state: RuntimeState | null = null;
  private nextRunId = 1;

  constructor(
    private readonly db: AppDatabase,
    private readonly readSettings: () => AppSettings,
    private readonly publish: (event: ServerEvent) => void,
    private readonly queueBootstrap: (accountId: number, options?: { force?: boolean }) => boolean,
  ) {}

  private describeBootstrapQueueRejectReason(account: RuntimeAccountRecord | null): string {
    if (!account) return "import_missing";
    if (account.disabledAt) return "disabled";
    if (account.hasApiKey || account.skipReason === "has_api_key") return "has_api_key";
    if (isLockedAccountRecord(account)) return "microsoft_account_locked";
    if (account.leaseJobId != null) return "leased";
    if (account.browserSession?.status === "ready") return "session_ready";
    return "bootstrap_queue_rejected";
  }

  getSnapshot(): AccountExtractorRuntimeSnapshot {
    const state = this.state;
    if (!state) {
      return createIdleAccountExtractorRuntimeSnapshot();
    }
    return {
      status: state.status,
      enabledSources: [...state.enabledSources],
      accountType: state.accountType,
      requestedUsableCount: state.requestedUsableCount,
      acceptedCount: state.acceptedCount,
      rawAttemptCount: state.rawAttemptCount,
      attemptBudget: state.attemptBudget,
      inFlightCount: state.inFlightCount,
      remainingWaitSec: Math.max(0, Math.ceil(state.remainingWaitMs / 1000)),
      maxWaitSec: Math.max(0, Math.ceil(state.maxWaitMs / 1000)),
      startedAt: state.startedAt,
      lastProvider: state.lastProvider,
      lastMessage: state.lastMessage,
      updatedAt: state.updatedAt,
      errorMessage: state.errorMessage,
      lastBatchId: state.lastBatchId,
    };
  }

  async start(input: AccountExtractorRunInput): Promise<AccountExtractorRuntimeSnapshot> {
    if (this.state?.status === "running" || this.state?.status === "stopping") {
      throw new Error("提号器正在运行，请等待当前轮次结束");
    }
    const settings = this.readSettings();
    if (
      !settings.microsoftGraphClientId.trim()
      || !settings.microsoftGraphClientSecret.trim()
      || !settings.microsoftGraphRedirectUri.trim()
    ) {
      throw new Error("请先配置完整的 Microsoft Graph 回调设置，再启动提号器");
    }

    const enabledSources = normalizeExtractorSources(input.sources);
    if (enabledSources.length === 0) {
      throw new Error("请至少选择一个号源");
    }

    const quantity = Math.max(1, Math.trunc(input.quantity || 0));
    const maxWaitSec = Math.max(1, Math.trunc(input.maxWaitSec || 0));
    const runtimeConfig = {
      zhanghaoyaKey: settings.extractorZhanghaoyaKey,
      shanyouxiangKey: settings.extractorShanyouxiangKey,
      shankeyunKey: settings.extractorShankeyunKey,
      hotmail666Key: settings.extractorHotmail666Key,
      timeoutMs: REQUEST_TIMEOUT_MS,
    };
    const missingProviders = enabledSources.filter((provider) => !keyConfiguredForProvider(provider, runtimeConfig));
    if (missingProviders.length > 0) {
      throw new Error(`提取器 KEY 未配置：${missingProviders.map(providerLabel).join("、")}`);
    }

    const startedAt = nowIso();
    const nowMs = Date.now();
    this.state = {
      runId: this.nextRunId++,
      status: "running",
      enabledSources,
      accountType: input.accountType || "outlook",
      requestedUsableCount: quantity,
      acceptedCount: 0,
      rawAttemptCount: 0,
      attemptBudget: 0,
      inFlightCount: 0,
      remainingWaitMs: maxWaitSec * 1000,
      maxWaitMs: maxWaitSec * 1000,
      startedAt,
      lastProvider: null,
      lastMessage: `准备提取 ${quantity} 个可用账号`,
      updatedAt: startedAt,
      errorMessage: null,
      lastBatchId: null,
      nextProviderIndex: 0,
      providerNextAttemptAtMs: createProviderAttemptClock(),
      providerInFlightCount: createProviderInFlightCounter(),
      lastBudgetTickMs: nowMs,
      lastPublishedAtMs: 0,
      requestControllers: new Map<string, AbortController>(),
    };
    this.publishSnapshot();
    this.publish({
      type: "toast",
      payload: {
        level: "info",
        message: `提号器已启动：${enabledSources.map(providerLabel).join("、")} · 目标 ${quantity}`,
      },
      timestamp: nowIso(),
    });
    void this.runCurrentRound(this.state.runId);
    return this.getSnapshot();
  }

  async stop(): Promise<AccountExtractorRuntimeSnapshot> {
    const state = this.state;
    if (!state) {
      throw new Error("提号器当前未在运行");
    }
    if (state.status === "stopped") {
      return this.getSnapshot();
    }
    if (state.status !== "running" && state.status !== "stopping") {
      throw new Error("提号器当前未在运行");
    }
    if (state.status === "running") {
      for (const controller of state.requestControllers.values()) {
        controller.abort(new Error("manual_stop"));
      }
      state.status = state.inFlightCount > 0 ? "stopping" : "stopped";
      state.errorMessage = null;
      state.lastMessage =
        state.inFlightCount > 0 ? formatManualStopDrainMessage(state.inFlightCount) : formatManualStopMessage(state.acceptedCount);
      state.updatedAt = nowIso();
      this.publishRunOutcome("warning", "提号器已收到取消指令");
      this.publishSnapshot();
    }
    return this.getSnapshot();
  }

  private publishSnapshot(): void {
    const state = this.state;
    if (state) {
      state.lastPublishedAtMs = Date.now();
    }
    this.publish({
      type: "extractor.updated",
      payload: { runtime: this.getSnapshot() },
      timestamp: nowIso(),
    });
  }

  private publishRunOutcome(level: "info" | "success" | "warning", message: string): void {
    this.publish({
      type: "toast",
      payload: { level, message },
      timestamp: nowIso(),
    });
  }

  private updateBudget(state: RuntimeState): void {
    const nowMs = Date.now();
    state.remainingWaitMs = Math.max(0, state.remainingWaitMs - (nowMs - state.lastBudgetTickMs));
    state.lastBudgetTickMs = nowMs;
    state.updatedAt = nowIso();
  }

  private pickDueProvider(state: RuntimeState, nowMs: number): AccountExtractorProvider | null {
    if (state.enabledSources.length === 0) return null;
    for (let offset = 0; offset < state.enabledSources.length; offset += 1) {
      const index = (state.nextProviderIndex + offset) % state.enabledSources.length;
      const provider = state.enabledSources[index];
      if (!provider) continue;
      if (
        state.providerNextAttemptAtMs[provider] <= nowMs
        && state.providerInFlightCount[provider] < REQUEST_WORKERS_PER_PROVIDER
      ) {
        state.nextProviderIndex = (index + 1) % state.enabledSources.length;
        return provider;
      }
    }
    return null;
  }

  private async runCurrentRound(runId: number): Promise<void> {
    while (this.state && this.state.runId === runId && (this.state.status === "running" || this.state.status === "stopping")) {
      const state = this.state;
      if (state.status === "stopping") {
        if (state.inFlightCount === 0) {
          state.status = "stopped";
          state.errorMessage = null;
          state.lastMessage = formatManualStopMessage(state.acceptedCount);
          state.updatedAt = nowIso();
          this.publishSnapshot();
          return;
        }
        if (Date.now() - state.lastPublishedAtMs >= SNAPSHOT_HEARTBEAT_MS) {
          state.lastMessage = formatManualStopDrainMessage(state.inFlightCount);
          state.updatedAt = nowIso();
          this.publishSnapshot();
        }
        await delay(100);
        continue;
      }
      this.updateBudget(state);
      this.maybeDispatchRequests(state);

      const targetReached = state.acceptedCount >= state.requestedUsableCount;
      const waitExhausted = state.remainingWaitMs <= 0;
      const rawBudgetExhausted = state.attemptBudget > 0 && state.rawAttemptCount >= state.attemptBudget;

      if (state.inFlightCount === 0 && (targetReached || waitExhausted || rawBudgetExhausted)) {
        if (targetReached || state.acceptedCount > 0) {
          state.status = "succeeded";
          state.errorMessage = null;
          state.lastMessage = targetReached
            ? `已接受 ${state.acceptedCount} / ${state.requestedUsableCount} 个账号`
            : `等待结束，本轮接受 ${state.acceptedCount} 个账号`;
          state.updatedAt = nowIso();
          this.publishRunOutcome("success", state.lastMessage);
        } else {
          state.status = "failed";
          state.errorMessage = `提号等待超时（${Math.ceil(state.maxWaitMs / 1000)} 秒）`;
          state.lastMessage = state.errorMessage;
          state.updatedAt = nowIso();
          this.publishRunOutcome("warning", state.errorMessage);
        }
        this.publishSnapshot();
        return;
      }

      if (state.inFlightCount > 0 && (targetReached || waitExhausted || rawBudgetExhausted)) {
        state.lastMessage = targetReached
          ? `目标达成，等待 ${state.inFlightCount} 个在途请求收尾`
          : waitExhausted || rawBudgetExhausted
            ? `等待时间已到，等待 ${state.inFlightCount} 个在途请求收尾`
            : `等待 ${state.inFlightCount} 个在途请求收尾`;
        state.updatedAt = nowIso();
        this.publishSnapshot();
      } else if (Date.now() - state.lastPublishedAtMs >= SNAPSHOT_HEARTBEAT_MS) {
        this.publishSnapshot();
      }

      await delay(100);
    }
  }

  private maybeDispatchRequests(state: RuntimeState): void {
    while (
      state.status === "running"
      && state.remainingWaitMs > 0
      && state.acceptedCount < state.requestedUsableCount
      && (state.attemptBudget <= 0 || state.rawAttemptCount < state.attemptBudget)
    ) {
      const nowMs = Date.now();
      const provider = this.pickDueProvider(state, nowMs);
      if (!provider) {
        return;
      }
      const dispatchStartedAt = nowIso();
      const requestId = `${state.runId}:${provider}:${state.rawAttemptCount + 1}:${nowMs}`;
      state.rawAttemptCount += 1;
      state.inFlightCount += 1;
      state.providerInFlightCount[provider] += 1;
      state.lastProvider = provider;
      state.lastMessage = `${providerLabel(provider)} 请求已发出`;
      state.providerNextAttemptAtMs[provider] = nowMs + REQUEST_INTERVAL_MS;
      state.updatedAt = dispatchStartedAt;
      this.publishSnapshot();
      void this.launchRequest(state.runId, provider, requestId, dispatchStartedAt);
    }
  }

  private async launchRequest(
    runId: number,
    provider: AccountExtractorProvider,
    requestId: string,
    dispatchStartedAt: string,
  ): Promise<void> {
    const state = this.state;
    if (!state || state.runId !== runId) return;
    const settings = this.readSettings();
    const runtimeConfig = {
      zhanghaoyaKey: settings.extractorZhanghaoyaKey,
      shanyouxiangKey: settings.extractorShanyouxiangKey,
      shankeyunKey: settings.extractorShankeyunKey,
      hotmail666Key: settings.extractorHotmail666Key,
      timeoutMs: REQUEST_TIMEOUT_MS,
    };
    const controller = new AbortController();
    state.requestControllers.set(requestId, controller);

    try {
      const result = await fetchSingleExtractedAccount({
        provider,
        accountType: state.accountType,
        config: runtimeConfig,
        signal: controller.signal,
      });
      this.finishRequest({
        runId,
        provider,
        requestId,
        dispatchStartedAt,
        result,
        rawResponse: result.rawResponse,
        maskedKey: result.maskedKey,
        errorMessage: result.message,
        failureCode: result.failureCode,
      });
    } catch (error) {
      const failureCode =
        controller.signal.aborted && isManualStopReason(controller.signal.reason) ? "manual_stop" : "upstream_error";
      const errorMessage =
        controller.signal.aborted && isManualStopReason(controller.signal.reason)
          ? "提号已取消"
          : controller.signal.aborted || isAbortError(error)
            ? controller.signal.reason instanceof Error
              ? controller.signal.reason.message
              : String(controller.signal.reason || "request aborted")
            : error instanceof Error
              ? error.message
              : String(error);
      this.finishRequest({
        runId,
        provider,
        requestId,
        dispatchStartedAt,
        result: null,
        rawResponse: null,
        maskedKey: maskConfiguredKey(getConfiguredExtractorKey(provider, runtimeConfig)),
        errorMessage,
        failureCode,
      });
    }
  }

  private finishRequest(input: {
    runId: number;
    provider: AccountExtractorProvider;
    requestId: string;
    dispatchStartedAt: string;
    result: Awaited<ReturnType<typeof fetchSingleExtractedAccount>> | null;
    rawResponse: string | null;
    maskedKey: string | null;
    errorMessage: string | null;
    failureCode: AccountExtractorFailureCode | "manual_stop" | null;
  }): void {
    const state = this.state;
    if (!state || state.runId !== input.runId) {
      return;
    }
    state.requestControllers.delete(input.requestId);
    state.inFlightCount = Math.max(0, state.inFlightCount - 1);
    state.providerInFlightCount[input.provider] = Math.max(0, state.providerInFlightCount[input.provider] - 1);

    let acceptedInBatch = 0;
    let batchStatus: ExtractBatchStatus = input.result ? "rejected" : mapFailureCodeToBatchStatus(input.failureCode);
    let batchErrorMessage = input.errorMessage;
    const batch = this.db.createAccountExtractBatch({
      jobId: null,
      provider: input.provider,
      accountType: state.accountType,
      requestedUsableCount: state.requestedUsableCount,
      attemptBudget: state.attemptBudget,
      acceptedCount: 0,
      status: batchStatus,
      errorMessage: batchErrorMessage,
      rawResponse: input.rawResponse,
      maskedKey: input.maskedKey,
      startedAt: input.dispatchStartedAt,
      completedAt: null,
    });
    state.lastBatchId = batch.id;

    if (input.result) {
      let acceptedRequestCandidate = false;
      for (const candidate of input.result.candidates) {
        if (candidate.parseStatus !== "parsed" || !candidate.email || !candidate.password) {
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: input.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: candidate.parseStatus,
            acceptStatus: "rejected",
            rejectReason: "parse_failed",
          });
          batchErrorMessage = batchErrorMessage || "响应中没有可解析的账号";
          continue;
        }
        if (acceptedRequestCandidate) {
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: input.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: "parsed",
            acceptStatus: "rejected",
            rejectReason: "request_returned_multiple_accounts",
          });
          batchErrorMessage = batchErrorMessage || "单次请求返回了多个账号";
          continue;
        }
        if (state.acceptedCount + acceptedInBatch >= state.requestedUsableCount) {
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: input.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: "parsed",
            acceptStatus: "rejected",
            rejectReason: "round_target_reached",
          });
          batchErrorMessage = batchErrorMessage || "本轮目标已达成";
          continue;
        }

        const existingAccount = this.db.getAccountsByEmails([candidate.email])[0] || null;
        const decision = decideManualExtractorAcceptance({
          existingAccount,
          candidatePassword: candidate.password,
        });
        if (!decision.accept) {
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: input.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: "parsed",
            acceptStatus: "rejected",
            rejectReason: decision.rejectReason,
            importedAccountId: existingAccount?.id ?? null,
          });
          batchErrorMessage = batchErrorMessage || decision.rejectReason;
          continue;
        }

        let importedAccount = existingAccount;
        if (decision.shouldImport) {
          this.db.importAccounts(
            [{ email: candidate.email, password: candidate.password }],
            {
              source: "extractor",
              accountSource: input.provider,
              rawPayloadByEmail: { [candidate.email]: candidate.rawPayload },
            },
          );
          importedAccount = this.db.getAccountsByEmails([candidate.email])[0] || null;
        }
        if (!importedAccount) {
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: input.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: "parsed",
            acceptStatus: "rejected",
            rejectReason: "import_missing",
          });
          batchErrorMessage = batchErrorMessage || "import_missing";
          continue;
        }

        const bootstrapQueued = this.queueBootstrap(
          importedAccount.id,
          decision.forceBootstrap ? { force: true } : undefined,
        );
        const latestImportedAccount = this.db.getAccount(importedAccount.id) || importedAccount;
        const bootstrapPending =
          latestImportedAccount.browserSession?.status === "pending"
          || latestImportedAccount.browserSession?.status === "bootstrapping";
        if (!bootstrapQueued && !bootstrapPending) {
          this.db.createAccountExtractItem({
            batchId: batch.id,
            provider: input.provider,
            rawPayload: candidate.rawPayload,
            email: candidate.email,
            password: candidate.password,
            parseStatus: "parsed",
            acceptStatus: "rejected",
            rejectReason: this.describeBootstrapQueueRejectReason(latestImportedAccount),
            importedAccountId: latestImportedAccount.id,
          });
          batchErrorMessage = batchErrorMessage || "bootstrap_queue_rejected";
          continue;
        }

        acceptedRequestCandidate = true;
        acceptedInBatch = 1;
        this.db.createAccountExtractItem({
          batchId: batch.id,
          provider: input.provider,
          rawPayload: candidate.rawPayload,
          email: candidate.email,
          password: candidate.password,
          parseStatus: "parsed",
          acceptStatus: "accepted",
          rejectReason: null,
          importedAccountId: latestImportedAccount.id,
        });
        this.publish({
          type: "account.updated",
          payload: { affectedIds: [latestImportedAccount.id], action: "extractor_import" },
          timestamp: nowIso(),
        });
      }

      batchStatus =
        acceptedInBatch > 0 ? "accepted" : input.result.ok ? "rejected" : mapFailureCodeToBatchStatus(input.result.failureCode);
      batchErrorMessage = acceptedInBatch > 0 ? null : batchErrorMessage || input.result.message || "当前批次没有导入可用账号";
    }

    this.db.updateAccountExtractBatch(batch.id, {
      acceptedCount: acceptedInBatch,
      status: batchStatus,
      errorMessage: batchErrorMessage,
      rawResponse: input.rawResponse,
      maskedKey: input.maskedKey,
      completedAt: nowIso(),
    });

    state.acceptedCount += acceptedInBatch;
    state.lastProvider = input.provider;
    if (state.status === "stopping" || state.status === "stopped") {
      const stopSettled = state.inFlightCount === 0;
      state.status = stopSettled ? "stopped" : "stopping";
      state.lastMessage = stopSettled
        ? formatManualStopMessage(state.acceptedCount)
        : formatManualStopDrainMessage(state.inFlightCount);
      state.errorMessage = null;
      state.updatedAt = nowIso();
      this.publishSnapshot();
      return;
    }
    state.lastMessage =
      acceptedInBatch > 0
        ? `${providerLabel(input.provider)} 接受了 ${acceptedInBatch} 个账号`
        : batchErrorMessage || `${providerLabel(input.provider)} 没有可接受账号`;
    state.errorMessage = acceptedInBatch > 0 ? null : batchErrorMessage;
    state.updatedAt = nowIso();
    if (acceptedInBatch > 0) {
      this.publishRunOutcome("success", state.lastMessage);
    }
    this.publishSnapshot();
  }
}
