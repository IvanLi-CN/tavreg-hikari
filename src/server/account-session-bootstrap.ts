import type { MicrosoftAccountRecord } from "../storage/app-db.js";

export const DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY = 3;
export const MAX_MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY = 10;
export const DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_WORKER_TIMEOUT_MS = 5 * 60_000;
export const DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_KILL_GRACE_MS = 10_000;
export const DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_LOGIN_MODE = "microsoft_graph";

export type AccountBatchBootstrapMode = "pending_only" | "force";
export type MicrosoftAccountBootstrapLoginMode = "microsoft_graph" | "tavily_home";
export type AccountSessionRebootstrapRequest = {
  force: boolean;
  proxyNode?: string | null;
};
export type AccountBatchBootstrapPreviewDecision =
  | "queue"
  | "blocked"
  | "already_bootstrapped"
  | "bootstrapping"
  | "missing";

type BootstrapQueueAccount = Pick<
  MicrosoftAccountRecord,
  "leaseJobId" | "disabledAt" | "skipReason" | "lastErrorCode" | "hasApiKey" | "mailboxStatus" | "browserSession"
>;

export function isLockedAccountRecord(
  account: Pick<MicrosoftAccountRecord, "skipReason" | "lastErrorCode" | "disabledAt"> | null | undefined,
): boolean {
  return (
    String(account?.skipReason || "").trim() === "microsoft_account_locked"
    || /^microsoft_account_locked/i.test(String(account?.lastErrorCode || "").trim())
  );
}

export function normalizeAccountBatchBootstrapMode(
  value: unknown,
  fallback: AccountBatchBootstrapMode = "pending_only",
): AccountBatchBootstrapMode {
  return value === "force" ? "force" : value === "pending_only" ? "pending_only" : fallback;
}

export function normalizeAccountSessionRebootstrapRequest(value: unknown): AccountSessionRebootstrapRequest {
  const body =
    value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const hasProxyNode = Object.prototype.hasOwnProperty.call(body, "proxyNode");
  const rawProxyNode = hasProxyNode ? body.proxyNode : undefined;
  const proxyNode =
    rawProxyNode === undefined
      ? undefined
      : typeof rawProxyNode === "string"
        ? rawProxyNode.trim() || null
        : rawProxyNode == null
          ? null
          : String(rawProxyNode).trim() || null;
  return proxyNode === undefined
    ? {
        force: body.force !== false,
      }
    : {
        force: body.force !== false,
        proxyNode,
      };
}

export function resolveRequestedSessionProxyNode(
  requestedProxyNode: string | null | undefined,
  availableNodeNames: Iterable<string>,
): { proxyNode: string | null | undefined; error: string | null } {
  if (requestedProxyNode === undefined) {
    return { proxyNode: undefined, error: null };
  }
  const normalized = String(requestedProxyNode || "").trim();
  if (!normalized) {
    return { proxyNode: null, error: null };
  }
  const matched = Array.from(availableNodeNames)
    .map((nodeName) => String(nodeName || "").trim())
    .find((nodeName) => nodeName === normalized);
  if (!matched) {
    return {
      proxyNode: null,
      error: `代理节点不存在：${normalized}`,
    };
  }
  return {
    proxyNode: matched,
    error: null,
  };
}

export function getAccountSessionBootstrapBlockMessage(account: BootstrapQueueAccount | null | undefined): string | null {
  if (!account) {
    return "账号不存在";
  }
  if (isLockedAccountRecord(account)) {
    return "Microsoft 账户已锁定，请先恢复可用后再 Bootstrap";
  }
  if (account.disabledAt) {
    return "账号已被禁用，请先恢复可用后再 Bootstrap";
  }
  if (account.leaseJobId != null) {
    return `账号正被 job #${account.leaseJobId} 使用，请等待当前任务结束后再重试`;
  }
  return null;
}

export function hasSuccessfulAccountBootstrap(account: BootstrapQueueAccount | null | undefined): boolean {
  return account?.browserSession?.status === "ready" && account.mailboxStatus === "available";
}

export function isAccountBootstrapping(account: BootstrapQueueAccount | null | undefined): boolean {
  return account?.browserSession?.status === "bootstrapping";
}

export function resolveAccountBatchBootstrapDecision(
  account: BootstrapQueueAccount | null | undefined,
  mode: AccountBatchBootstrapMode,
): { decision: AccountBatchBootstrapPreviewDecision; reason: string | null } {
  if (!account) {
    return { decision: "missing", reason: "账号不存在" };
  }
  const blockMessage = getAccountSessionBootstrapBlockMessage(account);
  if (blockMessage) {
    return { decision: "blocked", reason: blockMessage };
  }
  if (isAccountBootstrapping(account)) {
    return { decision: "bootstrapping", reason: "账号当前正在 Bootstrap" };
  }
  if (mode === "pending_only" && hasSuccessfulAccountBootstrap(account)) {
    return { decision: "already_bootstrapped", reason: "账号已经 Bootstrap 成功" };
  }
  return { decision: "queue", reason: null };
}

export function shouldQueueImportedAccountBootstrap(account: BootstrapQueueAccount | null | undefined): boolean {
  if (!account) return false;
  if (getAccountSessionBootstrapBlockMessage(account)) {
    return false;
  }
  if (account.hasApiKey) {
    return false;
  }
  return account.browserSession?.status !== "ready";
}

export function shouldReplayPendingAccountBootstrap(account: BootstrapQueueAccount | null | undefined): boolean {
  if (!account) return false;
  if (getAccountSessionBootstrapBlockMessage(account)) {
    return false;
  }
  return account.browserSession?.status === "pending";
}

export function hasConfiguredMicrosoftGraphBootstrap(
  settings:
    | {
        clientId?: string | null;
        clientSecret?: string | null;
        redirectUri?: string | null;
      }
    | null
    | undefined,
): boolean {
  return Boolean(
    String(settings?.clientId || "").trim()
      && String(settings?.clientSecret || "").trim()
      && String(settings?.redirectUri || "").trim(),
  );
}

export function resolveBootstrapQueueDisposition(input: { alreadyQueued: boolean; force?: boolean | null }): "queue" | "skip" | "defer_force" {
  if (!input.alreadyQueued) {
    return "queue";
  }
  return input.force ? "defer_force" : "skip";
}

export function normalizeMicrosoftAccountBootstrapConcurrency(value: unknown): number {
  const parsed = typeof value === "string" && value.trim()
    ? Number.parseInt(value.trim(), 10)
    : typeof value === "number"
      ? value
      : DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY;
  if (!Number.isFinite(parsed)) return DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY;
  return Math.min(MAX_MICROSOFT_ACCOUNT_BOOTSTRAP_CONCURRENCY, Math.max(1, Math.trunc(parsed)));
}

export function normalizeMicrosoftAccountBootstrapWorkerTimeoutMs(value: unknown): number {
  const parsed = typeof value === "string" && value.trim()
    ? Number.parseInt(value.trim(), 10)
    : typeof value === "number"
      ? value
      : DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_WORKER_TIMEOUT_MS;
  if (!Number.isFinite(parsed)) return DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_WORKER_TIMEOUT_MS;
  return Math.max(1_000, Math.trunc(parsed));
}

export function normalizeMicrosoftAccountBootstrapKillGraceMs(value: unknown): number {
  const parsed = typeof value === "string" && value.trim()
    ? Number.parseInt(value.trim(), 10)
    : typeof value === "number"
      ? value
      : DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_KILL_GRACE_MS;
  if (!Number.isFinite(parsed)) return DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_KILL_GRACE_MS;
  return Math.max(1_000, Math.trunc(parsed));
}

export function normalizeMicrosoftAccountBootstrapLoginMode(value: unknown): MicrosoftAccountBootstrapLoginMode {
  return value === "tavily_home" ? "tavily_home" : DEFAULT_MICROSOFT_ACCOUNT_BOOTSTRAP_LOGIN_MODE;
}

export type AccountBootstrapProxySnapshot = {
  proxyNode?: string | null;
  proxyIp?: string | null;
};

function normalizeBootstrapProxyIp(value: string | null | undefined): string {
  return String(value || "").trim();
}

export class AccountBootstrapProxyTracker {
  private readonly activeIps = new Set<string>();
  private allocationQueue: Promise<void> = Promise.resolve();

  excludedIps(): string[] {
    return Array.from(this.activeIps);
  }

  async reserve<T extends AccountBootstrapProxySnapshot>(
    open: (excludedIps: string[]) => Promise<T>,
  ): Promise<{ value: T; release: () => void }> {
    const previous = this.allocationQueue.catch(() => {});
    let unlock!: () => void;
    this.allocationQueue = previous.then(
      () =>
        new Promise<void>((resolve) => {
          unlock = resolve;
        }),
    );
    await previous;
    try {
      const value = await open(this.excludedIps());
      const ip = normalizeBootstrapProxyIp(value.proxyIp);
      if (ip) this.activeIps.add(ip);
      let released = false;
      return {
        value,
        release: () => {
          if (released) return;
          released = true;
          if (ip) this.activeIps.delete(ip);
        },
      };
    } finally {
      unlock();
    }
  }
}

export class AccountSessionBootstrapDispatcher {
  private readonly pendingAccountIds: number[] = [];
  private readonly pendingAccountIdSet = new Set<number>();
  private readonly activeAccountIds = new Set<number>();
  private pumping = false;

  constructor(
    private readonly getConcurrency: () => number,
    private readonly runAccount: (accountId: number) => Promise<void>,
    private readonly onAccountSettled?: (accountId: number) => void,
  ) {}

  queuedAccountIds(): ReadonlySet<number> {
    return new Set([...this.pendingAccountIdSet, ...this.activeAccountIds]);
  }

  activeCount(): number {
    return this.activeAccountIds.size;
  }

  isQueuedOrActive(accountId: number): boolean {
    return this.pendingAccountIdSet.has(accountId) || this.activeAccountIds.has(accountId);
  }

  enqueue(accountId: number): boolean {
    if (!Number.isInteger(accountId) || accountId < 1 || this.isQueuedOrActive(accountId)) {
      return false;
    }
    this.pendingAccountIds.push(accountId);
    this.pendingAccountIdSet.add(accountId);
    this.pump();
    return true;
  }

  private pump(): void {
    if (this.pumping) return;
    this.pumping = true;
    queueMicrotask(() => {
      this.pumping = false;
      const concurrency = normalizeMicrosoftAccountBootstrapConcurrency(this.getConcurrency());
      while (this.activeAccountIds.size < concurrency && this.pendingAccountIds.length > 0) {
        const accountId = this.pendingAccountIds.shift()!;
        this.pendingAccountIdSet.delete(accountId);
        if (this.activeAccountIds.has(accountId)) continue;
        this.activeAccountIds.add(accountId);
        void this.runAccount(accountId)
          .catch(() => {
            // The bootstrap flow owns account/session failure state.
          })
          .finally(() => {
            this.activeAccountIds.delete(accountId);
            this.onAccountSettled?.(accountId);
            this.pump();
          });
      }
    });
  }
}

export function shouldForceImportedAccountBootstrap(
  account: Pick<MicrosoftAccountRecord, "passwordPlaintext"> | null | undefined,
  nextPassword: string,
): boolean {
  if (!account) return false;
  return String(account.passwordPlaintext || "").trim() !== String(nextPassword || "").trim();
}
