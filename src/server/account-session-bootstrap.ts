import type { MicrosoftAccountRecord } from "../storage/app-db.js";

export type AccountBatchBootstrapMode = "pending_only" | "force";
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

export function getAccountSessionBootstrapBlockMessage(account: BootstrapQueueAccount | null | undefined): string | null {
  if (!account) {
    return "账号不存在";
  }
  if (isLockedAccountRecord(account)) {
    return "Microsoft 账户已锁定，请先恢复可用后再 Bootstrap";
  }
  if (account.hasApiKey) {
    return "账号已有关联 API key，无需重新 Bootstrap";
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
  return account.browserSession?.status !== "ready";
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

export function shouldForceImportedAccountBootstrap(
  account: Pick<MicrosoftAccountRecord, "passwordPlaintext"> | null | undefined,
  nextPassword: string,
): boolean {
  if (!account) return false;
  return String(account.passwordPlaintext || "").trim() !== String(nextPassword || "").trim();
}
