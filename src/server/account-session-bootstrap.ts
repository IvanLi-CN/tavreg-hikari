import type { MicrosoftAccountRecord } from "../storage/app-db.js";

type BootstrapQueueAccount = Pick<
  MicrosoftAccountRecord,
  "leaseJobId" | "disabledAt" | "skipReason" | "lastErrorCode" | "hasApiKey" | "browserSession"
>;

export function isLockedAccountRecord(
  account: Pick<MicrosoftAccountRecord, "skipReason" | "lastErrorCode" | "disabledAt"> | null | undefined,
): boolean {
  return (
    String(account?.skipReason || "").trim() === "microsoft_account_locked"
    || /^microsoft_account_locked/i.test(String(account?.lastErrorCode || "").trim())
  );
}

export function getAccountSessionBootstrapBlockMessage(account: BootstrapQueueAccount | null | undefined): string | null {
  if (!account) {
    return "账号不存在";
  }
  if (isLockedAccountRecord(account)) {
    return "Microsoft 账户已锁定，请先恢复可用后再连接";
  }
  if (account.hasApiKey) {
    return "账号已有关联 API key，无需重新 Bootstrap";
  }
  if (account.disabledAt) {
    return "账号已被禁用，请先恢复可用后再连接";
  }
  if (account.leaseJobId != null) {
    return `账号正被 job #${account.leaseJobId} 使用，请等待当前任务结束后再重试`;
  }
  return null;
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
