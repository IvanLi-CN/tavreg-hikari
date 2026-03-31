import type { MicrosoftAccountRecord } from "../storage/app-db.js";

type BootstrapQueueAccount = Pick<
  MicrosoftAccountRecord,
  "leaseJobId" | "disabledAt" | "skipReason" | "lastErrorCode" | "browserSession"
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
