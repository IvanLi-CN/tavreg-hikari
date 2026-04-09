import type { AppDatabase, JobAttemptRecord } from "../storage/app-db.js";

function parseMillis(value: unknown): number | null {
  if (typeof value !== "string" || !value.trim()) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function shouldIgnoreSignupTaskForAttempt(row: JobAttemptRecord, signupTask: Record<string, unknown> | null): boolean {
  if (!signupTask) return true;
  const signupRunId = signupTask.run_id == null ? null : String(signupTask.run_id);
  if (row.runId) {
    return signupRunId == null || signupRunId !== row.runId;
  }
  const attemptStartedAtMs = parseMillis(row.startedAt);
  const signupStartedAtMs = parseMillis(signupTask.started_at);
  const signupCompletedAtMs = parseMillis(signupTask.completed_at);
  if (attemptStartedAtMs == null) {
    return false;
  }
  if (signupStartedAtMs != null && signupStartedAtMs < attemptStartedAtMs) {
    return true;
  }
  if (signupCompletedAtMs != null && signupCompletedAtMs < attemptStartedAtMs) {
    return true;
  }
  return false;
}

export function serializeAttemptForApi(db: AppDatabase, row: JobAttemptRecord): Record<string, unknown> {
  const signupTask = db.getLatestSignupTask(row.jobId, row.accountId);
  if (shouldIgnoreSignupTaskForAttempt(row, signupTask)) {
    return {
      ...row,
      accountEmail: row.accountEmail || (row.accountId == null ? null : db.getAccount(row.accountId)?.microsoftEmail || null),
    };
  }
  const preferRuntimeSnapshot = row.status === "running";
  const preferLedgerDiagnostics = row.status === "running" || row.status === "failed";
  return {
    ...row,
    runId: signupTask?.run_id ? String(signupTask.run_id) : row.runId,
    status: preferRuntimeSnapshot && signupTask?.status ? String(signupTask.status) : row.status,
    stage: preferLedgerDiagnostics && signupTask?.failure_stage ? String(signupTask.failure_stage) : row.stage,
    proxyNode: preferLedgerDiagnostics && signupTask?.proxy_node ? String(signupTask.proxy_node) : row.proxyNode,
    proxyIp: preferLedgerDiagnostics && signupTask?.proxy_ip ? String(signupTask.proxy_ip) : row.proxyIp,
    errorCode: preferLedgerDiagnostics && signupTask?.error_code ? String(signupTask.error_code) : row.errorCode,
    errorMessage: preferLedgerDiagnostics && signupTask?.error_message ? String(signupTask.error_message) : row.errorMessage,
    accountEmail: row.accountEmail || (row.accountId == null ? null : db.getAccount(row.accountId)?.microsoftEmail || null),
  };
}
