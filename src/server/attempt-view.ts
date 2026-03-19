import type { AppDatabase, JobAttemptRecord } from "../storage/app-db.js";

export function serializeAttemptForApi(db: AppDatabase, row: JobAttemptRecord): Record<string, unknown> {
  const signupTask = db.getLatestSignupTask(row.jobId, row.accountId);
  return {
    ...row,
    runId: signupTask?.run_id ? String(signupTask.run_id) : row.runId,
    status: signupTask?.status ? String(signupTask.status) : row.status,
    stage: signupTask?.failure_stage ? String(signupTask.failure_stage) : row.stage,
    proxyNode: signupTask?.proxy_node ? String(signupTask.proxy_node) : row.proxyNode,
    proxyIp: signupTask?.proxy_ip ? String(signupTask.proxy_ip) : row.proxyIp,
    errorCode: signupTask?.error_code ? String(signupTask.error_code) : row.errorCode,
    errorMessage: signupTask?.error_message ? String(signupTask.error_message) : row.errorMessage,
    accountEmail: db.getAccount(row.accountId)?.microsoftEmail || null,
  };
}
