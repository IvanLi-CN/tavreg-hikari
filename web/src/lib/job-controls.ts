import type { JobStatus } from "./app-types";

export type PrimaryJobAction = "start" | "pause" | "resume" | null;

export function resolvePrimaryJobAction(status: JobStatus | null | undefined): PrimaryJobAction {
  if (!status || ["idle", "completed", "failed", "stopped"].includes(status)) return "start";
  if (status === "running") return "pause";
  if (status === "paused") return "resume";
  return null;
}

export function resolvePrimaryJobLabel(status: JobStatus | null | undefined): string {
  const action = resolvePrimaryJobAction(status);
  if (action === "start") return "启动";
  if (action === "pause") return "暂停";
  if (action === "resume") return "恢复";
  if (status === "stopping") return "停止中";
  if (status === "force_stopping") return "强停中";
  if (status === "completing") return "收尾中";
  return "启动";
}

export function primaryJobActionDisabled(status: JobStatus | null | undefined): boolean {
  return resolvePrimaryJobAction(status) == null;
}

export function canGracefullyStop(status: JobStatus | null | undefined): boolean {
  return status === "running" || status === "paused";
}

export function canForceStop(status: JobStatus | null | undefined): boolean {
  return status === "running" || status === "paused" || status === "stopping";
}

export function canUpdateJobLimits(status: JobStatus | null | undefined): boolean {
  return status === "running" || status === "paused" || status === "completing";
}

export function resolveStopHint(status: JobStatus | null | undefined): string | null {
  if (status === "stopping") {
    return "优雅停止中：不再派发新 attempt 或补号请求，正在等待已启动任务自然收尾。";
  }
  if (status === "force_stopping") {
    return "强行停止中：正在中断 worker 与补号请求，并等待退出收束。";
  }
  if (status === "stopped") {
    return "任务已手动停止，可直接重新启动新的 job。";
  }
  return null;
}
