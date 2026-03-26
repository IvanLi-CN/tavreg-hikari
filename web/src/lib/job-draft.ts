import type { JobDraft, JobSnapshot } from "./app-types";

export function normalizeMaxAttemptsForNeed(need: number, maxAttempts: number): number {
  const normalizedNeed = Math.max(1, Number.isFinite(need) ? Math.trunc(need) : 1);
  const normalizedMaxAttempts = Math.max(1, Number.isFinite(maxAttempts) ? Math.trunc(maxAttempts) : 1);
  if (normalizedMaxAttempts >= normalizedNeed) {
    return normalizedMaxAttempts;
  }
  return Math.max(normalizedNeed, Math.ceil(normalizedNeed * 1.5));
}

export function normalizeJobDraft(input: JobDraft): JobDraft {
  const need = Math.max(1, Number.isFinite(input.need) ? Math.trunc(input.need) : 1);
  const parallel = Math.max(1, Number.isFinite(input.parallel) ? Math.trunc(input.parallel) : 1);
  const maxAttempts = normalizeMaxAttemptsForNeed(need, input.maxAttempts);
  return {
    ...input,
    need,
    parallel,
    maxAttempts,
  };
}

export function jobToDraft(job: NonNullable<JobSnapshot["job"]>): JobDraft {
  return {
    runMode: job.runMode,
    need: job.need,
    parallel: job.parallel,
    maxAttempts: job.maxAttempts,
    autoExtractSources: job.autoExtractSources,
    autoExtractQuantity: job.autoExtractQuantity,
    autoExtractMaxWaitSec: job.autoExtractMaxWaitSec,
    autoExtractAccountType: job.autoExtractAccountType,
  };
}
