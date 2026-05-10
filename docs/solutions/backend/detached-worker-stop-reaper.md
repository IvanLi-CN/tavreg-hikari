---
title: Detached worker stop reaper
module: backend scheduler
problem_type: stale detached child process
component: job scheduler
tags:
  - scheduler
  - force-stop
  - detached-worker
status: active
related_specs:
  - docs/specs/3hrx4-grok-web-site/SPEC.md
  - docs/specs/r6h9s-job-stop-controls/SPEC.md
---

# Detached worker stop reaper

## Context

Batch schedulers launch browser workers as detached child process groups so force stop can signal the whole worker tree. The parent scheduler still owns the user-facing job state and must not depend on a single child-process event to make terminal progress.

## Symptoms

- UI shows `force_stopping` indefinitely.
- UI shows a normal `running` job that no longer launches new attempts.
- DB still has `job_attempts.status = 'running'`.
- The container has no live worker process for those attempts, or the attempt output directory already contains `error.json`.
- Repeating force stop returns the same non-terminal job state.

## Root cause

The scheduler tracks active work in memory and only deletes an active attempt from the map when the child `close` handler finishes. Detached browser workers can leave stale or zombie process state, and a missed or delayed `close` event keeps `activeAttempts.size > 0`. If the reaper only runs during `stopping` / `force_stopping`, a normal `running` job can also stay pinned even though worker artifacts already prove the attempt is terminal.

## Resolution

- Make stop and force-stop idempotent for already-stopping jobs.
- Add a scheduler-level reaper that runs during stop polling, duplicate stop requests, and ordinary running loop ticks.
- Reap an active attempt when its DB row is no longer running, its child has an exit or signal code, or force stop has exceeded the final reap threshold; error artifacts are diagnostic input once the reaper is allowed to clean up.
- For graceful stops, route exited children through the same result finalizer used by the child `close` handler so a successful `result.json` is preserved instead of being converted into an exit failure.
- For ordinary running jobs, route terminal `result.json` / `error.json` artifacts through the same result finalizer; if a worker stays quiet long enough without terminal artifacts, terminate the worker first and only release ownership after it exits or the force-stop reap window elapses.
- Treat ledger-visible signup-task updates as progress as well; quiet output alone should not trip the stale timer if the task ledger is still advancing.
- If a running worker has already written terminal artifacts but has not closed yet, keep ownership until the child exits rather than finalizing early.
- Keep the reaper scoped to `running` and stop-transition jobs only; paused, completing, and stopped states must not be treated as stale worker states.
- Store the active attempt's resource-release callback and force-stop request timestamp with the scheduler-owned active entry, so stale attempts can be reaped without leaking reserved runtime resources.
- After reaping active attempts, finalize the job with the same terminal `stopped` path used by normal stop completion.

## Guardrails / Reuse notes

- Keep this logic in the scheduler layer when the stale state is runtime-only; DB stale-state recovery is still useful on restart but cannot fix a live process stuck in memory.
- Preserve manual-stop semantics when completing attempts after stop has started; do not convert user-requested stop into an ordinary failure unless the job was only gracefully stopping and the worker produced a real failure artifact.
- Do not limit stale cleanup to stop-state branches. Running jobs must also free terminal or timed-out active entries so capacity can reopen.
- Do not race the child `close` handler with a second ad hoc completion path. Reuse an idempotent finalizer around result parsing, DB completion, resource release, and stopped-job finalization.
- Release any runtime resources owned by the active attempt when deleting it from the in-memory map, but keep ownership while the worker may still be alive even if it has already written `error.json`.
- Cover the failure mode with tests that do not launch a browser: create a running attempt, inject an active attempt into the scheduler, write `result.json` / `error.json` or age the active attempt progress timestamp, and assert the active entry is cleared with the correct terminal attempt status.

## References

- `src/server/grok-scheduler.ts`
- `src/server/scheduler.ts`
- `test/job-stop-controls.test.ts`
- `test/grok-scheduler.test.ts`
