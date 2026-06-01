---
title: Pending launch parallel capacity
module: backend scheduler
problem_type: slow attempt launch setup
component: job scheduler
tags:
  - scheduler
  - parallel
  - proxy-broker
status: active
related_specs:
  - docs/specs/5nkhw-tavreg-hikari-web-control/SPEC.md
---

# Pending launch parallel capacity

## Context

Batch schedulers often do meaningful setup before a worker child process exists: port lease reservation, browser executable checks, proxy node selection, domain probing, and broker session creation. These steps are part of an attempt launch even though they are not yet visible as active child processes.

## Symptoms

- A job is started with `parallel > 1`, but active attempts climb slowly or never reach the requested parallelism.
- Successful attempts finish before later slots are even launched.
- The UI can show available eligible accounts while `activeAttempts` stays below `parallel`.
- Operators misread the slow launch ramp as account-pool exhaustion.

## Root Cause

The scheduler awaited each `spawnAttempt` setup path inside the dispatch loop. Since `spawnAttempt` includes slow proxy and broker setup before the child is added to `activeAttempts`, the loop serialized launch preparation. Capacity calculations also only counted active child attempts, so pending launch work was invisible to terminal-state and stop-drain decisions.

## Resolution

- Treat pending launch setup as scheduler-owned work.
- Track pending launch tasks separately from active child attempts.
- Count `active + pending` when calculating launch capacity, so pending setup occupies a parallel slot and prevents launch storms.
- Start pending launch tasks without awaiting them inside the dispatch loop; each task owns its setup errors, attempt failure, event emission, and pending cleanup.
- Keep stop and shutdown semantics aware of pending launch work, marking pending launches for force stop and waiting for them to drain before terminal stop finalization.
- When evaluating job completion, max-attempt exhaustion, extractor fallback, or eligible-pool exhaustion, require both active and pending work to be drained.

## Guardrails / Reuse Notes

- Do not count only child-process-backed active attempts when setup can be slow. Pending setup is real work and must occupy capacity.
- Do not make pending launches unbounded. Capacity must be computed from `parallel`, remaining need, remaining attempt budget, and `active + pending`.
- Do not complete or fail a job while pending launches exist; those launches may still become active attempts or need rollback/failure accounting.
- Tests should block `spawnAttempt` before it creates a child and assert that the scheduler still fills the requested pending slots.

## References

- `src/server/scheduler.ts`
- `test/job-stop-controls.test.ts`
