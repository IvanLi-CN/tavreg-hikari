---
title: Chromium profile lock recovery
module: browser automation
problem_type: stale persistent profile lock
component: launchChromePersistent
tags:
  - chromium
  - profile
  - playwright
status: active
related_specs:
  - docs/specs/wht6n-persistent-account-browser-sessions/SPEC.md
---

# Chromium profile lock recovery

## Context

Persistent Chromium profiles can retain `SingletonLock`, `SingletonSocket`, or `SingletonCookie` after a worker exits unexpectedly. The next `launchPersistentContext` may fail before the browser opens even though no live browser owns the profile.

## Resolution

- Check singleton artifacts immediately before launching a persistent profile.
- Treat a lock as stale only when no live Chromium command owns the same `--user-data-dir`, and any PID hinted by the singleton artifact is missing or belongs to a non-Chromium process.
- Remove only the singleton artifacts for stale-lock recovery. Leave profile data, cookies, storage, and online assets untouched.
- If Playwright returns a singleton/profile-lock launch error, repeat the stale-lock check and retry the launch once.
- If a live Chromium process owns the profile, do not clean locks or start a second browser against the same profile.

## Guardrails

- Do not clean profiles globally or by account id alone; bind cleanup to the exact resolved profile directory.
- Do not assume a missing target for a symlink means the symlink path does not exist; use `lstat` so broken singleton symlinks are still visible.
- Keep recovery local to launch-time artifacts. Online profile cleanup or manual account retries require explicit operator authorization.
- Cover stale PID, active profile owner, and symlink PID cases with tests.
