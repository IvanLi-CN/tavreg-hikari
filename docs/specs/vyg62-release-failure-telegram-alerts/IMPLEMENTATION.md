# vyg62 · Release 失败 Oidrune 告警接入

## Contract Surface

- `.github/workflows/notify-release-failure.yml` remains the project-local entrypoint.
- Automatic notification remains limited to `Release` `workflow_run` completion with `failure` conclusion on `main`.
- Manual `workflow_dispatch` remains the notifier smoke path and carries the `release-alert-smoke` marker in its caller-provided summary.
- Both notification jobs call `IvanLi-CN/oidrune/.github/workflows/notify.yml@e48822f99c6402a753ed86557ea029754cbab20b`.
- Both caller jobs grant `id-token: write`, set `on_gateway_failure: fail`, and omit gateway URL, OIDC audience, and legacy Telegram secrets so Oidrune resolves its defaults while failed handoffs remain visible.

## Summary Contract

The caller owns the complete summary. Failure summaries include the project, repository, status, release title, resolved target SHA, run URL, ref, attempt, actor, event, and resolver details. Smoke summaries include the project, repository, failure status, smoke title, `release-alert-smoke`, target SHA, run URL, ref, attempt, actor, event, and smoke details. Each summary starts with an emoji, status, and project name.

The resolver keeps its existing priority: `RELEASE_TARGET_SHA` from Release logs, then `RELEASE_REQUESTED_SHA`, then `workflow_run.head_sha`. `release.yml` continues to emit both markers at the requested-target and resolved-target stages.

## Verification

- `.github/scripts/check_notify_release_failure_contract.py` parses the workflow YAML and checks the trigger, conditions, job permissions, pinned reusable workflow, input set, summary fields, legacy secret removal, and Release SHA markers.
- `CI PR` and `CI Main` compile and execute the contract test in their Typecheck & Quality Gates job.
- Live Oidrune facts verified for this implementation: the pinned commit is `oidrune/main` HEAD and latest release `v0.1.14`; its reusable workflow requires `outcome` and `summary`, grants its notification job OIDC access, and defaults gateway inputs when omitted.
