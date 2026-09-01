# Release 失败 Oidrune 告警接入历史（#vyg62）

## Lifecycle

- This topic owns the repo-local notification wrapper for failed `Release` runs and its manual smoke path.
- The normative trigger, input, summary, and SHA-resolution contract remains in `./SPEC.md`.

## Replacements

- The original shared Telegram reusable workflow reference was replaced by the pinned Oidrune `notify.yml` release published with the current Oidrune mainline.
- Notification metadata ownership moved to this repository's caller summary so the receiving workflow does not need to infer project-specific release context.
- Gateway handoff failures remain job failures through Oidrune's explicit `on_gateway_failure: fail` input, preserving observable delivery failure semantics.

## Compatibility

- `workflow_run` filtering, failure-only automatic notification, resolver SHA precedence, and `workflow_dispatch` smoke behavior remain compatible with the prior wrapper.
- The manual smoke path remains an available workflow path for authorized operators; this repository does not trigger it as part of local or PR validation.
