# Proxy Broker Timeout Recovery

## Context

Tavreg Hikari can show widespread account session failures when Proxy Broker still responds to catalog reads but session open or health catalog paths are degraded. The visible UI error may be `proxy_broker_request_timeout`, `proxy_broker_no_healthy_nodes`, or a secondary TypeError if the proxy payload endpoint is allowed to return a null catalog.

## Response Pattern

- Check account failures in `account_browser_sessions`, not only `job_attempts`; Microsoft account bootstrap failures are stored on persistent browser session rows.
- Compare Broker catalog counts, active sessions, and fresh healthy metadata from inside the `tavreg-hikari` container using the same Broker base URL and API key as production.
- Prefer the Docker network Broker API URL when both services share a network. Avoid sending same-host service-to-service traffic through the public HTTPS route.
- If direct `sessions/open` succeeds quickly but `projects/{project}/refresh` hangs, check whether the app is refreshing only because a minority of catalog metadata is stale. Existing healthy candidates should be used immediately; refresh should be reserved for no-candidate recovery.
- Close stale Broker sessions through `DELETE /api/v1/projects/{project}/sessions/{session_id}` before triggering a full probe. Stale persisted sessions can keep runtime restore noisy and make probe failures harder to interpret.
- Treat failed account session proxy IPs as diagnostics only. Do not reuse them as preferred IPs for later open-session calls.
- During concurrent account bootstrap, pass currently active bootstrap egress IPs into Broker `excludedIps` so new sessions do not immediately collide with another in-flight account.
- For Web scheduler attempts, record proxy binding as a lifecycle stage: `allocating_proxy` before Broker success, `proxy_bound` after session/probe success, and `spawned` only after the worker child process is actually spawned.

## Implementation Guardrails

- Broker API aborts should remain `proxy_broker_request_timeout` with method/path/timeout details.
- Catalog refresh should not be a synchronous preflight when fresh healthy candidates already exist, because the refresh endpoint can be much slower than session open and can fail every business flow before proxy binding.
- Proxy payload endpoints should preserve the last catalog snapshot and expose `syncError` if sessions or catalog reads fail.
- Only `ready` account browser sessions may seed a preferred proxy IP or region.
- Broker-open failures must not write an old proxy IP back into the latest failure snapshot, because that makes many unrelated accounts look pinned to the same failed IP.
- Broker-open and domain-probe failures should complete the attempt as failed with the original `proxy_broker_*` or `proxy_domain_unreachable` code. Do not leave the attempt running as `spawned` with null proxy fields.
- If Broker session succeeds but worker spawn fails, close the session and release local port leases in the same setup-failure path; resource release must remain idempotent because child close handlers and reapers can both observe terminal state.
- Regression tests should cover ready-only proxy reuse, failed-session proxy reuse suppression, active bootstrap IP exclusion, and Broker client timeout defaults.
