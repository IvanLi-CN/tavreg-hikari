# Proxy Broker Timeout Recovery

## Context

Tavreg Hikari can show widespread account session failures when Proxy Broker still responds to catalog reads but session open or health catalog paths are degraded. The visible UI error may be `proxy_broker_request_timeout`, `proxy_broker_no_healthy_nodes`, or a secondary TypeError if the proxy payload endpoint is allowed to return a null catalog.

## Response Pattern

- Check account failures in `account_browser_sessions`, not only `job_attempts`; Microsoft account bootstrap failures are stored on persistent browser session rows.
- Compare Broker catalog counts, active sessions, and fresh healthy metadata from inside the `tavreg-hikari` container using the same Broker base URL and API key as production.
- Prefer the Docker network Broker API URL when both services share a network. Avoid sending same-host service-to-service traffic through the public HTTPS route.
- Close stale Broker sessions through `DELETE /api/v1/projects/{project}/sessions/{session_id}` before triggering a full probe. Stale persisted sessions can keep runtime restore noisy and make probe failures harder to interpret.
- Treat failed account session proxy IPs as diagnostics only. Do not reuse them as preferred IPs for later open-session calls.

## Implementation Guardrails

- Broker API aborts should remain `proxy_broker_request_timeout` with method/path/timeout details.
- Proxy payload endpoints should preserve the last catalog snapshot and expose `syncError` if sessions or catalog reads fail.
- Only `ready` account browser sessions may seed a preferred proxy IP or region.
- Broker-open failures must not write an old proxy IP back into the latest failure snapshot, because that makes many unrelated accounts look pinned to the same failed IP.
- Regression tests should cover ready-only proxy reuse, failed-session proxy reuse suppression, and Broker client timeout defaults.
