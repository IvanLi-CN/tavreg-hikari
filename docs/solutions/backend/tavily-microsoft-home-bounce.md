# Tavily Microsoft Home Bounce Recovery

## Context

Tavily Microsoft login can fail at `stage_login_home` even when the last URL is `https://app.tavily.com/home`. In this state the Auth0 Microsoft provider POST has bounced back to Tavily Home before the browser ever reaches a Microsoft account surface, and Tavily Home stays on a thin loading shell without authenticated API signals.

## Response Pattern

- Treat `app.tavily.com/home` as a completed Microsoft login only when the flow has visited a Microsoft account URL or Tavily authenticated API probes confirm a valid session.
- When a provider submit lands on Tavily Home without those signals, relaunch the Tavily login entry instead of returning success from the Microsoft completion helper.
- Do not click the Microsoft provider while Auth0 managed challenge readiness is explicitly `wait`; first hydrate the challenge token and only submit the provider once the token path is ready or the passive challenge fallback says direct submit is safe.
- Keep `stage_login_home` distinct from account pool exhaustion. The former is an auth-flow state-machine failure; the latter is scheduler inventory state.

## Implementation Guardrails

- The provider direct-submit fallback is valid only when `waitForPassiveMicrosoftProviderReadiness` returns `ready` or `skipped`. A `wait` result means the page still has an active challenge surface and should not be bypassed.
- A Tavily Home bounce recovery should be bounded. After a small number of relaunches, fail with a specific unauthenticated-home error instead of looping until the outer login timeout.
- Regression tests should assert both negative conditions: no direct provider click in the `wait` branch, and no home completion without either Microsoft visitation or authenticated Tavily signals.
