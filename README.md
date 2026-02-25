# tavreg-hikari

Legacy local practice: automate Tavily registration + email verification + API key generation with Bun and TypeScript.

Workflow document: `docs/WORKFLOW.md`

## Prerequisites

1. Copy `.env.example` to `.env.local` in project root (already ignored by git), then fill required values:

```bash
cp .env.example .env.local
```

Minimal required values:

```env
OPENAI_KEY=...
OPENAI_BASE_URL=...
MODEL_NAME=...
MIHOMO_SUBSCRIPTION_URL=...
```

Optional settings (browser/proxy/retry/inspect) are maintained in `.env.example`.

2. Install dependencies:

```bash
bun install
```

3. Install Camoufox (from official Python docs):

```bash
pip install -U camoufox[geoip]
python3 -m camoufox fetch
```

4. Mihomo core is downloaded automatically on first run.

## Run

```bash
bun run start
```

Optional env flags:

```bash
RUN_MODE=headed SLOWMO_MS=50 MAX_CAPTCHA_ROUNDS=6 EMAIL_WAIT_MS=180000 DUCKMAIL_POLL_MS=2500 bun run start
```

Select a specific proxy node by name:

```bash
bun run start -- --proxy-node "US-1"
```

Run in headless mode:

```bash
bun run start -- --mode headless
```

Run both headed and headless in one command:

```bash
bun run start -- --mode both
```

Skip browser precheck temporarily (debug only):

```bash
bun run start -- --skip-precheck
```

Open headed browser for manual transparency inspection (`fingerprint.goldenowl.ai` + `ip.skk.moe`):

```bash
bun run start -- --inspect-sites
```

Force inspect mode to use system Chrome engine:

```bash
bun run start -- --inspect-sites --browser-engine chrome
```

For headed registration with native Chrome profile (lower automation fingerprint surface):

```bash
BROWSER_ENGINE=chrome CHROME_NATIVE_AUTOMATION=true bun run start -- --mode headed
```

`CHROME_NATIVE_AUTOMATION=true` first tries native Chrome CDP attach; if CDP handshake is unavailable in your environment, it automatically falls back to a persistent Chrome profile launched by Playwright.

If your Python binary is not `python3`, set:

```bash
CAMOUFOX_PYTHON=python bun run start
```

OCR retry tuning (useful when gateway is throttling):

```bash
OCR_RETRY_WINDOW_MS=300000 \
OCR_INITIAL_COOLDOWN_MS=12000 \
OCR_MAX_COOLDOWN_MS=120000 \
OCR_REQUEST_TIMEOUT_MS=25000 \
bun run start
```

Optional OCR fallback (disabled by default):

```bash
OCRSPACE_FALLBACK=true OCRSPACE_API_KEY=helloworld bun run start
```

If your LLM gateway is completely unavailable, you can skip LLM OCR attempts:

```bash
OCRSPACE_FALLBACK=true OCRSPACE_ONLY=true bun run start
```

`helloworld` is heavily rate-limited (about 10 requests / 600s). Use your own OCR.space key for stable fallback runs.

## Local Route Check

```bash
curl -v --resolve app.tavily.com:443:198.18.1.2 https://app.tavily.com -o /dev/null
```

You should see `Trying 198.18.1.2:443` and `Connected to app.tavily.com (198.18.1.2)`.

## Output

Script writes result to:

- `output/result.json`

Fields:

- `mode`: run mode (`headed` or `headless`)
- `email`: temporary mailbox used for signup
- `password`: generated password
- `verificationLink`: verification URL
- `apiKey`: generated Tavily key (if creation succeeded)
- `precheckPassed`: browser transparency precheck status
- `verifyPassed`: email verification status
- `notes`: step-by-step status notes

Additional artifacts:

- `output/browser_precheck.json`: latest browser precheck report
- `output/browser_precheck_headed.json`: headed precheck report
- `output/browser_precheck_headless.json`: headless precheck report
- `output/run_summary.json`: summary for single or multiple run modes
- `output/proxy/node-usage.json`: proxy node usage history and recent selection window
- `output/registry/signup-tasks.sqlite`: SQLite task ledger (run status, risk signals, proxy IP history)

## Notes

- Registration flow includes image captcha; OCR is done via OpenAI-compatible API in `.env.local`.
- OCR retries now use a long backoff window, so short-term `429/503` bursts do not fail immediately.
- Temporary email and verification polling use DuckMail API (`/domains`, `/accounts`, `/token`, `/messages`).
- Browser automation is executed by Python Camoufox (`camoufox.sync_api.Camoufox`) launched from Bun/TypeScript.
- Signup requires email verification success; missing verification link is treated as failure.
- Browser precheck visits 3 domestic IP sites (`myip.ipip.net`, `cip.cc`, `ip.3322.net`) + 2 global IP sites (`api.ip.sb/geoip`, `ipinfo.io/json`) + `fingerprint.goldenowl.ai`; all observed IPs must be fully consistent, otherwise the run is blocked.
- Proxy node selection is availability-first with anti-reuse scoring centered on egress IPs (recent egress IPs + cooldown + historical success/failure + latency), persisted in `output/proxy/node-usage.json`.
- SQLite ledger is initialized with WAL + busy_timeout to support concurrent readers/writers; recent `Too many signups from the same IP` history is used to avoid risky egress IP reuse.

Quick query example (requires `sqlite3` CLI):

```bash
sqlite3 output/registry/signup-tasks.sqlite \
  "select started_at,status,proxy_ip,error_code,has_ip_rate_limit from signup_tasks order by id desc limit 20;"
```

## Proxy Tools

Batch check all nodes:

```bash
bun run proxy:check-all
```

Check a single node:

```bash
bun run proxy:check --node "US-1"
```

Switch active node:

```bash
bun run proxy:set --node "US-1"
```

## Security Findings

See `docs/SECURITY_FINDINGS.md`.
