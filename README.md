# tavreg-hikari

CTF local practice: automate Tavily registration + email verification + API key generation with Bun and TypeScript.

## Prerequisites

1. Keep `.env.local` in project root (already ignored by git):

```env
OPENAI_KEY=...
OPENAI_BASE_URL=...
MODEL_NAME=...
#
# DuckMail API mailbox (default base URL already points to duckmail.sbs)
# DUCKMAIL_BASE_URL=https://api.duckmail.sbs
# DUCKMAIL_API_KEY=dk_...          # optional
# DUCKMAIL_DOMAIN=duckmail.sbs     # optional
# DUCKMAIL_POLL_MS=2500
#
# Human confirmation gate before signup submit
# HUMAN_CONFIRM_BEFORE_SIGNUP=true
# HUMAN_CONFIRM_TEXT=CONFIRM
```

2. Install dependencies:

```bash
bun install
```

3. Install Camoufox (from official Python docs):

```bash
pip install -U camoufox[geoip]
python3 -m camoufox fetch
```

## Run

```bash
bun run start
```

Optional env flags:

```bash
HEADLESS=false SLOWMO_MS=50 MAX_CAPTCHA_ROUNDS=6 EMAIL_WAIT_MS=180000 DUCKMAIL_POLL_MS=2500 bun run start
```

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

## Local CTF Route Check

```bash
curl -v --resolve app.tavily.com:443:198.18.1.2 https://app.tavily.com -o /dev/null
```

You should see `Trying 198.18.1.2:443` and `Connected to app.tavily.com (198.18.1.2)`.

## Output

Script writes result to:

- `output/result.json`

Fields:

- `email`: temporary mailbox used for signup
- `password`: generated password
- `verificationLink`: verification URL if found
- `apiKey`: generated Tavily key (if creation succeeded)
- `notes`: step-by-step status notes

## Notes

- Registration flow includes image captcha; OCR is done via OpenAI-compatible API in `.env.local`.
- OCR retries now use a long backoff window, so short-term `429/503` bursts do not fail immediately.
- Temporary email and verification polling use DuckMail API (`/domains`, `/accounts`, `/token`, `/messages`).
- Browser automation is executed by Python Camoufox (`camoufox.sync_api.Camoufox`) launched from Bun/TypeScript.
- Signup submit requires one interactive human confirmation by default.

## Security Findings

See `docs/CTF_FINDINGS.md`.
