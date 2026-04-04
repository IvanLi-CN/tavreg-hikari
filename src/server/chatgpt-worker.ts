import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { URL } from "node:url";
import process from "node:process";
import { getCfMailMessage, listCfMailMessages, normalizeCfMailBaseUrl } from "../cfmail-api.js";
import { startMihomo } from "../proxy/mihomo.js";
import { launchBrowserWithEngine, loadConfig } from "../main.js";

const OAUTH_ISSUER = "https://auth.openai.com";
const OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const OAUTH_SCOPE = "openid profile email offline_access";
const CALLBACK_HOST = "localhost";
const CALLBACK_PORT = 1455;
const CALLBACK_PATH = "/auth/callback";
const CALLBACK_ORIGIN = `http://${CALLBACK_HOST}:${CALLBACK_PORT}`;
const CALLBACK_URL = `${CALLBACK_ORIGIN}${CALLBACK_PATH}`;

interface WorkerArgs {
  proxyNode?: string;
}

interface WorkerPayload {
  email: string;
  password: string;
  nickname: string;
  birthDate: string;
  mailboxId: string;
}

interface CallbackResult {
  code: string;
  state: string;
}

function log(message: string): void {
  console.log(`[chatgpt-worker] ${message}`);
}

function nowIso(): string {
  return new Date().toISOString();
}

function parseArgs(argv: string[]): WorkerArgs {
  let proxyNode: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg) continue;
    if (arg === "--proxy-node" && argv[index + 1]) {
      proxyNode = String(argv[index + 1]).trim() || undefined;
      index += 1;
      continue;
    }
    if (arg.startsWith("--proxy-node=")) {
      proxyNode = arg.slice("--proxy-node=".length).trim() || undefined;
    }
  }
  return { proxyNode };
}

function requireEnv(name: string): string {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`missing_env:${name}`);
  return value;
}

function parsePayload(): WorkerPayload {
  return {
    email: requireEnv("CHATGPT_JOB_EMAIL").toLowerCase(),
    password: requireEnv("CHATGPT_JOB_PASSWORD"),
    nickname: requireEnv("CHATGPT_JOB_NICKNAME"),
    birthDate: requireEnv("CHATGPT_JOB_BIRTH_DATE"),
    mailboxId: requireEnv("CHATGPT_JOB_MAILBOX_ID"),
  };
}

function encodeBase64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function createPkcePair(): { verifier: string; challenge: string } {
  const verifier = encodeBase64Url(randomBytes(64));
  const challenge = encodeBase64Url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function createState(): string {
  return encodeBase64Url(randomBytes(32));
}

function buildAuthorizeUrl(input: { state: string; codeChallenge: string }): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: OAUTH_CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    scope: OAUTH_SCOPE,
    code_challenge: input.codeChallenge,
    code_challenge_method: "S256",
    state: input.state,
  });
  return `${OAUTH_ISSUER}/oauth/authorize?${params.toString()}`;
}

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function httpJson<T = unknown>(method: string, url: string, options?: { headers?: Record<string, string>; body?: unknown }): Promise<T> {
  const headers: Record<string, string> = { ...(options?.headers || {}) };
  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    headers["content-type"] = headers["content-type"] || "application/json";
    body = JSON.stringify(options.body);
  }
  const response = await fetch(url, {
    method,
    headers,
    body,
  });
  const text = await response.text();
  const parsed = text.trim() ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`http_failed:${response.status}:${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed as T;
}

function collectStrings(value: unknown, bucket: string[], depth = 0): void {
  if (depth > 8 || value == null) return;
  if (typeof value === "string") {
    bucket.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, bucket, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) collectStrings(item, bucket, depth + 1);
  }
}

function extractOpenAiOtpCode(payload: unknown): string | null {
  const texts: string[] = [];
  collectStrings(payload, texts);
  for (const text of texts) {
    const normalized = text.replace(/\s+/g, " ");
    for (const match of normalized.matchAll(/\b(\d{6})\b/g)) {
      const code = match[1];
      if (!code) continue;
      const start = Math.max(0, (match.index || 0) - 80);
      const end = Math.min(normalized.length, (match.index || 0) + code.length + 80);
      const context = normalized.slice(start, end);
      if (/(openai|chatgpt|verification|verify|one-time|one time|code|login|sign in)/i.test(context)) {
        return code;
      }
    }
  }
  return null;
}

async function waitForCfMailOtp(input: { address: string; notBefore: string; timeoutMs: number; pollMs: number }): Promise<string> {
  const baseUrl = normalizeCfMailBaseUrl(process.env.CFMAIL_BASE_URL || "https://api.cfm.707979.xyz");
  const apiKey = requireEnv("CFMAIL_API_KEY");
  const seen = new Set<string>();
  const deadline = Date.now() + input.timeoutMs;
  while (Date.now() < deadline) {
    const messages = await listCfMailMessages({
      baseUrl,
      apiKey,
      address: input.address,
      httpJson,
      since: input.notBefore,
    });
    for (const message of messages) {
      if (!message?.id || seen.has(message.id)) continue;
      seen.add(message.id);
      const detail = await getCfMailMessage({
        baseUrl,
        apiKey,
        messageId: message.id,
        httpJson,
      }).catch(() => null);
      const code = detail ? extractOpenAiOtpCode(detail) : null;
      if (code) return code;
    }
    await new Promise((resolve) => setTimeout(resolve, input.pollMs));
  }
  throw new Error("chatgpt_email_otp_timeout");
}

async function startCallbackServer(expectedState: string): Promise<{ waitForCode: Promise<CallbackResult>; close: () => Promise<void> }> {
  let resolveCode: ((value: CallbackResult) => void) | null = null;
  let rejectCode: ((reason?: unknown) => void) | null = null;
  const waitForCode = new Promise<CallbackResult>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  const server = createServer((req, res) => {
    try {
      const url = new URL(req.url || "/", CALLBACK_ORIGIN);
      if (url.pathname !== CALLBACK_PATH) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        res.end("Not found");
        return;
      }
      const code = String(url.searchParams.get("code") || "").trim();
      const state = String(url.searchParams.get("state") || "").trim();
      const error = String(url.searchParams.get("error") || "").trim();
      if (error) {
        rejectCode?.(new Error(`chatgpt_oauth_callback_error:${error}`));
      } else if (!code || state !== expectedState) {
        rejectCode?.(new Error(`chatgpt_oauth_callback_invalid:${state || "missing_state"}`));
      } else {
        resolveCode?.({ code, state });
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<html><body><h1>Authentication complete</h1><p>You can close this tab.</p></body></html>");
    } catch (error) {
      rejectCode?.(error);
      res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      res.end("Callback failed");
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(CALLBACK_PORT, CALLBACK_HOST, () => resolve());
  });
  return {
    waitForCode,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }).catch(() => {});
    },
  };
}

async function locatorVisible(locator: { count: () => Promise<number>; first: () => any }): Promise<boolean> {
  const count = await locator.count();
  if (count === 0) return false;
  return await locator.first().isVisible().catch(() => false);
}

async function fillFirstVisible(page: any, selectors: string[], value: string): Promise<boolean> {
  for (const selector of selectors) {
    const locator = page.locator(selector);
    if (!(await locatorVisible(locator))) continue;
    const element = locator.first();
    await element.click().catch(() => {});
    await element.fill(value);
    return true;
  }
  return false;
}

async function clickButtonByName(page: any, names: RegExp[]): Promise<boolean> {
  for (const name of names) {
    const locator = page.getByRole("button", { name });
    if (!(await locatorVisible(locator))) continue;
    await locator.first().click();
    return true;
  }
  return false;
}

async function fillCodeInputs(page: any, code: string): Promise<void> {
  const digitInputs = page.locator('input[id^="codeEntry-"], input[autocomplete="one-time-code"], input[inputmode="numeric"], input[maxlength="1"]');
  const digitCount = await digitInputs.count().catch(() => 0);
  if (digitCount >= code.length) {
    for (let index = 0; index < code.length; index += 1) {
      await digitInputs.nth(index).fill(code[index] || "");
    }
    return;
  }
  if (await fillFirstVisible(page, ['input[name="code"]', 'input[aria-label*="code" i]', 'input[placeholder*="code" i]', 'input[type="tel"]'], code)) {
    return;
  }
  throw new Error("chatgpt_otp_input_missing");
}

function hasPhoneVerificationSignal(text: string, url: string): boolean {
  return /(add phone|verify your phone|phone number|verify phone|\/add-phone|phone verification)/i.test(`${text} ${url}`);
}

async function pageText(page: any): Promise<string> {
  return String(await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
}

async function fillBirthDate(page: any, birthDate: string): Promise<boolean> {
  const [year, month, day] = birthDate.split("-");
  if (!year || !month || !day) return false;
  if (await fillFirstVisible(page, ['input[type="date"]'], birthDate)) {
    return true;
  }
  const selects = page.locator("select");
  const selectCount = await selects.count().catch(() => 0);
  if (selectCount >= 3) {
    await selects.nth(0).selectOption([{ value: month }, { label: String(Number(month)) }]).catch(() => {});
    await selects.nth(1).selectOption([{ value: day }, { label: String(Number(day)) }]).catch(() => {});
    await selects.nth(2).selectOption([{ value: year }, { label: year }]).catch(() => {});
    return true;
  }
  const yearFilled = await fillFirstVisible(page, ['input[name*="year" i]', 'input[placeholder*="year" i]'], year);
  const monthFilled = await fillFirstVisible(page, ['input[name*="month" i]', 'input[placeholder*="month" i]'], String(Number(month)));
  const dayFilled = await fillFirstVisible(page, ['input[name*="day" i]', 'input[placeholder*="day" i]'], String(Number(day)));
  return yearFilled || monthFilled || dayFilled;
}

async function handleProfileStep(page: any, nickname: string, birthDate: string): Promise<boolean> {
  const filledName = await fillFirstVisible(page, ['input[name*="name" i]', 'input[autocomplete="name"]', 'input[id*="name" i]'], nickname);
  const filledBirth = await fillBirthDate(page, birthDate);
  if (!filledName && !filledBirth) return false;
  await clickButtonByName(page, [/continue/i, /next/i, /finish/i, /submit/i]).catch(() => {});
  return true;
}

async function exchangeCodexTokens(input: { code: string; codeVerifier: string }): Promise<Record<string, unknown>> {
  const response = await fetch(`${OAUTH_ISSUER}/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: CALLBACK_URL,
      client_id: OAUTH_CLIENT_ID,
      code_verifier: input.codeVerifier,
    }),
  });
  const text = await response.text();
  const payload = text.trim() ? (JSON.parse(text) as Record<string, unknown>) : {};
  if (!response.ok) {
    throw new Error(`chatgpt_oauth_token_failed:${response.status}:${text.slice(0, 200)}`);
  }
  return payload;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return {};
    const raw = parts[1] || "";
    const padded = raw + "=".repeat((4 - (raw.length % 4 || 4)) % 4);
    return JSON.parse(Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function keepBrowserOpenOnFailure(page: any, browser: any, failureStage: string): Promise<void> {
  const enabled = /^(1|true|yes|on)$/i.test(String(process.env.KEEP_BROWSER_OPEN_ON_FAILURE || ""));
  if (!enabled) return;
  const holdMsRaw = Number.parseInt(String(process.env.KEEP_BROWSER_OPEN_MS || "").trim(), 10);
  const holdMs = Number.isFinite(holdMsRaw) && holdMsRaw > 0 ? holdMsRaw : 15 * 60_000;
  const currentUrl = page ? String(page.url?.() || "") : "";
  log(`holding headed browser for ${holdMs}ms after failure stage=${failureStage} url=${currentUrl}`);
  const deadline = Date.now() + holdMs;
  while (Date.now() < deadline) {
    const pageClosed = !page || (typeof page.isClosed === "function" ? page.isClosed() : false);
    const browserClosed = !browser || (typeof browser.isConnected === "function" ? !browser.isConnected() : false);
    if (pageClosed || browserClosed) return;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

async function run(): Promise<void> {
  const outputDir = requireEnv("CHATGPT_JOB_OUTPUT_DIR");
  await mkdir(outputDir, { recursive: true });
  const payload = parsePayload();
  const args = parseArgs(process.argv.slice(2));
  const cfg = loadConfig();
  const callbackState = createState();
  const { verifier, challenge } = createPkcePair();
  const callbackServer = await startCallbackServer(callbackState);
  const mihomo = await startMihomo({
    subscriptionUrl: requireEnv("MIHOMO_SUBSCRIPTION_URL"),
    apiPort: Number.parseInt(requireEnv("MIHOMO_API_PORT"), 10),
    mixedPort: Number.parseInt(requireEnv("MIHOMO_MIXED_PORT"), 10),
    groupName: requireEnv("MIHOMO_GROUP_NAME"),
    routeGroupName: requireEnv("MIHOMO_ROUTE_GROUP_NAME"),
    checkUrl: requireEnv("PROXY_CHECK_URL"),
    workDir: `${outputDir}/mihomo`,
    downloadDir: `${process.cwd()}/downloads/mihomo`,
  });
  let browser: any = null;
  let context: any = null;
  let page: any = null;
  let failureStage = "init";
  try {
    if (args.proxyNode) {
      await mihomo.setGroupProxy(args.proxyNode);
      log(`selected proxy node=${args.proxyNode}`);
    }

    browser = await launchBrowserWithEngine(cfg.browserEngine, cfg, "headed", mihomo.proxyServer, "en-US", "");
    context = await browser.newContext({
      locale: "en-US",
      viewport: { width: 1440, height: 960 },
      screen: { width: 1440, height: 960 },
    });
    page = await context.newPage();

    const authorizeUrl = buildAuthorizeUrl({ state: callbackState, codeChallenge: challenge });
    log(`opening authorize url for ${payload.email}`);
    await page.goto(authorizeUrl, { waitUntil: "domcontentloaded", timeout: 120000 });

    let otpRequestedAt = nowIso();
    const deadline = Date.now() + 12 * 60_000;
    while (Date.now() < deadline) {
      const currentUrl = String(page.url() || "");
      if (currentUrl.startsWith(CALLBACK_URL)) {
        break;
      }
      const text = await pageText(page);
      if (hasPhoneVerificationSignal(text, currentUrl)) {
        throw new Error("chatgpt_phone_verification_required");
      }
      if (/captcha|turnstile|hcaptcha|recaptcha/i.test(text) && /verify you are human/i.test(text)) {
        throw new Error("chatgpt_captcha_manual_required");
      }
      if (await fillFirstVisible(page, ['input[type="email"]', 'input[name="email"]', 'input[autocomplete="email"]'], payload.email)) {
        failureStage = "email_submit";
        otpRequestedAt = nowIso();
        await clickButtonByName(page, [/continue/i, /next/i, /submit/i, /email/i]).catch(() => {});
        await page.waitForTimeout(1200);
        continue;
      }
      const passwordFieldVisible = await locatorVisible(page.locator('input[type="password"], input[name="password"], input[autocomplete="new-password"], input[autocomplete="current-password"]'));
      if (passwordFieldVisible) {
        failureStage = "password_submit";
        const passwordInputs = page.locator('input[type="password"], input[name="password"], input[autocomplete="new-password"], input[autocomplete="current-password"]');
        const count = await passwordInputs.count();
        for (let index = 0; index < count; index += 1) {
          await passwordInputs.nth(index).fill(payload.password).catch(() => {});
        }
        await clickButtonByName(page, [/continue/i, /next/i, /sign up/i, /log in/i, /submit/i]).catch(() => {});
        await page.waitForTimeout(1200);
        continue;
      }
      const otpVisible = await locatorVisible(page.locator('input[id^="codeEntry-"], input[autocomplete="one-time-code"], input[name="code"], input[aria-label*="code" i], input[placeholder*="code" i]'));
      if (otpVisible || /verification code|enter code|one-time code|verify your email/i.test(text)) {
        failureStage = "email_otp";
        const code = await waitForCfMailOtp({
          address: payload.email,
          notBefore: otpRequestedAt,
          timeoutMs: 180_000,
          pollMs: 2500,
        });
        log(`received email otp (${code.length} digits)`);
        await fillCodeInputs(page, code);
        await clickButtonByName(page, [/continue/i, /verify/i, /next/i, /submit/i]).catch(() => {});
        await page.waitForTimeout(1200);
        continue;
      }
      if (await handleProfileStep(page, payload.nickname, payload.birthDate)) {
        failureStage = "profile_submit";
        await page.waitForTimeout(1200);
        continue;
      }
      if (await clickButtonByName(page, [/continue/i, /allow/i, /accept/i, /authorize/i])) {
        failureStage = "consent";
        await page.waitForTimeout(1200);
        continue;
      }
      await page.waitForTimeout(1000);
    }

    failureStage = "oauth_callback";
    const callback = await Promise.race([
      callbackServer.waitForCode,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("chatgpt_oauth_callback_timeout")), 120000)),
    ]);
    const tokenPayload = await exchangeCodexTokens({
      code: callback.code,
      codeVerifier: verifier,
    });
    const accessToken = String(tokenPayload.access_token || "").trim();
    const refreshToken = String(tokenPayload.refresh_token || "").trim();
    const idToken = String(tokenPayload.id_token || "").trim();
    if (!accessToken || !refreshToken || !idToken) {
      throw new Error("chatgpt_complete_credential_missing");
    }
    const idTokenPayload = decodeJwtPayload(idToken);
    const accountId = String(tokenPayload.account_id || idTokenPayload.sub || "").trim();
    const email = String(tokenPayload.email || idTokenPayload.email || payload.email).trim().toLowerCase();
    const expiresAt =
      typeof tokenPayload.expires_at === "string" && tokenPayload.expires_at.trim()
        ? tokenPayload.expires_at.trim()
        : typeof idTokenPayload.exp === "number" && Number.isFinite(idTokenPayload.exp)
          ? new Date(idTokenPayload.exp * 1000).toISOString()
          : null;

    await writeJson(`${outputDir}/result.json`, {
      mode: "headed",
      email,
      password: payload.password,
      nickname: payload.nickname,
      birthDate: payload.birthDate,
      credentials: {
        access_token: accessToken,
        refresh_token: refreshToken,
        id_token: idToken,
        account_id: accountId,
        expires_at: expiresAt,
        exp: typeof idTokenPayload.exp === "number" ? idTokenPayload.exp : null,
      },
      notes: [
        `mailbox=${payload.mailboxId}`,
        `proxy=${args.proxyNode || (await mihomo.getGroupSelection().catch(() => null)) || "default"}`,
      ],
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await writeJson(`${outputDir}/error.json`, {
      error: message,
      failureStage,
    });
    await keepBrowserOpenOnFailure(page, browser, failureStage);
    throw error;
  } finally {
    await callbackServer.close();
    await context?.close().catch(() => {});
    await browser?.close().catch(() => {});
    await mihomo.stop().catch(() => {});
  }
}

void run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
