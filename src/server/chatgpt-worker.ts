import { createHash, randomBytes } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { URL } from "node:url";
import process from "node:process";
import { promisify } from "node:util";
import { getCfMailMessage, listCfMailMessages, normalizeCfMailBaseUrl, type CfMailMessageSummary } from "../cfmail-api.js";
import { assertUsableFingerprintChromiumExecutablePath } from "../fingerprint-browser.js";
import { startMihomo } from "../proxy/mihomo.js";
import { calculateAgeYears, isBirthDateReadyFromVisibleValues, profileFullName } from "./chatgpt-profile.js";
import { completeMicrosoftLogin, launchBrowserWithEngine, launchNativeChromeCdp, loadConfig, type AppConfig } from "../main.js";
import {
  waitForMicrosoftMailboxVerificationCode,
} from "./microsoft-mailbox-verification.js";

const OAUTH_ISSUER = "https://auth.openai.com";
const OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const OAUTH_SCOPE = "openid profile email offline_access";
const CALLBACK_HOST = "localhost";
const CALLBACK_PORT = 1455;
const CALLBACK_PATH = "/auth/callback";
const CALLBACK_ORIGIN = `http://${CALLBACK_HOST}:${CALLBACK_PORT}`;
const CALLBACK_URL = `${CALLBACK_ORIGIN}${CALLBACK_PATH}`;
const execFile = promisify(execFileCallback);

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

type ChatGptAuthProvider = "email" | "microsoft";

type WorkerRunMode = AppConfig["runMode"];

interface ChatGptWorkerLaunchDeps {
  launchNativeChromeCdp: typeof launchNativeChromeCdp;
  launchBrowserWithEngine: typeof launchBrowserWithEngine;
}

interface ChatGptWorkerBrowserSession {
  browser: any;
  context: any;
  page: any;
  nativeChromeStop: (() => Promise<void>) | null;
  browserMode: "chrome-native-cdp" | "browser-engine";
  profileDir?: string;
}

interface CallbackResult {
  code: string;
  state: string;
}

interface SurfaceSnapshot {
  url: string;
  text: string;
  otpPrompt: boolean;
  otpVisible: boolean;
}

function log(message: string): void {
  console.log(`[chatgpt-worker] ${message}`);
}

export function assertTrustedChatGptWorkerChromiumExecutable(executablePath: string | undefined): string {
  try {
    return assertUsableFingerprintChromiumExecutablePath(executablePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`chatgpt_browser_not_project_provided:${message}`);
  }
}

function isPrimaryAuthSurface(url: string): boolean {
  return /auth\.openai\.com\/(log-in|create-account)(?:\/?$|\?)/i.test(url)
    || /auth\.openai\.com\/create-account\/password/i.test(url)
    || /auth\.openai\.com\/log-in\/password/i.test(url);
}

function nowIso(): string {
  return new Date().toISOString();
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function buildChatGptMicrosoftCompletionUrlPatterns(callbackUrl = CALLBACK_URL): RegExp[] {
  return [
    /^https:\/\/auth\.openai\.com\//i,
    new RegExp(`^${escapeRegex(callbackUrl)}`, "i"),
  ];
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function optionalEnv(name: string): string | null {
  const value = String(process.env[name] || "").trim();
  return value || null;
}

function getChatGptAuthProvider(): ChatGptAuthProvider {
  return String(process.env.CHATGPT_AUTH_PROVIDER || "").trim().toLowerCase() === "microsoft" ? "microsoft" : "email";
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
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeStageMarker(outputDir: string, stage: string, extra?: Record<string, unknown>): Promise<void> {
  await writeJson(`${outputDir}/stage.json`, {
    stage,
    updatedAt: nowIso(),
    ...(extra || {}),
  }).catch(() => {});
}

async function writeFailureArtifacts(outputDir: string, page: any, failureStage: string): Promise<void> {
  if (!page || (typeof page.isClosed === "function" && page.isClosed())) {
    return;
  }
  const currentUrl = String(page.url?.() || "");
  const title = await page.title().catch(() => "");
  const text = await pageText(page).catch(() => "");
  const payload = {
    failureStage,
    currentUrl,
    title,
    capturedAt: nowIso(),
    textPreview: text.slice(0, 4000),
  };
  const stageSlug = failureStage.replace(/[^a-z0-9_-]+/gi, "_").toLowerCase();
  const baseNames = [
    "failure-page",
    stageSlug ? `failure-page-${stageSlug}` : "",
  ].filter(Boolean);
  for (const baseName of baseNames) {
    await writeJson(`${outputDir}/${baseName}.json`, payload).catch(() => {});
    await writeFile(`${outputDir}/${baseName}.txt`, `${text}\n`, "utf8").catch(() => {});
    await page.screenshot({
      path: `${outputDir}/${baseName}.png`,
      fullPage: true,
    }).catch(() => {});
  }
}

export async function launchChatGptWorkerBrowser(
  cfg: AppConfig,
  proxyServer: string,
  deps: ChatGptWorkerLaunchDeps = {
    launchNativeChromeCdp,
    launchBrowserWithEngine,
  },
): Promise<ChatGptWorkerBrowserSession> {
  if (cfg.browserEngine === "chrome" && cfg.chromeNativeAutomation) {
    const launched = await deps.launchNativeChromeCdp(
      cfg,
      cfg.runMode,
      proxyServer,
      "en-US",
      "en-US,en;q=0.9",
      undefined,
      undefined,
      ["about:blank"],
    );
    const context = launched.context;
    const existingPages = typeof context.pages === "function" ? context.pages() : [];
    const page = existingPages.find((item: any) => item && typeof item.url === "function") || await context.newPage();
    return {
      browser: launched.browser,
      context,
      page,
      nativeChromeStop: launched.stop,
      browserMode: "chrome-native-cdp",
      profileDir: launched.details.profileDir,
    };
  }

  const browser = await deps.launchBrowserWithEngine(cfg.browserEngine, cfg, cfg.runMode, proxyServer, "en-US", "");
  const context = await browser.newContext({
    locale: "en-US",
    viewport: { width: 1440, height: 960 },
    screen: { width: 1440, height: 960 },
  });
  const page = await context.newPage();
  return {
    browser,
    context,
    page,
    nativeChromeStop: null,
    browserMode: "browser-engine",
  };
}

export function buildChatGptWorkerResult(input: {
  mode: WorkerRunMode;
  email: string;
  password: string;
  nickname: string;
  birthDate: string;
  accountId: string;
  expiresAt: string | null;
  tokenPayload: Record<string, unknown>;
  idTokenPayload: Record<string, unknown>;
  accessToken: string;
  refreshToken: string;
  idToken: string;
  notes: string[];
}): Record<string, unknown> {
  return {
    mode: input.mode,
    email: input.email,
    password: input.password,
    nickname: input.nickname,
    birthDate: input.birthDate,
    credentials: {
      access_token: input.accessToken,
      refresh_token: input.refreshToken,
      id_token: input.idToken,
      account_id: input.accountId,
      expires_at: input.expiresAt,
      token_type: typeof input.tokenPayload.token_type === "string" ? input.tokenPayload.token_type : null,
      exp: typeof input.idTokenPayload.exp === "number" ? input.idTokenPayload.exp : null,
    },
    notes: input.notes,
  };
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

async function waitForCfMailOtp(input: { address: string; mailboxId?: string; notBefore: string; timeoutMs: number; pollMs: number }): Promise<string> {
  const baseUrl = normalizeCfMailBaseUrl(process.env.CFMAIL_BASE_URL || "https://api.cfm.example.test");
  const apiKey = requireEnv("CFMAIL_API_KEY");
  const seen = new Set<string>();
  let lastMessageCount = 0;
  const deadline = Date.now() + input.timeoutMs;
  while (Date.now() < deadline) {
    let messages: CfMailMessageSummary[] = [];
    try {
      messages = await listCfMailMessages({
        baseUrl,
        apiKey,
        mailboxId: input.mailboxId,
        address: input.address,
        httpJson,
        since: input.notBefore,
      });
      const mailboxId = String(input.mailboxId || "").trim();
      const normalizedAddress = input.address.trim().toLowerCase();
      if (mailboxId || normalizedAddress) {
        messages = messages.filter((message) => {
          const messageMailboxId = String(message?.mailboxId || "").trim();
          const messageMailboxAddress = String(message?.mailboxAddress || "").trim().toLowerCase();
          if (mailboxId && messageMailboxId === mailboxId) return true;
          if (normalizedAddress && messageMailboxAddress === normalizedAddress) return true;
          return false;
        });
      }
      lastMessageCount = messages.length;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log(`cfmail poll failed for ${input.address}: ${message}`);
      await new Promise((resolve) => setTimeout(resolve, input.pollMs));
      continue;
    }
    for (const message of messages) {
      if (!message?.id || seen.has(message.id)) continue;
      seen.add(message.id);
      const detail = await getCfMailMessage({
        baseUrl,
        apiKey,
        messageId: message.id,
        httpJson,
      }).catch((error) => {
        const detailMessage = error instanceof Error ? error.message : String(error);
        log(`cfmail detail failed for ${input.address} message=${message.id}: ${detailMessage}`);
        return null;
      });
      const code = detail ? extractOpenAiOtpCode(detail) : null;
      if (code) return code;
    }
    await new Promise((resolve) => setTimeout(resolve, input.pollMs));
  }
  throw new Error(`chatgpt_email_otp_timeout:messages=${lastMessageCount}`);
}

async function startCallbackServer(expectedStateRef: { current: string }): Promise<{ waitForCode: Promise<CallbackResult>; close: () => Promise<void> }> {
  void expectedStateRef;
  log("callback capture ready; relying on observed callback urls without binding localhost:1455");
  return {
    waitForCode: new Promise<CallbackResult>(() => {}),
    close: async () => {},
  };
}

async function locatorVisible(locator: { count: () => Promise<number>; first: () => any }): Promise<boolean> {
  try {
    const count = await locator.count().catch(() => 0);
    if (count === 0) return false;
    return await locator.first().isVisible().catch(() => false);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`locator visibility probe failed: ${message}`);
    return false;
  }
}

function parseCallbackResultFromUrl(rawUrl: string, expectedState: string): CallbackResult | null {
  try {
    const url = new URL(rawUrl);
    if (`${url.origin}${url.pathname}` !== CALLBACK_URL) {
      return null;
    }
    const code = String(url.searchParams.get("code") || "").trim();
    const state = String(url.searchParams.get("state") || "").trim();
    if (!code || state !== expectedState) {
      return null;
    }
    return { code, state };
  } catch {
    return null;
  }
}

function randomTypingDelayMs(): number {
  return 100 + Math.floor(Math.random() * 401);
}

async function forceExactInputValue(element: any, value: string): Promise<boolean> {
  await element.fill("").catch(() => {});
  await element
    .evaluate((node: HTMLInputElement | HTMLTextAreaElement, nextValue: string) => {
      if ("value" in node) {
        node.value = "";
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        node.value = nextValue;
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }, value)
    .catch(() => {});
  await element.fill(value).catch(() => {});
  const typedValue = await element.inputValue().catch(() => "");
  return typedValue === value;
}

async function slowTypeIntoElement(page: any, element: any, value: string): Promise<boolean> {
  await page.waitForLoadState("domcontentloaded").catch(() => {});
  await sleepMs(randomTypingDelayMs());
  await element.focus().catch(() => {});
  await element.click({ timeout: 3000 }).catch(() => {});
  await element.press("Meta+A", { timeout: 3000 }).catch(() => {});
  await element.press("Control+A", { timeout: 3000 }).catch(() => {});
  await element.press("Backspace", { timeout: 3000 }).catch(() => {});
  await element.fill("", { timeout: 3000 }).catch(() => {});
  await element
    .evaluate((node: HTMLInputElement | HTMLTextAreaElement) => {
      if ("value" in node) {
        node.value = "";
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
      }
    })
    .catch(() => {});
  for (const ch of value) {
    await element.type(ch, { delay: 0, timeout: 3000 }).catch(() => null);
    await sleepMs(randomTypingDelayMs());
  }
  await sleepMs(300 + Math.floor(Math.random() * 901));
  const typedValue = await element.inputValue().catch(() => "");
  if (typedValue === value) {
    return true;
  }
  return forceExactInputValue(element, value);
}

async function fillFirstVisible(page: any, selectors: string[], value: string): Promise<boolean> {
  for (const selector of selectors) {
    const locator = page.locator(selector);
    if (!(await locatorVisible(locator))) continue;
    const element = locator.first();
    if (typeof element.isEditable === "function") {
      const editable = await element.isEditable().catch(() => true);
      if (!editable) continue;
    }
    if (await slowTypeIntoElement(page, element, value)) {
      return true;
    }
  }
  return false;
}

async function clickByRoleName(page: any, role: "button" | "link" | "option", names: RegExp[]): Promise<boolean> {
  for (const name of names) {
    const locator = page.getByRole(role, { name });
    if (!(await locatorVisible(locator))) continue;
    await locator.first().click({ force: true }).catch(() => locator.first().click());
    return true;
  }
  return false;
}

async function clickButtonByName(page: any, names: RegExp[]): Promise<boolean> {
  return clickByRoleName(page, "button", names);
}

async function clickVisibleText(page: any, names: RegExp[]): Promise<boolean> {
  for (const name of names) {
    const locator = page.getByText(name).first();
    if (!(await locator.isVisible().catch(() => false))) continue;
    await locator.click({ force: true }).catch(() => locator.click());
    return true;
  }
  return false;
}

async function activateAction(page: any, names: RegExp[]): Promise<boolean> {
  if (await clickByRoleName(page, "button", names)) return true;
  if (await clickByRoleName(page, "link", names)) return true;
  if (await clickVisibleText(page, names)) return true;
  return false;
}

async function clickMicrosoftProviderEntry(page: any): Promise<boolean> {
  return await activateAction(page, [
    /continue with microsoft/i,
    /sign in with microsoft/i,
    /^microsoft$/i,
  ]);
}

function getRetainPath(): string | null {
  return optionalEnv("ACCOUNT_BUSINESS_FLOW_RETAIN_PATH");
}

function isFingerprintBusinessFlow(): boolean {
  return String(process.env.ACCOUNT_BUSINESS_FLOW_MODE || "").trim().toLowerCase() === "fingerprint";
}

async function holdBrowserForBusinessFlowHandoff(
  page: any,
  browser: any,
  outputDir: string,
  stage: string,
  extra?: Record<string, unknown>,
): Promise<void> {
  const retainPath = getRetainPath();
  if (!retainPath) return;
  await writeJson(retainPath, {
    retainedAt: nowIso(),
    stage,
    currentUrl: page ? String(page.url?.() || "") : "",
    ...extra,
  }).catch(() => {});
  const currentUrl = page ? String(page.url?.() || "") : "";
  log(`holding browser for fingerprint handoff stage=${stage} url=${currentUrl}`);
  while (true) {
    const pageClosed = !page || (typeof page.isClosed === "function" ? page.isClosed() : false);
    const browserClosed = !browser || (typeof browser.isConnected === "function" ? !browser.isConnected() : false);
    if (pageClosed || browserClosed) return;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

async function requestSubmitVisibleAuthForm(page: any): Promise<string | null> {
  try {
    return await page.evaluate(() => {
      const isVisible = (el: Element | null): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        return style.display !== "none" && style.visibility !== "hidden";
      };
      const submitter =
        Array.from(
          document.querySelectorAll(
            'button[type="submit"], input[type="submit"], button[data-action-button-primary="true"], button[name="action"]',
          ),
        ).find(isVisible) || null;
      const form =
        (submitter instanceof HTMLElement ? submitter.closest("form") : null) ||
        Array.from(document.querySelectorAll("form")).find(isVisible) ||
        null;
      if (!(form instanceof HTMLFormElement)) return null;
      if (typeof form.requestSubmit === "function") {
        if (submitter instanceof HTMLElement) {
          form.requestSubmit(submitter as HTMLButtonElement);
          return "form.requestSubmit(submitter)";
        }
        form.requestSubmit();
        return "form.requestSubmit()";
      }
      if (submitter instanceof HTMLElement && typeof submitter.click === "function") {
        submitter.click();
        return "submitter.click()";
      }
      form.submit();
      return "form.submit()";
    });
  } catch {
    return null;
  }
}

async function submitCurrentStep(page: any, names: RegExp[], label: string): Promise<void> {
  if (await activateAction(page, names)) {
    log(`${label} submit triggered via role click`);
    return;
  }
  const submitted = await requestSubmitVisibleAuthForm(page);
  if (submitted) {
    log(`${label} submit triggered via ${submitted}`);
    return;
  }
  await page.keyboard.press("Enter").catch(() => {});
  log(`${label} submit triggered via Enter`);
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
  const labeledCodeInput = page.getByLabel(/code/i).first();
  if (await labeledCodeInput.isVisible().catch(() => false)) {
    await labeledCodeInput.click().catch(() => {});
    await labeledCodeInput.fill(code, { timeout: 5000 }).catch(() => null);
    const value = await labeledCodeInput.inputValue().catch(() => "");
    if (value === code) {
      return;
    }
  }
  if (await fillFirstVisible(page, ['input[name="code"]', 'input[aria-label*="code" i]', 'input[placeholder*="code" i]', 'input[type="tel"]'], code)) {
    return;
  }
  if (
    await fillFirstVisible(
      page,
      [
        'input:not([type="hidden"]):not([type="email"]):not([type="password"])',
        'textarea',
      ],
      code,
    )
  ) {
    return;
  }
  throw new Error("chatgpt_otp_input_missing");
}

async function hasOtpInput(page: any): Promise<boolean> {
  const directLocator = page.locator(
    'input[id^="codeEntry-"], input[autocomplete="one-time-code"], input[name="code"], input[aria-label*="code" i], input[placeholder*="code" i], input[type="tel"]',
  );
  if (await locatorVisible(directLocator)) {
    return true;
  }
  const labeledCodeInput = page.getByLabel(/code/i).first();
  if (await labeledCodeInput.isVisible().catch(() => false)) {
    return true;
  }
  const genericOtpInput = page.locator('input:not([type="hidden"]):not([type="email"]):not([type="password"]), textarea');
  return locatorVisible(genericOtpInput);
}

async function waitForOtpInputReady(page: any, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await hasOtpInput(page)) {
      return true;
    }
    await page.waitForTimeout(1000);
  }
  return hasOtpInput(page);
}

function hasPhoneVerificationSignal(text: string, url: string): boolean {
  return /(add phone|verify your phone|phone number|verify phone|\/add-phone|phone verification)/i.test(`${text} ${url}`);
}

function hasOtpPromptSignal(text: string): boolean {
  if (/use one-time code/i.test(text) && !/check your email|check your inbox|verification code|verify your email|enter code|email verification/i.test(text)) {
    return false;
  }
  return /check your email|check your inbox|verification code|verify your email|enter code|email verification|we sent a code/i.test(text);
}

function hasConsentPromptSignal(currentUrl: string, text: string): boolean {
  return /\/consent(?:\/|$)|allow access|authorize app|app permissions|continue to application|sign in to codex with chatgpt|share your name, email, and profile picture|codex will not receive your chat history/i.test(
    `${currentUrl} ${text}`,
  );
}

function hasProfileSetupSignal(currentUrl: string, text: string): boolean {
  return /about-you|birthday|date of birth|confirm your age|full name|use date of birth/i.test(`${currentUrl} ${text}`);
}

function hasOrganizationSelectionSignal(currentUrl: string, text: string): boolean {
  return /sign-in-with-chatgpt\/codex\/organization|default project|new organization|finish setting up on the next page|choose .*organization|select .*organization/i.test(
    `${currentUrl} ${text}`,
  );
}

function isPreOtpAuthSurface(currentUrl: string): boolean {
  return /auth\.openai\.com\/(?:oauth\/authorize|log-in|create-account)(?:\/|$|\?)/i.test(currentUrl);
}

function hasRecoverableAuthErrorSignal(text: string): boolean {
  return /oops,? an error occurred|operation timed out|something went wrong|request timed out|please try again|failed to fetch/i.test(text);
}

function hasRecoverableProfileErrorSignal(text: string): boolean {
  return /oops,? an error occurred|operation timed out|something went wrong|request timed out|please try again|invalid content type|route error/i.test(
    text,
  );
}

function hasAuthChallengeSignal(currentUrl: string, text: string): boolean {
  return /__cf_chl_rt_tk=|just a moment|checking your browser|cloudflare|security check|enable javascript and cookies/i.test(
    `${currentUrl} ${text}`,
  );
}

async function navigateBackForRecovery(page: any, reason: string): Promise<boolean> {
  const beforeUrl = String(page.url?.() || "");
  try {
    await page.goBack({ waitUntil: "domcontentloaded", timeout: 15000 });
  } catch {
    return false;
  }
  await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(2000);
  const afterUrl = String(page.url?.() || "");
  if (afterUrl && afterUrl !== beforeUrl) {
    log(`recovered from ${reason} via browser back navigation -> ${afterUrl}`);
    return true;
  }
  return false;
}

async function navigateForwardForRecovery(page: any, reason: string): Promise<boolean> {
  const beforeUrl = String(page.url?.() || "");
  try {
    await page.goForward({ waitUntil: "domcontentloaded", timeout: 15000 });
  } catch {
    return false;
  }
  await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(2000);
  const afterUrl = String(page.url?.() || "");
  if (afterUrl && afterUrl !== beforeUrl) {
    log(`recovered from ${reason} via browser forward navigation -> ${afterUrl}`);
    return true;
  }
  return false;
}

async function pageText(page: any): Promise<string> {
  try {
    const [title, raw] = await Promise.all([
      page.title().catch(() => ""),
      page.locator("body").innerText({ timeout: 5000 }).catch(() => ""),
    ]);
    return `${String(title || "")} ${String(raw || "")}`.replace(/\s+/g, " ").trim();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`page text read failed: ${message}`);
    return "";
  }
}

async function captureSurfaceSnapshot(page: any): Promise<SurfaceSnapshot> {
  const url = String(page.url() || "");
  const text = await pageText(page).catch(() => "");
  const otpPrompt = /email-verification/i.test(url) || hasOtpPromptSignal(text);
  const otpVisible = otpPrompt ? await hasOtpInput(page) : false;
  return {
    url,
    text,
    otpPrompt,
    otpVisible,
  };
}

async function waitForPostPasswordSurface(page: any, timeoutMs: number): Promise<SurfaceSnapshot> {
  const deadline = Date.now() + timeoutMs;
  let snapshot = await captureSurfaceSnapshot(page);
  while (Date.now() < deadline) {
    if (
      snapshot.otpPrompt
      || snapshot.otpVisible
      || hasPhoneVerificationSignal(snapshot.text, snapshot.url)
      || hasConsentPromptSignal(snapshot.url, snapshot.text)
      || hasProfileSetupSignal(snapshot.url, snapshot.text)
      || hasOrganizationSelectionSignal(snapshot.url, snapshot.text)
      || /auth\/callback/i.test(snapshot.url)
    ) {
      return snapshot;
    }
    await sleepMs(500);
    snapshot = await captureSurfaceSnapshot(page);
  }
  return snapshot;
}

async function settleLoadState(page: any, label: string, timeoutMs: number): Promise<void> {
  try {
    await page.waitForLoadState("domcontentloaded", { timeout: timeoutMs });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`${label} load wait failed: ${message}`);
  }
}

async function cleanupWithTimeout(task: Promise<unknown>, timeoutMs = 5_000): Promise<void> {
  await Promise.race([task.catch(() => {}), sleepMs(timeoutMs)]);
}

async function maybeSwitchToCreateAccount(page: any, currentUrl: string, text: string): Promise<boolean> {
  if (!/log[- ]?in|sign[- ]?in|sign in|continue with email/i.test(`${currentUrl} ${text}`)) {
    return false;
  }
  const activated = await activateAction(page, [/^create account$/i, /^sign up$/i, /sign up for free/i, /get started/i]);
  if (activated) {
    log("switched auth surface to create-account");
  }
  return activated;
}

async function maybeSwitchToLogin(page: any, currentUrl: string, text: string): Promise<boolean> {
  if (!/create-account/i.test(currentUrl)) {
    return false;
  }
  if (!/account for this email address already exists|email address already exists|already exists/i.test(text)) {
    return false;
  }
  const activated = await activateAction(page, [/^log in$/i, /^login$/i, /already have an account\?\s*log in/i, /sign in/i]);
  if (activated) {
    log("switched auth surface to log-in");
  }
  return activated;
}

async function maybeSwitchKnownAccountToLogin(page: any, currentUrl: string, text: string): Promise<boolean> {
  if (!/create-account|sign up|sign-up|create a password/i.test(`${currentUrl} ${text}`)) {
    return false;
  }
  const activated = await activateAction(page, [/^log in$/i, /^login$/i, /already have an account\?\s*log in/i, /sign in/i]);
  if (activated) {
    log("switched auth surface to log-in for a known existing account");
  }
  return activated;
}

async function maybeSwitchToOtpLogin(page: any, currentUrl: string, text: string): Promise<boolean> {
  if (!/log-in\/password/i.test(currentUrl)) {
    return false;
  }
  if (!/incorrect email address or password|log in with a one-time code|use one-time code/i.test(text)) {
    return false;
  }
  const activated = await activateAction(page, [/log in with a one-time code/i, /use one-time code/i, /one-time code/i]);
  if (activated) {
    log("switched auth surface to one-time-code login after password rejection");
  }
  return activated;
}

async function maybePreferOtpLogin(page: any, currentUrl: string, text: string, enabled: boolean): Promise<boolean> {
  if (!enabled || !/log-in\/password/i.test(currentUrl)) {
    return false;
  }
  if (!/log in with a one-time code|use one-time code|one-time code/i.test(text)) {
    return false;
  }
  const activated = await activateAction(page, [/log in with a one-time code/i, /use one-time code/i, /one-time code/i]);
  if (activated) {
    log("switched auth surface to one-time-code login proactively");
  }
  return activated;
}

async function pickSequentialOption(page: any, triggerSelector: string, index: number, optionNames: RegExp[]): Promise<boolean> {
  const triggers = page.locator(triggerSelector);
  const count = await triggers.count().catch(() => 0);
  if (count <= index) return false;
  await triggers.nth(index).click({ force: true }).catch(() => {});
  await page.waitForTimeout(300);
  return clickByRoleName(page, "option", optionNames);
}

async function fillBirthDate(page: any, birthDate: string): Promise<boolean> {
  const [year, month, day] = birthDate.split("-");
  if (!year || !month || !day) return false;
  const numericBirthDate = `${month}/${day}/${year}`;
  const expectedTokens = [year, month, day, String(Number(month)), String(Number(day))];
  const birthSelectors = [
    'input[type="date"]',
    'select',
    'input[name*="birthday" i]',
    'input[id*="birthday" i]',
    'input[aria-label*="birthday" i]',
    'input[placeholder*="MM / DD / YYYY" i]',
    'input[placeholder*="MM/DD/YYYY" i]',
    'input[name*="year" i]',
    'input[placeholder*="year" i]',
    'input[placeholder="YYYY" i]',
    'input[name*="month" i]',
    'input[placeholder*="month" i]',
    'input[placeholder="MM" i]',
    'input[name*="day" i]',
    'input[placeholder*="day" i]',
    'input[placeholder="DD" i]',
    '[role="combobox"]',
    'button[aria-haspopup="listbox"]',
    '[role="spinbutton"][data-type="month"]',
    '[role="spinbutton"][data-type="day"]',
    '[role="spinbutton"][data-type="year"]',
  ];
  const matchesBirthDate = async (): Promise<boolean> => {
    const values = await readVisibleValues(page, birthSelectors);
    const hiddenBirthValue = await readHiddenBirthValue(page);
    const visibleMatch = expectedTokens.every((part) => part && values.some((value) => value.includes(part) || value === part));
    if (!visibleMatch) return false;
    return !hiddenBirthValue || hiddenBirthValue === birthDate;
  };
  if (await syncHiddenBirthValue(page, birthDate).catch(() => false)) {
    await page.waitForTimeout(350);
    if (await matchesBirthDate()) return true;
  }
  if (await fillFirstVisible(page, ['input[type="date"]'], birthDate)) {
    await syncHiddenBirthValue(page, birthDate).catch(() => false);
    await page.waitForTimeout(250);
    if (await matchesBirthDate()) return true;
  }
  if (
    await fillFirstVisible(
      page,
      [
        'input[name*="birthday" i]',
        'input[id*="birthday" i]',
        'input[aria-label*="birthday" i]',
        'input[placeholder*="MM / DD / YYYY" i]',
        'input[placeholder*="MM/DD/YYYY" i]',
      ],
      numericBirthDate,
    )
  ) {
    await syncHiddenBirthValue(page, birthDate).catch(() => false);
    await page.waitForTimeout(250);
    if (await matchesBirthDate()) return true;
  }
  const visibleTextInputs = page.locator('input:not([type="hidden"]):not([type="password"]):not([type="email"])');
  const visibleTextCount = await visibleTextInputs.count().catch(() => 0);
  let fallbackBirthInputIndex = -1;
  for (let index = 0; index < visibleTextCount; index += 1) {
    const input = visibleTextInputs.nth(index);
    const visible = await input.isVisible().catch(() => false);
    if (!visible) continue;
    const attrs = [
      await input.getAttribute("name").catch(() => ""),
      await input.getAttribute("id").catch(() => ""),
      await input.getAttribute("aria-label").catch(() => ""),
      await input.getAttribute("placeholder").catch(() => ""),
      await input.inputValue().catch(() => ""),
    ]
      .filter(Boolean)
      .join(" ");
    if (/birth|date|mm|dd|yyyy|\d{1,2}\/\d{1,2}\/\d{4}/i.test(attrs)) {
      fallbackBirthInputIndex = index;
      break;
    }
  }
  if (fallbackBirthInputIndex >= 0) {
    const input = visibleTextInputs.nth(fallbackBirthInputIndex);
    await input.click({ force: true }).catch(() => {});
    const inputType = String((await input.getAttribute("type").catch(() => "")) || "").toLowerCase();
    const preferredValue = inputType === "date" ? birthDate : numericBirthDate;
    await page.keyboard.press("Meta+A").catch(() => {});
    await page.keyboard.press("Control+A").catch(() => {});
    await page.keyboard.press("Backspace").catch(() => {});
    await input.fill(preferredValue).catch(() => {});
    await page.keyboard.type(preferredValue, { delay: 40 }).catch(() => {});
    await input
      .evaluate((element: HTMLInputElement, value: string) => {
        element.value = value;
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
      }, preferredValue)
      .catch(() => {});
    await input.press("Tab").catch(() => {});
    const value = String(await input.inputValue().catch(() => "")).trim();
    await syncHiddenBirthValue(page, birthDate).catch(() => false);
    if ((value.includes(year) || value === numericBirthDate || value === birthDate) && (await matchesBirthDate())) {
      return true;
    }
  }
  const selects = page.locator("select");
  const selectCount = await selects.count().catch(() => 0);
  if (selectCount >= 3) {
    await selects.nth(0).selectOption([{ value: month }, { label: String(Number(month)) }]).catch(() => {});
    await selects.nth(1).selectOption([{ value: day }, { label: String(Number(day)) }]).catch(() => {});
    await selects.nth(2).selectOption([{ value: year }, { label: year }]).catch(() => {});
    await page.waitForTimeout(250);
    if (await matchesBirthDate()) return true;
  }
  const monthNumber = Number(month);
  const monthNames = [
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];
  const monthPatterns = [new RegExp(`^${monthNumber}$`), new RegExp(`^${monthNames[monthNumber] || monthNumber}$`, "i")];
  const dayPatterns = [new RegExp(`^${Number(day)}$`)];
  const yearPatterns = [new RegExp(`^${year}$`)];
  const pickedComboboxBirthDate =
    (await pickSequentialOption(page, '[role="combobox"]', 0, monthPatterns)) &&
    (await pickSequentialOption(page, '[role="combobox"]', 1, dayPatterns)) &&
    (await pickSequentialOption(page, '[role="combobox"]', 2, yearPatterns));
  if (pickedComboboxBirthDate) {
    await syncHiddenBirthValue(page, birthDate).catch(() => false);
    await page.waitForTimeout(250);
    if (await matchesBirthDate()) return true;
  }
  const pickedListboxBirthDate =
    (await pickSequentialOption(page, 'button[aria-haspopup="listbox"]', 0, monthPatterns)) &&
    (await pickSequentialOption(page, 'button[aria-haspopup="listbox"]', 1, dayPatterns)) &&
    (await pickSequentialOption(page, 'button[aria-haspopup="listbox"]', 2, yearPatterns));
  if (pickedListboxBirthDate) {
    await syncHiddenBirthValue(page, birthDate).catch(() => false);
    await page.waitForTimeout(400);
    if (await matchesBirthDate()) return true;
  }
  const spinbuttonValues = [
    { selector: '[role="spinbutton"][data-type="month"]', value: month },
    { selector: '[role="spinbutton"][data-type="day"]', value: day },
    { selector: '[role="spinbutton"][data-type="year"]', value: year },
  ];
  let filledSpinbuttons = true;
  for (const spinbutton of spinbuttonValues) {
    const control = page.locator(spinbutton.selector).first();
    const visible = await control.isVisible().catch(() => false);
    if (!visible) {
      filledSpinbuttons = false;
      break;
    }
    await control.click({ force: true }).catch(() => {});
    await page.keyboard.press("Meta+A").catch(() => {});
    await page.keyboard.press("Control+A").catch(() => {});
    await page.keyboard.press("Backspace").catch(() => {});
    await page.keyboard.type(spinbutton.value, { delay: 40 }).catch(() => {});
    await control
      .evaluate((element: HTMLElement, value: string) => {
        element.textContent = value;
        element.setAttribute("aria-valuenow", String(Number(value) || value));
        element.setAttribute("aria-valuetext", value);
        element.dispatchEvent(new InputEvent("beforeinput", { bubbles: true, inputType: "insertText", data: value }));
        element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
        element.dispatchEvent(new Event("blur", { bubbles: true }));
      }, spinbutton.value)
      .catch(() => {});
    await page.keyboard.press("Tab").catch(() => {});
  }
  if (filledSpinbuttons) {
    await syncHiddenBirthValue(page, birthDate).catch(() => false);
    await page.waitForTimeout(400);
    if (await matchesBirthDate()) return true;
  }
  const yearFilled = await fillFirstVisible(
    page,
    ['input[name*="year" i]', 'input[placeholder*="year" i]', 'input[placeholder="YYYY" i]', 'input[placeholder*="YYYY" i]'],
    year,
  );
  const monthFilled = await fillFirstVisible(
    page,
    ['input[name*="month" i]', 'input[placeholder*="month" i]', 'input[placeholder="MM" i]', 'input[placeholder^="MM" i]'],
    month,
  );
  const dayFilled = await fillFirstVisible(
    page,
    ['input[name*="day" i]', 'input[placeholder*="day" i]', 'input[placeholder="DD" i]', 'input[placeholder^="DD" i]'],
    day,
  );
  if (!(yearFilled && monthFilled && dayFilled)) {
    return false;
  }
  await syncHiddenBirthValue(page, birthDate).catch(() => false);
  await page.waitForTimeout(250);
  return await matchesBirthDate();
}

async function readHiddenBirthValue(page: any): Promise<string> {
  return String(
    await page
      .locator(
        'input[type="hidden"][name*="birthday" i], input[type="hidden"][id*="birthday" i], input[type="hidden"][name*="birth" i], input[type="hidden"][id*="birth" i]',
      )
      .first()
      .inputValue()
      .catch(() => ""),
  ).trim();
}

async function syncHiddenBirthValue(page: any, birthDate: string): Promise<boolean> {
  const hiddenLocator = page.locator(
    'input[type="hidden"][name*="birthday" i], input[type="hidden"][id*="birthday" i], input[type="hidden"][name*="birth" i], input[type="hidden"][id*="birth" i]',
  );
  const count = await hiddenLocator.count().catch(() => 0);
  if (count === 0) {
    return false;
  }
  await hiddenLocator
    .evaluateAll((elements: HTMLInputElement[], value: string) => {
      for (const element of elements) {
        element.value = value;
        element.defaultValue = value;
        element.setAttribute("value", value);
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
        element.dispatchEvent(new Event("blur", { bubbles: true }));
      }
    }, birthDate)
    .catch(() => {});
  return (await readHiddenBirthValue(page)) === birthDate;
}

async function fillAgeYears(page: any, birthDate: string): Promise<boolean> {
  const ageYears = calculateAgeYears(birthDate);
  return await fillFirstVisible(
    page,
    ['input[name*="age" i]', 'input[aria-label*="age" i]', 'input[placeholder*="age" i]', 'input[inputmode="numeric"]'],
    ageYears,
  );
}

async function readVisibleValues(page: any, selectors: string[]): Promise<string[]> {
  const values: string[] = [];
  for (const selector of selectors) {
    const locator = page.locator(selector);
    const count = await locator.count().catch(() => 0);
    for (let index = 0; index < count; index += 1) {
      const element = locator.nth(index);
      const visible = await element.isVisible().catch(() => false);
      if (!visible) continue;
      const value =
        (await element.inputValue?.().catch(() => "")) ||
        (await element.textContent?.().catch(() => "")) ||
        "";
      if (value.trim()) {
        values.push(value.trim());
      }
    }
  }
  return values;
}

async function writeProfileControlDiagnostics(page: any, outputDir: string, label: string): Promise<void> {
  const controls = await page
    .evaluate(() => {
      const selectors = [
        "input",
        "select",
        "textarea",
        "button",
        "[role='combobox']",
        "[aria-haspopup='listbox']",
      ];
      const nodes = Array.from(document.querySelectorAll(selectors.join(",")));
      return nodes.map((node) => {
        const element = node as HTMLElement & {
          value?: string;
          type?: string;
          name?: string;
          id?: string;
          placeholder?: string;
        };
        const style = window.getComputedStyle(element);
        const hidden =
          style.display === "none"
          || style.visibility === "hidden"
          || element.getAttribute("aria-hidden") === "true"
          || element.getAttribute("type") === "hidden";
        return {
          tag: element.tagName.toLowerCase(),
          type: String(element.getAttribute("type") || element.type || ""),
          name: String(element.getAttribute("name") || element.name || ""),
          id: String(element.getAttribute("id") || element.id || ""),
          placeholder: String(element.getAttribute("placeholder") || element.placeholder || ""),
          ariaLabel: String(element.getAttribute("aria-label") || ""),
          role: String(element.getAttribute("role") || ""),
          text: String(element.textContent || "").replace(/\s+/g, " ").trim(),
          value: "value" in element ? String(element.value || "") : "",
          hidden,
        };
      });
    })
    .catch(() => []);
  const html = await page.content().catch(() => "");
  const text = await pageText(page).catch(() => "");
  const filePath = `${outputDir}/profile-controls-${label}.json`;
  await writeJson(filePath, {
    capturedAt: nowIso(),
    currentUrl: page.url?.() || "",
    title: await page.title?.().catch(() => ""),
    text,
    html,
    controls,
  }).catch(() => {});
  log(`wrote profile controls diagnostics file=${filePath} controls=${Array.isArray(controls) ? controls.length : 0}`);
}

async function hasVisibleControl(page: any, selectors: string[]): Promise<boolean> {
  for (const selector of selectors) {
    if (await locatorVisible(page.locator(selector))) {
      return true;
    }
  }
  return false;
}

async function countVisibleControls(page: any, selector: string): Promise<number> {
  const locator = page.locator(selector);
  const count = await locator.count().catch(() => 0);
  let visibleCount = 0;
  for (let index = 0; index < count; index += 1) {
    if (await locator.nth(index).isVisible().catch(() => false)) {
      visibleCount += 1;
    }
  }
  return visibleCount;
}

async function maybeConfirmBirthDate(page: any): Promise<boolean> {
  const text = await pageText(page);
  if (!/you're setting your birthday|this is just for our records/i.test(text)) {
    return false;
  }
  const confirmed = await activateAction(page, [/^ok$/i, /^confirm$/i, /^continue$/i]);
  if (confirmed) {
    log("confirmed birth date review dialog");
    await page.waitForTimeout(1200);
  }
  return confirmed;
}

async function fillVisibleSelectDefaults(page: any): Promise<boolean> {
  const selects = page.locator("select");
  const count = await selects.count().catch(() => 0);
  let changed = false;
  for (let index = 0; index < count; index += 1) {
    const select = selects.nth(index);
    const visible = await select.isVisible().catch(() => false);
    if (!visible) continue;
    const currentValue = await select.inputValue().catch(() => "");
    if (currentValue.trim()) continue;
    const options = await select
      .locator("option")
      .evaluateAll((nodes: any[]) =>
        nodes.map((node: any) => ({
          value: String(node?.value || ""),
          label: String(node?.label || node?.textContent || "").trim(),
        })),
      )
      .catch(() => [] as Array<{ value: string; label: string }>);
    const preferred = options.find((option: { value: string; label: string }) => {
      const value = String(option.value || "").trim();
      const label = String(option.label || "").trim();
      if (!value) return false;
      return !/select|choose|pick/i.test(label);
    });
    if (!preferred?.value) continue;
    await select.selectOption(preferred.value).catch(() => {});
    changed = true;
  }
  return changed;
}

async function handleOrganizationStep(page: any): Promise<boolean> {
  if (await fillVisibleSelectDefaults(page)) {
  }
  if (
    (await clickByRoleName(page, "option", [/new organization/i, /default project/i])) ||
    (await clickVisibleText(page, [/new organization/i, /default project/i]))
  ) {
    await page.waitForTimeout(800);
  }
  if (await activateAction(page, [/default project/i, /new organization/i, /default/i, /select/i])) {
    await page.waitForTimeout(800);
  }
  await submitCurrentStep(page, [/continue/i, /finish/i, /next/i, /create/i, /confirm/i], "organization").catch(() => {});
  return true;
}

async function handleProfileStep(page: any, nickname: string, birthDate: string): Promise<boolean> {
  const fullName = profileFullName(nickname);
  const expectedAge = calculateAgeYears(birthDate);
  const birthdaySignal = /birthday|date of birth|confirm your age/i;
  const hasNameControl = await hasVisibleControl(page, ['input[name*="name" i]', 'input[autocomplete="name"]', 'input[id*="name" i]']);
  let hasAgeControl = await hasVisibleControl(page, ['input[name*="age" i]', 'input[aria-label*="age" i]', 'input[placeholder*="age" i]']);
  let birthModeActivated = false;
  let hasBirthControl =
    (await hasVisibleControl(page, [
      'input[type="date"]',
      'select',
      'input[name*="birthday" i]',
      'input[aria-label*="birthday" i]',
      'input[placeholder*="MM / DD / YYYY" i]',
      'input[name*="year" i]',
      'input[placeholder*="year" i]',
      'input[placeholder="MM" i]',
      'input[placeholder="DD" i]',
      'input[placeholder="YYYY" i]',
      '[role="spinbutton"][data-type="month"]',
      '[role="spinbutton"][data-type="day"]',
      '[role="spinbutton"][data-type="year"]',
    ])) ||
    (await hasVisibleControl(page, ['[role="combobox"]', 'button[aria-haspopup="listbox"]']));
  if (!hasBirthControl) {
    const profileText = await pageText(page);
    if (birthdaySignal.test(profileText)) {
      hasBirthControl = true;
    }
  }
  if (!hasBirthControl && (await activateAction(page, [/use date of birth/i]))) {
    birthModeActivated = true;
    log("switched profile form to date-of-birth mode");
    await page.waitForTimeout(500);
    hasAgeControl = await hasVisibleControl(page, ['input[name*="age" i]', 'input[aria-label*="age" i]', 'input[placeholder*="age" i]']);
    hasBirthControl =
      (await hasVisibleControl(page, [
        'input[type="date"]',
        'select',
        'input[name*="birthday" i]',
        'input[aria-label*="birthday" i]',
        'input[placeholder*="MM / DD / YYYY" i]',
        'input[name*="year" i]',
        'input[placeholder*="year" i]',
        'input[placeholder="MM" i]',
        'input[placeholder="DD" i]',
        'input[placeholder="YYYY" i]',
        '[role="spinbutton"][data-type="month"]',
        '[role="spinbutton"][data-type="day"]',
        '[role="spinbutton"][data-type="year"]',
      ])) ||
      (await hasVisibleControl(page, ['[role="combobox"]', 'button[aria-haspopup="listbox"]']));
    if (!hasBirthControl) {
      const profileText = await pageText(page);
      if (birthdaySignal.test(profileText)) {
        hasBirthControl = true;
      }
    }
  }
  const filledName = hasNameControl
    ? await fillFirstVisible(page, ['input[name*="name" i]', 'input[autocomplete="name"]', 'input[id*="name" i]'], fullName)
    : false;
  let birthControlsAvailable =
    (await hasVisibleControl(page, [
      'input[type="date"]',
      'select',
      'input[name*="birthday" i]',
      'input[aria-label*="birthday" i]',
      'input[placeholder*="MM / DD / YYYY" i]',
      'input[name*="year" i]',
      'input[placeholder*="year" i]',
      'input[placeholder="MM" i]',
      'input[placeholder="DD" i]',
      'input[placeholder="YYYY" i]',
      '[role="spinbutton"][data-type="month"]',
      '[role="spinbutton"][data-type="day"]',
      '[role="spinbutton"][data-type="year"]',
    ])) ||
    (await hasVisibleControl(page, ['[role="combobox"]', 'button[aria-haspopup="listbox"]']));
  if (!birthControlsAvailable) {
    const profileText = await pageText(page);
    if (birthdaySignal.test(profileText)) {
      birthControlsAvailable = true;
    }
  }
  const filledBirth = birthControlsAvailable ? await fillBirthDate(page, birthDate) : false;
  const filledAge = !filledBirth && hasAgeControl ? await fillAgeYears(page, birthDate) : false;
  await page.waitForLoadState("domcontentloaded", { timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(1200);
  const profileSnapshotText = await pageText(page);
  const visibleNameValues = await readVisibleValues(page, ['input[name*="name" i]', 'input[autocomplete="name"]', 'input[id*="name" i]']);
  const visibleAgeValues = await readVisibleValues(page, [
    'input[name*="age" i]',
    'input[aria-label*="age" i]',
    'input[placeholder*="age" i]',
    'input[inputmode="numeric"]',
  ]);
  const visibleBirthValues = await readVisibleValues(page, [
    'input[type="date"]',
    'select',
    'input[name*="birthday" i]',
    'input[aria-label*="birthday" i]',
    'input[placeholder*="MM / DD / YYYY" i]',
    'input[name*="year" i]',
    'input[placeholder*="year" i]',
    'input[placeholder="YYYY" i]',
    'input[name*="month" i]',
    'input[placeholder*="month" i]',
    'input[placeholder="MM" i]',
    'input[name*="day" i]',
    'input[placeholder*="day" i]',
    'input[placeholder="DD" i]',
    '[role="combobox"]',
    'button[aria-haspopup="listbox"]',
    '[role="spinbutton"][data-type="month"]',
    '[role="spinbutton"][data-type="day"]',
    '[role="spinbutton"][data-type="year"]',
  ]);
  const hiddenBirthValue = await readHiddenBirthValue(page);
  const nameReady = !hasNameControl || visibleNameValues.some((value) => value === fullName) || profileSnapshotText.includes(fullName);
  const ageReady = !hasAgeControl || visibleAgeValues.some((value) => value === expectedAge || value.includes(expectedAge));
  const birthReady =
    !birthControlsAvailable
    || hiddenBirthValue === birthDate
    || isBirthDateReadyFromVisibleValues(
      profileSnapshotText ? [...visibleBirthValues, profileSnapshotText] : visibleBirthValues,
      birthDate,
    );
  const requireBirthReady = birthControlsAvailable && (birthModeActivated || !hasAgeControl);
  if ((hasNameControl && !nameReady) || (hasAgeControl && !ageReady) || (requireBirthReady && !birthReady)) {
    log(
      `profile fields incomplete nameControl=${hasNameControl} nameReady=${nameReady} ageControl=${hasAgeControl} ageReady=${ageReady} birthControl=${birthControlsAvailable} birthModeActivated=${birthModeActivated} birthReady=${birthReady} hiddenBirthValue=${hiddenBirthValue} filledName=${filledName} filledAge=${filledAge} filledBirth=${filledBirth} nameValues=${JSON.stringify(visibleNameValues)} ageValues=${JSON.stringify(visibleAgeValues)} birthValues=${JSON.stringify(visibleBirthValues)}`,
    );
    return false;
  }
  if (!hasNameControl && !hasAgeControl && !birthControlsAvailable) return false;
  await submitCurrentStep(page, [/continue/i, /next/i, /finish/i, /submit/i], "profile").catch(() => {});
  await maybeConfirmBirthDate(page);
  return true;
}

async function tryResendOtp(page: any): Promise<boolean> {
  const resent = await activateAction(page, [/resend/i, /send code again/i, /send again/i, /email me a new code/i]);
  if (resent) {
    log("requested email otp resend");
  }
  return resent;
}

async function exchangeCodexTokens(input: { code: string; codeVerifier: string }): Promise<Record<string, unknown>> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: CALLBACK_URL,
    client_id: OAUTH_CLIENT_ID,
    code_verifier: input.codeVerifier,
  });
  const parsePayload = (text: string): Record<string, unknown> => (text.trim() ? (JSON.parse(text) as Record<string, unknown>) : {});
  try {
    const response = await fetch(`${OAUTH_ISSUER}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    });
    const text = await response.text();
    const payload = parsePayload(text);
    if (!response.ok) {
      throw new Error(`chatgpt_oauth_token_failed:${response.status}:${text.slice(0, 200)}`);
    }
    return payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`oauth token exchange via fetch failed; falling back to curl (${message})`);
    const { stdout, stderr } = await execFile("curl", [
      "-sS",
      "-X",
      "POST",
      `${OAUTH_ISSUER}/oauth/token`,
      "-H",
      "content-type: application/x-www-form-urlencoded",
      "--data",
      body.toString(),
      "--max-time",
      "30",
      "-w",
      "\n__CURL_STATUS__:%{http_code}",
    ], {
      maxBuffer: 1024 * 1024,
    });
    const normalized = String(stdout || "");
    const marker = "\n__CURL_STATUS__:";
    const markerIndex = normalized.lastIndexOf(marker);
    const responseText = markerIndex >= 0 ? normalized.slice(0, markerIndex) : normalized;
    const statusText = markerIndex >= 0 ? normalized.slice(markerIndex + marker.length).trim() : "";
    const status = Number.parseInt(statusText || "0", 10) || 0;
    const payload = parsePayload(responseText);
    if (!status || status >= 400) {
      const stderrText = String(stderr || "").trim();
      throw new Error(`chatgpt_oauth_token_failed:${status || "curl"}:${(responseText || stderrText).slice(0, 200)}`);
    }
    return payload;
  }
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
  const holdMs = Number.isFinite(holdMsRaw) && holdMsRaw >= 0 ? holdMsRaw : 15 * 60_000;
  if (holdMs === 0) return;
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
  await writeStageMarker(outputDir, "bootstrap:start");
  const payload = parsePayload();
  await writeStageMarker(outputDir, "bootstrap:payload_loaded", {
    email: payload.email,
    mailboxId: payload.mailboxId,
  });
  const args = parseArgs(process.argv.slice(2));
  const authProvider = getChatGptAuthProvider();
  await writeStageMarker(outputDir, "bootstrap:args_loaded", {
    proxyNode: args.proxyNode || null,
    authProvider,
  });
  log(`worker bootstrap start email=${payload.email} mailbox=${payload.mailboxId}`);
  const cfg = loadConfig();
  const chromeExecutablePath = assertTrustedChatGptWorkerChromiumExecutable(cfg.chromeExecutablePath);
  await writeStageMarker(outputDir, "bootstrap:config_loaded", {
    browserEngine: cfg.browserEngine,
    hasChromeExecutablePath: Boolean(cfg.chromeExecutablePath),
    chromeExecutablePath,
    runMode: cfg.runMode,
  });
  log(`browser executable path=${chromeExecutablePath}`);
  let callbackState = createState();
  let { verifier, challenge } = createPkcePair();
  const callbackStateRef = { current: callbackState };
  await writeStageMarker(outputDir, "bootstrap:oauth_prepared");
  const callbackServer = await startCallbackServer(callbackStateRef);
  await writeStageMarker(outputDir, "bootstrap:callback_capture_ready", {
    callbackUrl: CALLBACK_URL,
    mode: "observed_url_only",
  });
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
  await writeStageMarker(outputDir, "bootstrap:mihomo_ready", {
    proxyServer: mihomo.proxyServer,
  });
  let browser: any = null;
  let context: any = null;
  let page: any = null;
  let nativeChromeStop: (() => Promise<void>) | null = null;
  let failureStage = "init";
  try {
    if (args.proxyNode) {
      await mihomo.setGroupProxy(args.proxyNode);
      log(`selected proxy node=${args.proxyNode}`);
      await writeStageMarker(outputDir, "bootstrap:proxy_selected", {
        proxyNode: args.proxyNode,
      });
    }

    await writeStageMarker(outputDir, "bootstrap:browser_launching");
    const launchedBrowser = await launchChatGptWorkerBrowser(cfg, mihomo.proxyServer);
    browser = launchedBrowser.browser;
    context = launchedBrowser.context;
    page = launchedBrowser.page;
    nativeChromeStop = launchedBrowser.nativeChromeStop;
    if (launchedBrowser.browserMode === "chrome-native-cdp") {
      log("browser launched (native chrome cdp)");
      log(`browser profile dir=${launchedBrowser.profileDir}`);
      await writeStageMarker(outputDir, "bootstrap:browser_launched", {
        browserMode: launchedBrowser.browserMode,
        profileDir: launchedBrowser.profileDir || null,
      });
    } else {
      log("browser launched");
      await writeStageMarker(outputDir, "bootstrap:browser_launched", {
        browserMode: launchedBrowser.browserMode,
      });
    }
    log("browser context created");
    await writeStageMarker(outputDir, "bootstrap:context_created", {
      browserMode: launchedBrowser.browserMode,
    });
    log("browser page created");
    await writeStageMarker(outputDir, "bootstrap:page_created", {
      browserMode: launchedBrowser.browserMode,
    });

	    let authorizeUrl = buildAuthorizeUrl({ state: callbackState, codeChallenge: challenge });
	    let callbackFromObservedUrl: CallbackResult | null = null;
	    const observeCallbackUrl = (rawUrl: string, source: string): void => {
	      if (callbackFromObservedUrl) return;
	      const parsed = parseCallbackResultFromUrl(rawUrl, callbackStateRef.current);
	      if (!parsed) return;
	      callbackFromObservedUrl = parsed;
	      log(`observed oauth callback via ${source}`);
	    };
	    page.on("framenavigated", (frame: any) => {
	      try {
	        observeCallbackUrl(String(frame?.url?.() || ""), "frame");
	      } catch {}
	    });
	    page.on("request", (request: any) => {
	      try {
	        observeCallbackUrl(String(request?.url?.() || ""), "request");
	      } catch {}
	    });
	    page.on("response", (response: any) => {
	      try {
	        observeCallbackUrl(String(response?.url?.() || ""), "response");
	      } catch {}
	    });
      page.on("requestfailed", (request: any) => {
        try {
          observeCallbackUrl(String(request?.url?.() || ""), "requestfailed");
        } catch {}
      });
	    log(`opening authorize url for ${payload.email}`);
	    await writeStageMarker(outputDir, "oauth:navigating_authorize", {
	      authorizeUrl,
	    });
    await page.goto(authorizeUrl, { waitUntil: "domcontentloaded", timeout: 120000 });
    await writeStageMarker(outputDir, "oauth:authorize_loaded", {
      currentUrl: String(page.url() || ""),
    });
    if (authProvider === "microsoft") {
      failureStage = "oauth_microsoft_provider";
      const clickedMicrosoftProvider = await clickMicrosoftProviderEntry(page);
      if (!clickedMicrosoftProvider) {
        throw new Error("chatgpt_microsoft_provider_missing");
      }
      await page.waitForTimeout(1200);
      page = await completeMicrosoftLogin(page, cfg, mihomo.proxyServer, {
        completionUrlPatterns: buildChatGptMicrosoftCompletionUrlPatterns(),
        passkeyRecoveryUrl: authorizeUrl,
      });
      await writeStageMarker(outputDir, "oauth:microsoft_completed", {
        currentUrl: String(page.url() || ""),
      });
    }

    let otpRequestedAt = nowIso();
    let callbackFromNavigation: CallbackResult | null = null;
    let createAccountActivated = false;
    let preferLoginFlow = false;
    let otpResendCount = 0;
    let lastObservedUrl = "";
    let lastEmailSubmitUrl = "";
    let repeatedEmailSubmitCount = 0;
    let lastPasswordSubmitUrl = "";
    let repeatedPasswordSubmitCount = 0;
    let lastProfileSubmitUrl = "";
    let repeatedProfileSubmitCount = 0;
    let lastProfileSubmitAt = 0;
    let profileIncompleteCount = 0;
    let lastOrganizationSubmitUrl = "";
    let repeatedOrganizationSubmitCount = 0;
    let lastConsentSubmitUrl = "";
    let repeatedConsentSubmitCount = 0;
    let lastConsumedOtpCode = "";
    let lastConsumedOtpAt = 0;
    let otpSettlingUntil = 0;
    let allowOtpReplay = false;
    let lastProgressAt = Date.now();
    let authChallengeSeenAt = 0;
    let lastAuthChallengeLogAt = 0;
    let emailVerificationSeenAt = 0;
    let emailVerificationRecoveryCount = 0;
    let lastEmailVerificationPendingLogAt = 0;
    let addPhoneOauthRetryCount = 0;
    let authErrorFreshOauthRetryCount = 0;
    let accountKnownExists = false;
    let authSurfaceBlankWaitCount = 0;
    let forcedSurfaceSnapshot: SurfaceSnapshot | null = null;
    let loopCount = 0;
    const maxAddPhoneOauthRetries = 10;
    const maxAuthErrorFreshOauthRetries = 3;
    let preferOtpLogin = false;
    const restartOauthInCurrentBrowser = async (reason: string, extra: Record<string, unknown> = {}): Promise<void> => {
      callbackFromObservedUrl = null;
      callbackFromNavigation = null;
      callbackState = createState();
      callbackStateRef.current = callbackState;
      ({ verifier, challenge } = createPkcePair());
      authorizeUrl = buildAuthorizeUrl({ state: callbackState, codeChallenge: challenge });
      createAccountActivated = false;
      preferLoginFlow = true;
      if (/retry_after_add_phone/i.test(reason)) {
        preferOtpLogin = true;
      }
      otpRequestedAt = nowIso();
      otpResendCount = 0;
      otpSettlingUntil = 0;
      allowOtpReplay = false;
      authChallengeSeenAt = 0;
      lastAuthChallengeLogAt = 0;
      emailVerificationSeenAt = 0;
      emailVerificationRecoveryCount = 0;
      lastEmailVerificationPendingLogAt = 0;
      lastObservedUrl = "";
      lastEmailSubmitUrl = "";
      repeatedEmailSubmitCount = 0;
      lastPasswordSubmitUrl = "";
      repeatedPasswordSubmitCount = 0;
      lastProfileSubmitUrl = "";
      repeatedProfileSubmitCount = 0;
      lastOrganizationSubmitUrl = "";
      repeatedOrganizationSubmitCount = 0;
      lastConsentSubmitUrl = "";
      repeatedConsentSubmitCount = 0;
      lastProgressAt = Date.now();
      await writeStageMarker(outputDir, reason, {
        authorizeUrl,
        preferLoginFlow,
        ...extra,
      });
      await sleepMs(3500);
      await page.goto(authorizeUrl, { waitUntil: "domcontentloaded", timeout: 120000 });
      await page.waitForTimeout(1500);
    };
    const deadline = Date.now() + 12 * 60_000;
    while (Date.now() < deadline) {
      loopCount += 1;
      const seededSnapshot = forcedSurfaceSnapshot;
      forcedSurfaceSnapshot = null;
      const currentUrl = seededSnapshot?.url || String(page.url() || "");
      if (loopCount <= 5 || loopCount % 10 === 0) {
        log(`loop tick=${loopCount} url=${currentUrl || "<empty>"}`);
      }
      if (currentUrl && currentUrl !== lastObservedUrl) {
        lastObservedUrl = currentUrl;
        log(`navigated to ${currentUrl}`);
        await writeStageMarker(outputDir, "oauth:navigation_observed", {
          currentUrl,
        });
        lastProgressAt = Date.now();
      }
	      callbackFromNavigation = parseCallbackResultFromUrl(currentUrl, callbackStateRef.current) || callbackFromObservedUrl;
	      if (callbackFromNavigation) {
	        break;
	      }
      const text = seededSnapshot?.text || (await pageText(page));
      if (loopCount <= 5 || loopCount % 10 === 0) {
        log(`loop text tick=${loopCount} len=${text.length}`);
      }
      if (isPrimaryAuthSurface(currentUrl)) {
        if (text.length < 40) {
          authSurfaceBlankWaitCount += 1;
          if (authSurfaceBlankWaitCount <= 3 || authSurfaceBlankWaitCount % 5 === 0) {
            log(`auth surface still rendering len=${text.length} waitCount=${authSurfaceBlankWaitCount} url=${currentUrl}`);
          }
          await sleepMs(1200);
          continue;
        }
        authSurfaceBlankWaitCount = 0;
      } else {
        authSurfaceBlankWaitCount = 0;
      }
      const onEmailVerificationPage = /email-verification/i.test(currentUrl) || /check your inbox/i.test(text);
      const profileSurfaceVisible = hasProfileSetupSignal(currentUrl, text);
      const organizationSurfaceVisible = hasOrganizationSelectionSignal(currentUrl, text);
      const consentSurfaceVisible = hasConsentPromptSignal(currentUrl, text);
      const phoneSurfaceVisible = hasPhoneVerificationSignal(text, currentUrl);
      if (!accountKnownExists && (profileSurfaceVisible || organizationSurfaceVisible || consentSurfaceVisible || phoneSurfaceVisible)) {
        accountKnownExists = true;
        preferLoginFlow = true;
        createAccountActivated = false;
        log("account advanced beyond sign-up; future retries will stay on log-in");
      }
      if (onEmailVerificationPage) {
        if (!emailVerificationSeenAt) {
          emailVerificationSeenAt = Date.now();
          emailVerificationRecoveryCount = 0;
          lastEmailVerificationPendingLogAt = 0;
          log("entered email verification stage");
        }
      } else {
        emailVerificationSeenAt = 0;
        emailVerificationRecoveryCount = 0;
        lastEmailVerificationPendingLogAt = 0;
      }
      if (isPreOtpAuthSurface(currentUrl) && hasAuthChallengeSignal(currentUrl, text)) {
        if (!authChallengeSeenAt) {
          authChallengeSeenAt = Date.now();
          lastAuthChallengeLogAt = 0;
          log("auth challenge detected; allowing auto verification window");
        }
        const elapsedChallengeMs = Date.now() - authChallengeSeenAt;
        if (elapsedChallengeMs < 25_000) {
          if (elapsedChallengeMs - lastAuthChallengeLogAt >= 5_000) {
            log(`auth challenge still active (${elapsedChallengeMs}ms); waiting for automatic clearance`);
            lastAuthChallengeLogAt = elapsedChallengeMs;
          }
          await page.waitForTimeout(3000);
          continue;
        }
        await writeFailureArtifacts(outputDir, page, failureStage || "auth_challenge");
        throw new Error(`chatgpt_auth_challenge_detected:${currentUrl}`);
      } else {
        authChallengeSeenAt = 0;
        lastAuthChallengeLogAt = 0;
      }
      if (isPreOtpAuthSurface(currentUrl) && hasRecoverableAuthErrorSignal(text)) {
        if (await activateAction(page, [/try again/i, /retry/i, /continue/i])) {
          log("recoverable auth error encountered; retrying current step");
          lastProgressAt = Date.now();
          await page.waitForTimeout(2000);
          continue;
        }
        await writeFailureArtifacts(outputDir, page, failureStage || "auth_surface");
        throw new Error(`chatgpt_auth_surface_error:${currentUrl}`);
      }
      if (isPreOtpAuthSurface(currentUrl) && !hasOtpPromptSignal(text) && Date.now() - lastProgressAt > 45_000) {
        await writeFailureArtifacts(outputDir, page, failureStage || "auth_surface");
        throw new Error(`chatgpt_auth_stage_stuck:${currentUrl}`);
      }
	      if (phoneSurfaceVisible) {
	        if (callbackFromObservedUrl) {
	          callbackFromNavigation = callbackFromObservedUrl;
	          log("phone verification surfaced after callback was already observed; continuing with captured callback");
	          break;
	        }
          if (addPhoneOauthRetryCount < maxAddPhoneOauthRetries) {
            addPhoneOauthRetryCount += 1;
            log("phone verification surfaced; retrying with a fresh oauth authorize round in login mode");
            await restartOauthInCurrentBrowser("oauth:retry_after_add_phone", {
              retryCount: addPhoneOauthRetryCount,
              previousUrl: currentUrl,
            });
            continue;
          }
	        throw new Error("chatgpt_phone_verification_required");
	      }
      if (/captcha|turnstile|hcaptcha|recaptcha/i.test(text) && /verify you are human/i.test(text)) {
        throw new Error("chatgpt_captcha_manual_required");
      }
      if ((preferLoginFlow || accountKnownExists) && (await maybeSwitchKnownAccountToLogin(page, currentUrl, text))) {
        preferLoginFlow = true;
        createAccountActivated = false;
        lastEmailSubmitUrl = "";
        repeatedEmailSubmitCount = 0;
        lastPasswordSubmitUrl = "";
        repeatedPasswordSubmitCount = 0;
        lastProgressAt = Date.now();
        await page.waitForTimeout(1200);
        continue;
      }
      if (!preferLoginFlow && !createAccountActivated && (await maybeSwitchToCreateAccount(page, currentUrl, text))) {
        createAccountActivated = true;
        lastProgressAt = Date.now();
        await page.waitForTimeout(1200);
        continue;
      }
      const passwordFieldVisible = await locatorVisible(page.locator('input[type="password"], input[name="password"], input[autocomplete="new-password"], input[autocomplete="current-password"]'));
      if (passwordFieldVisible) {
        failureStage = "password_submit";
        if (await maybePreferOtpLogin(page, currentUrl, text, preferOtpLogin)) {
          lastPasswordSubmitUrl = "";
          repeatedPasswordSubmitCount = 0;
          lastProgressAt = Date.now();
          await page.waitForTimeout(1500);
          continue;
        }
        if (await maybeSwitchToOtpLogin(page, currentUrl, text)) {
          lastPasswordSubmitUrl = "";
          repeatedPasswordSubmitCount = 0;
          lastProgressAt = Date.now();
          await page.waitForTimeout(1500);
          continue;
        }
        if (await maybeSwitchToLogin(page, currentUrl, text)) {
          preferLoginFlow = true;
          createAccountActivated = false;
          lastEmailSubmitUrl = "";
          repeatedEmailSubmitCount = 0;
          lastPasswordSubmitUrl = "";
          repeatedPasswordSubmitCount = 0;
          log("locked auth surface to log-in after existing-account signal");
          lastProgressAt = Date.now();
          await page.waitForTimeout(1500);
          continue;
        }
        if (currentUrl === lastPasswordSubmitUrl) {
          repeatedPasswordSubmitCount += 1;
        } else {
          lastPasswordSubmitUrl = currentUrl;
          repeatedPasswordSubmitCount = 1;
        }
        if (
          !preferLoginFlow &&
          !createAccountActivated &&
          repeatedPasswordSubmitCount >= 2 &&
          (await maybeSwitchToCreateAccount(page, currentUrl, text))
        ) {
          createAccountActivated = true;
          repeatedPasswordSubmitCount = 0;
          lastProgressAt = Date.now();
          await page.waitForTimeout(1500);
          continue;
        }
        if (repeatedPasswordSubmitCount >= 4) {
          await writeFailureArtifacts(outputDir, page, failureStage);
          throw new Error(`chatgpt_password_submit_stuck:${currentUrl}`);
        }
        const passwordInputs = page.locator('input[type="password"], input[name="password"], input[autocomplete="new-password"], input[autocomplete="current-password"]');
        const count = await passwordInputs.count();
        for (let index = 0; index < count; index += 1) {
          await slowTypeIntoElement(page, passwordInputs.nth(index), payload.password).catch(() => false);
        }
        await submitCurrentStep(page, [/continue/i, /next/i, /sign up/i, /log in/i, /submit/i], "password").catch(() => {});
        lastProgressAt = Date.now();
        log("password submit post-click wait start");
        await settleLoadState(page, "password submit", 8000);
        log("password submit post-click wait settled");
        const postPasswordDelayMs = repeatedPasswordSubmitCount > 1 ? 3000 : 1500;
        log(`password submit local settle sleep start ms=${postPasswordDelayMs}`);
        await sleepMs(postPasswordDelayMs);
        log("password submit local settle sleep done");
        const postPasswordSnapshot = await waitForPostPasswordSurface(page, 15_000);
        forcedSurfaceSnapshot = postPasswordSnapshot;
        log(`password submit current url after settle=${postPasswordSnapshot.url || currentUrl}`);
        log(`password submit text probe length=${postPasswordSnapshot.text.length}`);
        if (postPasswordSnapshot.otpPrompt || postPasswordSnapshot.otpVisible) {
          log(`password submit advanced to otp surface url=${postPasswordSnapshot.url || currentUrl}`);
        } else if (hasPhoneVerificationSignal(postPasswordSnapshot.text, postPasswordSnapshot.url)) {
          log(`password submit advanced to phone surface url=${postPasswordSnapshot.url || currentUrl}`);
        }
        continue;
      }
      if (await fillFirstVisible(page, ['input[type="email"]', 'input[name="email"]', 'input[autocomplete="email"]'], payload.email)) {
        failureStage = "email_submit";
        if (currentUrl === lastEmailSubmitUrl) {
          repeatedEmailSubmitCount += 1;
        } else {
          lastEmailSubmitUrl = currentUrl;
          repeatedEmailSubmitCount = 1;
        }
        if (repeatedEmailSubmitCount >= 3) {
          await writeFailureArtifacts(outputDir, page, failureStage);
          throw new Error(`chatgpt_email_submit_stuck:${currentUrl}`);
        }
        otpRequestedAt = nowIso();
        await submitCurrentStep(page, [/continue/i, /next/i, /submit/i, /email/i], "email").catch(() => {});
        lastProgressAt = Date.now();
        await page.waitForTimeout(1200);
        continue;
      }
      const otpPromptVisible = seededSnapshot?.otpPrompt ?? hasOtpPromptSignal(text);
      const otpVisible = seededSnapshot?.otpVisible ?? (onEmailVerificationPage ? await hasOtpInput(page) : false);
      if (onEmailVerificationPage || otpPromptVisible) {
        failureStage = "email_otp";
        log(`email otp surface detected url=${currentUrl} otpPrompt=${otpPromptVisible} otpVisible=${otpVisible} resendCount=${otpResendCount}`);
        if (Date.now() < otpSettlingUntil && !hasRecoverableAuthErrorSignal(text)) {
          await sleepMs(1500);
          continue;
        }
        if (hasRecoverableAuthErrorSignal(text)) {
          await writeFailureArtifacts(outputDir, page, "email_verification_recoverable_error").catch(() => {});
          if (
            /max_check_attempts/i.test(text)
            && preferLoginFlow
            && authErrorFreshOauthRetryCount < maxAuthErrorFreshOauthRetries
          ) {
            authErrorFreshOauthRetryCount += 1;
            log(`email verification hit max_check_attempts; restarting oauth in login mode retry=${authErrorFreshOauthRetryCount}`);
            await restartOauthInCurrentBrowser("oauth:retry_after_email_verification_error", {
              retryCount: authErrorFreshOauthRetryCount,
              previousUrl: currentUrl,
              error: "max_check_attempts",
            });
            continue;
          }
          if (await activateAction(page, [/try again/i, /retry/i, /continue/i])) {
            log("email verification recoverable auth error; retrying current auth step");
            allowOtpReplay = true;
            otpRequestedAt = nowIso();
            lastProgressAt = Date.now();
            await sleepMs(1500);
            continue;
          }
          if (await navigateBackForRecovery(page, "email_verification_recoverable_error")) {
            await navigateForwardForRecovery(page, "email_verification_recoverable_error_resume").catch(() => false);
            allowOtpReplay = true;
            otpRequestedAt = nowIso();
            lastProgressAt = Date.now();
            await sleepMs(1500);
            continue;
          }
        }
        if (onEmailVerificationPage && !otpVisible && !otpPromptVisible) {
          const pendingMs = emailVerificationSeenAt ? Date.now() - emailVerificationSeenAt : 0;
          if (pendingMs - lastEmailVerificationPendingLogAt >= 10_000) {
            log(`email verification page pending without otp controls (${pendingMs}ms); waiting for scripts/mailbox`);
            lastEmailVerificationPendingLogAt = pendingMs;
          }
          if (pendingMs >= 12_000 && emailVerificationRecoveryCount < 2) {
            emailVerificationRecoveryCount += 1;
            await writeFailureArtifacts(outputDir, page, `email_verification_pending_${emailVerificationRecoveryCount}`).catch(() => {});
            if (await navigateBackForRecovery(page, "email_verification_pending")) {
              await navigateForwardForRecovery(page, "email_verification_pending_resume").catch(() => false);
              lastProgressAt = Date.now();
              await page.waitForTimeout(2000);
              continue;
            }
          }
        }
        try {
          const timeoutMs = otpResendCount === 0 ? 60_000 : 75_000;
          const code =
            authProvider === "microsoft"
              ? (log(`polling Microsoft mailbox for otp mailbox=${optionalEnv("MICROSOFT_MAILBOX_ID") || ""} notBefore=${otpRequestedAt} timeoutMs=${timeoutMs}`),
                (
                  await waitForMicrosoftMailboxVerificationCode({
                    graphSettings: {
                      clientId: requireEnv("MICROSOFT_GRAPH_CLIENT_ID"),
                      clientSecret: requireEnv("MICROSOFT_GRAPH_CLIENT_SECRET"),
                      redirectUri: requireEnv("MICROSOFT_GRAPH_REDIRECT_URI"),
                      authority: optionalEnv("MICROSOFT_GRAPH_AUTHORITY") || "common",
                    },
                    mailbox: {
                      refreshToken: optionalEnv("MICROSOFT_MAILBOX_REFRESH_TOKEN"),
                      accessToken: optionalEnv("MICROSOFT_MAILBOX_ACCESS_TOKEN"),
                      accessTokenExpiresAt: optionalEnv("MICROSOFT_MAILBOX_ACCESS_TOKEN_EXPIRES_AT"),
                      authority: optionalEnv("MICROSOFT_MAILBOX_AUTHORITY"),
                    },
                    notBefore: otpRequestedAt,
                    timeoutMs,
                    pollMs: 2500,
                    providers: ["chatgpt", "generic"],
                  })
                ).code)
              : (log(`polling cf-mail for otp mailbox=${payload.mailboxId || ""} notBefore=${otpRequestedAt} timeoutMs=${timeoutMs}`),
                await waitForCfMailOtp({
                  address: payload.email,
                  mailboxId: payload.mailboxId,
                  notBefore: otpRequestedAt,
                  timeoutMs,
                  pollMs: 2500,
                }));
          if (!allowOtpReplay && code === lastConsumedOtpCode && Date.now() - lastConsumedOtpAt < 45_000) {
            log("received duplicate email otp too soon; waiting before retry");
            await page.waitForTimeout(2500);
            continue;
          }
	          allowOtpReplay = false;
	          otpResendCount = 0;
	          lastConsumedOtpCode = code;
	          lastConsumedOtpAt = Date.now();
	          log(`received email otp (${code.length} digits)`);
	          let otpInputReady = await waitForOtpInputReady(page, 15_000);
	          let otpSurfaceText = await pageText(page).catch(() => "");
	          if (!otpInputReady) {
	            if (hasRecoverableAuthErrorSignal(otpSurfaceText) && (await activateAction(page, [/try again/i, /retry/i, /continue/i]))) {
	              log("otp surface showed recoverable error; retrying before entering code");
	              allowOtpReplay = true;
	              lastProgressAt = Date.now();
	              await page.waitForTimeout(1500);
	              continue;
	            }
	            if (await navigateBackForRecovery(page, "otp_error_recovery")) {
                await navigateForwardForRecovery(page, "otp_error_recovery_resume").catch(() => false);
	              allowOtpReplay = true;
	              lastProgressAt = Date.now();
                await page.waitForTimeout(1500);
	              continue;
	            }
	          }
	          otpInputReady = await hasOtpInput(page);
	          if (!otpInputReady) {
	            await writeFailureArtifacts(outputDir, page, "otp_input_wait_timeout").catch(() => {});
	          }
	          await fillCodeInputs(page, code);
	          await submitCurrentStep(page, [/continue/i, /verify/i, /next/i, /submit/i], "otp").catch(() => {});
	          otpSettlingUntil = Date.now() + 15_000;
	          lastProgressAt = Date.now();
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (/chatgpt_email_otp_timeout/i.test(message) && otpResendCount < 2 && (await tryResendOtp(page))) {
            otpResendCount += 1;
            otpRequestedAt = nowIso();
            await page.waitForTimeout(1500);
            continue;
          }
          throw error;
        }
        await page.waitForTimeout(1200);
        continue;
      }
      if (hasOrganizationSelectionSignal(currentUrl, text) && (await handleOrganizationStep(page))) {
        failureStage = "organization";
        if (currentUrl === lastOrganizationSubmitUrl) {
          repeatedOrganizationSubmitCount += 1;
        } else {
          lastOrganizationSubmitUrl = currentUrl;
          repeatedOrganizationSubmitCount = 1;
        }
        if (repeatedOrganizationSubmitCount === 1 || repeatedOrganizationSubmitCount % 3 === 0) {
          const organizationText = text.replace(/\s+/g, " ").slice(0, 500);
          log(`organization surface snapshot attempts=${repeatedOrganizationSubmitCount} text=${organizationText}`);
        }
        if (repeatedOrganizationSubmitCount > 1 && repeatedOrganizationSubmitCount % 4 === 0) {
          await writeFailureArtifacts(outputDir, page, `organization_submit_${repeatedOrganizationSubmitCount}`).catch(() => {});
        }
        if (repeatedOrganizationSubmitCount >= 10) {
          await writeFailureArtifacts(outputDir, page, failureStage).catch(() => {});
          throw new Error(`chatgpt_organization_submit_stuck:${currentUrl}`);
        }
        lastProgressAt = Date.now();
        await page.waitForLoadState("domcontentloaded", { timeout: 8000 }).catch(() => {});
        await page.waitForTimeout(repeatedOrganizationSubmitCount > 1 ? 2500 : 1500);
        continue;
      }
      if (hasProfileSetupSignal(currentUrl, text) && hasRecoverableProfileErrorSignal(text)) {
        failureStage = "profile_submit";
        await writeFailureArtifacts(outputDir, page, "profile_surface_error").catch(() => {});
        if (await activateAction(page, [/try again/i, /retry/i, /continue/i])) {
          log("profile surface showed recoverable error; retrying without re-submitting fields");
          lastProfileSubmitUrl = "";
          repeatedProfileSubmitCount = 0;
          lastProfileSubmitAt = 0;
          lastProgressAt = Date.now();
          await page.waitForTimeout(4000);
          continue;
        }
        if (await navigateBackForRecovery(page, "profile_surface_error")) {
          const recoveryText = await pageText(page).catch(() => "");
          if (/email verified|already been verified/i.test(recoveryText)) {
            await navigateForwardForRecovery(page, "profile_surface_resume").catch(() => false);
          }
          lastProfileSubmitUrl = "";
          repeatedProfileSubmitCount = 0;
          lastProfileSubmitAt = 0;
          lastProgressAt = Date.now();
          await page.waitForTimeout(2500);
          continue;
        }
      }
      if (hasProfileSetupSignal(currentUrl, text) && currentUrl === lastProfileSubmitUrl && lastProfileSubmitAt > 0) {
        const elapsedSinceProfileSubmit = Date.now() - lastProfileSubmitAt;
        if (elapsedSinceProfileSubmit < 12_000) {
          await page.waitForTimeout(1500);
          continue;
        }
      }
      if (hasProfileSetupSignal(currentUrl, text)) {
        const handledProfileStep = await handleProfileStep(page, payload.nickname, payload.birthDate);
        if (!handledProfileStep) {
          profileIncompleteCount += 1;
          if (profileIncompleteCount === 1 || profileIncompleteCount % 10 === 0) {
            await writeProfileControlDiagnostics(page, outputDir, `incomplete_${profileIncompleteCount}`).catch(() => {});
          }
        } else {
          profileIncompleteCount = 0;
        }
        if (!handledProfileStep) {
          await sleepMs(1000);
          continue;
        }
        failureStage = "profile_submit";
        lastProfileSubmitAt = Date.now();
        if (currentUrl === lastProfileSubmitUrl) {
          repeatedProfileSubmitCount += 1;
        } else {
          lastProfileSubmitUrl = currentUrl;
          repeatedProfileSubmitCount = 1;
        }
        if (repeatedProfileSubmitCount > 1 && repeatedProfileSubmitCount % 3 === 0) {
          await page.waitForLoadState("domcontentloaded", { timeout: 10000 }).catch(() => {});
          await page.waitForTimeout(8000);
          const settledUrl = String(page.url() || "");
          if (settledUrl !== currentUrl) {
            lastProgressAt = Date.now();
            continue;
          }
          await writeFailureArtifacts(outputDir, page, "profile_submit_prebounce").catch(() => {});
          if (await navigateBackForRecovery(page, "profile_submit_bounce")) {
            await writeFailureArtifacts(outputDir, page, "profile_submit_bounce").catch(() => {});
            const recoveryText = await pageText(page).catch(() => "");
            if (/email verified|already been verified/i.test(recoveryText)) {
              await navigateForwardForRecovery(page, "profile_submit_resume").catch(() => false);
            }
            lastProfileSubmitUrl = "";
            repeatedProfileSubmitCount = 0;
            lastProfileSubmitAt = 0;
            allowOtpReplay = true;
            lastProgressAt = Date.now();
            continue;
          }
        }
        if (repeatedProfileSubmitCount >= 8) {
          await writeFailureArtifacts(outputDir, page, failureStage);
          throw new Error(`chatgpt_profile_submit_stuck:${currentUrl}`);
        }
        lastProgressAt = Date.now();
        await page.waitForLoadState("domcontentloaded", { timeout: 8000 }).catch(() => {});
        await page.waitForTimeout(repeatedProfileSubmitCount > 1 ? 8000 : 6000);
        continue;
      }
      if (hasConsentPromptSignal(currentUrl, text) && (await activateAction(page, [/continue/i, /allow/i, /accept/i, /authorize/i]))) {
        failureStage = "consent";
        log("consent action triggered");
        lastProgressAt = Date.now();
        await page.waitForTimeout(1200);
        continue;
      }
      if (hasConsentPromptSignal(currentUrl, text)) {
        failureStage = "consent";
        if (currentUrl === lastConsentSubmitUrl) {
          repeatedConsentSubmitCount += 1;
        } else {
          lastConsentSubmitUrl = currentUrl;
          repeatedConsentSubmitCount = 1;
        }
        if (repeatedConsentSubmitCount >= 8) {
          await writeFailureArtifacts(outputDir, page, failureStage).catch(() => {});
          throw new Error(`chatgpt_consent_submit_stuck:${currentUrl}`);
        }
        await submitCurrentStep(page, [/continue/i, /allow/i, /accept/i, /authorize/i], "consent").catch(() => {});
        log(`consent submit fallback triggered attempts=${repeatedConsentSubmitCount}`);
        lastProgressAt = Date.now();
        await page.waitForLoadState("domcontentloaded", { timeout: 8000 }).catch(() => {});
        await page.waitForTimeout(repeatedConsentSubmitCount > 1 ? 2000 : 1200);
        continue;
      }
      await sleepMs(1000);
    }

    failureStage = "oauth_callback";
    const callback =
      callbackFromNavigation ||
      (await Promise.race([
        callbackServer.waitForCode,
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("chatgpt_oauth_callback_timeout")), 120000)),
      ]));
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

    await writeJson(`${outputDir}/result.json`, buildChatGptWorkerResult({
      mode: cfg.runMode,
      email,
      password: payload.password,
      nickname: payload.nickname,
      birthDate: payload.birthDate,
      accountId,
      expiresAt,
      tokenPayload: tokenPayload as Record<string, unknown>,
      idTokenPayload: idTokenPayload as Record<string, unknown>,
      accessToken,
      refreshToken,
      idToken,
      notes: [
        `mailbox=${payload.mailboxId}`,
        `proxy=${args.proxyNode || (await mihomo.getGroupSelection().catch(() => null)) || "default"}`,
      ],
    }));
    if (isFingerprintBusinessFlow()) {
      await holdBrowserForBusinessFlowHandoff(page, browser, outputDir, "chatgpt_login_ready", {
        success: true,
      });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await writeFailureArtifacts(outputDir, page, failureStage);
    await writeJson(`${outputDir}/error.json`, {
      error: message,
      failureStage,
    });
    if (isFingerprintBusinessFlow()) {
      await holdBrowserForBusinessFlowHandoff(page, browser, outputDir, failureStage, {
        success: false,
        error: message,
      });
    }
    await keepBrowserOpenOnFailure(page, browser, failureStage);
    throw error;
  } finally {
    await cleanupWithTimeout(callbackServer.close(), 3_000);
    await cleanupWithTimeout(context?.close?.() ?? Promise.resolve(), 5_000);
    await cleanupWithTimeout(browser?.close?.() ?? Promise.resolve(), 5_000);
    if (nativeChromeStop) {
      await cleanupWithTimeout(nativeChromeStop(), 5_000);
    }
    await cleanupWithTimeout(mihomo.stop(), 5_000);
  }
}

if (import.meta.main) {
  void run().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
