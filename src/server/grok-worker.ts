import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { Impit } from "impit";
import { startMihomo } from "../proxy/mihomo.js";
import { buildAcceptLanguage, lookupIpInfo, parseIpInfoPayload, type GeoInfo } from "../proxy/geo.js";
import { buildCfMailAuthHeaders, normalizeCfMailBaseUrl } from "../cfmail-api.js";
import { isFingerprintChromiumExecutable } from "../fingerprint-browser.js";
import {
  applyBrowserIdentityToContext,
  buildBrowserIdentityProfile,
  completeMicrosoftLogin,
  configureNativeChromePage,
  dispatchEnterViaCdp,
  dispatchMouseClickViaCdp,
  ensureManagedChallengeTokenBeforeSubmit,
  launchBrowserWithEngine,
  launchNativeChromeCdp,
  loadConfig,
} from "../main.js";
import { solveTurnstileToken } from "./grok-turnstile.js";
import { waitForGrokEmailCode, type GrokMailbox } from "./grok-mail-service.js";
import { waitForMicrosoftMailboxVerificationCode } from "./microsoft-mailbox-verification.js";

const execFile = promisify(execFileCallback);
const GROK_ACCOUNTS_URL = "https://accounts.x.ai";
const GROK_SIGNUP_URL = `${GROK_ACCOUNTS_URL}/sign-up?redirect=grok-com`;
const GROK_CONSOLE_URL = "https://console.x.ai/home";
const GROK_VALIDATE_URL = "https://api.x.ai/v1/models";
const GROK_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";
const DEFAULT_KEY_NAME_PREFIX = "grok-reg";
const API_KEY_REGEXES = [
  /\bxai-[A-Za-z0-9._-]{16,}\b/g,
  /\b(?:xai|sk)-[A-Za-z0-9._-]{16,}\b/g,
] as const;

interface WorkerArgs {
  proxyNode?: string;
}

type GrokAuthProvider = "email" | "microsoft";

interface SignupBootstrap {
  siteKey: string;
  nextAction: string;
  stateTree: string;
}

interface GrokWorkerResult {
  mode: "headed" | "headless";
  email: string;
  password: string;
  sso: string;
  ssoRw?: string | null;
  cfClearance?: string | null;
  checkoutUrl?: string | null;
  birthDate?: string | null;
  proxy: {
    nodeName: string | null;
    ip: string | null;
  };
  runId: string;
  notes: string[];
}

interface GrokSessionBundle {
  sso: string;
  ssoRw: string;
  cfClearance: string | null;
}

function log(message: string): void {
  console.log(`[grok-worker] ${message}`);
}

function nowIso(): string {
  return new Date().toISOString();
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requireEnv(name: string): string {
  const value = String(process.env[name] || "").trim();
  if (!value) {
    throw new Error(`missing_env:${name}`);
  }
  return value;
}

function optionalEnv(name: string): string | null {
  const value = String(process.env[name] || "").trim();
  return value || null;
}

function getGrokAuthProvider(): GrokAuthProvider {
  return String(process.env.GROK_AUTH_PROVIDER || "").trim().toLowerCase() === "microsoft" ? "microsoft" : "email";
}

function parseMailboxFromEnv(): GrokMailbox {
  const email = requireEnv("GROK_JOB_EMAIL").toLowerCase();
  const mailboxId = requireEnv("GROK_JOB_MAILBOX_ID");
  return {
    provider: "cfmail",
    address: email,
    accountId: mailboxId,
    baseUrl: normalizeCfMailBaseUrl(requireEnv("CFMAIL_BASE_URL")),
    headers: buildCfMailAuthHeaders(requireEnv("CFMAIL_API_KEY")),
  };
}

function randomPassword(length = 18): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=";
  let output = "";
  for (let index = 0; index < length; index += 1) {
    output += alphabet[Math.floor(Math.random() * alphabet.length)] || "A";
  }
  return output;
}

function randomSuffix(): string {
  return Math.random().toString(16).slice(2, 8);
}

function randomName(): string {
  const firstNames = ["Mika", "Luna", "Rin", "Sora", "Aiko", "Hana", "Nora", "Yuna"];
  const lastNames = ["Hoshino", "Amano", "Kobayashi", "Hayashi", "Minase", "Sakurai", "Kisaragi", "Morita"];
  const first = firstNames[Math.floor(Math.random() * firstNames.length)] || "Mika";
  const last = lastNames[Math.floor(Math.random() * lastNames.length)] || "Hoshino";
  return `${first} ${last}`;
}

function splitName(value: string): { givenName: string; familyName: string } {
  const parts = String(value || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const givenName = parts[0] || randomName().split(" ")[0] || "Mika";
  const familyName = parts[1] || randomName().split(" ")[1] || "Hoshino";
  return { givenName, familyName };
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

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeStageMarker(outputDir: string, stage: string, extra?: Record<string, unknown>): Promise<void> {
  await writeJson(path.join(outputDir, "stage.json"), {
    stage,
    updatedAt: nowIso(),
    ...(extra || {}),
  }).catch(() => {});
}

async function pageText(page: any): Promise<string> {
  try {
    const [title, text] = await Promise.all([
      page.title().catch(() => ""),
      page.locator("body").innerText({ timeout: 5_000 }).catch(() => ""),
    ]);
    return `${String(title || "")} ${String(text || "")}`.replace(/\s+/g, " ").trim();
  } catch {
    return "";
  }
}

async function applyTurnstileStealthInit(page: any): Promise<void> {
  await page
    .addInitScript(() => {
      try {
        const originalAttachShadow = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function attachShadowPatched(init: ShadowRootInit) {
          const shadow = originalAttachShadow.call(this, init);
          if (init?.mode === "closed") {
            (window as any).__lastClosedShadowRoot = shadow;
          }
          return shadow;
        };
      } catch {}
    })
    .catch(() => {});
}

function isPrivateIpv4(ip: string): boolean {
  if (/^(10|127)\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  const match = ip.match(/^172\.(\d+)\./);
  if (match) {
    const second = Number.parseInt(match[1] || "", 10);
    if (Number.isFinite(second) && second >= 16 && second <= 31) return true;
  }
  return false;
}

function extractPublicIpv4(text: string): string | null {
  const matches = String(text || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  for (const candidate of matches) {
    const parts = candidate.split(".").map((part) => Number.parseInt(part, 10));
    if (parts.length !== 4 || parts.some((part) => !Number.isFinite(part) || part < 0 || part > 255)) {
      continue;
    }
    if (isPrivateIpv4(candidate)) continue;
    return candidate;
  }
  return null;
}

async function collectBrowserProxyGeo(page: any): Promise<GeoInfo | null> {
  const context = typeof page?.context === "function" ? page.context() : null;
  const probePage = context && typeof context.newPage === "function" ? await context.newPage().catch(() => null) : null;
  const targetPage = probePage || page;
  try {
    await targetPage.goto("https://www.cloudflare.com/cdn-cgi/trace", {
      waitUntil: "domcontentloaded",
      timeout: 45_000,
    });
    await targetPage.waitForTimeout(1_200).catch(() => {});
    const traceText = await targetPage.locator("body").innerText({ timeout: 10_000 }).catch(() => "");
    const traceIp = traceText.match(/^ip=(.+)$/m)?.[1]?.trim() || "";
    const ip = extractPublicIpv4(traceIp || traceText);
    if (!ip) return null;
    try {
      return await lookupIpInfo(ip, String(process.env.IPINFO_TOKEN || "").trim() || undefined);
    } catch {
      return { ip };
    }
  } finally {
    if (probePage) {
      await probePage.close().catch(() => {});
    }
  }
}

async function collectProxyGeoViaProxy(proxyServer: string): Promise<GeoInfo | null> {
  const impit = new Impit({
    proxyUrl: proxyServer,
    timeout: 15_000,
  });
  const url = new URL("https://ipinfo.io/json");
  const token = String(process.env.IPINFO_TOKEN || "").trim();
  if (token) {
    url.searchParams.set("token", token);
  }
  const response = await impit.fetch(url.toString(), {
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`proxy_geo_fetch_failed:${response.status}`);
  }
  const payload = (await response.json()) as Record<string, unknown>;
  return parseIpInfoPayload(payload);
}

async function applyRuntimeTimezoneOverride(context: any, page: any, timezoneId: string): Promise<void> {
  if (!timezoneId.trim()) return;
  let cdp: any = null;
  try {
    cdp = await context.newCDPSession(page);
  } catch {
    cdp = null;
  }
  if (!cdp) return;
  await cdp.send("Emulation.setTimezoneOverride", { timezoneId: timezoneId.trim() }).catch(() => {});
}

async function alignBrowserIdentity(input: {
  cfg: ReturnType<typeof loadConfig>;
  browser: any;
  context: any;
  page: any;
  useNativeChrome: boolean;
  outputDir: string;
  prelaunchGeo?: GeoInfo | null;
  identityOutputFile?: string;
}): Promise<{
  browserGeo: GeoInfo | null;
  locale: string;
  acceptLanguage: string;
  userAgent: string;
}> {
  const browserGeo = await collectBrowserProxyGeo(input.page).catch(() => null);
  const effectiveGeo = browserGeo || input.prelaunchGeo || null;
  const locale = String(process.env.GROK_BROWSER_LOCALE || "en-US").trim() || "en-US";
  const acceptLanguage = buildAcceptLanguage(locale);
  const fingerprintBrowser = isFingerprintChromiumExecutable(input.cfg.chromeExecutablePath);
  const identityInjected = Boolean(input.cfg.chromeIdentityOverride && !fingerprintBrowser);
  const identity = identityInjected ? buildBrowserIdentityProfile(locale, input.browser?.version?.() || "") : null;
  if (identity) {
    await applyBrowserIdentityToContext(input.context, identity, effectiveGeo?.timezone, !input.useNativeChrome).catch(() => {});
    if (input.useNativeChrome) {
      await configureNativeChromePage(input.context, input.page, identity, effectiveGeo?.timezone).catch(() => {});
    }
  }
  if (effectiveGeo?.timezone) {
    await applyRuntimeTimezoneOverride(input.context, input.page, effectiveGeo.timezone).catch(() => {});
  }
  const navigatorSnapshot = await input.page
    .evaluate(() => ({
      userAgent: navigator.userAgent,
      webdriver: navigator.webdriver,
      language: navigator.language,
      languages: Array.isArray(navigator.languages) ? navigator.languages : [],
      platform: navigator.platform,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    }))
    .catch(() => null);
  await writeJson(path.join(input.outputDir, input.identityOutputFile || "browser-identity.json"), {
    capturedAt: nowIso(),
    prelaunchGeo: input.prelaunchGeo || null,
    browserGeo,
    effectiveGeo,
    locale,
    acceptLanguage,
    identity,
    identityInjected,
    fingerprintBrowser,
    navigator: navigatorSnapshot,
  }).catch(() => {});
  return {
    browserGeo,
    locale,
    acceptLanguage,
    userAgent:
      identity?.userAgent ||
      (typeof navigatorSnapshot?.userAgent === "string" && navigatorSnapshot.userAgent.trim()
        ? navigatorSnapshot.userAgent.trim()
        : GROK_USER_AGENT),
  };
}

async function writeFailureArtifacts(outputDir: string, page: any, failureStage: string): Promise<void> {
  if (!page || (typeof page.isClosed === "function" && page.isClosed())) {
    return;
  }
  const payload = {
    failureStage,
    url: String(page.url?.() || ""),
    title: await page.title().catch(() => ""),
    textPreview: (await pageText(page).catch(() => "")).slice(0, 4_000),
    capturedAt: nowIso(),
  };
  await writeJson(path.join(outputDir, "failure-page.json"), payload).catch(() => {});
  await writeFile(path.join(outputDir, "failure-page.txt"), `${payload.textPreview}\n`, "utf8").catch(() => {});
  await page.screenshot({ path: path.join(outputDir, "failure-page.png"), fullPage: true }).catch(() => {});
}

async function captureRuntimeBrowserSnapshot(page: any, outputDir: string, fileName: string): Promise<void> {
  const payload = await page
    .evaluate(() => ({
      url: window.location.href,
      title: document.title,
      navigator: {
        userAgent: navigator.userAgent,
        webdriver: navigator.webdriver,
        language: navigator.language,
        languages: Array.isArray(navigator.languages) ? navigator.languages : [],
        platform: navigator.platform,
        vendor: navigator.vendor,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        pluginsLength: navigator.plugins?.length ?? null,
        pluginsTag: Object.prototype.toString.call(navigator.plugins),
        mimeTypesLength: navigator.mimeTypes?.length ?? null,
        mimeTypesTag: Object.prototype.toString.call(navigator.mimeTypes),
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: (navigator as Navigator & { deviceMemory?: number }).deviceMemory ?? null,
        maxTouchPoints: navigator.maxTouchPoints,
      },
      windowMetrics: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio,
        screenWidth: window.screen?.width ?? null,
        screenHeight: window.screen?.height ?? null,
        availWidth: window.screen?.availWidth ?? null,
        availHeight: window.screen?.availHeight ?? null,
      },
      chromeKeys: Object.keys((window as Window & { chrome?: Record<string, unknown> }).chrome || {}).slice(0, 20),
    }))
    .catch(() => null);
  if (!payload) return;
  await writeJson(path.join(outputDir, fileName), {
    capturedAt: nowIso(),
    ...payload,
  }).catch(() => {});
}

async function keepBrowserOpenOnFailure(page: any, browser: any, failureStage: string): Promise<void> {
  const keepOpen = String(process.env.KEEP_BROWSER_OPEN_ON_FAILURE || "false").trim().toLowerCase();
  if (!["1", "true", "yes", "on"].includes(keepOpen)) {
    return;
  }
  const keepMs = Math.max(0, Number.parseInt(String(process.env.KEEP_BROWSER_OPEN_MS || "0"), 10) || 0);
  if (page && !page.isClosed?.()) {
    log(`keeping browser open after ${failureStage} for ${keepMs}ms`);
  }
  if (keepMs > 0) {
    await sleepMs(keepMs);
  } else {
    await sleepMs(30_000);
  }
  await browser?.close?.().catch(() => {});
}

async function locatorVisible(locator: any): Promise<boolean> {
  try {
    const count = await locator.count().catch(() => 0);
    if (count <= 0) return false;
    return await locator.first().isVisible().catch(() => false);
  } catch {
    return false;
  }
}

async function clickLocatorViaCdp(page: any, locator: any): Promise<boolean> {
  try {
    const target = locator.first();
    const visible = await target.isVisible?.().catch(() => false);
    if (!visible) return false;
    await target.scrollIntoViewIfNeeded?.().catch(() => {});
    const box = await target.boundingBox?.().catch(() => null);
    if (!box || !Number.isFinite(box.x) || !Number.isFinite(box.y) || !Number.isFinite(box.width) || !Number.isFinite(box.height)) {
      return false;
    }
    const x = box.x + box.width / 2;
    const y = box.y + box.height / 2;
    if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
    await dispatchMouseClickViaCdp(page, x, y);
    await page.waitForTimeout(500).catch(() => {});
    return true;
  } catch {
    return false;
  }
}

async function clickFirstVisibleByText(page: any, patterns: RegExp[]): Promise<boolean> {
  for (const pattern of patterns) {
    const roleLocators = [
      page.getByRole("button", { name: pattern }).first(),
      page.getByRole("link", { name: pattern }).first(),
      page.getByRole("tab", { name: pattern }).first(),
      page.getByText(pattern).first(),
    ];
    for (const locator of roleLocators) {
      if (await clickLocatorViaCdp(page, locator)) return true;
      const visible = await locator.isVisible?.().catch(() => false);
      if (!visible) continue;
      await locator.click({ force: true }).catch(() => {});
      await page.waitForTimeout(500).catch(() => {});
      return true;
    }
  }
  return false;
}

async function clickMicrosoftProviderEntry(page: any): Promise<boolean> {
  return await clickFirstVisibleByText(page, [
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
  log(`holding browser for fingerprint handoff stage=${stage} url=${String(page?.url?.() || "")}`);
  while (true) {
    const pageClosed = !page || (typeof page.isClosed === "function" ? page.isClosed() : false);
    const browserClosed = !browser || (typeof browser.isConnected === "function" ? !browser.isConnected() : false);
    if (pageClosed || browserClosed) return;
    await sleepMs(1000);
  }
}

async function isMicrosoftVerificationCodeSurface(page: any): Promise<boolean> {
  const text = await pageText(page);
  return /verification code|security code|enter code|one[- ]time code|temporary code/i.test(text);
}

async function fillVisibleField(page: any, patterns: RegExp[], value: string): Promise<boolean> {
  const candidates = [
    ...patterns.map((pattern) => page.getByLabel(pattern).first()),
    ...patterns.map((pattern) => page.getByPlaceholder(pattern).first()),
    page.locator('input:not([type="hidden"])').filter({ has: page.locator(":scope") }).first(),
  ];
  for (const locator of candidates) {
    const visible = await locator.isVisible?.().catch(() => false);
    if (!visible) continue;
    await clickLocatorViaCdp(page, locator).catch(() => false);
    await locator.click({ force: true }).catch(() => {});
    await locator.fill("").catch(() => {});
    await locator.fill(value).catch(() => {});
    await locator.dispatchEvent?.("input").catch(() => {});
    return true;
  }
  const genericInputs = page.locator('input:not([type="hidden"]), textarea');
  const count = await genericInputs.count().catch(() => 0);
  for (let index = 0; index < count; index += 1) {
    const locator = genericInputs.nth(index);
    const visible = await locator.isVisible().catch(() => false);
    if (!visible) continue;
    const attrs = [
      await locator.getAttribute("name").catch(() => ""),
      await locator.getAttribute("id").catch(() => ""),
      await locator.getAttribute("placeholder").catch(() => ""),
      await locator.getAttribute("aria-label").catch(() => ""),
    ]
      .filter(Boolean)
      .join(" ");
    if (!patterns.some((pattern) => pattern.test(attrs))) continue;
    await clickLocatorViaCdp(page, locator).catch(() => false);
    await locator.click({ force: true }).catch(() => {});
    await locator.fill(value).catch(() => {});
    return true;
  }
  return false;
}

async function waitForAnyVisibleText(page: any, patterns: RegExp[], timeoutMs = 20_000): Promise<boolean> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    for (const pattern of patterns) {
      const locators = [
        page.getByText(pattern).first(),
        page.getByRole("heading", { name: pattern }).first(),
        page.getByRole("button", { name: pattern }).first(),
      ];
      for (const locator of locators) {
        const visible = await locator.isVisible?.().catch(() => false);
        if (visible) {
          return true;
        }
      }
    }
    await page.waitForTimeout(300).catch(() => {});
  }
  return false;
}

function extractApiKeyCandidate(text: string): string | null {
  const normalized = String(text || "");
  for (const pattern of API_KEY_REGEXES) {
    const match = normalized.match(pattern);
    if (match?.[0]) {
      return match[0];
    }
  }
  return null;
}

async function extractApiKeyFromPage(page: any): Promise<string | null> {
  const result = await page
    .evaluate(() => {
      const parts: string[] = [];
      const pushValue = (value: unknown) => {
        if (typeof value === "string" && value.trim()) {
          parts.push(value.trim());
        }
      };
      const selectors = ["code", "pre", "textarea", "input", "[data-testid]", "[role='dialog']", "body"];
      for (const selector of selectors) {
        for (const element of Array.from(document.querySelectorAll(selector))) {
          pushValue((element as HTMLInputElement).value);
          pushValue((element as HTMLElement).innerText);
          pushValue(element.textContent);
          pushValue(element.getAttribute("value"));
          pushValue(element.getAttribute("data-value"));
        }
      }
      return parts.join("\n");
    })
    .catch(() => "");
  return extractApiKeyCandidate(result);
}

async function captureCookies(context: any, outputDir: string): Promise<void> {
  const cookies = await context.cookies().catch(() => []);
  await writeJson(path.join(outputDir, "session-cookies.json"), cookies).catch(() => {});
}

function encodeGrpcFrame(payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = 0;
  const view = new DataView(frame.buffer);
  view.setUint32(1, payload.length);
  frame.set(payload, 5);
  return frame;
}

function encodeLengthDelimitedField(fieldId: number, value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  const payload = new Uint8Array(2 + encoded.length);
  payload[0] = (fieldId << 3) | 2;
  payload[1] = encoded.length;
  payload.set(encoded, 2);
  return payload;
}

function parseGrpcTrailerFromText(input: string): {
  grpcStatus: string | null;
  grpcMessage: string | null;
} {
  const decoded = String(input || "");
  const statusMatch = decoded.match(/grpc-status:(\d+)/i);
  const messageMatch = decoded.match(/grpc-message:([^\r\n]+)/i);
  return {
    grpcStatus: statusMatch?.[1] || null,
    grpcMessage: messageMatch?.[1] ? decodeURIComponent(messageMatch[1]) : null,
  };
}

async function createEmailValidationCode(page: any, email: string): Promise<{
  ok: boolean;
  status: number;
  contentType: string | null;
  grpcStatus: string | null;
  grpcMessage: string | null;
  textPreview: string;
  bodyHexPrefix: string;
}> {
  return await page.evaluate(async ({ email, siteUrl }: { email: string; siteUrl: string }) => {
    const payload = (() => {
      const body = new Uint8Array(2 + new TextEncoder().encode(email).length);
      body[0] = (1 << 3) | 2;
      body[1] = new TextEncoder().encode(email).length;
      body.set(new TextEncoder().encode(email), 2);
      const frame = new Uint8Array(5 + body.length);
      const view = new DataView(frame.buffer);
      frame[0] = 0;
      view.setUint32(1, body.length);
      frame.set(body, 5);
      return frame;
    })();
    const response = await fetch(`${siteUrl}/auth_mgmt.AuthManagement/CreateEmailValidationCode`, {
      method: "POST",
      headers: {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        origin: siteUrl,
        referer: `${siteUrl}/sign-up?redirect=grok-com`,
      },
      credentials: "include",
      body: payload,
    });
    const clone = response.clone();
    const bytes = new Uint8Array(await clone.arrayBuffer().catch(() => new ArrayBuffer(0)));
    const bodyHexPrefix = Array.from(bytes.slice(0, 64))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    const textPreview = (() => {
      try {
        return new TextDecoder().decode(bytes.slice(0, 512));
      } catch {
        return "";
      }
    })();
    return {
      ok: response.ok,
      status: response.status,
      contentType: response.headers.get("content-type"),
      grpcStatus: response.headers.get("grpc-status"),
      grpcMessage: response.headers.get("grpc-message"),
      textPreview,
      bodyHexPrefix,
    };
  }, { email, siteUrl: GROK_ACCOUNTS_URL });
}

async function verifyEmailValidationCode(page: any, email: string, code: string): Promise<{
  ok: boolean;
  status: number;
  grpcStatus: string | null;
  grpcMessage: string | null;
  trailerText: string;
  bodyHexPrefix: string;
}> {
  return await page.evaluate(async ({ email, code, siteUrl }: { email: string; code: string; siteUrl: string }) => {
    const emailBytes = new TextEncoder().encode(email);
    const codeBytes = new TextEncoder().encode(code);
    const body = new Uint8Array(4 + emailBytes.length + codeBytes.length);
    let offset = 0;
    body[offset++] = (1 << 3) | 2;
    body[offset++] = emailBytes.length;
    body.set(emailBytes, offset);
    offset += emailBytes.length;
    body[offset++] = (2 << 3) | 2;
    body[offset++] = codeBytes.length;
    body.set(codeBytes, offset);
    const frame = new Uint8Array(5 + body.length);
    const view = new DataView(frame.buffer);
    frame[0] = 0;
    view.setUint32(1, body.length);
    frame.set(body, 5);
    const response = await fetch(`${siteUrl}/auth_mgmt.AuthManagement/VerifyEmailValidationCode`, {
      method: "POST",
      headers: {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        origin: siteUrl,
        referer: `${siteUrl}/sign-up?redirect=grok-com`,
      },
      credentials: "include",
      body: frame,
    });
    const bytes = new Uint8Array(await response.clone().arrayBuffer().catch(() => new ArrayBuffer(0)));
    const trailerText = (() => {
      try {
        return new TextDecoder().decode(bytes.slice(0, 512));
      } catch {
        return "";
      }
    })();
    const bodyHexPrefix = Array.from(bytes.slice(0, 64))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    return {
      ok: response.ok,
      status: response.status,
      grpcStatus: response.headers.get("grpc-status"),
      grpcMessage: response.headers.get("grpc-message"),
      trailerText,
      bodyHexPrefix,
    };
  }, { email, code, siteUrl: GROK_ACCOUNTS_URL });
}

async function readGrpcResponseArtifact(response: any): Promise<{
  ok: boolean;
  status: number;
  contentType?: string | null;
  grpcStatus: string | null;
  grpcMessage: string | null;
  textPreview: string;
  trailerText: string;
  bodyHexPrefix: string;
}> {
  const bytes = new Uint8Array(await response.body().catch(() => new ArrayBuffer(0)));
  const textPreview = (() => {
    try {
      return new TextDecoder().decode(bytes.slice(0, 512));
    } catch {
      return "";
    }
  })();
  const bodyHexPrefix = Array.from(bytes.slice(0, 64))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  return {
    ok: response.ok(),
    status: response.status(),
    contentType: response.headers()["content-type"] || null,
    grpcStatus: response.headers()["grpc-status"] || null,
    grpcMessage: response.headers()["grpc-message"] || null,
    textPreview,
    trailerText: textPreview,
    bodyHexPrefix,
  };
}

async function startEmailSignupInPage(page: any, email: string): Promise<{
  ok: boolean;
  status: number;
  contentType?: string | null;
  grpcStatus: string | null;
  grpcMessage: string | null;
  textPreview: string;
  trailerText: string;
  bodyHexPrefix: string;
}> {
  await clickFirstVisibleByText(page, [/sign up with email/i]);
  const emailReady = await fillVisibleField(page, [/^email$/i], email);
  if (!emailReady) {
    throw new Error("grok_email_input_missing");
  }
  const responsePromise = page.waitForResponse(
    (response: any) =>
      /auth_mgmt\.AuthManagement\/CreateEmailValidationCode/i.test(String(response.url?.() || "")),
    { timeout: 30_000 },
  );
  const clicked =
    (await clickFirstVisibleByText(page, [/^sign up$/i])) ||
    (await clickFirstVisibleByText(page, [/continue/i, /next/i]));
  if (!clicked) {
    throw new Error("grok_email_signup_submit_missing");
  }
  const response = await responsePromise;
  await waitForAnyVisibleText(page, [/verify your email/i, /confirm email/i], 15_000).catch(() => false);
  return await readGrpcResponseArtifact(response);
}

async function submitEmailCodeInPage(page: any, code: string): Promise<{
  ok: boolean;
  status: number;
  contentType?: string | null;
  grpcStatus: string | null;
  grpcMessage: string | null;
  textPreview: string;
  trailerText: string;
  bodyHexPrefix: string;
}> {
  const responsePromise = page.waitForResponse(
    (response: any) =>
      /auth_mgmt\.AuthManagement\/VerifyEmailValidationCode/i.test(String(response.url?.() || "")),
    { timeout: 30_000 },
  );
  const allInputs = page.locator('input:not([type="hidden"])');
  const inputCount = await allInputs.count().catch(() => 0);
  const codeInputs: any[] = [];
  for (let index = 0; index < inputCount; index += 1) {
    const locator = allInputs.nth(index);
    const visible = await locator.isVisible().catch(() => false);
    if (!visible) continue;
    const type = String((await locator.getAttribute("type").catch(() => "")) || "").toLowerCase();
    const maxLength = Number.parseInt(String((await locator.getAttribute("maxlength").catch(() => "")) || "0"), 10) || 0;
    const inputMode = String((await locator.getAttribute("inputmode").catch(() => "")) || "").toLowerCase();
    if (type === "email" || type === "password") continue;
    if (maxLength === 1 || inputMode === "numeric" || inputMode === "decimal") {
      codeInputs.push(locator);
    }
  }
  if (codeInputs.length >= code.length) {
    for (let index = 0; index < code.length; index += 1) {
      const locator = codeInputs[index];
      await clickLocatorViaCdp(page, locator).catch(() => false);
      await locator.click({ force: true }).catch(() => {});
      await locator.fill("").catch(() => {});
      await locator.fill(code[index] || "").catch(() => {});
    }
  } else {
    const firstInput = allInputs.first();
    await clickLocatorViaCdp(page, firstInput).catch(() => false);
    await firstInput.click({ force: true }).catch(() => {});
    await page.keyboard.type(code, { delay: 60 }).catch(() => {});
  }
  await page.waitForTimeout(300).catch(() => {});
  await clickFirstVisibleByText(page, [/confirm email/i, /^confirm$/i]).catch(() => false);
  const response = await responsePromise;
  await waitForAnyVisibleText(page, [/complete your sign up/i, /first name/i, /verify you are human/i], 20_000).catch(
    () => false,
  );
  return await readGrpcResponseArtifact(response);
}

function extractVerifyUrlFromText(text: string): string | null {
  return text.match(/https:\/\/[^"'\s]+set-cookie\?q=[^"'\s:]+/)?.[0] || null;
}

function extractSuccessUrlFromSetCookieUrl(setCookieUrl: string): string | null {
  try {
    const parsed = new URL(setCookieUrl);
    const token = parsed.searchParams.get("q")?.trim() || "";
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = parts[1] || "";
    const padding = "=".repeat((4 - (payload.length % 4)) % 4);
    const decoded = Buffer.from((payload + padding).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const parsedPayload = JSON.parse(decoded) as {
      config?: {
        success_url?: string;
      };
    };
    const successUrl = String(parsedPayload?.config?.success_url || "").trim();
    return successUrl || null;
  } catch {
    return null;
  }
}

async function recoverSetCookieFlow(page: any, outputDir: string, reason: string): Promise<void> {
  const initialUrl = String(page.url?.() || "");
  if (!/set-cookie\?q=/i.test(initialUrl)) {
    return;
  }
  const chain: Array<{
    step: number;
    requestUrl: string;
    responseUrl: string;
    status: number;
    nextSuccessUrl: string | null;
  }> = [];
  let nextUrl: string | null = initialUrl;
  let finalUrl = initialUrl;
  for (let step = 1; step <= 4 && nextUrl; step += 1) {
    const successUrl = extractSuccessUrlFromSetCookieUrl(nextUrl);
    if (!successUrl) {
      break;
    }
    const response = await page
      .goto(successUrl, {
        waitUntil: "domcontentloaded",
        timeout: 60_000,
        referer: nextUrl,
      })
      .catch(() => null);
    await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
    finalUrl = String(page.url?.() || response?.url?.() || successUrl);
    nextUrl = /set-cookie\?q=/i.test(finalUrl) ? finalUrl : extractSuccessUrlFromSetCookieUrl(finalUrl);
    chain.push({
      step,
      requestUrl: successUrl,
      responseUrl: finalUrl,
      status: response?.status?.() ?? 0,
      nextSuccessUrl: nextUrl || null,
    });
    if (!/set-cookie\?q=/i.test(finalUrl) && !nextUrl) {
      break;
    }
  }
  await writeJson(path.join(outputDir, "set-cookie-recovery.json"), {
    reason,
    initialUrl,
    finalUrl,
    chain,
    capturedAt: nowIso(),
  }).catch(() => {});
  if (finalUrl && finalUrl !== String(page.url?.() || "")) {
    await page.goto(finalUrl, { waitUntil: "domcontentloaded", timeout: 60_000 }).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
  }
}

function normalizeCookieDomain(domain: string | null | undefined): string {
  return String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^\./, "");
}

function isUsableSsoDomain(domain: string | null | undefined): boolean {
  const normalized = normalizeCookieDomain(domain);
  if (!normalized) return false;
  return normalized === "x.ai" || normalized.endsWith(".x.ai") || normalized === "grok.com" || normalized.endsWith(".grok.com");
}

function isUsableClearanceDomain(domain: string | null | undefined): boolean {
  return isUsableSsoDomain(domain);
}

function matchesCookieRootDomain(domain: string | null | undefined, rootDomain: string): boolean {
  const normalized = normalizeCookieDomain(domain);
  return normalized === rootDomain || normalized.endsWith(`.${rootDomain}`);
}

function selectCookieValue(
  cookies: any[],
  name: string,
  acceptedDomain: (domain: string | null | undefined) => boolean,
  preferredRoots: string[],
): string | null {
  const matched = (cookies || []).filter((cookie: any) => cookie?.name === name && cookie?.value && acceptedDomain(cookie?.domain));
  for (const root of preferredRoots) {
    const preferred = matched.find((cookie: any) => matchesCookieRootDomain(cookie?.domain, root));
    const value = String(preferred?.value || "").trim();
    if (value) return value;
  }
  const fallback = matched.find((cookie: any) => cookie?.value);
  const fallbackValue = String(fallback?.value || "").trim();
  return fallbackValue || null;
}

async function hasSsoCookie(page: any): Promise<boolean> {
  const cookies = await page.context()?.cookies?.().catch(() => []) || [];
  return cookies.some((cookie: any) => cookie?.name === "sso" && cookie?.value && isUsableSsoDomain(cookie?.domain));
}

async function getSsoCookieValue(page: any): Promise<string | null> {
  const cookies = await page.context()?.cookies?.().catch(() => []) || [];
  return selectCookieValue(cookies, "sso", isUsableSsoDomain, ["x.ai", "grok.com"]);
}

async function getGrokSessionBundle(page: any): Promise<GrokSessionBundle | null> {
  const cookies = await page.context()?.cookies?.().catch(() => []) || [];
  const sso = selectCookieValue(cookies, "sso", isUsableSsoDomain, ["x.ai", "grok.com"]);
  const ssoRw = selectCookieValue(cookies, "sso-rw", isUsableSsoDomain, ["x.ai", "grok.com"]);
  if (!sso || !ssoRw) {
    return null;
  }
  return {
    sso,
    ssoRw,
    cfClearance: selectCookieValue(cookies, "cf_clearance", isUsableClearanceDomain, ["grok.com", "x.ai"]),
  };
}

async function hydrateGrokDomainSessionCookies(context: any, bundle: GrokSessionBundle): Promise<void> {
  const expires = Math.floor(Date.now() / 1000) + 180 * 24 * 60 * 60;
  await context
    .addCookies([
      {
        name: "sso",
        value: bundle.sso,
        domain: ".grok.com",
        path: "/",
        expires,
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
      },
      {
        name: "sso-rw",
        value: bundle.ssoRw,
        domain: ".grok.com",
        path: "/",
        expires,
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
      },
    ])
    .catch(() => {});
}

function randomBirthDate(minAge = 20, maxAge = 40): string {
  const now = new Date();
  const age = Math.floor(Math.random() * (maxAge - minAge + 1)) + minAge;
  const year = now.getUTCFullYear() - age;
  const month = Math.floor(Math.random() * 12) + 1;
  const day = Math.floor(Math.random() * 28) + 1;
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T16:00:00.000Z`;
}

async function gotoPageOrigin(page: any, url: string): Promise<void> {
  try {
    const current = new URL(String(page.url?.() || ""));
    const target = new URL(url);
    if (current.origin === target.origin) {
      return;
    }
  } catch {}
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await page.waitForLoadState("networkidle", { timeout: 30_000 }).catch(() => {});
}

interface GrokPageProbe {
  url: string;
  title: string;
  textPreview: string;
}

function normalizePageProbeText(probe: GrokPageProbe): string {
  return `${probe.title} ${probe.textPreview} ${probe.url}`.replace(/\s+/g, " ").trim().toLowerCase();
}

function isCloudflareChallengeProbe(probe: GrokPageProbe): boolean {
  const combined = normalizePageProbeText(probe);
  return (
    combined.includes("__cf_chl_rt_tk") ||
    combined.includes("just a moment") ||
    combined.includes("请稍候") ||
    combined.includes("进行安全验证") ||
    combined.includes("security check") ||
    combined.includes("verifying you are human") ||
    combined.includes("checking your browser")
  );
}

function isCloudflareBlockedProbe(probe: GrokPageProbe): boolean {
  const combined = normalizePageProbeText(probe);
  return (
    combined.includes("attention required! | cloudflare") ||
    combined.includes("sorry, you have been blocked") ||
    combined.includes("unable to access grok.com")
  );
}

async function readGrokPageProbe(page: any): Promise<GrokPageProbe> {
  const [title, textPreview] = await Promise.all([
    page.title().catch(() => ""),
    page.locator("body").innerText({ timeout: 5_000 }).catch(() => ""),
  ]);
  return {
    url: String(page.url?.() || ""),
    title: String(title || ""),
    textPreview: String(textPreview || "").replace(/\s+/g, " ").slice(0, 1_200),
  };
}

async function ensureGrokPageReady(
  page: any,
  outputDir: string,
  tag: string,
): Promise<{ ok: boolean; blocked: boolean; probe: GrokPageProbe | null }> {
  await gotoPageOrigin(page, "https://grok.com/");
  const probes: Array<GrokPageProbe & { elapsedMs: number }> = [];
  const startedAt = Date.now();
  let stablePasses = 0;
  let lastProbe: GrokPageProbe | null = null;
  while (Date.now() - startedAt < 45_000) {
    const probe = await readGrokPageProbe(page);
    lastProbe = probe;
    probes.push({
      ...probe,
      elapsedMs: Date.now() - startedAt,
    });
    if (isCloudflareBlockedProbe(probe)) {
      await writeJson(path.join(outputDir, `grok-ready-${tag}.json`), {
        ok: false,
        blocked: true,
        probes,
        capturedAt: nowIso(),
      }).catch(() => {});
      return { ok: false, blocked: true, probe };
    }
    if (isCloudflareChallengeProbe(probe)) {
      stablePasses = 0;
      await sleepMs(1_000);
      continue;
    }
    stablePasses += 1;
    if (stablePasses >= 2) {
      await writeJson(path.join(outputDir, `grok-ready-${tag}.json`), {
        ok: true,
        blocked: false,
        probes,
        capturedAt: nowIso(),
      }).catch(() => {});
      return { ok: true, blocked: false, probe };
    }
    await sleepMs(1_000);
  }
  await writeJson(path.join(outputDir, `grok-ready-${tag}.json`), {
    ok: false,
    blocked: Boolean(lastProbe && isCloudflareBlockedProbe(lastProbe)),
    probes,
    capturedAt: nowIso(),
  }).catch(() => {});
  return {
    ok: false,
    blocked: Boolean(lastProbe && isCloudflareBlockedProbe(lastProbe)),
    probe: lastProbe,
  };
}

async function postJsonInPage(
  page: any,
  input: {
    url: string;
    body: unknown;
    headers?: Record<string, string>;
  },
): Promise<{ status: number; ok: boolean; textPreview: string; json: unknown | null; responseUrl: string }> {
  return await page.evaluate(
    async ({ url, body, headers }: { url: string; body: unknown; headers: Record<string, string> }) => {
      const targetUrl = new URL(url, window.location.href);
      const requestUrl = targetUrl.origin === window.location.origin
        ? `${targetUrl.pathname}${targetUrl.search}${targetUrl.hash}`
        : targetUrl.toString();
      const response = await fetch(requestUrl, {
        method: "POST",
        credentials: "include",
        headers: {
          accept: "*/*",
          "content-type": "application/json",
          ...(headers || {}),
        },
        body: JSON.stringify(body),
      });
      const text = await response.text();
      let parsed: unknown | null = null;
      try {
        parsed = text.trim() ? JSON.parse(text) : null;
      } catch {}
      return {
        status: response.status,
        ok: response.ok,
        textPreview: text.slice(0, 1_500),
        json: parsed,
        responseUrl: response.url,
      };
    },
    {
      url: input.url,
      body: input.body,
      headers: input.headers || {},
    },
  );
}

async function postGrpcWebInPage(
  page: any,
  input: {
    url: string;
    bodyHex: string;
    headers?: Record<string, string>;
  },
): Promise<{
  status: number;
  ok: boolean;
  grpcStatus: string | null;
  grpcMessage: string | null;
  bodyHexPrefix: string;
  textPreview: string;
  responseUrl: string;
}> {
  return await page.evaluate(
    async ({ url, bodyHex, headers }: { url: string; bodyHex: string; headers: Record<string, string> }) => {
      const bytes = new Uint8Array((bodyHex.match(/[0-9a-f]{2}/gi) || []).map((part: string) => Number.parseInt(part, 16)));
      const targetUrl = new URL(url, window.location.href);
      const requestUrl = targetUrl.origin === window.location.origin
        ? `${targetUrl.pathname}${targetUrl.search}${targetUrl.hash}`
        : targetUrl.toString();
      const response = await fetch(requestUrl, {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/grpc-web+proto",
          "x-grpc-web": "1",
          ...(headers || {}),
        },
        body: bytes,
      });
      const buffer = new Uint8Array(await response.arrayBuffer());
      const hex = Array.from(buffer.slice(0, 512))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
      const text = new TextDecoder().decode(buffer.slice(0, 2048));
      return {
        status: response.status,
        ok: response.ok,
        grpcStatus: response.headers.get("grpc-status"),
        grpcMessage: response.headers.get("grpc-message"),
        bodyHexPrefix: hex,
        textPreview: text,
        responseUrl: response.url,
      };
    },
    {
      url: input.url,
      bodyHex: input.bodyHex,
      headers: input.headers || {},
    },
  );
}

async function acceptTosVersion(page: any, outputDir: string): Promise<{ ok: boolean; status: number; grpcStatus: string | null; textPreview: string }> {
  await gotoPageOrigin(page, "https://accounts.x.ai/accept-tos");
  const result = await postGrpcWebInPage(page, {
    url: "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion",
    bodyHex: "00000000021001",
  });
  await writeJson(path.join(outputDir, "tos-accept.json"), result).catch(() => {});
  const trailer = parseGrpcTrailerFromText(result.textPreview);
  return {
    ok: result.status === 200 && (result.grpcStatus === "0" || trailer.grpcStatus === "0" || (!result.grpcStatus && !trailer.grpcStatus)),
    status: result.status,
    grpcStatus: result.grpcStatus || trailer.grpcStatus,
    textPreview: result.textPreview,
  };
}

async function setBirthDate(page: any, outputDir: string, birthDate: string): Promise<{ ok: boolean; status: number }> {
  const ready = await ensureGrokPageReady(page, outputDir, "birth-date");
  if (!ready.ok) {
    await writeJson(path.join(outputDir, "birth-date.json"), {
      status: 0,
      ok: false,
      textPreview: ready.probe?.textPreview || "",
      json: null,
      responseUrl: ready.probe?.url || "",
      birthDate,
      blocked: ready.blocked,
      error: ready.blocked ? "cloudflare_blocked_before_birth_date" : "grok_page_not_ready_before_birth_date",
    }).catch(() => {});
    return {
      ok: false,
      status: ready.blocked ? 403 : 0,
    };
  }
  const result = await postJsonInPage(page, {
    url: "https://grok.com/rest/auth/set-birth-date",
    body: { birthDate },
  });
  await writeJson(path.join(outputDir, "birth-date.json"), {
    ...result,
    birthDate,
  }).catch(() => {});
  return {
    ok: result.status === 200,
    status: result.status,
  };
}

async function enableNsfw(page: any, outputDir: string): Promise<{ ok: boolean; status: number; grpcStatus: string | null }> {
  const ready = await ensureGrokPageReady(page, outputDir, "nsfw");
  if (!ready.ok) {
    await writeJson(path.join(outputDir, "nsfw-settings.json"), {
      status: 0,
      ok: false,
      grpcStatus: null,
      grpcMessage: null,
      bodyHexPrefix: "",
      textPreview: ready.probe?.textPreview || "",
      responseUrl: ready.probe?.url || "",
      blocked: ready.blocked,
      error: ready.blocked ? "cloudflare_blocked_before_nsfw" : "grok_page_not_ready_before_nsfw",
    }).catch(() => {});
    return {
      ok: false,
      status: ready.blocked ? 403 : 0,
      grpcStatus: null,
    };
  }
  const result = await postGrpcWebInPage(page, {
    url: "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls",
    bodyHex: "00000000200a021001121a0a18616c776179735f73686f775f6e7366775f636f6e74656e74",
    headers: {
      "x-user-agent": "connect-es/2.1.1",
    },
  });
  await writeJson(path.join(outputDir, "nsfw-settings.json"), result).catch(() => {});
  const trailer = parseGrpcTrailerFromText(result.textPreview);
  return {
    ok: result.status === 200 && (result.grpcStatus === "0" || trailer.grpcStatus === "0" || (!result.grpcStatus && !trailer.grpcStatus)),
    status: result.status,
    grpcStatus: result.grpcStatus || trailer.grpcStatus,
  };
}

async function updateUserSettings(page: any, outputDir: string): Promise<{ ok: boolean; status: number }> {
  const ready = await ensureGrokPageReady(page, outputDir, "user-settings");
  if (!ready.ok) {
    await writeJson(path.join(outputDir, "user-settings.json"), {
      status: 0,
      ok: false,
      textPreview: ready.probe?.textPreview || "",
      json: null,
      responseUrl: ready.probe?.url || "",
      blocked: ready.blocked,
      error: ready.blocked ? "cloudflare_blocked_before_user_settings" : "grok_page_not_ready_before_user_settings",
    }).catch(() => {});
    return {
      ok: false,
      status: ready.blocked ? 403 : 0,
    };
  }
  const result = await postJsonInPage(page, {
    url: "https://grok.com/rest/user-settings",
    body: {
      excludeFromTraining: false,
      preferences: {
        enableEarlyAccessModels: true,
        enableMemory: true,
        enableStarBackground: true,
        showConversationPreviews: true,
      },
      allowXPersonalization: true,
      enableMemory: true,
    },
    headers: {
      "x-xai-request-id": crypto.randomUUID(),
    },
  });
  await writeJson(path.join(outputDir, "user-settings.json"), result).catch(() => {});
  return {
    ok: result.status === 200,
    status: result.status,
  };
}

async function createCheckoutUrl(page: any, outputDir: string, email: string): Promise<{ ok: boolean; status: number | null; checkoutUrl: string }> {
  const ready = await ensureGrokPageReady(page, outputDir, "checkout");
  if (!ready.ok) {
    await writeJson(path.join(outputDir, "checkout-url.json"), {
      customer: null,
      subscription: null,
      checkoutUrl: "",
      blocked: ready.blocked,
      error: ready.blocked ? "cloudflare_blocked_before_checkout" : "grok_page_not_ready_before_checkout",
      probe: ready.probe,
    }).catch(() => {});
    return {
      ok: false,
      status: ready.blocked ? 403 : 0,
      checkoutUrl: "",
    };
  }
  const customer = await postJsonInPage(page, {
    url: "https://grok.com/rest/subscriptions/customer/new",
    body: {
      billingInfo: {
        name: randomName(),
        email,
      },
    },
    headers: {
      "x-xai-request-id": crypto.randomUUID(),
      "sentry-trace": `${crypto.randomUUID().replaceAll("-", "")}-${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}-0`,
    },
  });
  const subscription = customer.status === 200 || customer.status === 201 || customer.status === 204
    ? await postJsonInPage(page, {
        url: "https://grok.com/rest/subscriptions/subscribe/new",
        body: {
          stripeHosted: {
            successUrl: "https://grok.com/?checkout=success&tier=SUBSCRIPTION_TIER_GROK_PRO&interval=monthly#subscribe",
          },
          priceId: "price_1R6nQ9HJohyvID2ck7FNrVdw",
          campaignId: "subcamp_HeAxW",
          ignoreExistingActiveSubscriptions: false,
          subscriptionType: "MONTHLY",
          requestedTier: "REQUESTED_TIER_GROK_PRO",
        },
        headers: {
          "x-xai-request-id": crypto.randomUUID(),
          "sentry-trace": `${crypto.randomUUID().replaceAll("-", "")}-${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}-0`,
        },
      })
    : null;
  const checkoutUrl =
    typeof subscription?.json === "object" && subscription?.json && !Array.isArray(subscription.json)
      ? String((subscription.json as Record<string, unknown>).url || (subscription.json as Record<string, unknown>).checkoutUrl || "").trim()
      : "";
  await writeJson(path.join(outputDir, "checkout-url.json"), {
    customer,
    subscription,
    checkoutUrl,
  }).catch(() => {});
  if (checkoutUrl) {
    await writeFile(path.join(outputDir, "payurl.txt"), `${checkoutUrl}\n`, "utf8").catch(() => {});
  }
  return {
    ok: Boolean(subscription && subscription.status === 200 && checkoutUrl),
    status: subscription?.status ?? (customer.status || null),
    checkoutUrl,
  };
}

async function fillCompleteSignupFields(page: any, displayName: string, password: string): Promise<void> {
  const { givenName, familyName } = splitName(displayName);
  const visibleInputs = page.locator('input:not([type="hidden"])');
  const count = await visibleInputs.count().catch(() => 0);
  const textInputs: any[] = [];
  let passwordInput: any | null = null;
  for (let index = 0; index < count; index += 1) {
    const locator = visibleInputs.nth(index);
    const visible = await locator.isVisible().catch(() => false);
    if (!visible) continue;
    const type = String((await locator.getAttribute("type").catch(() => "")) || "").toLowerCase();
    if (type === "password") {
      passwordInput = locator;
      continue;
    }
    if (type === "email") continue;
    textInputs.push(locator);
  }

  const fillLocator = async (locator: any, value: string) => {
    await clickLocatorViaCdp(page, locator).catch(() => false);
    await locator.click({ force: true }).catch(() => {});
    await locator.fill("").catch(() => {});
    await page.keyboard.press("Meta+A").catch(() => {});
    await page.keyboard.press("Control+A").catch(() => {});
    await page.keyboard.press("Backspace").catch(() => {});
    await page.keyboard.type(value, { delay: 40 }).catch(() => {});
    await locator
      .evaluate((element: HTMLInputElement, nextValue: string) => {
        element.value = nextValue;
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.dispatchEvent(new Event("change", { bubbles: true }));
        element.dispatchEvent(new Event("blur", { bubbles: true }));
      }, value)
      .catch(() => {});
    await locator.press("Tab").catch(() => {});
  };

  if (textInputs[0]) {
    await fillLocator(textInputs[0], givenName);
  } else {
    await fillVisibleField(page, [/first name/i, /^first$/i, /given name/i], givenName);
  }
  if (textInputs[1]) {
    await fillLocator(textInputs[1], familyName);
  } else {
    await fillVisibleField(page, [/last name/i, /^last$/i, /family name/i, /surname/i], familyName);
  }

  if (passwordInput) {
    await fillLocator(passwordInput, password);
  } else {
    const filled = await fillVisibleField(page, [/password/i], password);
    if (!filled) {
      throw new Error("grok_complete_signup_password_missing");
    }
  }
}

async function submitCompleteSignupInPage(page: any, outputDir?: string): Promise<{
  verifyUrl: string | null;
  status: number | null;
  textPreview: string;
  challengeStatus: "not_run" | "triggered" | "ready" | "timeout" | "rejected";
  rejection?: string | null;
  currentUrl: string;
  navigated: boolean;
  buttonState?: {
    text: string | null;
    disabled: boolean | null;
    ariaDisabled: string | null;
  };
}> {
  let challengeStatus: "not_run" | "triggered" | "ready" | "timeout" | "rejected" = "not_run";
  let rejection: string | null = null;
  let lastStatus: number | null = null;
  let lastTextPreview = "";
  let lastKnownUrl = String(page.url?.() || "");
  let lastButtonState:
    | {
        text: string | null;
        disabled: boolean | null;
        ariaDisabled: string | null;
      }
    | undefined;

  const readButtonState = async () => {
    const button = page.getByRole("button", { name: /complete sign up|continue|submit/i }).first();
    const visible = await button.isVisible().catch(() => false);
    if (!visible) {
      return {
        text: null,
        disabled: null,
        ariaDisabled: null,
      };
    }
    return await button
      .evaluate((element: HTMLButtonElement) => ({
        text: (element.innerText || element.textContent || "").trim() || null,
        disabled: typeof element.disabled === "boolean" ? element.disabled : null,
        ariaDisabled: element.getAttribute("aria-disabled"),
      }))
      .catch(() => ({
        text: null,
        disabled: null,
        ariaDisabled: null,
      }));
  };

  const clickSubmit = async (): Promise<boolean> => {
    const clicked =
      (await clickFirstVisibleByText(page, [/complete sign up/i])) ||
      (await clickFirstVisibleByText(page, [/continue/i, /^submit$/i]));
    if (!clicked) {
      await dispatchEnterViaCdp(page).catch(() => {});
    }
    return clicked;
  };

  for (let attempt = 1; attempt <= 2; attempt += 1) {
    if (/set-cookie\?q=/i.test(String(page.url?.() || "")) && outputDir) {
      await recoverSetCookieFlow(page, outputDir, `before_native_submit_attempt_${attempt}`).catch(() => {});
    }
    lastKnownUrl = String(page.url?.() || "");
    lastButtonState = await readButtonState();
    const responsePromise = page
      .waitForResponse(
        (response: any) =>
          response.request?.().method?.() === "POST" &&
          /accounts\.x\.ai\/sign-up(?:\?|$)/i.test(String(response.url?.() || "")),
        { timeout: attempt === 1 ? 8_000 : 12_000 },
      )
      .catch(() => null);

    const clicked = await clickSubmit();
    if (!clicked) {
      const currentUrl = String(page.url?.() || "");
      if (!/accounts\.x\.ai\/sign-up(?:\?|$)/i.test(currentUrl)) {
        return {
          verifyUrl: /set-cookie\?q=/i.test(currentUrl) ? currentUrl : null,
          status: lastStatus,
          textPreview: lastTextPreview,
          challengeStatus,
          rejection,
          currentUrl,
          navigated: currentUrl !== lastKnownUrl,
          buttonState: lastButtonState,
        };
      }
      throw new Error("grok_complete_signup_submit_missing");
    }
    await page.waitForTimeout(1_500).catch(() => {});
    lastKnownUrl = String(page.url?.() || "");
    if (await hasSsoCookie(page)) {
      return {
        verifyUrl: null,
        status: null,
        textPreview: "",
        challengeStatus,
        rejection,
        currentUrl: lastKnownUrl,
        navigated: true,
        buttonState: lastButtonState,
      };
    }
    if (!/accounts\.x\.ai\/sign-up(?:\?|$)/i.test(lastKnownUrl)) {
      return {
        verifyUrl: /set-cookie\?q=/i.test(lastKnownUrl) ? lastKnownUrl : null,
        status: lastStatus,
        textPreview: lastTextPreview,
        challengeStatus,
        rejection,
        currentUrl: lastKnownUrl,
        navigated: true,
        buttonState: lastButtonState,
      };
    }

    const response = await responsePromise;
    if (response) {
      lastStatus = response.status();
      lastTextPreview = (await response.text().catch(() => "")).slice(0, 4_000);
      const verifyUrl = extractVerifyUrlFromText(lastTextPreview);
      if (verifyUrl) {
        return {
          verifyUrl,
          status: lastStatus,
          textPreview: lastTextPreview,
          challengeStatus,
          rejection,
          currentUrl: String(page.url?.() || ""),
          navigated: true,
          buttonState: lastButtonState,
        };
      }
    }

    if (await hasSsoCookie(page)) {
      return {
        verifyUrl: null,
        status: lastStatus,
        textPreview: lastTextPreview,
        challengeStatus,
        rejection,
        currentUrl: String(page.url?.() || ""),
        navigated: true,
        buttonState: lastButtonState,
      };
    }

    const challengeOutcome = await ensureManagedChallengeTokenBeforeSubmit(page, "signup").catch((error: unknown) => ({
      status: "rejected" as const,
      snapshot: null,
      rejection: error instanceof Error ? error.message : String(error),
    }));
    challengeStatus =
      challengeOutcome.status === "token_ready"
        ? "ready"
        : challengeOutcome.status === "timeout"
          ? "timeout"
          : "rejected";
    rejection = challengeOutcome.rejection || null;

    if (challengeOutcome.status === "rejected") {
      break;
    }
    if (challengeOutcome.status === "token_ready" || challengeOutcome.status === "timeout") {
      challengeStatus = "triggered";
      continue;
    }
  }

  return {
    verifyUrl: null,
    status: lastStatus,
    textPreview: lastTextPreview,
    challengeStatus,
    rejection,
    currentUrl: String(page.url?.() || ""),
    navigated: String(page.url?.() || "") !== lastKnownUrl,
    buttonState: lastButtonState,
  };
}

async function solveNativeTurnstileTokenOnPage(page: any, outputDir?: string): Promise<string | null> {
  const dismissCookieBanner = async () => {
    await clickFirstVisibleByText(page, [/reject all/i, /accept all cookies/i, /accept all/i]).catch(() => false);
  };

  const readToken = async (): Promise<string | null> => {
    return await page
      .evaluate(() => {
        const direct = document.querySelector('textarea[name="cf-turnstile-response"],input[name="cf-turnstile-response"]') as
          | HTMLInputElement
          | HTMLTextAreaElement
          | null;
        const value = String(direct?.value || "").trim();
        return value || null;
      })
      .catch(() => null);
  };

  const pollSnapshots: Array<Record<string, unknown>> = [];
  await dismissCookieBanner();
  const beforeToken = await readToken();
  const beforeFrame = page
    .frames()
    .find((frame: any) => /challenges\.cloudflare\.com\/.*turnstile/i.test(String(frame.url?.() || "")));
  const beforeFrameElement = beforeFrame ? await beforeFrame.frameElement().catch(() => null) : null;
  pollSnapshots.push({
    phase: "before_activation",
    tokenLength: beforeToken?.length || 0,
    frameUrl: String(beforeFrame?.url?.() || ""),
    frameBox: beforeFrameElement ? await beforeFrameElement.boundingBox().catch(() => null) : null,
    capturedAt: nowIso(),
  });
  if (!beforeToken) {
    const outcome = await ensureManagedChallengeTokenBeforeSubmit(page, "signup").catch((error: unknown) => ({
      status: "rejected" as const,
      snapshot: null,
      rejection: error instanceof Error ? error.message : String(error),
    }));
    const afterToken = await readToken();
    const afterFrame = page
      .frames()
      .find((frame: any) => /challenges\.cloudflare\.com\/.*turnstile/i.test(String(frame.url?.() || "")));
    const afterFrameElement = afterFrame ? await afterFrame.frameElement().catch(() => null) : null;
    pollSnapshots.push({
      phase: "after_activation",
      status: outcome.status,
      rejection: outcome.rejection || null,
      snapshot: outcome.snapshot || null,
      tokenLength: afterToken?.length || 0,
      frameUrl: String(afterFrame?.url?.() || ""),
      frameBox: afterFrameElement ? await afterFrameElement.boundingBox().catch(() => null) : null,
      capturedAt: nowIso(),
    });
    if (outputDir) {
      await writeJson(path.join(outputDir, "turnstile-native-check.json"), {
        mode: "native",
        pollSnapshots,
        capturedAt: nowIso(),
        url: String(page.url?.() || ""),
      }).catch(() => {});
      await page.screenshot({ path: path.join(outputDir, "turnstile-native.png"), fullPage: true }).catch(() => {});
    }
    return afterToken || null;
  }
  if (outputDir) {
    await writeJson(path.join(outputDir, "turnstile-native-check.json"), {
      mode: "native",
      pollSnapshots,
      capturedAt: nowIso(),
      url: String(page.url?.() || ""),
    }).catch(() => {});
    await page.screenshot({ path: path.join(outputDir, "turnstile-native.png"), fullPage: true }).catch(() => {});
  }
  return await readToken();
}

async function fetchTextWithinPage(page: any, targetUrl: string): Promise<string> {
  return await page.evaluate(async (url: string) => {
    const response = await fetch(url, { credentials: "include" });
    return await response.text();
  }, targetUrl);
}

async function resolveSignupBootstrap(page: any): Promise<SignupBootstrap> {
  const html = await page.content();
  const siteKeyMatch = html.match(/sitekey":"(0x4[a-zA-Z0-9_-]+)"/);
  const stateTreeMatch = html.match(/next-router-state-tree":"([^"]+)"/);
  const scriptUrls = Array.from(String(html).matchAll(/<script[^>]+src=["']([^"']+)["']/g), (match) => match[1]).filter((value): value is string => Boolean(value));
  let nextAction = "";
  for (const rawScriptUrl of scriptUrls) {
    if (!rawScriptUrl.includes("_next/static")) continue;
    const targetUrl = new URL(rawScriptUrl, GROK_ACCOUNTS_URL).toString();
    const scriptText = await fetchTextWithinPage(page, targetUrl).catch(() => "");
    const match = scriptText.match(/7f[a-fA-F0-9]{40}/);
    if (match?.[0]) {
      nextAction = match[0];
      break;
    }
  }
  const siteKey = siteKeyMatch?.[1] || "0x4AAAAAAAhr9JGVDZbrZOo0";
  const stateTree = stateTreeMatch?.[1] ||
    "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D";
  if (!nextAction) {
    throw new Error("grok_next_action_missing");
  }
  return { siteKey, nextAction, stateTree };
}

async function submitSignup(page: any, input: {
  email: string;
  password: string;
  emailValidationCode: string;
  turnstileToken: string;
  bootstrap: SignupBootstrap;
  displayName: string;
  userAgent?: string;
}): Promise<{ ok: boolean; status: number; text: string; verifyUrl: string | null }> {
  const { givenName, familyName } = splitName(input.displayName);
  const response = await page.evaluate(async ({
    payload,
    bootstrap,
    siteUrl,
    userAgent,
  }: {
    payload: {
      emailValidationCode: string;
      createUserAndSessionRequest: {
        email: string;
        givenName: string;
        familyName: string;
        clearTextPassword: string;
        tosAcceptedVersion: string;
      };
      turnstileToken: string;
      promptOnDuplicateEmail: boolean;
    };
    bootstrap: SignupBootstrap;
    siteUrl: string;
    userAgent: string;
  }) => {
    const response = await fetch(`${siteUrl}/sign-up`, {
      method: "POST",
      headers: {
        accept: "text/x-component",
        "content-type": "text/plain;charset=UTF-8",
        origin: siteUrl,
        referer: `${siteUrl}/sign-up`,
        "user-agent": userAgent,
        "next-router-state-tree": bootstrap.stateTree,
        "next-action": bootstrap.nextAction,
      },
      credentials: "include",
      body: JSON.stringify([payload]),
    });
    return {
      ok: response.ok,
      status: response.status,
      text: await response.text(),
    };
  }, {
    siteUrl: GROK_ACCOUNTS_URL,
    userAgent: input.userAgent || GROK_USER_AGENT,
    bootstrap: input.bootstrap,
    payload: {
      emailValidationCode: input.emailValidationCode,
      createUserAndSessionRequest: {
        email: input.email,
        givenName,
        familyName,
        clearTextPassword: input.password,
        tosAcceptedVersion: "$undefined",
      },
      turnstileToken: input.turnstileToken,
      promptOnDuplicateEmail: true,
    },
  });
  const verifyUrlMatch = response.text.match(/https:\/\/[^"'\s]+set-cookie\?q=[^"'\s:]+/);
  return {
    ...response,
    verifyUrl: verifyUrlMatch?.[0] || null,
  };
}

async function completeSsoVerification(page: any, verifyUrl: string, outputDir?: string): Promise<void> {
  const response = await page.request.get(verifyUrl, {
    failOnStatusCode: false,
    headers: {
      referer: `${GROK_ACCOUNTS_URL}/sign-up?redirect=grok-com`,
    },
    maxRedirects: 10,
    timeout: 60_000,
  });
  if (outputDir) {
    const textPreview = (await response.text().catch(() => "")).slice(0, 4_000);
    await writeJson(path.join(outputDir, "sso-verify-response.json"), {
      ok: response.ok(),
      status: response.status(),
      url: response.url(),
      headers: response.headers(),
      textPreview,
      capturedAt: nowIso(),
    }).catch(() => {});
  }
  await page.waitForTimeout(1_000).catch(() => {});
}

function extractTeamIdFromConsoleUrl(url: string): string | null {
  const match = String(url || "").match(/\/team\/([0-9a-f-]+)/i);
  return match?.[1] || null;
}

async function fillConsoleTextField(page: any, locator: any, value: string): Promise<boolean> {
  const visible = await locator?.isVisible?.().catch(() => false);
  if (!visible) return false;
  await clickLocatorViaCdp(page, locator).catch(() => false);
  await locator.click({ force: true }).catch(() => {});
  await locator.fill("").catch(() => {});
  await page.keyboard.press("Meta+A").catch(() => {});
  await page.keyboard.press("Control+A").catch(() => {});
  await page.keyboard.press("Backspace").catch(() => {});
  await page.keyboard.type(value, { delay: 35 }).catch(() => {});
  await locator
    .evaluate((element: HTMLInputElement, nextValue: string) => {
      element.value = nextValue;
      element.dispatchEvent(new Event("input", { bubbles: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
      element.dispatchEvent(new Event("blur", { bubbles: true }));
    }, value)
    .catch(() => {});
  await locator.press("Tab").catch(() => {});
  return true;
}

async function ensureConsoleTeamReady(page: any): Promise<void> {
  const text = await pageText(page);
  if (!/welcome to the xai console/i.test(text) || !/team name/i.test(text) || !/create team/i.test(text)) {
    return;
  }
  const teamName = `${DEFAULT_KEY_NAME_PREFIX}-${randomSuffix()}`;
  const teamInput = page.locator('input[name="name"]').first();
  const filled = await fillConsoleTextField(page, teamInput, teamName);
  if (!filled) {
    throw new Error("grok_console_team_name_missing");
  }
  const createButton = page.getByRole("button", { name: /create team/i }).first();
  const createVisible = await createButton.isVisible().catch(() => false);
  if (!createVisible) {
    throw new Error("grok_console_create_team_missing");
  }
  await clickLocatorViaCdp(page, createButton).catch(() => false);
  await createButton.click({ force: true }).catch(() => {});
  await Promise.race([
    page.waitForURL(/\/team\/[0-9a-f-]+(?:\/|$)/i, { timeout: 30_000 }).catch(() => null),
    waitForAnyVisibleText(page, [/dashboard/i, /^api keys$/i, /create your first api key/i], 30_000).catch(() => false),
  ]).catch(() => {});
  await page.waitForLoadState("networkidle", { timeout: 20_000 }).catch(() => {});
  const currentUrl = String(page.url() || "");
  if (/\/onboarding(?:\?|$)/i.test(currentUrl)) {
    throw new Error("grok_console_team_create_timeout");
  }
}

async function ensureConsoleApiKeysPage(page: any): Promise<void> {
  if (/\/api-keys(?:\/create)?(?:\?|$)/i.test(String(page.url() || ""))) {
    return;
  }
  await ensureConsoleTeamReady(page);
  const openedByClick =
    (await clickFirstVisibleByText(page, [/^api keys$/i, /manage api keys/i]).catch(() => false)) ||
    (await clickFirstVisibleByText(page, [/create your first api key/i]).catch(() => false));
  if (openedByClick) {
    await Promise.race([
      page.waitForURL(/\/api-keys(?:\/create)?(?:\?|$)/i, { timeout: 20_000 }).catch(() => null),
      waitForAnyVisibleText(page, [/api keys are used to authenticate/i, /no api keys found/i, /create api key/i], 20_000).catch(() => false),
    ]).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
  }
  if (/\/api-keys(?:\/create)?(?:\?|$)/i.test(String(page.url() || ""))) {
    return;
  }
  const teamId = extractTeamIdFromConsoleUrl(String(page.url() || ""));
  if (!teamId) {
    throw new Error(`grok_console_team_route_missing:${String(page.url() || "")}`);
  }
  await page.goto(`https://console.x.ai/team/${teamId}/api-keys`, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });
  await page.waitForLoadState("networkidle", { timeout: 20_000 }).catch(() => {});
}

async function ensureConsoleCreateApiKeyPage(page: any): Promise<void> {
  await ensureConsoleApiKeysPage(page);
  if (/\/api-keys\/create(?:\?|$)/i.test(String(page.url() || ""))) {
    return;
  }
  const opened =
    (await clickFirstVisibleByText(page, [/^create api key$/i, /^new api key$/i, /^generate api key$/i, /^create key$/i]).catch(() => false)) ||
    (await clickFirstVisibleByText(page, [/create your first api key/i]).catch(() => false));
  if (opened) {
    await Promise.race([
      page.waitForURL(/\/api-keys\/create(?:\?|$)/i, { timeout: 20_000 }).catch(() => null),
      waitForAnyVisibleText(page, [/create api key/i, /human friendly name/i, /restrict access/i], 20_000).catch(() => false),
    ]).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
  }
  if (/\/api-keys\/create(?:\?|$)/i.test(String(page.url() || ""))) {
    return;
  }
  const teamId = extractTeamIdFromConsoleUrl(String(page.url() || ""));
  if (!teamId) {
    throw new Error(`grok_console_api_keys_route_missing:${String(page.url() || "")}`);
  }
  await page.goto(`https://console.x.ai/team/${teamId}/api-keys/create`, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });
  await page.waitForLoadState("networkidle", { timeout: 20_000 }).catch(() => {});
}

async function waitForConsoleReady(page: any): Promise<void> {
  await page.goto(GROK_CONSOLE_URL, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await page.waitForLoadState("networkidle", { timeout: 30_000 }).catch(() => {});
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    let text = await pageText(page);
    if (/page not found/i.test(text) && /go home/i.test(text)) {
      await clickFirstVisibleByText(page, [/go home/i]).catch(() => false);
      await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
      text = await pageText(page);
    }
    const currentUrl = String(page.url() || "");
    if (
      /accounts\.x\.ai|sign-up|sign-in|log-in/i.test(currentUrl) ||
      (/sign in/i.test(text) && /create an account/i.test(text) && !/logout/i.test(text))
    ) {
      throw new Error(`grok_console_session_missing:${currentUrl}`);
    }
    if (/\/api-keys(?:\/create)?(?:\?|$)/i.test(currentUrl) || /api keys/i.test(text)) {
      return;
    }
    await ensureConsoleTeamReady(page).catch(() => {});
    await ensureConsoleApiKeysPage(page).catch(() => {});
    const refreshedUrl = String(page.url() || "");
    const refreshedText = await pageText(page);
    if (/\/api-keys(?:\/create)?(?:\?|$)/i.test(refreshedUrl) || /api keys/i.test(refreshedText)) {
      return;
    }
    await page.waitForTimeout(1_000).catch(() => {});
  }
  throw new Error(`grok_console_not_ready:${String(page.url() || "")}`);
}

async function solveTurnstileTokenInBrowser(
  page: any,
  siteKey: string,
  action?: string | null,
  cdata?: string | null,
  outputDir?: string,
): Promise<string | null> {
  const dismissCookieBanner = async () => {
    await clickFirstVisibleByText(page, [/reject all/i, /accept all cookies/i, /accept all/i]).catch(() => false);
  };

  const readToken = async (): Promise<string | null> => {
    return await page.evaluate(() => {
      const tokenFromRuntime = typeof (window as any).__grokTurnstileToken === "string" ? String((window as any).__grokTurnstileToken).trim() : "";
      if (tokenFromRuntime) return tokenFromRuntime;
      try {
        const direct = typeof (window as any).turnstile?.getResponse === "function" ? String((window as any).turnstile.getResponse() || "").trim() : "";
        if (direct) return direct;
      } catch {}
      const selectors = [
        'textarea[name="cf-turnstile-response"]',
        'input[name="cf-turnstile-response"]',
        'textarea[name="g-recaptcha-response"]',
        'input[name="g-recaptcha-response"]',
        'input[name="turnstileToken"]',
      ];
      for (const selector of selectors) {
        for (const element of Array.from(document.querySelectorAll(selector))) {
          const value = String((element as HTMLInputElement).value || (element as HTMLElement).textContent || "").trim();
          if (value) return value;
        }
      }
      return null;
    }).catch(() => null);
  };

  const injectWidget = async () => {
    const script = `
      const inputSiteKey = ${JSON.stringify(siteKey)};
      return (async () => {
        const setTokenValue = (token) => {
          const selectors = [
            'textarea[name="cf-turnstile-response"]',
            'input[name="cf-turnstile-response"]',
            'textarea[name="g-recaptcha-response"]',
            'input[name="g-recaptcha-response"]',
            'input[name="turnstileToken"]'
          ];
          let updated = 0;
          const apply = (element) => {
            if (!element) return;
            element.value = token;
            element.setAttribute('value', token);
            element.dispatchEvent(new Event('input', { bubbles: true }));
            element.dispatchEvent(new Event('change', { bubbles: true }));
            updated += 1;
          };
          for (const selector of selectors) {
            document.querySelectorAll(selector).forEach((element) => apply(element));
          }
          const form = document.querySelector('form');
          if (form && !form.querySelector('textarea[name="cf-turnstile-response"]')) {
            const hidden = document.createElement('textarea');
            hidden.name = 'cf-turnstile-response';
            hidden.style.display = 'none';
            form.appendChild(hidden);
            apply(hidden);
          }
          return updated;
        };
        if (typeof window.__grokTurnstileToken === 'string' && window.__grokTurnstileToken.trim()) {
          const token = String(window.__grokTurnstileToken).trim();
          setTokenValue(token);
          return { ok: true, reason: 'existing_token', tokenLength: token.length };
        }
        const existing = document.querySelector('script[src*="https://challenges.cloudflare.com/turnstile/v0/api.js"]');
        if (!existing) {
          const injected = document.createElement('script');
          injected.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
          injected.async = true;
          injected.defer = true;
          document.head.appendChild(injected);
          await new Promise((resolve) => {
            injected.onload = () => resolve();
            injected.onerror = () => resolve();
            setTimeout(resolve, 5000);
          });
        }
        let container = document.getElementById('__grok-turnstile-container');
        if (!container) {
          container = document.createElement('div');
          container.id = '__grok-turnstile-container';
          container.className = 'cf-turnstile';
          container.setAttribute('data-sitekey', inputSiteKey);
          Object.assign(container.style, {
            position: 'fixed',
            top: '20px',
            left: '20px',
            zIndex: '2147483647',
            minWidth: '320px',
            minHeight: '90px',
            backgroundColor: '#ffffff',
            padding: '16px',
            borderRadius: '12px',
            border: '2px solid #0f79af',
            boxShadow: '0 6px 24px rgba(0,0,0,0.24)'
          });
          document.body.appendChild(container);
        }
        let renderError = null;
        try {
          if (window.turnstile && typeof window.turnstile.render === 'function') {
            window.turnstile.render(container, {
              sitekey: inputSiteKey,
              callback: (token) => {
                window.__grokTurnstileToken = token;
                setTokenValue(token);
              },
              'error-callback': (error) => {
                window.__grokTurnstileError = String(error || '');
              },
              'expired-callback': () => {
                window.__grokTurnstileExpired = true;
              }
            });
          }
        } catch (error) {
          renderError = String(error || '');
          window.__grokTurnstileError = renderError;
        }
        return {
          ok: !renderError,
          reason: renderError ? 'render_failed' : 'rendered',
          hasContainer: !!document.getElementById('__grok-turnstile-container'),
          hasTurnstile: typeof window.turnstile !== 'undefined',
          iframeCount: document.querySelectorAll('iframe[src*="turnstile"], iframe[src*="challenges.cloudflare.com"]').length,
          error: renderError
        };
      })();
    `;
    return await page.evaluate((source: string) => new Function(source)(), script).catch((error: unknown) => ({
      ok: false,
      reason: "inject_eval_failed",
      error: String(error || ""),
    }));
  };

  const tryClickStrategies = async () => {
    const iframeSelectors = [
      'iframe[src*="challenges.cloudflare.com"]',
      'iframe[src*="turnstile"]',
      'iframe[title*="widget"]',
    ];
    for (const selector of iframeSelectors) {
      const iframe = page.locator(selector).first();
      const count = await iframe.count().catch(() => 0);
      if (count <= 0) continue;
      try {
        const element = await iframe.elementHandle();
        const frame = await element?.contentFrame();
        if (frame) {
          for (const checkboxSelector of ['input[type="checkbox"]', '.cb-lb input[type="checkbox"]', 'label input[type="checkbox"]']) {
            const checkbox = frame.locator(checkboxSelector).first();
            const checkboxCount = await checkbox.count().catch(() => 0);
            if (checkboxCount <= 0) continue;
            await checkbox.click({ timeout: 2_000 }).catch(() => {});
          }
        }
        await iframe.click({ timeout: 1_500 }).catch(() => {});
      } catch {}
    }
    for (const selector of [
      ".cf-turnstile",
      '[data-sitekey]',
      'iframe[src*="turnstile"]',
      'iframe[title*="widget"]',
      '*[class*="turnstile"]',
    ]) {
      const locator = page.locator(selector).first();
      const count = await locator.count().catch(() => 0);
      if (count <= 0) continue;
      await locator.click({ force: true, timeout: 1_500 }).catch(() => {});
    }
  };

  await dismissCookieBanner();
  const existingToken = await readToken();
  if (existingToken) {
    return existingToken;
  }
  const injectResult = await injectWidget();
  if (outputDir) {
    await writeJson(path.join(outputDir, "turnstile-browser-check.json"), {
      injectResult,
      capturedAt: nowIso(),
      url: String(page.url?.() || ""),
    }).catch(() => {});
    await page.screenshot({ path: path.join(outputDir, "turnstile-browser.png"), fullPage: true }).catch(() => {});
  }
  for (let index = 0; index < 45; index += 1) {
    const token = await readToken();
    if (token) {
      return token;
    }
    if (index % 4 === 0) {
      await dismissCookieBanner();
      await tryClickStrategies();
    }
    await page.waitForTimeout(1_000).catch(() => {});
  }
  return await readToken();
}

async function createConsoleApiKey(page: any, outputDir: string, keyName: string): Promise<string> {
  let networkCapturedKey: string | null = null;
  const responseListener = async (response: any) => {
    const url = String(response.url?.() || "");
    if (!/api[-_ ]?keys|graphql|console\.x\.ai/i.test(url)) return;
    const text = await response.text().catch(() => "");
    const candidate = extractApiKeyCandidate(text);
    if (candidate) {
      networkCapturedKey = candidate;
    }
  };
  page.on("response", responseListener);
  try {
    await ensureConsoleCreateApiKeyPage(page);
    const keyNameInput = page.locator('input[name="name"], #api-key-name').first();
    const filled =
      (await fillConsoleTextField(page, keyNameInput, keyName).catch(() => false)) ||
      (await fillVisibleField(page, [/name/i, /key name/i, /display name/i], keyName).catch(() => false));
    if (!filled) {
      throw new Error("grok_console_key_name_missing");
    }
    const submitButton = page.getByRole("button", { name: /^create api key$/i }).first();
    if (!(await clickLocatorViaCdp(page, submitButton).catch(() => false))) {
      const submitVisible = await submitButton.isVisible().catch(() => false);
      if (!submitVisible) {
        throw new Error("grok_console_create_button_missing");
      }
      await submitButton.click({ force: true }).catch(() => {});
    }
    await page.waitForLoadState("networkidle", { timeout: 20_000 }).catch(() => {});
    const startedAt = Date.now();
    let pageKey: string | null = null;
    while (Date.now() - startedAt < 30_000) {
      const previewText = await pageText(page);
      pageKey = networkCapturedKey || (await extractApiKeyFromPage(page)) || extractApiKeyCandidate(previewText);
      if (pageKey) break;
      await page.waitForTimeout(500).catch(() => {});
    }
    if (!pageKey) {
      const maybeCopy = await clickFirstVisibleByText(page, [/copy/i, /show/i, /reveal/i]).catch(() => false);
      if (maybeCopy) {
        await page.waitForTimeout(800).catch(() => {});
      }
      pageKey = networkCapturedKey || (await extractApiKeyFromPage(page)) || extractApiKeyCandidate(await pageText(page));
    }
    await writeJson(path.join(outputDir, "console-page-snapshot.json"), {
      url: String(page.url?.() || ""),
      textPreview: (await pageText(page)).slice(0, 5_000),
      capturedAt: nowIso(),
    }).catch(() => {});
    if (!pageKey) {
      throw new Error("grok_api_key_not_found");
    }
    await writeFile(path.join(outputDir, "console-api-key.txt"), `${pageKey}\n`, "utf8").catch(() => {});
    return pageKey;
  } finally {
    page.off("response", responseListener);
  }
}

function classifyApiKeyValidation(status: number | null, responseText: string): {
  ok: boolean;
  retryable: boolean;
  reason: string;
} {
  if (status === 200) {
    return { ok: true, retryable: false, reason: "http_200" };
  }
  if (
    status === 403 &&
    /does not have permission to execute the specified operation|credits or licenses yet|purchase those on https:\/\/console\.x\.ai/i.test(
      responseText,
    )
  ) {
    return { ok: true, retryable: false, reason: "http_403_no_credits_but_key_accepted" };
  }
  if (
    (status === 400 || status === 401 || status === 403) &&
    /incorrect api key provided|client specified an invalid argument|api key/i.test(responseText)
  ) {
    return {
      ok: false,
      retryable: true,
      reason: `http_${status}_key_not_propagated_yet`,
    };
  }
  return {
    ok: false,
    retryable: false,
    reason: `http_${Number.isFinite(status || 0) ? status : "unknown"}`,
  };
}

async function validateApiKeyWithCurl(input: {
  apiKey: string;
  proxyServer: string;
  outputDir: string;
}): Promise<{ ok: boolean; status: number | null; reason: string }> {
  const attempts: Array<{
    mode: "proxy" | "direct";
    status: number | null;
    reason: string;
    responseTextPreview: string;
  }> = [];
  const runAttempt = async (mode: "proxy" | "direct"): Promise<{ ok: boolean; status: number | null; reason: string }> => {
    const responseFile =
      mode === "proxy" ? path.join(input.outputDir, "validate-response.json") : path.join(input.outputDir, "validate-response-direct.json");
    const stderrFile = mode === "proxy" ? path.join(input.outputDir, "validate-stderr.txt") : path.join(input.outputDir, "validate-stderr-direct.txt");
    const env =
      mode === "proxy"
        ? {
            ...process.env,
            HTTPS_PROXY: input.proxyServer,
            HTTP_PROXY: input.proxyServer,
            ALL_PROXY: input.proxyServer,
          }
        : { ...process.env };
    try {
      const { stdout, stderr } = await execFile(
        "curl",
        [
          "-sS",
          "-o",
          responseFile,
          "-w",
          "%{http_code}",
          "-H",
          `Authorization: Bearer ${input.apiKey}`,
          "-H",
          "Accept: application/json",
          GROK_VALIDATE_URL,
        ],
        { env },
      );
      if (stderr?.trim()) {
        await writeFile(stderrFile, `${stderr}\n`, "utf8").catch(() => {});
      }
      const status = Number.parseInt(String(stdout || "").trim(), 10);
      const responseText = await readFile(responseFile, "utf8").catch(() => "");
      const classified = classifyApiKeyValidation(Number.isFinite(status) ? status : null, responseText);
      attempts.push({
        mode,
        status: Number.isFinite(status) ? status : null,
        reason: classified.reason,
        responseTextPreview: responseText.slice(0, 1_000),
      });
      return {
        ok: classified.ok,
        status: Number.isFinite(status) ? status : null,
        reason: classified.reason,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await writeFile(stderrFile, `${message}\n`, "utf8").catch(() => {});
      attempts.push({
        mode,
        status: null,
        reason: message,
        responseTextPreview: "",
      });
      return { ok: false, status: null, reason: message };
    }
  };

  const plan: Array<"proxy" | "direct"> = ["proxy", "proxy", "direct", "direct"];
  let last = { ok: false, status: null as number | null, reason: "not_run" };
  for (let index = 0; index < plan.length; index += 1) {
    const mode = plan[index]!;
    last = await runAttempt(mode);
    if (last.ok) {
      await writeJson(path.join(input.outputDir, "validate-attempts.json"), {
        attempts,
        capturedAt: nowIso(),
      }).catch(() => {});
      return last;
    }
    const retryable = /key_not_propagated_yet|Failed to connect|timed out|Could not resolve host|Connection reset/i.test(last.reason);
    if (!retryable || index === plan.length - 1) {
      break;
    }
    await sleepMs(5_000);
  }
  await writeJson(path.join(input.outputDir, "validate-attempts.json"), {
    attempts,
    capturedAt: nowIso(),
  }).catch(() => {});
  return last;
}

async function cleanupWithTimeout(task: Promise<unknown>, timeoutMs = 5_000): Promise<void> {
  await Promise.race([task.catch(() => {}), sleepMs(timeoutMs)]);
}

async function run(): Promise<void> {
  const outputDir = requireEnv("GROK_JOB_OUTPUT_DIR");
  await writeStageMarker(outputDir, "bootstrap:start");
  const args = parseArgs(process.argv.slice(2));
  const cfg = loadConfig();
  const authProvider = getGrokAuthProvider();
  const runMode = cfg.runMode === "headless" ? "headless" : "headed";
  const runId = `grok-${Date.now()}`;
  const password = randomPassword();
  const displayName = randomName();
  let failureStage = "bootstrap_mihomo";

  const mihomo = await startMihomo({
    subscriptionUrl: requireEnv("MIHOMO_SUBSCRIPTION_URL"),
    apiPort: Number.parseInt(requireEnv("MIHOMO_API_PORT"), 10),
    mixedPort: Number.parseInt(requireEnv("MIHOMO_MIXED_PORT"), 10),
    groupName: requireEnv("MIHOMO_GROUP_NAME"),
    routeGroupName: requireEnv("MIHOMO_ROUTE_GROUP_NAME"),
    checkUrl: requireEnv("PROXY_CHECK_URL"),
    workDir: path.join(outputDir, "mihomo"),
    downloadDir: path.join(process.cwd(), "downloads", "mihomo"),
  });
  await writeStageMarker(outputDir, "bootstrap:mihomo_ready", {
    proxyServer: mihomo.proxyServer,
  });
  if (args.proxyNode) {
    await mihomo.setGroupProxy(args.proxyNode);
    await writeStageMarker(outputDir, "bootstrap:proxy_selected", {
      proxyNode: args.proxyNode,
    });
  }

  failureStage = "bootstrap_mailbox";
  const mailbox = parseMailboxFromEnv();
  const email = mailbox.address.toLowerCase();
  await writeJson(path.join(outputDir, "mailbox-session.json"), {
    provider: mailbox.provider,
    address: mailbox.address,
    accountId: mailbox.accountId,
    baseUrl: mailbox.baseUrl,
    proxyServer: mihomo.proxyServer,
    capturedAt: nowIso(),
  }).catch(() => {});
  log(`mailbox ready: provider=${mailbox.provider} address=${email}`);
  await writeStageMarker(outputDir, "bootstrap:mailbox_ready", {
    email,
    mailboxId: mailbox.accountId,
    provider: mailbox.provider,
    authProvider,
  });

  let browser: any = null;
  let context: any = null;
  let page: any = null;
  let nativeChromeStop: (() => Promise<void>) | null = null;
  const useNativeChrome = cfg.browserEngine === "chrome" && cfg.chromeNativeAutomation;
  let effectiveUserAgent = GROK_USER_AGENT;
  const prelaunchGeo = await collectProxyGeoViaProxy(mihomo.proxyServer).catch(() => null);
  const launchWorkerBrowserSession = async (
    identityOutputFile = "browser-identity.json",
    options?: { proxyServer?: string; forcePlaywright?: boolean },
  ) => {
    let nextBrowser: any = null;
    let nextContext: any = null;
    let nextPage: any = null;
    let nextNativeChromeStop: (() => Promise<void>) | null = null;
    const sessionProxyServer = options?.proxyServer;
    const shouldUseNativeChrome = useNativeChrome && !options?.forcePlaywright;
    if (shouldUseNativeChrome) {
      const launched = await launchNativeChromeCdp(
        cfg,
        runMode,
        sessionProxyServer || mihomo.proxyServer,
        "en-US",
        "en-US,en;q=0.9",
        prelaunchGeo?.timezone,
        undefined,
        ["about:blank"],
      );
      nextBrowser = launched.browser;
      nextContext = launched.context;
      nextNativeChromeStop = launched.stop;
      const existingPages = typeof nextContext.pages === "function" ? nextContext.pages() : [];
      nextPage = existingPages.find((item: any) => item && typeof item.url === "function") || (await nextContext.newPage());
    } else {
      nextBrowser = await launchBrowserWithEngine(cfg.browserEngine, cfg, runMode, sessionProxyServer, "en-US", "");
      nextContext = await nextBrowser.newContext({
        locale: "en-US",
        viewport: { width: 1512, height: 982 },
        screen: { width: 1512, height: 982 },
        deviceScaleFactor: 2,
        extraHTTPHeaders: {
          "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        },
      });
      nextPage = await nextContext.newPage();
    }
    const browserIdentity = await alignBrowserIdentity({
      cfg,
      browser: nextBrowser,
      context: nextContext,
      page: nextPage,
      useNativeChrome: shouldUseNativeChrome,
      outputDir,
      prelaunchGeo: sessionProxyServer ? prelaunchGeo : null,
      identityOutputFile,
    });
    await applyTurnstileStealthInit(nextPage);
    return {
      browser: nextBrowser,
      context: nextContext,
      page: nextPage,
      nativeChromeStop: nextNativeChromeStop,
      browserIdentity,
    };
  };
  failureStage = "init";
  try {
    await writeStageMarker(outputDir, "bootstrap:browser_launching", {
      runMode,
      proxyNode: args.proxyNode || null,
      prelaunchGeo,
    });
    const launchedSession = await launchWorkerBrowserSession();
    browser = launchedSession.browser;
    context = launchedSession.context;
    page = launchedSession.page;
    nativeChromeStop = launchedSession.nativeChromeStop;
    const browserIdentity = launchedSession.browserIdentity;
    effectiveUserAgent = browserIdentity.userAgent;
    await writeStageMarker(outputDir, "bootstrap:browser_ready", {
      browserMode: useNativeChrome ? "chrome-native-cdp" : cfg.browserEngine,
      proxyGeo: browserIdentity.browserGeo,
      locale: browserIdentity.locale,
      timezone: browserIdentity.browserGeo?.timezone || null,
    });

    failureStage = "accounts_signup_load";
    await page.goto(GROK_SIGNUP_URL, { waitUntil: "domcontentloaded", timeout: 90_000 });
    await page.waitForLoadState("networkidle", { timeout: 30_000 }).catch(() => {});
    await captureRuntimeBrowserSnapshot(page, outputDir, "signup-page-browser.json");
    const bootstrap = await resolveSignupBootstrap(page);
    await writeStageMarker(outputDir, "accounts:bootstrap_resolved", {
      siteKey: bootstrap.siteKey,
      nextAction: bootstrap.nextAction,
      stateTree: bootstrap.stateTree,
    });

    let verificationCode: string | null = null;
    if (authProvider === "microsoft") {
      const microsoftVerificationNotBefore = nowIso();
      failureStage = "accounts_open_microsoft_login";
      const clickedMicrosoft = await clickMicrosoftProviderEntry(page);
      if (!clickedMicrosoft) {
        throw new Error("grok_microsoft_entry_missing");
      }
      await writeStageMarker(outputDir, "accounts:microsoft_entry_opened", {});
      page = await completeMicrosoftLogin(page, cfg, mihomo.proxyServer, {
        completionUrlPatterns: [
          /^https:\/\/accounts\.x\.ai/i,
          /^https:\/\/grok\.com/i,
          /^https:\/\/x\.ai/i,
        ],
        passkeyRecoveryUrl: GROK_SIGNUP_URL,
      });
      await page.waitForLoadState("domcontentloaded", { timeout: 45_000 }).catch(() => {});
      await writeStageMarker(outputDir, "accounts:microsoft_login_completed", {
        currentUrl: String(page.url?.() || ""),
      });
      await captureRuntimeBrowserSnapshot(page, outputDir, "microsoft-login-browser.json");
      await recoverSetCookieFlow(page, outputDir, "after_microsoft_login").catch(() => {});
      if (!(await hasSsoCookie(page)) && (await isMicrosoftVerificationCodeSurface(page))) {
        failureStage = "accounts_wait_microsoft_code";
        const verification = await waitForMicrosoftMailboxVerificationCode({
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
          timeoutMs: 75_000,
          pollMs: 2500,
          notBefore: microsoftVerificationNotBefore,
          providers: ["grok", "generic"],
        });
        verificationCode = verification.code;
        await writeStageMarker(outputDir, "accounts:microsoft_code_received", {
          codeLength: verification.code.length,
          provider: verification.provider,
        });
        failureStage = "accounts_verify_microsoft_code";
        const verified = await submitEmailCodeInPage(page, verification.code);
        const verifiedGrpc = verified.grpcStatus
          ? { grpcStatus: verified.grpcStatus, grpcMessage: verified.grpcMessage }
          : parseGrpcTrailerFromText(verified.trailerText);
        await writeJson(path.join(outputDir, "microsoft-code-verify.json"), verified).catch(() => {});
        if (!verified.ok || (verifiedGrpc.grpcStatus && verifiedGrpc.grpcStatus !== "0")) {
          throw new Error(`grok_microsoft_code_verify_failed:${verifiedGrpc.grpcStatus || "unknown"}:${verifiedGrpc.grpcMessage || "no_message"}`);
        }
        await recoverSetCookieFlow(page, outputDir, "after_microsoft_code_verify").catch(() => {});
      }
      if (await hasSsoCookie(page)) {
        await writeStageMarker(outputDir, "accounts:sso_ready_after_microsoft", {});
      } else {
        await writeStageMarker(outputDir, "accounts:profile_completion_after_microsoft", {
          currentUrl: String(page.url?.() || ""),
        });
      }
    } else {
      failureStage = "accounts_send_email_code";
      const sent = await startEmailSignupInPage(page, email);
      const sentGrpc = sent.grpcStatus
        ? { grpcStatus: sent.grpcStatus, grpcMessage: sent.grpcMessage }
        : parseGrpcTrailerFromText(sent.textPreview);
      await writeJson(path.join(outputDir, "email-code-send.json"), sent).catch(() => {});
      if (!sent.ok || (sentGrpc.grpcStatus && sentGrpc.grpcStatus !== "0")) {
        throw new Error(`grok_email_code_send_failed:${sent.status}:${sentGrpc.grpcStatus || "unknown"}`);
      }
      await writeStageMarker(outputDir, "accounts:email_code_sent", {
        email,
        status: sent.status,
      });

      failureStage = "accounts_wait_email_code";
      await writeStageMarker(outputDir, "accounts:waiting_email_code", {
        provider: mailbox.provider,
      });
      const verification = await waitForGrokEmailCode({
        mailbox,
        cfg,
        proxyUrl: mihomo.proxyServer,
      });
      verificationCode = verification.code;
      await writeStageMarker(outputDir, "accounts:email_code_received", {
        provider: mailbox.provider,
        codeLength: verification.code.length,
      });

      failureStage = "accounts_verify_email_code";
      const verified = await submitEmailCodeInPage(page, verification.code);
      const verifiedGrpc = verified.grpcStatus
        ? { grpcStatus: verified.grpcStatus, grpcMessage: verified.grpcMessage }
        : parseGrpcTrailerFromText(verified.trailerText);
      await writeJson(path.join(outputDir, "email-code-verify.json"), verified).catch(() => {});
      if (!verified.ok || (verifiedGrpc.grpcStatus && verifiedGrpc.grpcStatus !== "0")) {
        throw new Error(`grok_email_code_verify_failed:${verifiedGrpc.grpcStatus || "unknown"}:${verifiedGrpc.grpcMessage || "no_message"}`);
      }
      await writeStageMarker(outputDir, "accounts:email_verified", {
        codeLength: verification.code.length,
      });
      await writeStageMarker(outputDir, "accounts:complete_signup_ready", {
        email,
      });
      await captureRuntimeBrowserSnapshot(page, outputDir, "complete-signup-browser.json");
      await recoverSetCookieFlow(page, outputDir, "after_email_verify").catch(() => {});
    }

    let completedViaNative = false;
    let turnstileProvider: string | null = null;
    if (authProvider !== "microsoft" || !(await hasSsoCookie(page))) {
      failureStage = "accounts_submit_signup_native";
      await fillCompleteSignupFields(page, displayName, password);
      const nativeSignup = await submitCompleteSignupInPage(page, outputDir);
      await writeJson(path.join(outputDir, "signup-native.json"), nativeSignup).catch(() => {});
      if (/set-cookie\?q=|auth\.grok\.com|auth\.x\.ai|grok\.com/i.test(nativeSignup.currentUrl || "")) {
        await recoverSetCookieFlow(page, outputDir, "after_native_signup").catch(() => {});
      }

      if (nativeSignup.verifyUrl) {
        await writeStageMarker(outputDir, "accounts:signup_submitted", {
          mode: "native_page",
          status: nativeSignup.status,
          hasVerifyUrl: true,
        });
        failureStage = "accounts_complete_sso";
        await completeSsoVerification(page, nativeSignup.verifyUrl, outputDir);
        completedViaNative = true;
      } else if (await hasSsoCookie(page)) {
        await writeStageMarker(outputDir, "accounts:signup_submitted", {
          mode: "native_page",
          status: nativeSignup.status,
          hasVerifyUrl: false,
          ssoReady: true,
          currentUrl: nativeSignup.currentUrl,
        });
        completedViaNative = true;
      }
    } else if (await hasSsoCookie(page)) {
      completedViaNative = true;
    }

    if (authProvider === "microsoft" && !completedViaNative) {
      throw new Error("grok_microsoft_post_sso_profile_unhandled");
    }

    if (!completedViaNative) {
      failureStage = "accounts_turnstile";
      let turnstile: { token: string; provider: string };
      try {
        const nativeToken = await solveNativeTurnstileTokenOnPage(page, outputDir);
        if (nativeToken) {
          turnstile = { token: nativeToken, provider: "browser_turnstile_native" };
        } else {
          throw new Error("native_turnstile_token_missing");
        }
      } catch (nativeError) {
        try {
          turnstile = await solveTurnstileToken({
            siteUrl: String(page.url?.() || GROK_SIGNUP_URL),
            siteKey: bootstrap.siteKey,
          });
        } catch (solverError) {
          const browserToken = await solveTurnstileTokenInBrowser(page, bootstrap.siteKey, null, null, outputDir);
          if (!browserToken) {
            throw nativeError instanceof Error ? nativeError : solverError;
          }
          turnstile = { token: browserToken, provider: "browser_turnstile_injected" };
        }
      }
      turnstileProvider = turnstile.provider;
      await writeStageMarker(outputDir, "accounts:turnstile_solved", {
        provider: turnstile.provider,
      });

      failureStage = "accounts_submit_signup";
      const signupResponse = await submitSignup(page, {
        email,
        password,
        emailValidationCode: verificationCode || "",
        turnstileToken: turnstile.token,
        bootstrap,
        displayName,
        userAgent: effectiveUserAgent,
      });
      await writeFile(path.join(outputDir, "signup-response.txt"), `${signupResponse.text}\n`, "utf8").catch(() => {});
      if (!signupResponse.ok || !signupResponse.verifyUrl) {
        throw new Error(`grok_signup_failed:${signupResponse.status}`);
      }
      await writeStageMarker(outputDir, "accounts:signup_submitted", {
        mode: "direct_post",
        status: signupResponse.status,
        hasVerifyUrl: Boolean(signupResponse.verifyUrl),
      });

      failureStage = "accounts_complete_sso";
      await completeSsoVerification(page, signupResponse.verifyUrl, outputDir);
    }
    await captureCookies(context, outputDir);
    const cookies = await context.cookies().catch(() => []);
    const hasSsoCookieValue = cookies.some((cookie: any) => cookie?.name === "sso" && cookie?.value && isUsableSsoDomain(cookie?.domain));
    if (!hasSsoCookieValue) {
      throw new Error("grok_sso_cookie_missing");
    }
    await writeStageMarker(outputDir, "accounts:sso_ready", {
      cookieCount: cookies.length,
    });

    const sessionBundle = await getGrokSessionBundle(page);
    if (!sessionBundle) {
      throw new Error("grok_session_bundle_missing");
    }
    await hydrateGrokDomainSessionCookies(context, sessionBundle);
    await captureCookies(context, outputDir);
    await writeJson(path.join(outputDir, "grok-session.json"), sessionBundle).catch(() => {});

    failureStage = "accounts_accept_tos";
    const accountsPage = await context.newPage();
    try {
      const tosAccepted = await acceptTosVersion(accountsPage, outputDir);
      if (!tosAccepted.ok) {
        throw new Error(`grok_accept_tos_failed:${tosAccepted.status}:${tosAccepted.grpcStatus || "unknown"}`);
      }
    } finally {
      await accountsPage.close().catch(() => {});
    }
    await writeStageMarker(outputDir, "accounts:tos_accepted", {});

    const handoffCookies = await context.cookies().catch(() => []);
    let freshPostProvision: Awaited<ReturnType<typeof launchWorkerBrowserSession>> | null = null;
    let postProvisionError = "grok_post_provision_page_not_ready";
    for (let handoffAttempt = 1; handoffAttempt <= 3; handoffAttempt += 1) {
      const candidate = await launchWorkerBrowserSession(`post-provision-browser-identity-${handoffAttempt}.json`, {
        proxyServer: undefined,
        forcePlaywright: true,
      });
      await candidate.context
        .addCookies((handoffCookies || []).filter((cookie: any) => cookie?.name && cookie?.value))
        .catch(() => {});
      await hydrateGrokDomainSessionCookies(candidate.context, sessionBundle);
      const ready = await ensureGrokPageReady(candidate.page, outputDir, `post-provision-${handoffAttempt}`);
      if (ready.ok) {
        freshPostProvision = candidate;
        break;
      }
      postProvisionError = ready.blocked ? "grok_post_provision_page_blocked" : "grok_post_provision_page_not_ready";
      await cleanupWithTimeout(candidate.context?.close?.() ?? Promise.resolve(), 5_000);
      await cleanupWithTimeout(candidate.browser?.close?.() ?? Promise.resolve(), 5_000);
      if (candidate.nativeChromeStop) {
        await cleanupWithTimeout(candidate.nativeChromeStop(), 5_000);
      }
      if (handoffAttempt < 3) {
        await sleepMs(8_000 * handoffAttempt);
      }
    }
    if (!freshPostProvision) {
      throw new Error(postProvisionError);
    }
    await captureRuntimeBrowserSnapshot(freshPostProvision.page, outputDir, "post-provision-browser.json");
    const previousBrowser = browser;
    const previousContext = context;
    const previousPage = page;
    const previousNativeChromeStop = nativeChromeStop;
    browser = freshPostProvision.browser;
    context = freshPostProvision.context;
    page = freshPostProvision.page;
    nativeChromeStop = freshPostProvision.nativeChromeStop;
    effectiveUserAgent = freshPostProvision.browserIdentity.userAgent;
    await cleanupWithTimeout(previousPage?.close?.() ?? Promise.resolve(), 2_000);
    await cleanupWithTimeout(previousContext?.close?.() ?? Promise.resolve(), 5_000);
    await cleanupWithTimeout(previousBrowser?.close?.() ?? Promise.resolve(), 5_000);
    if (previousNativeChromeStop) {
      await cleanupWithTimeout(previousNativeChromeStop(), 5_000);
    }

    failureStage = "accounts_set_birth_date";
    const birthDate = randomBirthDate();
    const birthDateResult = await setBirthDate(page, outputDir, birthDate);
    if (!birthDateResult.ok) {
      throw new Error(`grok_birth_date_failed:${birthDateResult.status}`);
    }
    await writeStageMarker(outputDir, "accounts:birth_date_set", {
      birthDate,
    });

    failureStage = "accounts_enable_nsfw";
    const nsfwResult = await enableNsfw(page, outputDir);
    if (!nsfwResult.ok) {
      throw new Error(`grok_nsfw_failed:${nsfwResult.status}:${nsfwResult.grpcStatus || "unknown"}`);
    }
    await writeStageMarker(outputDir, "accounts:nsfw_enabled", {});

    failureStage = "accounts_update_user_settings";
    const userSettingsResult = await updateUserSettings(page, outputDir);
    if (!userSettingsResult.ok) {
      throw new Error(`grok_user_settings_failed:${userSettingsResult.status}`);
    }
    await writeStageMarker(outputDir, "accounts:user_settings_updated", {});

    failureStage = "accounts_create_checkout_url";
    const checkoutResult = await createCheckoutUrl(page, outputDir, email);
    if (!checkoutResult.ok) {
      throw new Error(`grok_checkout_url_failed:${checkoutResult.status || "unknown"}`);
    }
    await writeStageMarker(outputDir, "accounts:checkout_url_ready", {
      checkoutUrl: checkoutResult.checkoutUrl,
    });

    await captureCookies(context, outputDir);
    const finalSessionBundle = (await getGrokSessionBundle(page)) || sessionBundle;
    const sso = finalSessionBundle.sso;
    await writeFile(path.join(outputDir, "grok-sso.txt"), `${sso}\n`, "utf8").catch(() => {});
    await writeFile(path.join(outputDir, "grok-sso-rw.txt"), `${finalSessionBundle.ssoRw}\n`, "utf8").catch(() => {});
    if (finalSessionBundle.cfClearance) {
      await writeFile(path.join(outputDir, "grok-cf-clearance.txt"), `${finalSessionBundle.cfClearance}\n`, "utf8").catch(
        () => {},
      );
    }
    await writeFile(path.join(outputDir, "grok-account.txt"), `${email}|${password}|${sso}\n`, "utf8").catch(() => {});
    await writeFile(
      path.join(outputDir, "grok-account-full.txt"),
      `${email}|${password}|${sso}|${finalSessionBundle.ssoRw}|${finalSessionBundle.cfClearance || ""}|${checkoutResult.checkoutUrl}|${birthDate}\n`,
      "utf8",
    ).catch(() => {});
    await writeJson(path.join(outputDir, "grok-session-bundle.json"), {
      email,
      password,
      sso,
      ssoRw: finalSessionBundle.ssoRw,
      cfClearance: finalSessionBundle.cfClearance,
      checkoutUrl: checkoutResult.checkoutUrl,
      birthDate,
      capturedAt: nowIso(),
    }).catch(() => {});
    await writeStageMarker(outputDir, "accounts:sso_exported", {
      prefix: sso.slice(0, 12),
      url: String(page.url() || ""),
      checkoutUrl: checkoutResult.checkoutUrl,
      hasSsoRw: Boolean(finalSessionBundle.ssoRw),
      hasCfClearance: Boolean(finalSessionBundle.cfClearance),
    });

    const proxyNode = args.proxyNode || (await mihomo.getGroupSelection().catch(() => null)) || null;
    await writeJson(path.join(outputDir, "result.json"), {
      mode: runMode,
      email,
      password,
      sso,
      ssoRw: finalSessionBundle.ssoRw,
      cfClearance: finalSessionBundle.cfClearance,
      checkoutUrl: checkoutResult.checkoutUrl,
      birthDate,
      proxy: {
        nodeName: proxyNode,
        ip: null,
      },
      runId,
      notes: [
        `mailbox=${mailbox.accountId}`,
        `mail_provider=${mailbox.provider}`,
        `proxy=${proxyNode || "default"}`,
        `turnstile=${turnstileProvider || (completedViaNative ? "native_page" : "unknown")}`,
        `artifact=sso`,
        `tos=accepted`,
        `nsfw=enabled`,
        `settings=updated`,
        `checkout=ready`,
      ],
    } satisfies GrokWorkerResult);
    if (isFingerprintBusinessFlow()) {
      await holdBrowserForBusinessFlowHandoff(page, browser, "grok_ready", {
        email,
        checkoutUrl: checkoutResult.checkoutUrl,
      });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await writeFailureArtifacts(outputDir, page, failureStage);
    await writeJson(path.join(outputDir, "error.json"), {
      error: message,
      failureStage,
    });
    if (isFingerprintBusinessFlow()) {
      await holdBrowserForBusinessFlowHandoff(page, browser, "grok_failed", {
        success: false,
        error: message,
        failureStage,
      });
    }
    await keepBrowserOpenOnFailure(page, browser, failureStage);
    throw error;
  } finally {
    await cleanupWithTimeout(captureCookies(context, outputDir), 2_000);
    await cleanupWithTimeout(context?.close?.() ?? Promise.resolve(), 5_000);
    await cleanupWithTimeout(browser?.close?.() ?? Promise.resolve(), 5_000);
    if (nativeChromeStop) {
      await cleanupWithTimeout(nativeChromeStop(), 5_000);
    }
    await cleanupWithTimeout(mihomo.stop(), 5_000);
  }
}

void run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
