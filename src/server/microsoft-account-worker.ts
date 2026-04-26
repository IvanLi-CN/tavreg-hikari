import path from "node:path";
import process from "node:process";
import { mkdir, writeFile } from "node:fs/promises";
import { Impit } from "impit";
import { buildAcceptLanguage, deriveLocale, parseIpInfoPayload, type GeoInfo } from "../proxy/geo.js";
import { startMihomo } from "../proxy/mihomo.js";
import {
  cleanupManagedChromeProcessesUnder,
  completeMicrosoftLogin,
  launchChromePersistent,
  loadConfig,
} from "../main.js";
import {
  assessMicrosoftAccountSurface,
  formatMicrosoftAccountSurfaceSummary,
  isMicrosoftAccountAuthIntermediateUrl,
  isMicrosoftAccountHomeUrl,
  isMicrosoftLoginSurfaceUrl,
  type MicrosoftAccountSurfaceAssessment,
  type MicrosoftAccountSurfaceSnapshot,
} from "./microsoft-account-surface.js";

interface WorkerArgs {
  proxyNode: string | null;
}

interface WorkerResult {
  ok: boolean;
  finalUrl?: string | null;
  proxy?: {
    nodeName: string | null;
    ip: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
    timezone: string | null;
  } | null;
  error?: string | null;
}

const MICROSOFT_ACCOUNT_HOME_URL = "https://account.microsoft.com/";
const MICROSOFT_ACCOUNT_COMPLETION_PATTERNS = [/^https:\/\/account\.microsoft\.com(?!\/auth\/)(?:\/|$)/i];
const MICROSOFT_SIGN_IN_PATTERNS = [/sign in/i, /登录/, /登入/i, /继续登录/, /继续登入/];
const MICROSOFT_LOGIN_ENTRY_URLS = ["https://login.live.com/", "https://login.live.com/login.srf", "https://account.live.com/"];

function nowIso(): string {
  return new Date().toISOString();
}

function optionalEnv(name: string): string | null {
  const value = String(process.env[name] || "").trim();
  return value || null;
}

function isRecoverableMicrosoftNavigationError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || "");
  return /ERR_EMPTY_RESPONSE|ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET|ERR_ABORTED|ERR_TIMED_OUT|Timeout \d+ms exceeded/i.test(message);
}

function getOutputDir(): string {
  return path.resolve(optionalEnv("MICROSOFT_ACCOUNT_JOB_OUTPUT_DIR") || process.cwd());
}

function getRetainPath(): string | null {
  return optionalEnv("ACCOUNT_BUSINESS_FLOW_RETAIN_PATH");
}

function isFingerprintBusinessFlow(): boolean {
  return String(process.env.ACCOUNT_BUSINESS_FLOW_MODE || "").trim().toLowerCase() === "fingerprint";
}

function parseArgs(argv: string[]): WorkerArgs {
  let proxyNode = "";
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index] || "";
    if (raw === "--proxy-node") {
      proxyNode = String(argv[index + 1] || "").trim();
      index += 1;
      continue;
    }
    const inlineMatch = raw.match(/^--proxy-node=(.*)$/);
    if (inlineMatch) {
      proxyNode = String(inlineMatch[1] || "").trim();
    }
  }
  return { proxyNode: proxyNode || null };
}

async function writeJson(filePath: string, payload: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

async function writeResult(outputDir: string, payload: WorkerResult): Promise<void> {
  await writeJson(path.join(outputDir, "result.json"), payload);
}

async function writeError(outputDir: string, error: string): Promise<void> {
  await writeJson(path.join(outputDir, "error.json"), { error });
}

async function waitForManualBrowserClose(page: any, browser: any): Promise<void> {
  while (true) {
    const pageClosed = !page || (typeof page.isClosed === "function" ? page.isClosed() : false);
    const browserClosed = !browser || (typeof browser.isConnected === "function" ? !browser.isConnected() : false);
    if (pageClosed || browserClosed) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
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
  await waitForManualBrowserClose(page, browser).catch(() => {});
}

async function fetchProxyGeo(proxyUrl: string, timeoutMs: number, token?: string): Promise<GeoInfo> {
  const impit = new Impit({ proxyUrl, timeout: timeoutMs });
  const url = new URL("https://ipinfo.io/json");
  if (token?.trim()) {
    url.searchParams.set("token", token.trim());
  }
  const resp = await impit.fetch(url.toString(), {
    headers: {
      Accept: "application/json",
    },
  });
  if (!resp.ok) {
    throw new Error(`proxy_geo_lookup_failed:${resp.status}`);
  }
  const payload = (await resp.json()) as Record<string, unknown>;
  return parseIpInfoPayload(payload);
}

async function locatorVisible(locator: any): Promise<boolean> {
  return Boolean(await locator?.isVisible?.().catch(() => false));
}

async function clickFirstVisibleByName(page: any, patterns: RegExp[]): Promise<boolean> {
  for (const pattern of patterns) {
    const candidates = [
      page.getByRole("button", { name: pattern }).first(),
      page.getByRole("link", { name: pattern }).first(),
      page.getByText(pattern).first(),
    ];
    for (const locator of candidates) {
      if (!(await locatorVisible(locator))) continue;
      await locator.click({ force: true }).catch(() => locator.click().catch(() => {}));
      return true;
    }
  }
  return false;
}


async function readMicrosoftAccountSurfaceSnapshot(page: any): Promise<MicrosoftAccountSurfaceSnapshot> {
  return await page
    .evaluate(() => {
      const normalize = (value: string): string =>
        String(value || "")
          .replace(/[\u200e\u200f\u202a-\u202e]/g, " ")
          .replace(/\s+/g, " ")
          .trim();
      const isVisible = (node: Element | null): node is HTMLElement => {
        if (!(node instanceof HTMLElement)) return false;
        const rect = node.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(node);
        return style.display !== "none" && style.visibility !== "hidden";
      };
      const visibleActions = Array.from(document.querySelectorAll("button, a, [role=button]"))
        .filter(isVisible)
        .map((node) => normalize((node as HTMLElement).innerText || node.textContent || ""))
        .filter((value) => value.length > 0 && value.length <= 120)
        .slice(0, 120);
      return {
        url: window.location.href,
        title: normalize(document.title || ""),
        bodyText: normalize(document.body?.innerText || "").slice(0, 5000),
        visibleActions,
      };
    })
    .catch(() => ({
      url: String(page.url?.() || ""),
      title: "",
      bodyText: "",
      visibleActions: [],
    }));
}

async function openMicrosoftLoginEntry(page: any): Promise<boolean> {
  for (const url of MICROSOFT_LOGIN_ENTRY_URLS) {
    try {
      await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: 60_000,
      });
      await page.waitForTimeout(1200).catch(() => {});
      if (isMicrosoftLoginSurfaceUrl(String(page.url?.() || ""))) {
        return true;
      }
    } catch {
      // keep trying the next login entry
    }
  }
  return false;
}

async function inspectMicrosoftAccountSurface(page: any): Promise<{ snapshot: MicrosoftAccountSurfaceSnapshot; assessment: MicrosoftAccountSurfaceAssessment }> {
  const snapshot = await readMicrosoftAccountSurfaceSnapshot(page);
  const assessment = assessMicrosoftAccountSurface(snapshot);
  return { snapshot, assessment };
}

async function waitForMicrosoftAccountSurfaceResolution(
  page: any,
  timeoutMs: number,
): Promise<{ snapshot: MicrosoftAccountSurfaceSnapshot; assessment: MicrosoftAccountSurfaceAssessment }> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  let last = await inspectMicrosoftAccountSurface(page);
  while (Date.now() < deadline) {
    if (last.assessment.authenticated || last.assessment.requiresLogin || isMicrosoftLoginSurfaceUrl(last.snapshot.url)) {
      return last;
    }
    await page.waitForTimeout(800).catch(() => {});
    last = await inspectMicrosoftAccountSurface(page);
  }
  return last;
}

async function hasMeaningfulMicrosoftPageContent(page: any): Promise<boolean> {
  return await page
    .evaluate(() => {
      const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const title = String(document.title || "").trim();
      const actionCount = Array.from(document.querySelectorAll("button, a, [role=button]")).filter((node) => {
        if (!(node instanceof HTMLElement)) return false;
        const rect = node.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(node);
        return style.display !== "none" && style.visibility !== "hidden";
      }).length;
      return document.readyState !== "loading" && (bodyText.length > 0 || title.length > 0 || actionCount > 0);
    })
    .catch(() => false);
}

async function openMicrosoftAccountHome(page: any): Promise<void> {
  let lastError: unknown = null;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      await page.goto(MICROSOFT_ACCOUNT_HOME_URL, {
        waitUntil: "domcontentloaded",
        timeout: 120_000,
      });
      await page.waitForTimeout(1200).catch(() => {});
      return;
    } catch (error) {
      lastError = error;
      const currentUrl = String(page.url?.() || "");
      if (
        /Timeout \d+ms exceeded/i.test(error instanceof Error ? error.message : String(error || ""))
        && (isMicrosoftAccountHomeUrl(currentUrl) || isMicrosoftAccountAuthIntermediateUrl(currentUrl) || isMicrosoftLoginSurfaceUrl(currentUrl))
        && (await hasMeaningfulMicrosoftPageContent(page))
      ) {
        await page.waitForTimeout(1500).catch(() => {});
        return;
      }
      if (!isRecoverableMicrosoftNavigationError(error) || attempt >= 4) {
        throw error;
      }
      await page.waitForTimeout(1200 * attempt).catch(() => {});
    }
  }
  if (lastError) {
    throw lastError;
  }
}

async function settleAuthenticatedMicrosoftAccountHome(
  page: any,
  cfg: ReturnType<typeof loadConfig>,
  proxyUrl?: string,
): Promise<{ page: any; snapshot: MicrosoftAccountSurfaceSnapshot; assessment: MicrosoftAccountSurfaceAssessment }> {
  let last = await waitForMicrosoftAccountSurfaceResolution(page, 12_000);
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    if (last.assessment.authenticated && isMicrosoftAccountHomeUrl(last.snapshot.url)) {
      return { page, ...last };
    }
    if (isMicrosoftLoginSurfaceUrl(last.snapshot.url)) {
      page = await completeMicrosoftLogin(page, cfg, proxyUrl, {
        completionUrlPatterns: MICROSOFT_ACCOUNT_COMPLETION_PATTERNS,
        passkeyRecoveryUrl: MICROSOFT_ACCOUNT_HOME_URL,
      });
      last = await waitForMicrosoftAccountSurfaceResolution(page, 15_000);
      continue;
    }
    if (isMicrosoftAccountAuthIntermediateUrl(last.snapshot.url)) {
      await page.waitForTimeout(1_500).catch(() => {});
      await openMicrosoftAccountHome(page);
      last = await waitForMicrosoftAccountSurfaceResolution(page, 15_000);
      continue;
    }
    if (last.assessment.requiresLogin && isMicrosoftAccountHomeUrl(last.snapshot.url)) {
      const clickedSignIn = await clickFirstVisibleByName(page, MICROSOFT_SIGN_IN_PATTERNS);
      if (clickedSignIn) {
        await page.waitForLoadState("domcontentloaded", { timeout: 60_000 }).catch(() => {});
        await page.waitForTimeout(1_500).catch(() => {});
        last = await waitForMicrosoftAccountSurfaceResolution(page, 12_000);
        continue;
      }
    }
    const missingSignalsOnAccountHome = isMicrosoftAccountHomeUrl(last.snapshot.url) && !last.assessment.authenticated && !last.assessment.requiresLogin;
    const hasMeaningfulSurface = Boolean(last.snapshot.title || last.snapshot.bodyText || last.snapshot.visibleActions.length > 0);
    if (missingSignalsOnAccountHome || !hasMeaningfulSurface) {
      const openedLoginEntry = await openMicrosoftLoginEntry(page);
      if (openedLoginEntry) {
        last = await waitForMicrosoftAccountSurfaceResolution(page, 12_000);
        continue;
      }
    }
    await openMicrosoftAccountHome(page);
    last = await waitForMicrosoftAccountSurfaceResolution(page, 15_000);
  }
  return { page, ...last };
}

async function ensureMicrosoftAccountHome(page: any, cfg: ReturnType<typeof loadConfig>, proxyUrl?: string): Promise<any> {
  await openMicrosoftAccountHome(page);
  const resolved = await settleAuthenticatedMicrosoftAccountHome(page, cfg, proxyUrl);
  page = resolved.page;
  if (!isMicrosoftAccountHomeUrl(resolved.snapshot.url)) {
    throw new Error(`microsoft_account_home_unreachable:${formatMicrosoftAccountSurfaceSummary(resolved.snapshot, resolved.assessment)}`);
  }
  if (!resolved.assessment.authenticated) {
    throw new Error(`microsoft_account_not_authenticated:${formatMicrosoftAccountSurfaceSummary(resolved.snapshot, resolved.assessment)}`);
  }
  return page;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const cfg = loadConfig();
  const outputDir = getOutputDir();
  const downloadsDir = path.join(process.cwd(), "downloads", "mihomo");
  const ipinfoToken = (process.env.IPINFO_TOKEN || "").trim() || undefined;

  let browser: Awaited<ReturnType<typeof launchChromePersistent>>["browser"] | null = null;
  let context: Awaited<ReturnType<typeof launchChromePersistent>>["context"] | null = null;
  let page: any = null;
  let mihomoController: Awaited<ReturnType<typeof startMihomo>> | null = null;
  let proxyGeo: GeoInfo | null = null;
  let proxyServer: string | undefined;

  try {
    await mkdir(outputDir, { recursive: true });
    await cleanupManagedChromeProcessesUnder(cfg.chromeProfileDir).catch(() => {});
    if (args.proxyNode) {
      mihomoController = await startMihomo({
        subscriptionUrl: cfg.mihomoSubscriptionUrl,
        groupName: cfg.mihomoGroupName,
        routeGroupName: cfg.mihomoRouteGroupName,
        checkUrl: cfg.proxyCheckUrl,
        apiPort: cfg.mihomoApiPort,
        mixedPort: cfg.mihomoMixedPort,
        workDir: path.join(outputDir, "mihomo"),
        downloadDir: downloadsDir,
      });
      await mihomoController.setGroupProxy(args.proxyNode);
      proxyServer = mihomoController.proxyServer;
      proxyGeo = await fetchProxyGeo(proxyServer, cfg.proxyCheckTimeoutMs, ipinfoToken).catch(() => ({ ip: "" }));
    }
    const locale = deriveLocale(proxyGeo?.country);
    const acceptLanguage = buildAcceptLanguage(locale);
    const launched = await launchChromePersistent(cfg, cfg.runMode, proxyServer, locale, {
      locale,
      viewport: { width: 1512, height: 982 },
      screen: { width: 1512, height: 982 },
      deviceScaleFactor: 2,
      ...(proxyGeo?.timezone ? { timezoneId: proxyGeo.timezone } : {}),
      extraHTTPHeaders: {
        "Accept-Language": acceptLanguage,
      },
    });
    browser = launched.browser;
    context = launched.context;
    page = context.pages()[0] || (await context.newPage());
    page = await ensureMicrosoftAccountHome(page, cfg, proxyServer);
    const finalUrl = String(page.url() || MICROSOFT_ACCOUNT_HOME_URL);
    await writeResult(outputDir, {
      ok: true,
      finalUrl,
      proxy: {
        nodeName: args.proxyNode,
        ip: proxyGeo?.ip || null,
        country: proxyGeo?.country || null,
        region: proxyGeo?.region || null,
        city: proxyGeo?.city || null,
        timezone: proxyGeo?.timezone || null,
      },
    });
    if (isFingerprintBusinessFlow()) {
      await holdBrowserForBusinessFlowHandoff(page, browser, "microsoft_account", { success: true });
    }
  } catch (error) {
    const message = error instanceof Error ? error.stack || error.message : String(error);
    await writeError(outputDir, message).catch(() => {});
    if (isFingerprintBusinessFlow() && page && browser) {
      await holdBrowserForBusinessFlowHandoff(page, browser, "microsoft_account_failed", { success: false, error: message }).catch(() => {});
    }
    process.exitCode = 1;
  } finally {
    if (context) {
      await context.close().catch(() => {});
    }
    if (browser) {
      await browser.close().catch(() => {});
    }
    if (mihomoController) {
      await mihomoController.stop().catch(() => {});
    }
  }
}

await main();
