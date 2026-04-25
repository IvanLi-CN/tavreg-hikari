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
import { isMicrosoftPasskeyInterruptUrl } from "../microsoft-passkey.js";
import {
  getMicrosoftOauthBrowserOutcome,
  isMicrosoftOauthCallbackUrl,
  isMicrosoftOauthCompletionUrl,
} from "./microsoft-mail.js";
import { buildServerAuthConfig, buildTrustedForwardAuthHeaders } from "./auth-gate.js";

interface WorkerArgs {
  authUrl: string;
  mailboxId: number;
  redirectUri: string;
  localServerOrigin: string;
  proxyNode: string;
  resultPath: string;
}

interface WorkerResult {
  ok: boolean;
  finalUrl?: string | null;
  oauthOutcome?: string | null;
  profilePath?: string | null;
  proxy?: {
    nodeName: string;
    ip: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
    timezone: string | null;
  } | null;
  error?: string | null;
}

interface OauthRelayState {
  finalUrl: string | null;
  oauthOutcome: "success" | "error" | null;
  callbackUrl: string | null;
}

function envFlagEnabled(value: string | undefined | null): boolean {
  return /^(1|true|yes|on)$/i.test(String(value || "").trim());
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

interface LocalMailboxApiRow {
  accountId: number;
  oauthConnectedAt: string | null;
  isAuthorized: boolean;
}

function parseArgs(argv: string[]): WorkerArgs {
  const args = new Map<string, string>();
  for (const raw of argv) {
    const match = raw.match(/^--([^=]+)=(.*)$/);
    if (!match) continue;
    args.set(match[1] || "", match[2] || "");
  }
  const authUrl = (args.get("auth-url") || "").trim();
  const mailboxIdRaw = (args.get("mailbox-id") || "").trim();
  const redirectUri = (args.get("redirect-uri") || "").trim();
  const localServerOrigin = (args.get("local-server-origin") || "").trim();
  const proxyNode = (args.get("proxy-node") || "").trim();
  const resultPath = (args.get("result-path") || "").trim();
  if (!authUrl) {
    throw new Error("missing --auth-url");
  }
  const mailboxId = Number.parseInt(mailboxIdRaw, 10);
  if (!Number.isInteger(mailboxId) || mailboxId < 1) {
    throw new Error("missing --mailbox-id");
  }
  if (!redirectUri) {
    throw new Error("missing --redirect-uri");
  }
  if (!localServerOrigin) {
    throw new Error("missing --local-server-origin");
  }
  if (!proxyNode) {
    throw new Error("missing --proxy-node");
  }
  if (!resultPath) {
    throw new Error("missing --result-path");
  }
  return {
    authUrl,
    mailboxId,
    redirectUri,
    localServerOrigin,
    proxyNode,
    resultPath: path.resolve(resultPath),
  };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function writeResult(resultPath: string, payload: WorkerResult): Promise<void> {
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeFile(resultPath, JSON.stringify(payload, null, 2), "utf8");
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

async function waitForMicrosoftOauthBrowserCompletion(
  page: any,
  redirectUri: string,
  relayState: OauthRelayState,
  timeoutMs = 45_000,
): Promise<{ finalUrl: string | null; oauthOutcome: "success" | "error" | null }> {
  if (relayState.oauthOutcome) {
    return {
      finalUrl: relayState.finalUrl,
      oauthOutcome: relayState.oauthOutcome,
    };
  }
  const currentUrl = String(page.url() || "");
  const currentOutcome = getMicrosoftOauthBrowserOutcome(currentUrl, redirectUri);
  if (currentOutcome) {
    return {
      finalUrl: currentUrl,
      oauthOutcome: currentOutcome,
    };
  }
  if (!isMicrosoftOauthCompletionUrl(currentUrl, redirectUri)) {
    return {
      finalUrl: relayState.callbackUrl || currentUrl,
      oauthOutcome: null,
    };
  }
  try {
    await page.waitForURL(
      (url: URL) => Boolean(getMicrosoftOauthBrowserOutcome(url.toString(), redirectUri)),
      { timeout: timeoutMs },
    );
  } catch {
    await page.waitForLoadState("domcontentloaded", { timeout: 5_000 }).catch(() => {});
    await page.waitForTimeout(1_000).catch(() => {});
  }
  const finalUrl = String(page.url() || "");
  if (relayState.oauthOutcome) {
    return {
      finalUrl: relayState.finalUrl,
      oauthOutcome: relayState.oauthOutcome,
    };
  }
  return {
    finalUrl: relayState.callbackUrl || finalUrl,
    oauthOutcome: getMicrosoftOauthBrowserOutcome(finalUrl, redirectUri),
  };
}

function buildMicrosoftOauthOutcomeUrl(
  redirectUri: string,
  outcome: "success" | "error",
  accountId?: number | null,
): string {
  const redirectTarget = new URL(redirectUri);
  const url = new URL("/mailboxes", redirectTarget.origin);
  url.searchParams.set("oauth", outcome);
  if (accountId && Number.isInteger(accountId) && accountId > 0) {
    url.searchParams.set("accountId", String(accountId));
  }
  return url.toString();
}

function buildLocalServerAuthHeaders(): HeadersInit {
  return buildTrustedForwardAuthHeaders(buildServerAuthConfig(process.env), {
    user: "mailbox-oauth-worker",
    email: "mailbox-oauth-worker@localhost",
  });
}

async function fetchLocalMailboxCompletion(
  localServerOrigin: string,
  mailboxId: number,
  redirectUri: string,
): Promise<{ finalUrl: string | null; oauthOutcome: "success" | "error" | null }> {
  try {
    const response = await fetch(new URL(`/api/microsoft-mail/mailboxes/${mailboxId}`, localServerOrigin), {
      headers: buildLocalServerAuthHeaders(),
    });
    if (!response.ok) {
      return { finalUrl: null, oauthOutcome: null };
    }
    const payload = (await response.json()) as { ok?: boolean; row?: LocalMailboxApiRow | null };
    const row = payload?.row;
    if (!row) {
      return { finalUrl: null, oauthOutcome: null };
    }
    if (row.isAuthorized || row.oauthConnectedAt) {
      return {
        finalUrl: buildMicrosoftOauthOutcomeUrl(redirectUri, "success", row.accountId),
        oauthOutcome: "success",
      };
    }
  } catch {
    // best effort only
  }
  return { finalUrl: null, oauthOutcome: null };
}

function isRedirectOriginUrl(url: string, redirectOrigin: string): boolean {
  try {
    return new URL(url).origin === redirectOrigin;
  } catch {
    return false;
  }
}

async function proxyRedirectOriginRequest(
  route: any,
  input: { redirectOrigin: string; localServerOrigin: string; redirectUri: string; relayState: OauthRelayState },
): Promise<void> {
  const request = route.request();
  const requestUrl = request.url();
  if (!isRedirectOriginUrl(requestUrl, input.redirectOrigin)) {
    await route.continue();
    return;
  }
  const requestOutcome = getMicrosoftOauthBrowserOutcome(requestUrl, input.redirectUri);
  if (requestOutcome) {
    input.relayState.finalUrl = requestUrl;
    input.relayState.oauthOutcome = requestOutcome;
  } else if (isMicrosoftOauthCallbackUrl(requestUrl, input.redirectUri)) {
    input.relayState.callbackUrl = requestUrl;
  }
  const original = new URL(requestUrl);
  const upstream = new URL(`${original.pathname}${original.search}`, input.localServerOrigin);
  const headers = { ...request.headers() } as Record<string, string>;
  delete headers.host;
  delete headers["content-length"];
  delete headers["accept-encoding"];
  delete headers.connection;
  headers["x-forwarded-proto"] = original.protocol.replace(/:$/, "");
  headers["x-forwarded-host"] = original.host;
  let response: Response;
  try {
    response = await fetch(upstream, {
      method: request.method(),
      headers,
      body: request.method() === "GET" || request.method() === "HEAD" ? undefined : (request.postDataBuffer() ?? undefined),
      redirect: "manual",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await route.fulfill({
      status: 502,
      contentType: "text/plain; charset=utf-8",
      body: `oauth relay fetch failed: ${message}`,
    });
    return;
  }
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });
  const responseLocationRaw = response.headers.get("location");
  if (responseLocationRaw) {
    const responseLocation = new URL(responseLocationRaw, requestUrl).toString();
    const responseOutcome = getMicrosoftOauthBrowserOutcome(responseLocation, input.redirectUri);
    if (responseOutcome) {
      input.relayState.finalUrl = responseLocation;
      input.relayState.oauthOutcome = responseOutcome;
    } else if (isMicrosoftOauthCallbackUrl(responseLocation, input.redirectUri)) {
      input.relayState.callbackUrl = responseLocation;
    }
  }
  delete responseHeaders["content-encoding"];
  delete responseHeaders["transfer-encoding"];
  delete responseHeaders["content-length"];
  await route.fulfill({
    status: response.status,
    headers: responseHeaders,
    body: Buffer.from(await response.arrayBuffer()),
  });
}

async function main(): Promise<void> {
  const MAX_PASSKEY_RESTARTS = 2;
  const args = parseArgs(process.argv.slice(2));
  const cfg = loadConfig();
  const outputDir = path.dirname(args.resultPath);
  const downloadsDir = path.join(process.cwd(), "downloads", "mihomo");
  const ipinfoToken = (process.env.IPINFO_TOKEN || "").trim() || undefined;
  const redirectTarget = new URL(args.redirectUri);
  const localServerOrigin = new URL(args.localServerOrigin).origin;
  const relayState: OauthRelayState = {
    finalUrl: null,
    oauthOutcome: null,
    callbackUrl: null,
  };
  const completionUrlPatterns = [
    new RegExp(`^${escapeRegex(args.redirectUri)}(?:[?#].*)?$`, "i"),
    new RegExp(`^${escapeRegex(`${redirectTarget.origin}/mailboxes`)}(?:[?#].*)?$`, "i"),
  ];

  let browser: Awaited<ReturnType<typeof launchChromePersistent>>["browser"] | null = null;
  let context: Awaited<ReturnType<typeof launchChromePersistent>>["context"] | null = null;
  let page: any = null;
  let mihomoController: Awaited<ReturnType<typeof startMihomo>> | null = null;
  let proxyGeo: GeoInfo | null = null;

  try {
    await cleanupManagedChromeProcessesUnder(cfg.chromeProfileDir).catch(() => {});
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
    proxyGeo = await fetchProxyGeo(mihomoController.proxyServer, cfg.proxyCheckTimeoutMs, ipinfoToken).catch(() => ({
      ip: "",
    }));
    const locale = deriveLocale(proxyGeo.country);
    const acceptLanguage = buildAcceptLanguage(locale);
    const launched = await launchChromePersistent(cfg, cfg.runMode, mihomoController.proxyServer, locale, {
      locale,
      viewport: { width: 1512, height: 982 },
      screen: { width: 1512, height: 982 },
      deviceScaleFactor: 2,
      ...(proxyGeo.timezone ? { timezoneId: proxyGeo.timezone } : {}),
      extraHTTPHeaders: {
        "Accept-Language": acceptLanguage,
      },
    });
    browser = launched.browser;
    context = launched.context;
    await context.route(new RegExp(`^${escapeRegex(redirectTarget.origin)}(?:/|$)`, "i"), (route: any) =>
      proxyRedirectOriginRequest(route, {
        redirectOrigin: redirectTarget.origin,
        localServerOrigin,
        redirectUri: args.redirectUri,
        relayState,
      }),
    );

    page = context.pages()[0] || (await context.newPage());
    await page.goto(args.authUrl, {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    for (let attempt = 1; attempt <= MAX_PASSKEY_RESTARTS; attempt += 1) {
      const currentCompletion = await waitForMicrosoftOauthBrowserCompletion(page, args.redirectUri, relayState);
      const currentMailboxCompletion = currentCompletion.oauthOutcome
        ? currentCompletion
        : await fetchLocalMailboxCompletion(localServerOrigin, args.mailboxId, args.redirectUri);
      if (currentMailboxCompletion.oauthOutcome) {
        await writeResult(args.resultPath, {
          ok: true,
          finalUrl: currentMailboxCompletion.finalUrl,
          oauthOutcome: currentMailboxCompletion.oauthOutcome,
          profilePath: launched.details.profileDir,
          proxy: {
            nodeName: args.proxyNode,
            ip: proxyGeo.ip || null,
            country: proxyGeo.country || null,
            region: proxyGeo.region || null,
            city: proxyGeo.city || null,
            timezone: proxyGeo.timezone || null,
          },
        });
        return;
      }
      if (isMicrosoftOauthCallbackUrl(currentCompletion.finalUrl, args.redirectUri)) {
        await writeResult(args.resultPath, {
          ok: false,
          finalUrl: currentCompletion.finalUrl,
          profilePath: launched.details.profileDir,
          proxy: {
            nodeName: args.proxyNode,
            ip: proxyGeo.ip || null,
            country: proxyGeo.country || null,
            region: proxyGeo.region || null,
            city: proxyGeo.city || null,
            timezone: proxyGeo.timezone || null,
          },
          error: `microsoft_oauth_incomplete:${currentCompletion.finalUrl || "unknown"}`,
        });
        return;
      }
      let loginError: unknown = null;
      try {
        page = await completeMicrosoftLogin(page, cfg, mihomoController.proxyServer, {
          completionUrlPatterns,
          passkeyRecoveryUrl: args.authUrl,
        });
      } catch (error) {
        loginError = error;
      }
      const completion = await waitForMicrosoftOauthBrowserCompletion(page, args.redirectUri, relayState);
      const mailboxCompletion = completion.oauthOutcome
        ? completion
        : await fetchLocalMailboxCompletion(localServerOrigin, args.mailboxId, args.redirectUri);
      if (mailboxCompletion.oauthOutcome) {
        await writeResult(args.resultPath, {
          ok: true,
          finalUrl: mailboxCompletion.finalUrl,
          oauthOutcome: mailboxCompletion.oauthOutcome,
          profilePath: launched.details.profileDir,
          proxy: {
            nodeName: args.proxyNode,
            ip: proxyGeo.ip || null,
            country: proxyGeo.country || null,
            region: proxyGeo.region || null,
            city: proxyGeo.city || null,
            timezone: proxyGeo.timezone || null,
          },
        });
        return;
      }
      if (loginError) {
        throw loginError;
      }
      const finalUrl = String(completion.finalUrl || page.url() || "");
      if (isMicrosoftPasskeyInterruptUrl(finalUrl) && attempt < MAX_PASSKEY_RESTARTS) {
        await page.goto(args.authUrl, {
          waitUntil: "domcontentloaded",
          timeout: 120_000,
        });
        continue;
      }
      await writeResult(args.resultPath, {
        ok: false,
        finalUrl,
        profilePath: launched.details.profileDir,
        proxy: {
          nodeName: args.proxyNode,
          ip: proxyGeo.ip || null,
          country: proxyGeo.country || null,
          region: proxyGeo.region || null,
          city: proxyGeo.city || null,
          timezone: proxyGeo.timezone || null,
        },
        error: `microsoft_oauth_incomplete:${finalUrl || "unknown"}`,
      });
      return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.stack || error.message : String(error);
    await writeResult(args.resultPath, {
      ok: false,
      error: message,
      proxy: proxyGeo
        ? {
            nodeName: args.proxyNode,
            ip: proxyGeo.ip || null,
            country: proxyGeo.country || null,
            region: proxyGeo.region || null,
            city: proxyGeo.city || null,
            timezone: proxyGeo.timezone || null,
          }
        : null,
      profilePath: cfg.chromeProfileDir || null,
    });
    process.exitCode = 1;
  } finally {
    const preserveBrowserOnFailure =
      Boolean(process.exitCode) &&
      envFlagEnabled(process.env.KEEP_BROWSER_OPEN_ON_FAILURE) &&
      cfg.runMode === "headed";
    if (preserveBrowserOnFailure) {
      const holdUrl = page ? String(page.url() || "") : "unknown";
      console.error(`microsoft oauth worker: keeping browser open on failure at ${holdUrl}`);
      await waitForManualBrowserClose(page, browser).catch(() => {});
    }
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
