import path from "node:path";
import process from "node:process";
import { mkdir, writeFile } from "node:fs/promises";
import { Impit } from "impit";
import { buildAcceptLanguage, deriveLocale, parseIpInfoPayload, type GeoInfo } from "../proxy/geo.js";
import { startMihomo } from "../proxy/mihomo.js";
import {
  CaptchaSolver,
  cleanupManagedChromeProcessesUnder,
  completeMicrosoftLogin,
  launchChromePersistent,
  loadConfig,
  loginAndReachHome,
} from "../main.js";
import { isMicrosoftPasskeyInterruptUrl } from "../microsoft-passkey.js";
import { isMicrosoftOauthCompletionUrl } from "./microsoft-mail.js";

interface WorkerArgs {
  authUrl: string;
  redirectUri: string;
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

function parseArgs(argv: string[]): WorkerArgs {
  const args = new Map<string, string>();
  for (const raw of argv) {
    const match = raw.match(/^--([^=]+)=(.*)$/);
    if (!match) continue;
    args.set(match[1] || "", match[2] || "");
  }
  const authUrl = (args.get("auth-url") || "").trim();
  const redirectUri = (args.get("redirect-uri") || "").trim();
  const proxyNode = (args.get("proxy-node") || "").trim();
  const resultPath = (args.get("result-path") || "").trim();
  if (!authUrl) {
    throw new Error("missing --auth-url");
  }
  if (!redirectUri) {
    throw new Error("missing --redirect-uri");
  }
  if (!proxyNode) {
    throw new Error("missing --proxy-node");
  }
  if (!resultPath) {
    throw new Error("missing --result-path");
  }
  return {
    authUrl,
    redirectUri,
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

async function main(): Promise<void> {
  const MAX_PASSKEY_RESTARTS = 2;
  const args = parseArgs(process.argv.slice(2));
  const cfg = loadConfig();
  const outputDir = path.dirname(args.resultPath);
  const downloadsDir = path.join(process.cwd(), "downloads", "mihomo");
  const ipinfoToken = (process.env.IPINFO_TOKEN || "").trim() || undefined;
  const redirectTarget = new URL(args.redirectUri);
  const completionUrlPatterns = [
    new RegExp(`^${escapeRegex(args.redirectUri)}(?:[?#].*)?$`, "i"),
    new RegExp(`^${escapeRegex(`${redirectTarget.origin}/mailboxes`)}(?:[?#].*)?$`, "i"),
  ];

  let browser: Awaited<ReturnType<typeof launchChromePersistent>>["browser"] | null = null;
  let context: Awaited<ReturnType<typeof launchChromePersistent>>["context"] | null = null;
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
    proxyGeo = await fetchProxyGeo(mihomoController.proxyServer, cfg.proxyCheckTimeoutMs, ipinfoToken);
    const locale = deriveLocale(proxyGeo.country);
    const acceptLanguage = buildAcceptLanguage(locale);
    const launched = await launchChromePersistent(cfg, "headless", mihomoController.proxyServer, locale, {
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

    const solver = new CaptchaSolver();
    let page = context.pages()[0] || (await context.newPage());
    page = await loginAndReachHome(
      page,
      solver,
      cfg.microsoftAccountEmail || "",
      cfg.microsoftAccountPassword || "",
      cfg,
      null,
      mihomoController.proxyServer,
      2,
      null,
    );
    await page.goto(args.authUrl, {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    for (let attempt = 1; attempt <= MAX_PASSKEY_RESTARTS; attempt += 1) {
      const currentUrl = String(page.url() || "");
      if (isMicrosoftOauthCompletionUrl(currentUrl, args.redirectUri)) {
        await writeResult(args.resultPath, {
          ok: true,
          finalUrl: currentUrl,
          oauthOutcome: new URL(currentUrl).searchParams.get("oauth") || null,
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
      page = await completeMicrosoftLogin(page, cfg, mihomoController.proxyServer, {
        completionUrlPatterns,
        passkeyRecoveryUrl: args.authUrl,
      });
      const finalUrl = String(page.url() || "");
      if (isMicrosoftOauthCompletionUrl(finalUrl, args.redirectUri)) {
        await writeResult(args.resultPath, {
          ok: true,
          finalUrl,
          oauthOutcome: new URL(finalUrl).searchParams.get("oauth") || null,
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
