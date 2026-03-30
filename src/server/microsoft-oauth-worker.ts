import path from "node:path";
import process from "node:process";
import { mkdir, writeFile } from "node:fs/promises";
import { buildAcceptLanguage } from "../proxy/geo.js";
import {
  cleanupManagedChromeProcessesUnder,
  completeMicrosoftLogin,
  loadConfig,
  launchBrowserWithEngine,
} from "../main.js";
import { isMicrosoftPasskeyInterruptUrl } from "../microsoft-passkey.js";
import { isMicrosoftOauthCompletionUrl } from "./microsoft-mail.js";

interface WorkerArgs {
  authUrl: string;
  redirectUri: string;
  resultPath: string;
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
  const resultPath = (args.get("result-path") || "").trim();
  if (!authUrl) {
    throw new Error("missing --auth-url");
  }
  if (!redirectUri) {
    throw new Error("missing --redirect-uri");
  }
  if (!resultPath) {
    throw new Error("missing --result-path");
  }
  return {
    authUrl,
    redirectUri,
    resultPath: path.resolve(resultPath),
  };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function writeResult(resultPath: string, payload: Record<string, unknown>): Promise<void> {
  await mkdir(path.dirname(resultPath), { recursive: true });
  await writeFile(resultPath, JSON.stringify(payload, null, 2), "utf8");
}

async function main(): Promise<void> {
  const MAX_PASSKEY_RESTARTS = 2;
  const args = parseArgs(process.argv.slice(2));
  const cfg = loadConfig();
  const locale = "zh-CN";
  const acceptLanguage = buildAcceptLanguage(locale);
  const redirectTarget = new URL(args.redirectUri);
  const completionUrlPatterns = [
    new RegExp(`^${escapeRegex(args.redirectUri)}(?:[?#].*)?$`, "i"),
    new RegExp(`^${escapeRegex(`${redirectTarget.origin}/mailboxes`)}(?:[?#].*)?$`, "i"),
  ];
  const contextOptions = {
    locale,
    viewport: { width: 1512, height: 982 },
    screen: { width: 1512, height: 982 },
    deviceScaleFactor: 2,
    extraHTTPHeaders: {
      "Accept-Language": acceptLanguage,
    },
  };

  let browser: Awaited<ReturnType<typeof launchBrowserWithEngine>> | null = null;
  let context: any = null;
  try {
    await cleanupManagedChromeProcessesUnder(cfg.chromeProfileDir).catch(() => {});
    browser = await launchBrowserWithEngine(cfg.browserEngine, cfg, "headless", undefined, locale, "");
    context = await browser.newContext(contextOptions);
    let page = await context.newPage();
    await page.goto(args.authUrl, {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });
    for (let attempt = 1; attempt <= MAX_PASSKEY_RESTARTS; attempt += 1) {
      page = await completeMicrosoftLogin(page, cfg, undefined, {
        completionUrlPatterns,
        passkeyRecoveryUrl: args.authUrl,
      });
      const finalUrl = String(page.url() || "");
      if (isMicrosoftOauthCompletionUrl(finalUrl, args.redirectUri)) {
        await writeResult(args.resultPath, {
          ok: true,
          finalUrl,
          oauthOutcome: new URL(finalUrl).searchParams.get("oauth") || null,
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
        error: `microsoft_oauth_incomplete:${finalUrl || "unknown"}`,
      });
      return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.stack || error.message : String(error);
    await writeResult(args.resultPath, {
      ok: false,
      error: message,
    });
    process.exitCode = 1;
  } finally {
    if (context) {
      await context.close().catch(() => {});
    }
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

await main();
