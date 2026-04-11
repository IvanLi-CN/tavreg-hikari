import { expect, test } from "bun:test";

import type { AppConfig } from "../src/main.js";
import { buildChatGptWorkerResult, launchChatGptWorkerBrowser } from "../src/server/chatgpt-worker.js";

function createWorkerConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    runMode: "headed",
    browserEngine: "chrome",
    inspectBrowserEngine: "chrome",
    chromeExecutablePath: "/tmp/Chromium",
    chromeNativeAutomation: true,
    chromeActivateOnLaunch: false,
    chromeAutoOpenDevtools: false,
    chromeIdentityOverride: true,
    chromeStealthJsEnabled: true,
    chromeWebrtcHardened: true,
    chromeProfileDir: "/tmp/profile",
    chromeRemoteDebuggingPort: 0,
    slowMoMs: 0,
    maxCaptchaRounds: 1,
    allowPasswordSubmitWithoutCaptcha: false,
    humanConfirmBeforeSignup: false,
    humanConfirmText: "CONFIRM",
    mailProvider: "gptmail",
    blockedMailboxDomains: [],
    mailPollMs: 1000,
    gptmailBaseUrl: "https://mail.example.test",
    vmailBaseUrl: "",
    vmailApiKey: undefined,
    vmailDomain: undefined,
    cfmailBaseUrl: "https://cfmail.example.test",
    cfmailApiKey: "cfm_test",
    duckmailBaseUrl: "",
    duckmailApiKey: undefined,
    duckmailDomain: undefined,
    emailWaitMs: 60_000,
    keyName: "test-key",
    keyLimit: 100,
    existingEmail: undefined,
    existingPassword: undefined,
    microsoftAccountEmail: undefined,
    microsoftAccountPassword: undefined,
    microsoftProofMailboxProvider: undefined,
    microsoftProofMailboxAddress: undefined,
    microsoftProofMailboxId: undefined,
    microsoftKeepSignedIn: true,
    mihomoSubscriptionUrl: "https://example.com/sub.yaml",
    mihomoGroupName: "CODEX_AUTO",
    mihomoRouteGroupName: "CODEX_ROUTE",
    mihomoApiPort: 39090,
    mihomoMixedPort: 49090,
    proxyCheckUrl: "https://example.com/trace",
    proxyCheckTimeoutMs: 1000,
    proxyLatencyMaxMs: 1000,
    ipinfoToken: undefined,
    browserPrecheckEnabled: true,
    browserPrecheckStrict: true,
    browserPrecheckCheckHostingProvider: false,
    requireWebrtcVisible: false,
    verifyHostAllowlist: ["auth.openai.com"],
    modeRetryMax: 1,
    browserLaunchRetryMax: 1,
    taskAttemptTimeoutMs: 60_000,
    nodeReuseCooldownMs: 12 * 60 * 60_000,
    nodeRecentWindow: 4,
    nodeCheckCacheTtlMs: 60_000,
    nodeScanMaxChecks: 5,
    nodeScanMaxMs: 15_000,
    nodeDeferLogMax: 1,
    allowSameEgressIpFallback: false,
    cfProbeEnabled: false,
    cfProbeUrl: "https://example.com/cf",
    cfProbeTimeoutMs: 3000,
    cfProbeCacheTtlMs: 60_000,
    inspectKeepOpenMs: 30_000,
    inspectChromeNative: true,
    inspectChromeProfileDir: "/tmp/inspect-profile",
    taskLedger: {
      enabled: true,
      dbPath: "/tmp/task-ledger.sqlite",
      busyTimeoutMs: 1000,
      ipRateLimitCooldownMs: 60_000,
      ipRateLimitMax: 10,
      captchaMissingCooldownMs: 60_000,
      captchaMissingMax: 10,
      captchaMissingThreshold: 2,
      invalidCaptchaCooldownMs: 60_000,
      invalidCaptchaMax: 10,
      invalidCaptchaThreshold: 3,
      allowRateLimitedIpFallback: false,
    },
    ...overrides,
  };
}

test("chatgpt worker forwards headless mode to native chrome cdp launch", async () => {
  const cfg = createWorkerConfig({ runMode: "headless", chromeNativeAutomation: true });
  const page = { url: () => "about:blank" };
  const context = {
    pages: () => [page],
    newPage: async () => {
      throw new Error("unexpected_new_page");
    },
  };
  const calls: Array<{ mode: string; proxyServer: string | undefined }> = [];

  const launched = await launchChatGptWorkerBrowser(cfg, "http://127.0.0.1:7890", {
    launchNativeChromeCdp: async (_cfg, mode, proxyServer) => {
      calls.push({ mode, proxyServer });
      return {
        browser: { kind: "native" },
        context,
        stop: async () => undefined,
        details: { profileDir: "/tmp/native-profile", debugPort: 9222 },
      } as any;
    },
    launchBrowserWithEngine: async () => {
      throw new Error("unexpected_engine_launch");
    },
  });

  expect(calls).toEqual([{ mode: "headless", proxyServer: "http://127.0.0.1:7890" }]);
  expect(launched.browserMode).toBe("chrome-native-cdp");
  expect(launched.page).toBe(page);
  expect(launched.profileDir).toBe("/tmp/native-profile");
});

test("chatgpt worker forwards headless mode to browser engine launch when native automation is disabled", async () => {
  const cfg = createWorkerConfig({ runMode: "headless", chromeNativeAutomation: false });
  const page = { url: () => "about:blank" };
  const context = {
    newPage: async () => page,
  };
  const calls: Array<{ engine: string | undefined; mode: string; proxyServer: string | undefined }> = [];

  const launched = await launchChatGptWorkerBrowser(cfg, "http://127.0.0.1:7891", {
    launchNativeChromeCdp: async () => {
      throw new Error("unexpected_native_launch");
    },
    launchBrowserWithEngine: async (engine, _cfg, mode, proxyServer) => {
      calls.push({ engine, mode, proxyServer });
      return {
        newContext: async (options: unknown) => {
          expect(options).toEqual({
            locale: "en-US",
            viewport: { width: 1440, height: 960 },
            screen: { width: 1440, height: 960 },
          });
          return context;
        },
      } as any;
    },
  });

  expect(calls).toEqual([{ engine: "chrome", mode: "headless", proxyServer: "http://127.0.0.1:7891" }]);
  expect(launched.browserMode).toBe("browser-engine");
  expect(launched.page).toBe(page);
  expect(launched.nativeChromeStop).toBeNull();
});

test("chatgpt worker result payload keeps configured run mode", () => {
  const result = buildChatGptWorkerResult({
    mode: "headless",
    email: "demo@example.com",
    password: "secret",
    nickname: "Hana Sakurai",
    birthDate: "1998-08-31",
    accountId: "acc_demo",
    expiresAt: "2026-04-11T12:00:00.000Z",
    tokenPayload: { token_type: "Bearer" },
    idTokenPayload: { exp: 1_777_777_777 },
    accessToken: "access-demo",
    refreshToken: "refresh-demo",
    idToken: "id-demo",
    notes: ["mailbox=mbx_demo", "proxy=default"],
  });

  expect(result).toMatchObject({
    mode: "headless",
    email: "demo@example.com",
    credentials: {
      account_id: "acc_demo",
      token_type: "Bearer",
      exp: 1_777_777_777,
    },
    notes: ["mailbox=mbx_demo", "proxy=default"],
  });
});
