import { describe, expect, test } from "bun:test";
import { completeMicrosoftLogin, type AppConfig } from "../src/main.ts";

let fakeNow = 10_000;

class MockLocator {
  constructor(private readonly page: MockMicrosoftPage) {}

  first(): MockLocator {
    return this;
  }

  async count(): Promise<number> {
    return this.page.hasPasswordInput() ? 1 : 0;
  }

  async inputValue(): Promise<string> {
    return this.page.passwordValue;
  }

  async click(): Promise<void> {}

  async fill(value: string): Promise<void> {
    this.page.passwordValue = value;
  }

  async type(value: string): Promise<void> {
    this.page.passwordValue += value;
  }

  async dispatchEvent(): Promise<void> {}

  async evaluate(_fn: unknown, value?: string): Promise<boolean> {
    if (typeof value === "string") {
      this.page.passwordValue = value;
    }
    return true;
  }

  async evaluateAll(): Promise<boolean> {
    return this.page.hasPasswordInput();
  }
}

class MockMicrosoftPage {
  readonly events = new Map<string, Array<(...args: any[]) => void>>();
  passwordValue = "";
  passwordSubmitCount = 0;
  private phase: "password" | "transition" | "password-return" | "done" = "password";
  private transitionWaits = 0;
  private passwordReturnWaits = 0;
  private readonly authUrl = "https://login.live.com/oauth20_authorize.srf?client_id=123&scope=openid";
  private readonly callbackUrl = "https://tavreg-hikari.ivanli.cc/api/microsoft-mail/oauth/callback?code=ok&state=ok";

  constructor(
    private readonly options: {
      transitionWaitsToPasswordReturn?: number;
      passwordReturnWaitsToDone?: number;
      advanceClockMs?: number;
    } = {},
  ) {}

  url(): string {
    return this.phase === "done" ? this.callbackUrl : this.authUrl;
  }

  title(): Promise<string> {
    return Promise.resolve(this.phase === "password" ? "Enter your password" : "Sign in to your Microsoft account");
  }

  hasPasswordInput(): boolean {
    return this.phase === "password" || this.phase === "password-return";
  }

  bodyText(): string {
    return this.hasPasswordInput() ? "Enter your password" : "Please wait while Microsoft continues sign in";
  }

  on(event: string, handler: (...args: any[]) => void): void {
    const handlers = this.events.get(event) || [];
    handlers.push(handler);
    this.events.set(event, handlers);
  }

  off(event: string, handler: (...args: any[]) => void): void {
    const handlers = this.events.get(event) || [];
    this.events.set(event, handlers.filter((item) => item !== handler));
  }

  context(): { newCDPSession: () => Promise<{ send: (method: string, payload?: any) => Promise<any> }> } {
    return {
      newCDPSession: async () => ({
        send: async (method: string, payload?: any) => {
          if (method === "Input.dispatchMouseEvent" && payload?.type === "mouseReleased") {
            this.passwordSubmitCount += 1;
            this.phase = "transition";
            this.transitionWaits = 0;
            this.passwordReturnWaits = 0;
          }
          if (method === "Accessibility.getFullAXTree") {
            return { nodes: [] };
          }
          return {};
        },
      }),
    };
  }

  locator(_selector: string): MockLocator {
    return new MockLocator(this);
  }

  async waitForSelector(): Promise<void> {}

  async waitForLoadState(): Promise<void> {}

  async waitForTimeout(): Promise<void> {
    if (this.options.advanceClockMs) {
      fakeNow += this.options.advanceClockMs;
    }
    if (this.phase === "transition") {
      this.transitionWaits += 1;
      if (this.transitionWaits >= (this.options.transitionWaitsToPasswordReturn ?? 3)) {
        this.phase = "password-return";
      }
      return;
    }
    if (this.phase === "password-return") {
      this.passwordReturnWaits += 1;
      if (this.passwordReturnWaits >= (this.options.passwordReturnWaitsToDone ?? 2)) {
        this.phase = "done";
      }
    }
  }

  async evaluate(fnOrSource: unknown, arg?: unknown): Promise<any> {
    if (typeof fnOrSource === "string") {
      return [];
    }
    const source = String(fnOrSource);
    if (source.includes(".error-code") || source.includes("chrome-error://")) {
      return null;
    }
    if (source.includes("incorrect password") || source.includes("try again later")) {
      return [];
    }
    if (source.includes("textParts")) {
      return {
        title: await this.title(),
        bodyText: this.bodyText(),
        controlText: "",
      };
    }
    if (source.includes("hasVisibleInput") && source.includes("likelySurface")) {
      return {
        hasVisibleInput: this.hasPasswordInput(),
        likelySurface: this.hasPasswordInput(),
      };
    }
    if (source.includes("data-codex-visible-control")) {
      return this.hasPasswordInput();
    }
    if (source.includes("compiledPatterns")) {
      return this.hasPasswordInput() ? { x: 100, y: 40 } : null;
    }
    if (source.includes("rawSelector")) {
      return this.hasPasswordInput() ? { x: 100, y: 40 } : null;
    }
    if (source.includes("visiblePasswordInput")) {
      return {
        hasVisibleInput: this.hasPasswordInput(),
        likelySurface: this.hasPasswordInput(),
      };
    }
    if (source.includes("hasProofOptionsSelect")) {
      return {
        url: this.url(),
        title: await this.title(),
        bodyText: this.bodyText(),
        hasProofOptionsSelect: false,
        hasAddEmailInput: false,
        hasConfirmationEmailInput: false,
        hasProofRadio: false,
        hasCodeInput: false,
      };
    }
    if (source.includes("bodyText.match")) {
      return {
        url: this.url(),
        title: await this.title(),
        bodyText: this.bodyText(),
        accountHint: "",
      };
    }
    if (source.includes("window.location.href")) {
      return {
        url: this.url(),
        title: await this.title(),
        bodyText: this.bodyText(),
      };
    }
    if (source.includes("document.body?.innerText")) {
      return this.bodyText();
    }
    return arg ? true : null;
  }
}

function createConfig(): AppConfig {
  return {
    runMode: "headless",
    browserEngine: "chrome",
    inspectBrowserEngine: "chrome",
    chromeNativeAutomation: false,
    chromeActivateOnLaunch: false,
    chromeAutoOpenDevtools: false,
    chromeIdentityOverride: false,
    chromeStealthJsEnabled: false,
    chromeProfileDir: "/tmp/tavreg-hikari-test-profile",
    keepBrowserOpenOnFailure: false,
    keepBrowserOpenMs: 0,
    chromeExecutablePath: "/opt/fingerprint-browser/chrome",
    headlessChromeExecutablePath: "/opt/fingerprint-browser/chrome",
    outputRoot: "/tmp/tavreg-hikari-test-output",
    userDataRoot: "/tmp/tavreg-hikari-test-user-data",
    existingEmail: "",
    existingPassword: "",
    microsoftAccountEmail: "account@example.test",
    microsoftAccountPassword: "pass-123",
    microsoftProofMailboxProvider: "cfmail",
    microsoftProofMailboxAddress: "",
    microsoftProofMailboxId: "",
    microsoftKeepSignedIn: true,
    mailProvider: "duckmail",
    duckmailDomain: "",
    gptmailBaseUrl: "",
    gptmailApiKey: "",
    gptmailDomain: "",
    vmailBaseUrl: "",
    vmailApiKey: "",
    vmailDomain: "",
    cfMailBaseUrl: "",
    cfMailApiKey: "",
    cfMailDomain: "",
    mihomoSubscriptionUrl: "",
    mihomoGroupName: "",
    mihomoRouteGroupName: "",
    mihomoApiPort: 0,
    mihomoMixedPort: 0,
    proxyCheckUrl: "",
    proxyCheckTimeoutMs: 1000,
    proxyLatencyMaxMs: 1000,
    proxyBrokerBaseUrl: "",
    proxyBrokerApiKey: "",
    proxyBrokerProfileId: "",
    proxyBrokerTimeoutMs: 1000,
    proxyBrokerDomainProbeEnabled: false,
    proxyBrokerDomainProbeTimeoutMs: 1000,
    proxyBrokerDomainProbeRetries: 1,
    proxyBrokerDomainProbeSites: [],
    siteProxyDomainProbes: {},
    openaiApiKey: "",
    openaiBaseUrl: "",
    openaiModel: "",
    ocrProvider: "openai",
    ocrModel: "",
    ocrPrompt: "",
    signupNeed: 0,
    signupParallel: 1,
    signupMaxAttempts: 1,
    signupModeRetryMax: 1,
    signupAttemptTimeoutMs: 1000,
    webHost: "127.0.0.1",
    webPort: 3717,
  } as unknown as AppConfig;
}

describe("Microsoft login flow password submit", () => {
  const realDateNow = Date.now;

  test("runs the real login state machine without duplicate password submit during OAuth authorize transition", async () => {
    const page = new MockMicrosoftPage();

    try {
      await completeMicrosoftLogin(page, createConfig(), "http://127.0.0.1:1080", {
        completionUrlPatterns: [/^https:\/\/tavreg-hikari\.ivanli\.cc\/api\/microsoft-mail\/oauth\/callback/i],
      });
    } catch (error) {
      throw new Error(
        `completeMicrosoftLogin rejected after ${page.passwordSubmitCount} submits: ${
          error instanceof Error ? error.stack || error.message : String(error)
        }`,
      );
    }

    expect(page.passwordSubmitCount).toBe(1);
  });

  test("keeps waiting after eight seconds during the preserved Microsoft password transition", async () => {
    fakeNow = 10_000;
    Date.now = () => fakeNow;
    const page = new MockMicrosoftPage({
      transitionWaitsToPasswordReturn: 1,
      passwordReturnWaitsToDone: 3,
      advanceClockMs: 5_000,
    });

    try {
      await completeMicrosoftLogin(page, createConfig(), "http://127.0.0.1:1080", {
        completionUrlPatterns: [/^https:\/\/tavreg-hikari\.ivanli\.cc\/api\/microsoft-mail\/oauth\/callback/i],
      });
    } catch (error) {
      throw new Error(
        `completeMicrosoftLogin rejected after ${page.passwordSubmitCount} submits at fakeNow=${fakeNow}: ${
          error instanceof Error ? error.stack || error.message : String(error)
        }`,
      );
    } finally {
      Date.now = realDateNow;
    }

    expect(page.passwordSubmitCount).toBe(1);
  });
});
