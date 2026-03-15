import { describe, expect, test } from "bun:test";
import {
  getFingerprintChromiumArgs,
  resolveFingerprintChromiumPlatform,
  shouldFallbackToPersistentBrowser,
  shouldUseVirtualDisplay,
} from "./runtime.js";

describe("shouldUseVirtualDisplay", () => {
  test("enables xvfb only for linux headed chrome without display", () => {
    expect(
      shouldUseVirtualDisplay({
        platform: "linux",
        mode: "headed",
        browserEngine: "chrome",
        enabled: true,
      }),
    ).toBe(true);
  });

  test("skips xvfb when display is already provided", () => {
    expect(
      shouldUseVirtualDisplay({
        platform: "linux",
        mode: "headed",
        browserEngine: "chrome",
        displayEnv: ":0",
        enabled: true,
      }),
    ).toBe(false);
  });

  test("skips xvfb for headless or non-chrome engines", () => {
    expect(
      shouldUseVirtualDisplay({
        platform: "linux",
        mode: "headless",
        browserEngine: "chrome",
        enabled: true,
      }),
    ).toBe(false);
    expect(
      shouldUseVirtualDisplay({
        platform: "linux",
        mode: "headed",
        browserEngine: "camoufox",
        enabled: true,
      }),
    ).toBe(false);
  });
});

describe("fingerprint chromium args", () => {
  test("maps supported platforms", () => {
    expect(resolveFingerprintChromiumPlatform("linux")).toBe("linux");
    expect(resolveFingerprintChromiumPlatform("darwin")).toBe("macos");
    expect(resolveFingerprintChromiumPlatform("win32")).toBeNull();
  });

  test("injects linux fingerprint platform for fingerprint chromium", () => {
    const args = getFingerprintChromiumArgs({
      platform: "linux",
      executablePath: "/opt/fingerprint-chromium/chromium",
      profileDir: "/tmp/profile-a",
      proxyServer: "http://127.0.0.1:7890",
      locale: "en-US",
      acceptLanguage: "en-US,en;q=0.9",
      timezoneId: "America/Los_Angeles",
    });
    expect(args).toContain("--fingerprint-platform=linux");
    expect(args).toContain("--fingerprint-brand=Chrome");
    expect(args).toContain("--timezone=America/Los_Angeles");
  });

  test("returns no fingerprint args for plain chrome", () => {
    expect(
      getFingerprintChromiumArgs({
        platform: "linux",
        executablePath: "/usr/bin/google-chrome",
        profileDir: "/tmp/profile-b",
        proxyServer: "http://127.0.0.1:7890",
        locale: "en-US",
        acceptLanguage: "en-US,en;q=0.9",
      }),
    ).toEqual([]);
  });
});

describe("shouldFallbackToPersistentBrowser", () => {
  test("only falls back for headed native chrome automation", () => {
    expect(shouldFallbackToPersistentBrowser("chrome", "headed", true)).toBe(true);
    expect(shouldFallbackToPersistentBrowser("chrome", "headless", true)).toBe(false);
    expect(shouldFallbackToPersistentBrowser("camoufox", "headed", true)).toBe(false);
    expect(shouldFallbackToPersistentBrowser("chrome", "headed", false)).toBe(false);
  });
});
