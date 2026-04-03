import { describe, expect, test } from "bun:test";
import {
  getAccountSessionBootstrapBlockMessage,
  hasConfiguredMicrosoftGraphBootstrap,
  isLockedAccountRecord,
  resolveBootstrapQueueDisposition,
  shouldForceImportedAccountBootstrap,
  shouldQueueImportedAccountBootstrap,
} from "../src/server/account-session-bootstrap.ts";

describe("account session bootstrap helpers", () => {
  test("does not auto-queue accounts whose persistent session is already ready", () => {
    expect(
      shouldQueueImportedAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        browserSession: {
          status: "ready",
        },
      } as never),
    ).toBe(false);
  });

  test("auto-queues imported accounts when session is missing or not ready", () => {
    expect(
      shouldQueueImportedAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        browserSession: null,
      } as never),
    ).toBe(true);
    expect(
      shouldQueueImportedAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        browserSession: {
          status: "failed",
        },
      } as never),
    ).toBe(true);
  });

  test("forces bootstrap when an import changes the stored password", () => {
    expect(
      shouldForceImportedAccountBootstrap(
        {
          passwordPlaintext: "old-pass",
        } as never,
        "new-pass",
      ),
    ).toBe(true);
    expect(
      shouldForceImportedAccountBootstrap(
        {
          passwordPlaintext: "same-pass",
        } as never,
        "same-pass",
      ),
    ).toBe(false);
    expect(shouldForceImportedAccountBootstrap(null, "fresh-pass")).toBe(false);
  });

  test("auto-bootstrap waits until the Graph callback settings are complete", () => {
    expect(
      hasConfiguredMicrosoftGraphBootstrap({
        clientId: "client-id",
        clientSecret: "client-secret",
        redirectUri: "https://example.com/callback",
      }),
    ).toBe(true);
    expect(
      hasConfiguredMicrosoftGraphBootstrap({
        clientId: "client-id",
        clientSecret: "",
        redirectUri: "https://example.com/callback",
      }),
    ).toBe(false);
  });

  test("force rebootstrap requests are deferred instead of dropped while a bootstrap is already queued", () => {
    expect(resolveBootstrapQueueDisposition({ alreadyQueued: false, force: false })).toBe("queue");
    expect(resolveBootstrapQueueDisposition({ alreadyQueued: true, force: false })).toBe("skip");
    expect(resolveBootstrapQueueDisposition({ alreadyQueued: true, force: true })).toBe("defer_force");
  });

  test("blocks rebootstrap for leased, disabled, or locked accounts", () => {
    expect(
      getAccountSessionBootstrapBlockMessage({
        leaseJobId: 7,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        browserSession: { status: "ready" },
      } as never),
    ).toContain("job #7");
    expect(
      getAccountSessionBootstrapBlockMessage({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: true,
        browserSession: { status: "ready" },
      } as never),
    ).toContain("API key");
    expect(
      getAccountSessionBootstrapBlockMessage({
        leaseJobId: null,
        disabledAt: "2026-03-31T00:00:00.000Z",
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: false,
        browserSession: { status: "ready" },
      } as never),
    ).toContain("已被禁用");
    expect(
      getAccountSessionBootstrapBlockMessage({
        leaseJobId: null,
        disabledAt: null,
        skipReason: "microsoft_account_locked",
        lastErrorCode: null,
        hasApiKey: false,
        browserSession: { status: "ready" },
      } as never),
    ).toContain("已锁定");
  });

  test("recognizes locked account markers from skip reason or error code", () => {
    expect(isLockedAccountRecord({ skipReason: "microsoft_account_locked", lastErrorCode: null, disabledAt: null } as never)).toBe(true);
    expect(isLockedAccountRecord({ skipReason: null, lastErrorCode: "microsoft_account_locked:challenge", disabledAt: null } as never)).toBe(true);
    expect(isLockedAccountRecord({ skipReason: null, lastErrorCode: "oauth_timeout", disabledAt: null } as never)).toBe(false);
  });
});
