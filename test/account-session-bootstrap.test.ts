import { describe, expect, test } from "bun:test";
import {
  getAccountSessionBootstrapBlockMessage,
  isLockedAccountRecord,
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
        disabledAt: "2026-03-31T00:00:00.000Z",
        skipReason: null,
        lastErrorCode: null,
        browserSession: { status: "ready" },
      } as never),
    ).toContain("已被禁用");
    expect(
      getAccountSessionBootstrapBlockMessage({
        leaseJobId: null,
        disabledAt: null,
        skipReason: "microsoft_account_locked",
        lastErrorCode: null,
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
