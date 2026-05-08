import { describe, expect, test } from "bun:test";
import {
  AccountSessionBootstrapDispatcher,
  getAccountSessionBootstrapBlockMessage,
  hasConfiguredMicrosoftGraphBootstrap,
  hasSuccessfulAccountBootstrap,
  isLockedAccountRecord,
  normalizeMicrosoftAccountBootstrapConcurrency,
  normalizeMicrosoftAccountBootstrapKillGraceMs,
  normalizeMicrosoftAccountBootstrapWorkerTimeoutMs,
  normalizeAccountSessionRebootstrapRequest,
  resolveAccountBatchBootstrapDecision,
  resolveBootstrapQueueDisposition,
  resolveRequestedSessionProxyNode,
  shouldReplayPendingAccountBootstrap,
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
        hasApiKey: false,
        mailboxStatus: "available",
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
        hasApiKey: false,
        mailboxStatus: "preparing",
        browserSession: null,
      } as never),
    ).toBe(true);
    expect(
      shouldQueueImportedAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: false,
        mailboxStatus: "failed",
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

  test("normalizes bootstrap concurrency and timeout settings", () => {
    expect(normalizeMicrosoftAccountBootstrapConcurrency("0")).toBe(1);
    expect(normalizeMicrosoftAccountBootstrapConcurrency("12")).toBe(10);
    expect(normalizeMicrosoftAccountBootstrapConcurrency("4")).toBe(4);
    expect(normalizeMicrosoftAccountBootstrapWorkerTimeoutMs(500)).toBe(1000);
    expect(normalizeMicrosoftAccountBootstrapWorkerTimeoutMs("90000")).toBe(90000);
    expect(normalizeMicrosoftAccountBootstrapKillGraceMs(500)).toBe(1000);
    expect(normalizeMicrosoftAccountBootstrapKillGraceMs("12000")).toBe(12000);
  });

  test("bootstrap dispatcher runs different accounts in parallel while deduping the same account", async () => {
    let active = 0;
    let maxActive = 0;
    const started: number[] = [];
    const releaseByAccount = new Map<number, () => void>();
    const dispatcher = new AccountSessionBootstrapDispatcher(
      () => 2,
      async (accountId) => {
        started.push(accountId);
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise<void>((resolve) => {
          releaseByAccount.set(accountId, resolve);
        });
        active -= 1;
      },
    );

    expect(dispatcher.enqueue(1)).toBe(true);
    expect(dispatcher.enqueue(1)).toBe(false);
    expect(dispatcher.enqueue(2)).toBe(true);
    expect(dispatcher.enqueue(3)).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(started).toEqual([1, 2]);
    expect(maxActive).toBe(2);
    expect(dispatcher.isQueuedOrActive(1)).toBe(true);

    releaseByAccount.get(1)?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(started).toEqual([1, 2, 3]);
    releaseByAccount.get(2)?.();
    releaseByAccount.get(3)?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(dispatcher.activeCount()).toBe(0);
  });

  test("bootstrap dispatcher settlement callback can requeue the same account after active release", async () => {
    const started: number[] = [];
    const releases: Array<() => void> = [];
    let requeued = false;
    const dispatcher = new AccountSessionBootstrapDispatcher(
      () => 1,
      async (accountId) => {
        started.push(accountId);
        await new Promise<void>((resolve) => {
          releases.push(resolve);
        });
      },
      (accountId) => {
        if (!requeued) {
          requeued = true;
          expect(dispatcher.enqueue(accountId)).toBe(true);
        }
      },
    );

    expect(dispatcher.enqueue(1)).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(started).toEqual([1]);

    releases.shift()?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(started).toEqual([1, 1]);

    releases.shift()?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(dispatcher.activeCount()).toBe(0);
  });

  test("force rebootstrap requests are deferred instead of dropped while a bootstrap is already queued", () => {
    expect(resolveBootstrapQueueDisposition({ alreadyQueued: false, force: false })).toBe("queue");
    expect(resolveBootstrapQueueDisposition({ alreadyQueued: true, force: false })).toBe("skip");
    expect(resolveBootstrapQueueDisposition({ alreadyQueued: true, force: true })).toBe("defer_force");
  });

  test("normalizes manual rebootstrap requests with optional proxy override", () => {
    expect(normalizeAccountSessionRebootstrapRequest(null)).toEqual({
      force: true,
    });
    expect(normalizeAccountSessionRebootstrapRequest({ force: false, proxyNode: "  Seoul-02  " })).toEqual({
      force: false,
      proxyNode: "Seoul-02",
    });
    expect(normalizeAccountSessionRebootstrapRequest({ force: true, proxyNode: "" })).toEqual({
      force: true,
      proxyNode: null,
    });
    expect(normalizeAccountSessionRebootstrapRequest({ force: false })).toEqual({
      force: false,
    });
  });

  test("validates requested session proxy nodes against current inventory", () => {
    expect(resolveRequestedSessionProxyNode(undefined, ["Tokyo-01", "Seoul-02"])).toEqual({
      proxyNode: undefined,
      error: null,
    });
    expect(resolveRequestedSessionProxyNode(null, ["Tokyo-01", "Seoul-02"])).toEqual({
      proxyNode: null,
      error: null,
    });
    expect(resolveRequestedSessionProxyNode("Seoul-02", ["Tokyo-01", "Seoul-02"])).toEqual({
      proxyNode: "Seoul-02",
      error: null,
    });
    expect(resolveRequestedSessionProxyNode("Missing-01", ["Tokyo-01", "Seoul-02"])).toEqual({
      proxyNode: null,
      error: "代理节点不存在：Missing-01",
    });
  });

  test("blocks rebootstrap for leased, disabled, or locked accounts while keeping linked accounts manually retryable", () => {
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
        mailboxStatus: "available",
        browserSession: { status: "ready" },
      } as never),
    ).toBeNull();
    expect(
      getAccountSessionBootstrapBlockMessage({
        leaseJobId: null,
        disabledAt: "2026-03-31T00:00:00.000Z",
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: false,
        mailboxStatus: "preparing",
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
        mailboxStatus: "locked",
        browserSession: { status: "ready" },
      } as never),
    ).toContain("已锁定");
  });

  test("recognizes locked account markers from skip reason or error code", () => {
    expect(isLockedAccountRecord({ skipReason: "microsoft_account_locked", lastErrorCode: null, disabledAt: null } as never)).toBe(true);
    expect(isLockedAccountRecord({ skipReason: null, lastErrorCode: "microsoft_account_locked:challenge", disabledAt: null } as never)).toBe(true);
    expect(isLockedAccountRecord({ skipReason: null, lastErrorCode: "oauth_timeout", disabledAt: null } as never)).toBe(false);
  });

  test("treats only ready session + available mailbox as successful bootstrap", () => {
    expect(
      hasSuccessfulAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: false,
        mailboxStatus: "available",
        browserSession: { status: "ready" },
      } as never),
    ).toBe(true);
    expect(
      hasSuccessfulAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: false,
        mailboxStatus: "preparing",
        browserSession: { status: "ready" },
      } as never),
    ).toBe(false);
  });

  test("batch bootstrap preview skips successful or in-flight accounts only in pending-only mode", () => {
    expect(
      resolveAccountBatchBootstrapDecision({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: true,
        mailboxStatus: "available",
        browserSession: { status: "ready" },
      } as never, "pending_only"),
    ).toMatchObject({ decision: "already_bootstrapped" });
    expect(
      resolveAccountBatchBootstrapDecision({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: true,
        mailboxStatus: "available",
        browserSession: { status: "ready" },
      } as never, "force"),
    ).toMatchObject({ decision: "queue" });
    expect(
      resolveAccountBatchBootstrapDecision({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: false,
        mailboxStatus: "preparing",
        browserSession: { status: "bootstrapping" },
      } as never, "force"),
    ).toMatchObject({ decision: "bootstrapping" });
  });

  test("auto import bootstrap still skips linked accounts that already own API keys", () => {
    expect(
      shouldQueueImportedAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: true,
        mailboxStatus: "available",
        browserSession: { status: "failed" },
      } as never),
    ).toBe(false);
  });

  test("restart recovery can replay pending bootstraps even for linked accounts", () => {
    expect(
      shouldReplayPendingAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: true,
        mailboxStatus: "available",
        browserSession: { status: "pending" },
      } as never),
    ).toBe(true);
    expect(
      shouldReplayPendingAccountBootstrap({
        leaseJobId: null,
        disabledAt: null,
        skipReason: null,
        lastErrorCode: null,
        hasApiKey: true,
        mailboxStatus: "available",
        browserSession: { status: "ready" },
      } as never),
    ).toBe(false);
  });
});
