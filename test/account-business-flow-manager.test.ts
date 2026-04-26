import { expect, test } from "bun:test";
import {
  AccountBusinessFlowManager,
  type AccountBusinessFlowMode,
  type AccountBusinessFlowSite,
} from "../src/server/account-business-flow.ts";

function createManagerFixture(input: {
  account: Record<string, unknown> | null;
  mailbox?: Record<string, unknown> | null;
}) {
  const db = {
    getAccount(accountId: number) {
      if (!input.account) return null;
      return Number(input.account.id) === accountId ? input.account : null;
    },
    getMailboxByAccountId(accountId: number) {
      if (!input.account || Number(input.account.id) !== accountId) return null;
      return input.mailbox ?? null;
    },
  } as any;

  const browserAvailability = {
    getAccountBusinessFlowAvailability() {
      return {
        headless: true,
        headed: true,
        fingerprint: true,
        headedReason: null,
        fingerprintReason: null,
        deAvailable: true,
      };
    },
    async ensureFresh() {},
  } as any;

  const manager = new AccountBusinessFlowManager(
    db,
    process.cwd(),
    "/tmp/tavreg-hikari-test-ledger.db",
    () =>
      ({
        microsoftGraphClientId: "",
        microsoftGraphClientSecret: "",
        microsoftGraphRedirectUri: "",
        microsoftGraphAuthority: "common",
      }) as any,
    () => {},
    (async () => ({})) as any,
    browserAvailability,
  );

  return manager as any;
}

function createAccount(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 245,
    microsoftEmail: "drummondwolley46@outlook.com",
    passwordPlaintext: "test-password",
    proofMailboxProvider: null,
    proofMailboxAddress: null,
    proofMailboxId: null,
    browserSession: null,
    ...overrides,
  };
}

test("allows Tavily account business flow to start without a configured proof mailbox", async () => {
  const manager = createManagerFixture({
    account: createAccount(),
  });
  const calls: Array<{ site: AccountBusinessFlowSite; mode: AccountBusinessFlowMode; key: string }> = [];
  manager.startTavilyFlow = async (_account: unknown, site: AccountBusinessFlowSite, mode: AccountBusinessFlowMode, key: string) => {
    calls.push({ site, mode, key });
  };

  await expect(manager.start({ accountId: 245, site: "tavily", mode: "fingerprint" })).resolves.toBeUndefined();
  expect(calls).toEqual([{ site: "tavily", mode: "fingerprint", key: "245:tavily" }]);
});

test("allows the none business flow option to open the Microsoft account page without mailbox auth", async () => {
  const manager = createManagerFixture({
    account: createAccount(),
  });
  const calls: Array<{ mode: AccountBusinessFlowMode; key: string }> = [];
  manager.startMicrosoftAccountFlow = async (_account: unknown, mode: AccountBusinessFlowMode, key: string) => {
    calls.push({ mode, key });
  };

  await expect(manager.start({ accountId: 245, site: "none", mode: "headed" })).resolves.toBeUndefined();
  expect(calls).toEqual([{ mode: "headed", key: "245:none" }]);
});

test("allows ChatGPT and Grok account business flows to start without a configured proof mailbox when mailbox auth exists", async () => {
  for (const site of ["chatgpt", "grok"] as const) {
    const manager = createManagerFixture({
      account: createAccount(),
      mailbox: {
        id: 991,
        refreshToken: "refresh-token",
      },
    });
    const calls: Array<{ site: AccountBusinessFlowSite; mode: AccountBusinessFlowMode; key: string }> = [];
    if (site === "chatgpt") {
      manager.startChatGptFlow = async (_account: unknown, _mailbox: unknown, mode: AccountBusinessFlowMode, key: string) => {
        calls.push({ site, mode, key });
      };
    } else {
      manager.startGrokFlow = async (_account: unknown, _mailbox: unknown, mode: AccountBusinessFlowMode, key: string) => {
        calls.push({ site, mode, key });
      };
    }

    await expect(manager.start({ accountId: 245, site, mode: "headless" })).resolves.toBeUndefined();
    expect(calls).toEqual([{ site, mode: "headless", key: `245:${site}` }]);
  }
});

test("still requires Microsoft mailbox authorization for ChatGPT and Grok code extraction", async () => {
  for (const site of ["chatgpt", "grok"] as const) {
    const manager = createManagerFixture({
      account: createAccount(),
      mailbox: {
        id: 991,
        refreshToken: "",
      },
    });

    await expect(manager.start({ accountId: 245, site, mode: "headless" })).rejects.toThrow(
      "当前账号还没有完成 Microsoft 邮箱授权，暂时无法自动提取验证码",
    );
  }
});
