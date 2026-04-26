import { afterEach, describe, expect, test } from "bun:test";
import { extractEmailCodeFromPayload, loadConfig } from "../src/main";
import {
  createGrokMailbox,
  rememberGrokBlockedMailbox,
  resetRememberedGrokBlockedMailboxes,
  waitForGrokEmailCode,
} from "../src/server/grok-mail-service";

const originalFetch = globalThis.fetch;
const envBackup = { ...process.env };

function createTestConfig(overrides: Record<string, unknown> = {}) {
  process.env.MIHOMO_SUBSCRIPTION_URL = process.env.MIHOMO_SUBSCRIPTION_URL || "https://subscription.example.test";
  return {
    ...loadConfig(),
    ...overrides,
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  resetRememberedGrokBlockedMailboxes();
  for (const key of Object.keys(process.env)) {
    if (!(key in envBackup)) {
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(envBackup)) {
    process.env[key] = value;
  }
});

describe("grok mail service", () => {
  test("project email extraction accepts Grok hyphenated codes", () => {
    expect(extractEmailCodeFromPayload({ html: "<div>Your verification code is ABC-123</div>" })).toBe("ABC123");
  });

  test("createGrokMailbox provisions a project cfmail mailbox", async () => {
    process.env.CFMAIL_API_KEY = "cf_key_test";
    process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
    process.env.CHATGPT_CFMAIL_ROOT_DOMAIN = "707979.xyz";
    const calls: Array<{ url: string; method: string; body?: string | null; authorization?: string | null }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({
        url,
        method: init?.method || "GET",
        body: typeof init?.body === "string" ? init.body : null,
        authorization: new Headers(init?.headers).get("authorization"),
      });
      if (url === "https://api.cfm.example.test/api/mailboxes") {
        return new Response(
          JSON.stringify({
            id: "mbx-grok-1",
            address: "koha@alpha.707979.xyz",
            localPart: "koha",
            subdomain: "alpha",
            rootDomain: "707979.xyz",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    const mailbox = await createGrokMailbox({
      cfg: createTestConfig({ cfmailBaseUrl: "https://api.cfm.example.test", cfmailApiKey: "cf_key_test" }),
    });
    expect(mailbox.provider).toBe("cfmail");
    expect(mailbox.address).toBe("koha@alpha.707979.xyz");
    expect(mailbox.accountId).toBe("mbx-grok-1");
    expect(mailbox.headers.Authorization).toBe("Bearer cf_key_test");
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      url: "https://api.cfm.example.test/api/mailboxes",
      method: "POST",
      authorization: "Bearer cf_key_test",
    });
    expect(calls[0]?.body || "").toContain('"rootDomain":"707979.xyz"');
  });

  test("waitForGrokEmailCode uses project cfmail polling rules", async () => {
    process.env.CFMAIL_API_KEY = "cf_key_test";
    process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "https://api.cfm.example.test/api/messages?mailboxId=mbx-grok-1&since=2026-04-11T00%3A00%3A00.000Z") {
        expect(new Headers(init?.headers).get("authorization")).toBe("Bearer cf_key_test");
        return new Response(
          JSON.stringify({
            messages: [
              {
                id: "msg-1",
                mailboxId: "mbx-grok-1",
                mailboxAddress: "koha@alpha.707979.xyz",
                subject: "Verify your email",
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://api.cfm.example.test/api/messages/msg-1") {
        return new Response(
          JSON.stringify({
            message: {
              id: "msg-1",
              html: "<div>Verification code: ABC-123</div>",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    const result = await waitForGrokEmailCode({
      mailbox: {
        provider: "cfmail",
        address: "koha@alpha.707979.xyz",
        accountId: "mbx-grok-1",
        baseUrl: "https://api.cfm.example.test",
        headers: { Authorization: "Bearer cf_key_test", Accept: "application/json" },
      },
      cfg: createTestConfig({
        cfmailBaseUrl: "https://api.cfm.example.test",
        cfmailApiKey: "cf_key_test",
        mailPollMs: 10,
        emailWaitMs: 1500,
      }),
      timeoutMs: 1500,
      pollMs: 10,
      notBefore: "2026-04-11T00:00:00.000Z",
    });
    expect(result).toEqual({ code: "ABC123" });
  });

  test("createGrokMailbox prefers the verified Grok cfmail root domain from project meta", async () => {
    process.env.CFMAIL_API_KEY = "cf_key_test";
    process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
    delete process.env.GROK_CFMAIL_ROOT_DOMAIN;
    delete process.env.CHATGPT_CFMAIL_ROOT_DOMAIN;
    const calls: Array<{ url: string; method: string; body?: string | null }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({
        url,
        method: init?.method || "GET",
        body: typeof init?.body === "string" ? init.body : null,
      });
      if (url === "https://api.cfm.example.test/api/meta") {
        return new Response(
          JSON.stringify({
            domains: ["707079.xyz", "707979.xyz", "ivanli.asia"],
            defaultMailboxTtlMinutes: 30,
            minMailboxTtlMinutes: 10,
            maxMailboxTtlMinutes: 120,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://api.cfm.example.test/api/mailboxes") {
        return new Response(
          JSON.stringify({
            id: "mbx-grok-priority",
            address: "koha@alpha.707979.xyz",
            localPart: "koha",
            subdomain: "alpha",
            rootDomain: "707979.xyz",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    const mailbox = await createGrokMailbox({
      cfg: createTestConfig({ cfmailBaseUrl: "https://api.cfm.example.test", cfmailApiKey: "cf_key_test" }),
    });
    expect(mailbox.address).toBe("koha@alpha.707979.xyz");
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({ url: "https://api.cfm.example.test/api/meta", method: "GET" });
    expect(calls[1]).toMatchObject({ url: "https://api.cfm.example.test/api/mailboxes", method: "POST" });
    expect(calls[1]?.body || "").toContain('"rootDomain":"707979.xyz"');
  });

  test("remembered blocked mailbox domains are skipped for later Grok mailbox creation", async () => {
    process.env.CFMAIL_API_KEY = "cf_key_test";
    process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
    process.env.CHATGPT_CFMAIL_ROOT_DOMAIN = "707979.xyz";
    const generated = [
      { id: "mbx-blocked", address: "first@bad-domain.test" },
      { id: "mbx-good", address: "second@good-domain.test" },
    ];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://api.cfm.example.test/api/mailboxes") {
        const next = generated.shift();
        return new Response(
          JSON.stringify({
            id: next?.id,
            address: next?.address,
            localPart: "grok",
            subdomain: "alpha",
            rootDomain: "707979.xyz",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    expect(rememberGrokBlockedMailbox("first@bad-domain.test")).toBe("bad-domain.test");
    const mailbox = await createGrokMailbox({
      cfg: createTestConfig({ cfmailBaseUrl: "https://api.cfm.example.test", cfmailApiKey: "cf_key_test" }),
    });
    expect(mailbox.address).toBe("second@good-domain.test");
  });

  test("remembered blocked cfmail subdomains collapse to root domain", async () => {
    process.env.CFMAIL_API_KEY = "cf_key_test";
    process.env.CFMAIL_BASE_URL = "https://api.cfm.example.test";
    process.env.CHATGPT_CFMAIL_ROOT_DOMAIN = "707079.xyz";
    const generated = [
      { id: "mbx-blocked", address: "first@box-a.707079.xyz" },
      { id: "mbx-good", address: "second@box-b.ivanli.asia" },
    ];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://api.cfm.example.test/api/mailboxes") {
        const next = generated.shift();
        return new Response(
          JSON.stringify({
            id: next?.id,
            address: next?.address,
            localPart: "grok",
            subdomain: "alpha",
            rootDomain: next?.address?.split(".").slice(-2).join("."),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    expect(rememberGrokBlockedMailbox("first@box-a.707079.xyz")).toBe("707079.xyz");
    const mailbox = await createGrokMailbox({
      cfg: createTestConfig({ cfmailBaseUrl: "https://api.cfm.example.test", cfmailApiKey: "cf_key_test" }),
    });
    expect(mailbox.address).toBe("second@box-b.ivanli.asia");
  });

  test("grok microsoft signup keeps the native profile-completion path before direct-post fallbacks", async () => {
    const { readFile } = await import("node:fs/promises");
    const source = await readFile(new URL("../src/server/grok-worker.ts", import.meta.url), "utf8");
    expect(source).toContain('authProvider !== "microsoft" || !(await hasSsoCookie(page))');
    expect(source).toContain('throw new Error("grok_microsoft_post_sso_profile_unhandled")');
    expect(source).toContain('accounts:profile_completion_after_microsoft');
  });
});
