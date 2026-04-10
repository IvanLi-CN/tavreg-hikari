import { describe, expect, test } from "bun:test";
import {
  buildCfMailAuthHeaders,
  buildCfMailRawMessageUrl,
  ensureCfMailMailbox,
  extractMicrosoftProofCodeFromPayload,
  fetchCfMailMeta,
  getCfMailMessage,
  listCfMailMessages,
  normalizeCfMailBaseUrl,
  provisionCfMailMailbox,
  resolveCfMailMailbox,
  type CfMailHttpJson,
  type CfMailHttpJsonOptions,
} from "../src/cfmail-api.ts";

describe("CF Mail API", () => {
  test("normalizes base url and auth headers", () => {
    expect(normalizeCfMailBaseUrl("https://api.cfm.example.test///")).toBe("https://api.cfm.example.test");
    expect(normalizeCfMailBaseUrl("")).toBe("https://api.cfm.example.test");
    expect(buildCfMailAuthHeaders(" secret-key ")).toEqual({
      Accept: "application/json",
      Authorization: "Bearer secret-key",
    });
  });

  test("fetches meta and preserves ttl and address rules", async () => {
    const calls: Array<{ method: string; url: string }> = [];
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string) => {
      calls.push({ method, url });
      return {
        domains: ["example.test"],
        defaultMailboxTtlMinutes: 60,
        minMailboxTtlMinutes: 5,
        maxMailboxTtlMinutes: 1440,
        addressRules: {
          format: "localPart@subdomain.rootDomain",
          localPartPattern: "local",
          subdomainPattern: "sub",
          examples: ["build@alpha.example.test"],
        },
      } as T;
    };

    const meta = await fetchCfMailMeta({
      baseUrl: "https://api.cfm.example.test/",
      httpJson,
    });

    expect(meta).toMatchObject({
      domains: ["example.test"],
      defaultMailboxTtlMinutes: 60,
      minMailboxTtlMinutes: 5,
      maxMailboxTtlMinutes: 1440,
      addressRules: {
        format: "localPart@subdomain.rootDomain",
        examples: ["build@alpha.example.test"],
      },
    });
    expect(calls).toEqual([{ method: "GET", url: "https://api.cfm.example.test/api/meta" }]);
  });

  test("resolves mailbox by address and returns null on 404", async () => {
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string, options?: CfMailHttpJsonOptions) => {
      expect(method).toBe("GET");
      expect(url).toBe("https://api.cfm.example.test/api/mailboxes/resolve?address=proof%40alpha.example.test");
      expect(options?.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer cfm-key",
      });
      return {
        id: "mbx-proof",
        address: "proof@alpha.example.test",
        localPart: "proof",
        subdomain: "alpha",
        rootDomain: "example.test",
      } as T;
    };

    await expect(
      resolveCfMailMailbox({
        baseUrl: "https://api.cfm.example.test/",
        apiKey: "cfm-key",
        address: "proof@alpha.example.test",
        httpJson,
      }),
    ).resolves.toMatchObject({ id: "mbx-proof", address: "proof@alpha.example.test" });

    const notFoundHttpJson: CfMailHttpJson = async () => {
      throw new Error('http_failed:404:{"error":"not found","details":null}');
    };

    await expect(
      resolveCfMailMailbox({
        baseUrl: "https://api.cfm.example.test/",
        apiKey: "cfm-key",
        address: "missing@alpha.example.test",
        httpJson: notFoundHttpJson,
      }),
    ).resolves.toBeNull();
  });

  test("provisions and ensures mailboxes with direct mailbox responses", async () => {
    const calls: Array<{ method: string; url: string; body?: unknown }> = [];
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string, options?: CfMailHttpJsonOptions) => {
      calls.push({ method, url, body: options?.body });
      return {
        id: method === "POST" && url.endsWith("/ensure") ? "mbx-existing" : "mbx-new",
        address: "proof@alpha.example.test",
        localPart: "proof",
        subdomain: "alpha",
        rootDomain: "example.test",
      } as T;
    };

    await expect(
      provisionCfMailMailbox({
        baseUrl: "https://api.cfm.example.test/",
        apiKey: "cfm-key",
        httpJson,
        rootDomain: "example.test",
        expiresInMinutes: 90,
      }),
    ).resolves.toMatchObject({ id: "mbx-new" });

    await expect(
      ensureCfMailMailbox({
        baseUrl: "https://api.cfm.example.test/",
        apiKey: "cfm-key",
        address: "proof@alpha.example.test",
        httpJson,
        expiresInMinutes: 90,
      }),
    ).resolves.toMatchObject({ id: "mbx-existing" });

    expect(calls).toEqual([
      {
        method: "POST",
        url: "https://api.cfm.example.test/api/mailboxes",
        body: {
          localPart: undefined,
          subdomain: undefined,
          rootDomain: "example.test",
          expiresInMinutes: 90,
        },
      },
      {
        method: "POST",
        url: "https://api.cfm.example.test/api/mailboxes/ensure",
        body: {
          address: "proof@alpha.example.test",
          expiresInMinutes: 90,
        },
      },
    ]);
  });

  test("lists messages with incremental polling filters and unwraps details", async () => {
    const calls: Array<{ method: string; url: string }> = [];
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string) => {
      calls.push({ method, url });
      if (url.includes("/api/messages?")) {
        return {
          messages: [
            {
              id: "msg-alpha",
              mailboxId: "mbx-alpha",
              mailboxAddress: "proof@alpha.example.test",
              subject: "Microsoft account security code",
              previewText: "Your security code is 456123.",
              fromName: "Microsoft account team",
              fromAddress: "account-security-noreply@accountprotection.microsoft.com",
              receivedAt: "2026-04-04T01:02:03.000Z",
              sizeBytes: 1024,
              attachmentCount: 0,
              hasHtml: true,
            },
          ],
        } as T;
      }
      return {
        message: {
          id: "msg-alpha",
          text: "Use security code 456123 to verify your identity.",
          mailboxAddress: "proof@alpha.example.test",
        },
      } as T;
    };

    const messages = await listCfMailMessages({
      baseUrl: "https://api.cfm.example.test/",
      apiKey: "cfm-key",
      address: "proof@alpha.example.test",
      httpJson,
      after: "2026-04-04T00:00:00.000Z",
      since: "2026-04-03T00:00:00.000Z",
    });
    const detail = await getCfMailMessage({
      baseUrl: "https://api.cfm.example.test/",
      apiKey: "cfm-key",
      messageId: "msg-alpha",
      httpJson,
    });

    expect(messages).toHaveLength(1);
    expect(detail).toMatchObject({
      id: "msg-alpha",
      text: "Use security code 456123 to verify your identity.",
    });
    expect(extractMicrosoftProofCodeFromPayload(detail)).toBe("456123");
    expect(buildCfMailRawMessageUrl("https://api.cfm.example.test/", "msg-alpha")).toBe(
      "https://api.cfm.example.test/api/messages/msg-alpha/raw",
    );
    expect(calls).toEqual([
      {
        method: "GET",
        url: "https://api.cfm.example.test/api/messages?mailbox=proof%40alpha.example.test&after=2026-04-04T00%3A00%3A00.000Z&since=2026-04-03T00%3A00%3A00.000Z",
      },
      {
        method: "GET",
        url: "https://api.cfm.example.test/api/messages/msg-alpha",
      },
    ]);
  });

  test("lists messages by mailbox id when provided", async () => {
    const calls: Array<{ method: string; url: string }> = [];
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string) => {
      calls.push({ method, url });
      return { messages: [] } as T;
    };

    await listCfMailMessages({
      baseUrl: "https://api.cfm.example.test/",
      apiKey: "cfm-key",
      mailboxId: "mbx-proof",
      address: "proof@alpha.example.test",
      httpJson,
      since: "2026-04-03T00:00:00.000Z",
    });

    expect(calls).toEqual([
      {
        method: "GET",
        url: "https://api.cfm.example.test/api/messages?mailboxId=mbx-proof&since=2026-04-03T00%3A00%3A00.000Z",
      },
    ]);
  });

  test("fails fast when CF Mail API key is missing", async () => {
    const httpJson: CfMailHttpJson = async <T>() => ({ domains: [] } as T);
    await expect(
      fetchCfMailMeta({
        baseUrl: "https://api.cfm.example.test/",
        httpJson,
      }),
    ).resolves.toBeDefined();
    await expect(
      resolveCfMailMailbox({
        baseUrl: "https://api.cfm.example.test/",
        apiKey: "   ",
        address: "proof@alpha.example.test",
        httpJson,
      }),
    ).rejects.toThrow("cfmail_api_key_missing");
  });
});
