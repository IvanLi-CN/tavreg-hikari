import { describe, expect, test } from "bun:test";
import {
  buildMoeMailAuthHeaders,
  extractFreshMicrosoftProofCodeFromMoeMailResponse,
  extractMicrosoftProofCodeFromPayload,
  normalizeMoeMailBaseUrl,
  resolveMoeMailMailboxId,
  type MoeMailHttpJson,
  type MoeMailHttpJsonOptions,
} from "../src/moemail-openapi.ts";

describe("MoeMail OpenAPI", () => {
  test("normalizes base url and auth headers", () => {
    expect(normalizeMoeMailBaseUrl("https://moemail.707079.xyz///")).toBe("https://moemail.707079.xyz");
    expect(normalizeMoeMailBaseUrl("")).toBe("https://moemail.707079.xyz");
    expect(buildMoeMailAuthHeaders(" secret-key ")).toEqual({
      Accept: "application/json",
      "X-API-Key": "secret-key",
    });
  });

  test("resolves mailbox id by address across paginated email lists", async () => {
    const calls: Array<{ method: string; url: string; headers?: Record<string, string>; proxyUrl?: string }> = [];
    const httpJson: MoeMailHttpJson = async <T>(method: string, url: string, options?: MoeMailHttpJsonOptions) => {
      calls.push({ method, url, headers: options?.headers, proxyUrl: options?.proxyUrl });
      if (calls.length === 1) {
        return {
          emails: [{ id: "mailbox-other", address: "other@mail-us.707079.xyz" }],
          nextCursor: "cursor:page-2",
        } as T;
      }
      return {
        emails: [{ id: "mailbox-proof", address: "proof@mail-us.707079.xyz" }],
        nextCursor: null,
      } as T;
    };

    const mailboxId = await resolveMoeMailMailboxId({
      baseUrl: "https://moemail.707079.xyz/",
      apiKey: " api-key-1 ",
      address: "Proof@mail-us.707079.xyz",
      httpJson,
      proxyUrl: "http://127.0.0.1:8899",
    });

    expect(mailboxId).toBe("mailbox-proof");
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      method: "GET",
      url: "https://moemail.707079.xyz/api/emails",
      proxyUrl: "http://127.0.0.1:8899",
      headers: {
        Accept: "application/json",
        "X-API-Key": "api-key-1",
      },
    });
    expect(calls[1]?.url).toBe("https://moemail.707079.xyz/api/emails?cursor=cursor%3Apage-2");
  });

  test("fails fast when MoeMail API key is missing", async () => {
    const httpJson: MoeMailHttpJson = async <T>() => ({ emails: [], nextCursor: null } as T);
    await expect(
      resolveMoeMailMailboxId({
        baseUrl: "https://moemail.707079.xyz",
        apiKey: "   ",
        address: "proof@mail-us.707079.xyz",
        httpJson,
      }),
    ).rejects.toThrow("moemail_api_key_missing");
  });
});

describe("Microsoft proof code extraction", () => {
  test("extracts the Microsoft six-digit code from MoeMail message payloads", () => {
    const payload = {
      messages: [
        {
          id: "msg-1",
          subject: "Microsoft account security code",
          content: "Use security code 252757 to verify your identity.",
          html: "<p>Use security code <strong>252757</strong> to verify your identity.</p>",
        },
      ],
    };

    expect(extractMicrosoftProofCodeFromPayload(payload)).toBe("252757");
  });

  test("supports localized Microsoft messages and ignores unrelated six-digit numbers", () => {
    const localizedPayload = {
      messages: [
        {
          subject: "Microsoft 帐户",
          content: "你的安全代码是 481903。请输入该验证码以继续。",
        },
      ],
    };
    const unrelatedPayload = {
      messages: [
        {
          subject: "Shipping update",
          content: "Order 123456 has been packed and will arrive tomorrow.",
        },
      ],
    };

    expect(extractMicrosoftProofCodeFromPayload(localizedPayload)).toBe("481903");
    expect(extractMicrosoftProofCodeFromPayload(unrelatedPayload)).toBeNull();
  });

  test("ignores stale Microsoft proof codes when MoeMail returns old persistent messages", () => {
    const now = Date.now();
    const payload = {
      messages: [
        {
          id: "msg-old",
          subject: "Microsoft account security code",
          content: "Use security code 111111 to verify your identity.",
          received_at: now - 120_000,
        },
        {
          id: "msg-new",
          subject: "Microsoft account security code",
          content: "Use security code 222222 to verify your identity.",
          received_at: now - 2_000,
        },
      ],
    };
    const repeatedFreshPayload = {
      messages: [
        {
          id: "msg-fresh-older",
          subject: "Microsoft account security code",
          content: "Use security code 333333 to verify your identity.",
          received_at: now - 8_000,
        },
        {
          id: "msg-fresh-newer",
          subject: "Microsoft account security code",
          content: "Use security code 444444 to verify your identity.",
          received_at: now - 1_000,
        },
      ],
    };

    expect(extractFreshMicrosoftProofCodeFromMoeMailResponse(payload, now - 15_000)).toBe("222222");
    expect(extractFreshMicrosoftProofCodeFromMoeMailResponse(repeatedFreshPayload, now - 15_000)).toBe("444444");
    expect(
      extractFreshMicrosoftProofCodeFromMoeMailResponse(
        {
          messages: [payload.messages[0]],
        },
        now - 15_000,
      ),
    ).toBeNull();
  });
});
