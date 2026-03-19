import { describe, expect, test } from "bun:test";
import {
  buildMoeMailAuthHeaders,
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
});
