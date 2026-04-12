import { describe, expect, test } from "bun:test";

import { buildChatGptDraft } from "../src/server/chatgpt-draft.ts";
import { isRealisticMailboxLocalPart } from "../src/mailbox-address.ts";
import type { CfMailHttpJson, CfMailHttpJsonOptions } from "../src/cfmail-api.ts";

describe("buildChatGptDraft", () => {
  test("uses provider-managed cfmail mailbox generation first", async () => {
    const calls: Array<{ method: string; url: string; body?: unknown }> = [];
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string, options?: CfMailHttpJsonOptions) => {
      calls.push({ method, url, body: options?.body });
      return {
        id: "mbx-provider",
        address: "mika.hayashi318@alpha.example.test",
        localPart: "mika.hayashi318",
        subdomain: "alpha",
        rootDomain: "example.test",
      } as T;
    };

    const draft = await buildChatGptDraft({
      apiKey: "cfm-key",
      baseUrl: "https://api.cfm.example.test/",
      httpJson,
      createPassword: () => "Password123!",
      createNickname: () => "Mika Hayashi",
      createBirthDate: () => "1998-07-14",
      nowIso: () => "2026-04-12T08:00:00.000Z",
    });

    expect(draft).toMatchObject({
      email: "mika.hayashi318@alpha.example.test",
      mailboxId: "mbx-provider",
      password: "Password123!",
      nickname: "Mika Hayashi",
      birthDate: "1998-07-14",
      generatedAt: "2026-04-12T08:00:00.000Z",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      method: "POST",
      url: "https://api.cfm.example.test/api/mailboxes",
      body: {
        localPart: undefined,
        subdomain: undefined,
        rootDomain: undefined,
        expiresInMinutes: undefined,
      },
    });
  });

  test("falls back to realistic local part generation when provider-managed provisioning is unsupported", async () => {
    const calls: Array<{ method: string; url: string; body?: unknown }> = [];
    const httpJson: CfMailHttpJson = async <T>(method: string, url: string, options?: CfMailHttpJsonOptions) => {
      calls.push({ method, url, body: options?.body });
      if (calls.length === 1) {
        throw new Error('http_failed:422:{"error":"provider-managed mailbox requires localPart"}');
      }
      const localPart = String((options?.body as Record<string, unknown>)?.localPart || "");
      return {
        id: "mbx-fallback",
        address: `${localPart}@alpha.example.test`,
        localPart,
        subdomain: "alpha",
        rootDomain: "example.test",
      } as T;
    };

    const draft = await buildChatGptDraft({
      apiKey: "cfm-key",
      baseUrl: "https://api.cfm.example.test/",
      httpJson,
      createPassword: () => "Password123!",
      createNickname: () => "Mika Hayashi",
      createBirthDate: () => "1998-07-14",
      nowIso: () => "2026-04-12T08:00:00.000Z",
    });

    expect(draft.mailboxId).toBe("mbx-fallback");
    expect(calls).toHaveLength(2);
    const providerBody = calls[0]?.body as Record<string, unknown>;
    const fallbackBody = calls[1]?.body as Record<string, unknown>;
    expect(providerBody.rootDomain).toBeUndefined();
    expect(isRealisticMailboxLocalPart(String(fallbackBody.localPart || ""))).toBe(true);
    expect(String(fallbackBody.localPart || "")).toMatch(/^[a-z0-9]+(?:-?[a-z0-9]+)*$/);
    expect(String(fallbackBody.localPart || "")).not.toMatch(/[._]/);
    expect(fallbackBody.subdomain).toBeUndefined();
    expect(fallbackBody.rootDomain).toBeUndefined();
  });

  test("retries fallback mailbox provisioning when the generated address conflicts", async () => {
    const localParts: string[] = [];
    const httpJson: CfMailHttpJson = async <T>(_method: string, _url: string, options?: CfMailHttpJsonOptions) => {
      const localPart = String((options?.body as Record<string, unknown>)?.localPart || "");
      if (!localPart) {
        throw new Error('http_failed:422:{"error":"localPart required"}');
      }
      localParts.push(localPart);
      if (localParts.length === 1) {
        throw new Error('http_failed:409:{"error":"already exists"}');
      }
      return {
        id: "mbx-conflict-retry",
        address: `${localPart}@alpha.example.test`,
        localPart,
        subdomain: "alpha",
        rootDomain: "example.test",
      } as T;
    };

    const draft = await buildChatGptDraft({
      apiKey: "cfm-key",
      baseUrl: "https://api.cfm.example.test/",
      httpJson,
      createPassword: () => "Password123!",
      createNickname: () => "Mika Hayashi",
      createBirthDate: () => "1998-07-14",
      nowIso: () => "2026-04-12T08:00:00.000Z",
    });

    expect(draft.mailboxId).toBe("mbx-conflict-retry");
    expect(localParts.length).toBe(2);
    expect(isRealisticMailboxLocalPart(localParts[0] || "")).toBe(true);
    expect(isRealisticMailboxLocalPart(localParts[1] || "")).toBe(true);
  });

  test("adds a human-friendly subdomain when cfmail fallback requires it", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const httpJson: CfMailHttpJson = async <T>(_method: string, _url: string, options?: CfMailHttpJsonOptions) => {
      const body = (options?.body as Record<string, unknown>) || {};
      calls.push(body);
      if (calls.length === 1) {
        throw new Error('http_failed:422:{"error":"provider-managed mailbox requires localPart"}');
      }
      if (!body.subdomain) {
        throw new Error('http_failed:422:{"error":"subdomain required"}');
      }
      return {
        id: "mbx-subdomain-fallback",
        address: `${body.localPart}@${body.subdomain}.example.test`,
        localPart: String(body.localPart || ""),
        subdomain: String(body.subdomain || ""),
        rootDomain: "example.test",
      } as T;
    };

    const draft = await buildChatGptDraft({
      apiKey: "cfm-key",
      baseUrl: "https://api.cfm.example.test/",
      httpJson,
      createPassword: () => "Password123!",
      createNickname: () => "Mika Hayashi",
      createBirthDate: () => "1998-07-14",
      nowIso: () => "2026-04-12T08:00:00.000Z",
    });

    expect(draft.mailboxId).toBe("mbx-subdomain-fallback");
    expect(calls).toHaveLength(3);
    expect(calls[1]?.rootDomain).toBeUndefined();
    expect(calls[1]?.subdomain).toBeUndefined();
    expect(calls[2]?.rootDomain).toBeUndefined();
    expect(calls[2]?.subdomain).toMatch(/^[a-z]+$/);
  });
});
