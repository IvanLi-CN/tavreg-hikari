import { afterEach, describe, expect, test } from "bun:test";

import {
  normalizeMailboxProviderError,
  resetMailboxProviderGuardStateForTests,
  resolveMailboxProviderIdentity,
  setMailboxProviderCooldownForTests,
  withMailboxProviderProvisioningGuard,
} from "../src/server/mailbox-provider-guard";

afterEach(() => {
  resetMailboxProviderGuardStateForTests();
});

describe("mailbox provider guard", () => {
  test("normalizes 429 mailbox provisioning failures", () => {
    const normalized = normalizeMailboxProviderError(new Error('http_failed:429:{"error":"Limit Exceeded","details":null}'));
    expect(normalized.message).toBe("mailbox_rate_limited");
  });

  test("normalizes 503 mailbox provisioning failures", () => {
    const normalized = normalizeMailboxProviderError(new Error('http_failed:503:{"error":"Service unavailable","details":null}'));
    expect(normalized.message).toBe("mailbox_provider_unavailable");
  });

  test("serializes provisioning calls for the same provider identity", async () => {
    const identity = resolveMailboxProviderIdentity({
      provider: "cfmail",
      baseUrl: "https://api.cfm.example.test",
      credential: "cf_key_test",
    });
    expect(identity).not.toBeNull();

    const timeline: string[] = [];
    const first = withMailboxProviderProvisioningGuard(identity, async () => {
      timeline.push("first:start");
      await Bun.sleep(30);
      timeline.push("first:end");
      return "first";
    });
    const second = withMailboxProviderProvisioningGuard(identity, async () => {
      timeline.push("second:start");
      timeline.push("second:end");
      return "second";
    });

    await expect(Promise.all([first, second])).resolves.toEqual(["first", "second"]);
    expect(timeline).toEqual(["first:start", "first:end", "second:start", "second:end"]);
  });

  test("shared cooldown state is visible across all users of the same provider identity", async () => {
    const identity = resolveMailboxProviderIdentity({
      provider: "cfmail",
      baseUrl: "https://api.cfm.example.test",
      credential: "cf_key_test",
    });
    expect(identity).not.toBeNull();
    setMailboxProviderCooldownForTests(identity!, "mailbox_rate_limited", new Date(Date.now() + 60_000).toISOString());

    await expect(
      withMailboxProviderProvisioningGuard(identity, async () => "never-runs"),
    ).rejects.toThrow("mailbox_rate_limited");
  });
});
