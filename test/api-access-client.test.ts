import { describe, expect, test } from "bun:test";
import { executeIntegrationApiKeyMutation, finalizeIntegrationApiKeyMutation } from "../web/src/lib/api-access.ts";
import type { IntegrationApiKeyMutationPayload } from "../web/src/lib/app-types.ts";

const payload: IntegrationApiKeyMutationPayload = {
  ok: true,
  record: {
    id: 7,
    label: "relay-east",
    notes: "primary",
    keyPrefix: "thki_demo_secret",
    status: "active",
    createdAt: "2026-04-24T10:00:00.000Z",
    updatedAt: "2026-04-24T10:00:00.000Z",
    rotatedAt: null,
    revokedAt: null,
    lastUsedAt: null,
    lastUsedIp: null,
  },
  plainTextKey: "thki_demo_secret_123",
};

describe("api access mutation finalize helper", () => {
  test("preserves the revealed secret when the refresh step fails", async () => {
    const result = await finalizeIntegrationApiKeyMutation({
      mode: "create",
      payload,
      refresh: async () => {
        throw new Error("refresh failed");
      },
    });

    expect(result.revealedSecret).toMatchObject({
      mode: "create",
      plainTextKey: "thki_demo_secret_123",
    });
    expect(result.refreshError?.message).toBe("refresh failed");
  });

  test("keeps the refresh error clear when the follow-up refresh succeeds", async () => {
    const result = await finalizeIntegrationApiKeyMutation({
      mode: "rotate",
      payload,
      refresh: async () => {},
    });

    expect(result.revealedSecret).toMatchObject({
      mode: "rotate",
      plainTextKey: "thki_demo_secret_123",
    });
    expect(result.refreshError).toBeNull();
  });

  test("keeps the editor open when the mutation itself fails", async () => {
    const result = await executeIntegrationApiKeyMutation({
      mode: "create",
      mutate: async () => {
        throw new Error("create failed");
      },
      refresh: async () => {},
    });

    expect(result.shouldCloseEditor).toBe(false);
    expect(result.mutationError?.message).toBe("create failed");
    expect(result.revealedSecret).toBeNull();
    expect(result.refreshError).toBeNull();
  });

  test("still closes the editor when the mutation succeeds but refresh fails", async () => {
    const result = await executeIntegrationApiKeyMutation({
      mode: "rotate",
      mutate: async () => payload,
      refresh: async () => {
        throw new Error("refresh failed");
      },
    });

    expect(result.shouldCloseEditor).toBe(true);
    expect(result.mutationError).toBeNull();
    expect(result.revealedSecret).toMatchObject({
      mode: "rotate",
      plainTextKey: "thki_demo_secret_123",
    });
    expect(result.refreshError?.message).toBe("refresh failed");
  });
});
