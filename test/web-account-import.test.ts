import { describe, expect, test } from "bun:test";
import { buildImportCommitEntries, type ImportPreviewPayloadLike } from "../web/src/lib/account-import.ts";

function createPreview(): ImportPreviewPayloadLike {
  return {
    effectiveEntries: [
      { email: "new@example.test", password: "password321" },
      { email: "beta@example.test", password: "password789" },
    ],
    items: [
      {
        email: "new@example.test",
        normalizedEmail: "new@example.test",
        password: "password321",
        decision: "create",
      },
      {
        email: "beta@example.test",
        normalizedEmail: "beta@example.test",
        password: "password789",
        decision: "update_password",
      },
      {
        email: "gamma@example.test",
        normalizedEmail: "gamma@example.test",
        password: "pass-111",
        decision: "keep_existing",
      },
      {
        email: "gamma@example.test",
        normalizedEmail: "gamma@example.test",
        password: "pass-000",
        decision: "input_duplicate",
      },
      {
        email: "",
        normalizedEmail: "",
        password: "",
        decision: "invalid",
      },
    ],
  };
}

describe("buildImportCommitEntries", () => {
  test("keeps existing accounts out of commit payload when no group is requested", () => {
    expect(buildImportCommitEntries(createPreview(), "")).toEqual([
      { email: "new@example.test", password: "password321" },
      { email: "beta@example.test", password: "password789" },
    ]);
  });

  test("includes keep_existing accounts when group assignment is requested", () => {
    expect(buildImportCommitEntries(createPreview(), "retry-pool")).toEqual([
      { email: "new@example.test", password: "password321" },
      { email: "beta@example.test", password: "password789" },
      { email: "gamma@example.test", password: "pass-111" },
    ]);
  });
});
