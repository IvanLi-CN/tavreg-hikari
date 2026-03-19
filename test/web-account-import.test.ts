import { describe, expect, test } from "bun:test";
import { buildImportCommitEntries, type ImportPreviewPayloadLike } from "../web/src/lib/account-import.ts";

function createPreview(): ImportPreviewPayloadLike {
  return {
    effectiveEntries: [
      { email: "new@outlook.com", password: "password321" },
      { email: "beta@outlook.com", password: "password789" },
    ],
    items: [
      {
        email: "new@outlook.com",
        normalizedEmail: "new@outlook.com",
        password: "password321",
        decision: "create",
      },
      {
        email: "beta@outlook.com",
        normalizedEmail: "beta@outlook.com",
        password: "password789",
        decision: "update_password",
      },
      {
        email: "gamma@outlook.com",
        normalizedEmail: "gamma@outlook.com",
        password: "pass-111",
        decision: "keep_existing",
      },
      {
        email: "gamma@outlook.com",
        normalizedEmail: "gamma@outlook.com",
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
      { email: "new@outlook.com", password: "password321" },
      { email: "beta@outlook.com", password: "password789" },
    ]);
  });

  test("includes keep_existing accounts when group assignment is requested", () => {
    expect(buildImportCommitEntries(createPreview(), "retry-pool")).toEqual([
      { email: "new@outlook.com", password: "password321" },
      { email: "beta@outlook.com", password: "password789" },
      { email: "gamma@outlook.com", password: "pass-111" },
    ]);
  });
});
