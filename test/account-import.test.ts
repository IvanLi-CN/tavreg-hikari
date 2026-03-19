import { describe, expect, test } from "bun:test";
import { buildImportPreview, parseImportContent, parseImportLine } from "../src/server/account-import.js";

describe("parseImportLine", () => {
  test("supports common separators and format correction", () => {
    expect(parseImportLine("alpha@outlook.com,password123", 1)).toMatchObject({
      email: "alpha@outlook.com",
      password: "password123",
    });
    expect(parseImportLine("beta@outlook.com:password456", 1)).toMatchObject({
      email: "beta@outlook.com",
      password: "password456",
    });
    expect(parseImportLine("gamma@outlook.com | password789", 1)).toMatchObject({
      email: "gamma@outlook.com",
      password: "password789",
    });
    expect(parseImportLine("delta@outlook.com password999", 1)).toMatchObject({
      email: "delta@outlook.com",
      password: "password999",
    });
    expect(parseImportLine("omega@outlook.com----password777", 1)).toMatchObject({
      email: "omega@outlook.com",
      password: "password777",
    });
    expect(parseImportLine("password888 ---- sigma@outlook.com", 1)).toMatchObject({
      email: "sigma@outlook.com",
      password: "password888",
    });
  });

  test("preserves separator characters when they belong to passwords", () => {
    expect(parseImportLine("user@example.com,-Secret123", 1)).toMatchObject({
      email: "user@example.com",
      password: "-Secret123",
    });
    expect(parseImportLine("user@example.com,_Secret123", 2)).toMatchObject({
      email: "user@example.com",
      password: "_Secret123",
    });
    expect(parseImportLine("user@example.com,Secret123-", 3)).toMatchObject({
      email: "user@example.com",
      password: "Secret123-",
    });
    expect(parseImportLine("Secret123- user@example.com", 4)).toMatchObject({
      email: "user@example.com",
      password: "Secret123-",
    });
  });

  test("reports invalid rows with reason codes", () => {
    expect(parseImportLine("just-text", 2)).toEqual({
      lineNumber: 2,
      rawLine: "just-text",
      reason: "email_not_found",
    });
    expect(parseImportLine("alpha@outlook.com", 3)).toEqual({
      lineNumber: 3,
      rawLine: "alpha@outlook.com",
      reason: "password_not_found",
    });
  });
});

describe("parseImportContent", () => {
  test("keeps valid entries and collects invalid rows", () => {
    const parsed = parseImportContent(`
alpha@outlook.com,password123
beta@outlook.com----password456
invalid-line
password789 gamma@outlook.com
    `);

    expect(parsed.entries).toHaveLength(3);
    expect(parsed.entries.map((entry) => entry.email)).toEqual([
      "alpha@outlook.com",
      "beta@outlook.com",
      "gamma@outlook.com",
    ]);
    expect(parsed.invalidRows).toEqual([
      {
        lineNumber: 4,
        rawLine: "invalid-line",
        reason: "email_not_found",
      },
    ]);
  });
});

describe("buildImportPreview", () => {
  test("marks input duplicates and existing-account actions", () => {
    const parsed = parseImportContent(`
alpha@outlook.com,password123
alpha@outlook.com,password456
beta@outlook.com,password789
gamma@outlook.com,password789
bad-line
    `);

    const preview = buildImportPreview(parsed.entries, parsed.invalidRows, [
      {
        id: 7,
        microsoftEmail: "beta@outlook.com",
        passwordPlaintext: "old-pass",
        hasApiKey: true,
        groupName: "linked",
      },
      {
        id: 8,
        microsoftEmail: "gamma@outlook.com",
        passwordPlaintext: "password789",
        hasApiKey: false,
        groupName: null,
      },
    ]);

    expect(preview.summary).toMatchObject({
      parsed: 4,
      invalid: 1,
      create: 1,
      updatePassword: 1,
      keepExisting: 1,
      inputDuplicate: 1,
    });

    expect(preview.items.find((item) => item.email === "alpha@outlook.com" && item.decision === "input_duplicate")).toMatchObject({
      duplicateOfLine: 3,
    });
    expect(preview.items.find((item) => item.email === "beta@outlook.com")).toMatchObject({
      decision: "update_password",
      existingHasApiKey: true,
      groupName: "linked",
    });
    expect(preview.items.find((item) => item.email === "beta@outlook.com")).not.toHaveProperty("existingPassword");
    expect(preview.items.find((item) => item.email === "gamma@outlook.com")).toMatchObject({
      decision: "keep_existing",
    });
    expect(preview.effectiveEntries).toEqual([
      { email: "alpha@outlook.com", password: "password456" },
      { email: "beta@outlook.com", password: "password789" },
    ]);
  });
});
