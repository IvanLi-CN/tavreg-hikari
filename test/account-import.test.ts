import { describe, expect, test } from "bun:test";
import { buildImportPreview, parseImportContent, parseImportLine } from "../src/server/account-import.js";
import { parseImportLine as parseWebImportLine } from "../web/src/lib/account-import";

describe("parseImportLine", () => {
  test("supports common separators and format correction", () => {
    expect(parseImportLine("alpha@example.test,password123", 1)).toMatchObject({
      email: "alpha@example.test",
      password: "password123",
    });
    expect(parseImportLine("beta@example.test:password456", 1)).toMatchObject({
      email: "beta@example.test",
      password: "password456",
    });
    expect(parseImportLine("gamma@example.test | password789", 1)).toMatchObject({
      email: "gamma@example.test",
      password: "password789",
    });
    expect(parseImportLine("delta@example.test password999", 1)).toMatchObject({
      email: "delta@example.test",
      password: "password999",
    });
    expect(parseImportLine("omega@example.test----password777", 1)).toMatchObject({
      email: "omega@example.test",
      password: "password777",
    });
    expect(parseImportLine("password888 ---- sigma@example.test", 1)).toMatchObject({
      email: "sigma@example.test",
      password: "password888",
    });
  });

  test("keeps only the first password segment for microsoft dashed payloads", () => {
    const rawLine =
      "SusanHoward8543@outlook.com----mqyv3929----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C531_BL2.0.U.-abcdefghijklmnopqrstuvwxyz1234567890token$$";

    expect(parseImportLine(rawLine, 1)).toMatchObject({
      email: "SusanHoward8543@outlook.com",
      password: "mqyv3929",
    });
    expect(parseWebImportLine(rawLine, 1)).toMatchObject({
      email: "SusanHoward8543@outlook.com",
      password: "mqyv3929",
    });
  });

  test("supports microsoft consumer mailboxes with multi-level domains", () => {
    const rawLine =
      "user@outlook.co.uk----secret123----123e4567-e89b-12d3-a456-426614174000----M.C531_BL2.0.U.-abcdefghijklmnopqrstuvwxyz1234567890token$$";

    expect(parseImportLine(rawLine, 1)).toMatchObject({
      email: "user@outlook.co.uk",
      password: "secret123",
    });
    expect(parseWebImportLine(rawLine, 1)).toMatchObject({
      email: "user@outlook.co.uk",
      password: "secret123",
    });
  });

  test("keeps dashed passwords intact when trailing fields do not look like microsoft metadata", () => {
    const rawLine = "user@example.com----abc----def";

    expect(parseImportLine(rawLine, 1)).toMatchObject({
      email: "user@example.com",
      password: "abc----def",
    });
    expect(parseWebImportLine(rawLine, 1)).toMatchObject({
      email: "user@example.com",
      password: "abc----def",
    });
  });

  test("keeps dashed passwords intact when the suffix is only uuid-like", () => {
    const rawLine = "user@example.com----secret----123e4567-e89b-12d3-a456-426614174000";

    expect(parseImportLine(rawLine, 1)).toMatchObject({
      email: "user@example.com",
      password: "secret----123e4567-e89b-12d3-a456-426614174000",
    });
    expect(parseWebImportLine(rawLine, 1)).toMatchObject({
      email: "user@example.com",
      password: "secret----123e4567-e89b-12d3-a456-426614174000",
    });
  });

  test("keeps dashed passwords intact when the token-like suffix does not match the microsoft sample shape", () => {
    const rawLine = "user@example.com----secret----123e4567-e89b-12d3-a456-426614174000----M.C531_BL2.0.U.-token-part-more-token$$";

    expect(parseImportLine(rawLine, 1)).toMatchObject({
      email: "user@example.com",
      password: "secret----123e4567-e89b-12d3-a456-426614174000----M.C531_BL2.0.U.-token-part-more-token$$",
    });
    expect(parseWebImportLine(rawLine, 1)).toMatchObject({
      email: "user@example.com",
      password: "secret----123e4567-e89b-12d3-a456-426614174000----M.C531_BL2.0.U.-token-part-more-token$$",
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
    expect(parseImportLine("alpha@example.test", 3)).toEqual({
      lineNumber: 3,
      rawLine: "alpha@example.test",
      reason: "password_not_found",
    });
    expect(parseImportLine("alpha@example.test----", 4)).toEqual({
      lineNumber: 4,
      rawLine: "alpha@example.test----",
      reason: "password_not_found",
    });
  });
});

describe("parseImportContent", () => {
  test("keeps valid entries and collects invalid rows", () => {
    const parsed = parseImportContent(`
alpha@example.test,password123
beta@example.test----password456
SusanHoward8543@outlook.com----mqyv3929----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C531_BL2.0.U.-abcdefghijklmnopqrstuvwxyz1234567890token$$
invalid-line
password789 gamma@example.test
    `);

    expect(parsed.entries).toHaveLength(4);
    expect(parsed.entries.map((entry) => entry.email)).toEqual([
      "alpha@example.test",
      "beta@example.test",
      "SusanHoward8543@outlook.com",
      "gamma@example.test",
    ]);
    expect(parsed.entries.find((entry) => entry.email === "SusanHoward8543@outlook.com")).toMatchObject({
      password: "mqyv3929",
    });
    expect(parsed.invalidRows).toEqual([
      {
        lineNumber: 5,
        rawLine: "invalid-line",
        reason: "email_not_found",
      },
    ]);
  });
});

describe("buildImportPreview", () => {
  test("marks input duplicates and existing-account actions", () => {
    const parsed = parseImportContent(`
alpha@example.test,password123
alpha@example.test,password456
beta@example.test,password789
gamma@example.test,password789
bad-line
    `);

    const preview = buildImportPreview(parsed.entries, parsed.invalidRows, [
      {
        id: 7,
        microsoftEmail: "beta@example.test",
        passwordPlaintext: "old-pass",
        hasApiKey: true,
        groupName: "linked",
      },
      {
        id: 8,
        microsoftEmail: "gamma@example.test",
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

    expect(preview.items.find((item) => item.email === "alpha@example.test" && item.decision === "input_duplicate")).toMatchObject({
      duplicateOfLine: 3,
    });
    expect(preview.items.find((item) => item.email === "beta@example.test")).toMatchObject({
      decision: "update_password",
      existingHasApiKey: true,
      groupName: "linked",
    });
    expect(preview.items.find((item) => item.email === "beta@example.test")).not.toHaveProperty("existingPassword");
    expect(preview.items.find((item) => item.email === "gamma@example.test")).toMatchObject({
      decision: "keep_existing",
    });
    expect(preview.effectiveEntries).toEqual([
      { email: "alpha@example.test", password: "password456" },
      { email: "beta@example.test", password: "password789" },
    ]);
  });
});
