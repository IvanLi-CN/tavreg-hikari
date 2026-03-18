import { describe, expect, test } from "bun:test";
import { parseAccountImportContent, parseAccountImportLine } from "../src/server/account-import.js";

describe("parseAccountImportLine", () => {
  test("supports comma, colon, pipe, and whitespace separators", () => {
    expect(parseAccountImportLine("alpha@outlook.com,password123")).toEqual({
      email: "alpha@outlook.com",
      password: "password123",
    });
    expect(parseAccountImportLine("beta@outlook.com:password456")).toEqual({
      email: "beta@outlook.com",
      password: "password456",
    });
    expect(parseAccountImportLine("gamma@outlook.com | password789")).toEqual({
      email: "gamma@outlook.com",
      password: "password789",
    });
    expect(parseAccountImportLine("delta@outlook.com password999")).toEqual({
      email: "delta@outlook.com",
      password: "password999",
    });
  });

  test("ignores invalid or incomplete lines", () => {
    expect(parseAccountImportLine("")).toBeNull();
    expect(parseAccountImportLine("just-text")).toBeNull();
    expect(parseAccountImportLine("alpha@outlook.com,")).toBeNull();
    expect(parseAccountImportLine("alpha@outlook.com")).toBeNull();
  });
});

describe("parseAccountImportContent", () => {
  test("keeps valid lines and skips invalid rows", () => {
    expect(
      parseAccountImportContent(`
alpha@outlook.com,password123
beta@outlook.com:password456
invalid-line
gamma@outlook.com password789
      `),
    ).toEqual([
      { email: "alpha@outlook.com", password: "password123" },
      { email: "beta@outlook.com", password: "password456" },
      { email: "gamma@outlook.com", password: "password789" },
    ]);
  });
});
