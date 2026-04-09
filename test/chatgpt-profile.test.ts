import { describe, expect, test } from "bun:test";
import { isBirthDateReadyFromVisibleValues, profileFullName } from "../src/server/chatgpt-profile.js";

describe("chatgpt profile helpers", () => {
  test("accepts abbreviated visible birth tokens", () => {
    expect(isBirthDateReadyFromVisibleValues(["4", "30", "1991", "Apr", "30", "1991"], "1991-04-30")).toBe(true);
  });

  test("rejects incomplete visible birth tokens", () => {
    expect(isBirthDateReadyFromVisibleValues(["30", "1991"], "1991-04-30")).toBe(false);
  });

  test("normalizes profile full name into two words", () => {
    expect(profileFullName("Hana Kobayashi 2026")).toBe("Hana Kobayashi");
    expect(profileFullName("Hana")).toBe("Hana Hoshino");
  });
});
