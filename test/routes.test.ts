import { expect, test } from "bun:test";
import { getPageFromPathname, normalizeAppPath } from "../web/src/lib/routes.ts";

test("normalizeAppPath trims trailing slashes for SPA routes", () => {
  expect(normalizeAppPath("/accounts/")).toBe("/accounts");
  expect(normalizeAppPath("/keys///")).toBe("/keys");
  expect(normalizeAppPath("/api-keys///")).toBe("/api-keys");
  expect(normalizeAppPath("/")).toBe("/");
});

test("getPageFromPathname maps trailing-slash routes to the intended page", () => {
  expect(getPageFromPathname("/accounts/")).toBe("accounts");
  expect(getPageFromPathname("/grok/")).toBe("grok");
  expect(getPageFromPathname("/chatgpt/")).toBe("chatgpt");
  expect(getPageFromPathname("/keys/")).toBe("keys");
  expect(getPageFromPathname("/api-keys/")).toBe("keys");
  expect(getPageFromPathname("/proxies/")).toBe("proxies");
  expect(getPageFromPathname("/unknown/")).toBe("tavily");
});
