import { expect, test } from "bun:test";
import {
  getMailboxAccountIdFromLocation,
  getPageFromPathname,
  isMailboxSettingsPath,
  isSiteKeysViewPath,
  normalizeAppPath,
} from "../web/src/lib/routes.ts";

test("normalizeAppPath trims trailing slashes for SPA routes", () => {
  expect(normalizeAppPath("/accounts/")).toBe("/accounts");
  expect(normalizeAppPath("/keys///")).toBe("/keys");
  expect(normalizeAppPath("/api-keys///")).toBe("/api-keys");
  expect(normalizeAppPath("/")).toBe("/");
});

test("getPageFromPathname maps trailing-slash routes to the intended page", () => {
  expect(getPageFromPathname("/accounts/")).toBe("accounts");
  expect(getPageFromPathname("/mailboxes/")).toBe("accounts");
  expect(getPageFromPathname("/grok/")).toBe("grok");
  expect(getPageFromPathname("/chatgpt/")).toBe("chatgpt");
  expect(getPageFromPathname("/keys/")).toBe("tavily");
  expect(getPageFromPathname("/keys/", "?site=grok")).toBe("grok");
  expect(getPageFromPathname("/api-keys/", "?site=chatgpt")).toBe("chatgpt");
  expect(getPageFromPathname("/proxies/")).toBe("proxies");
  expect(getPageFromPathname("/unknown/")).toBe("tavily");
});

test("mailbox/settings and site keys helpers resolve compatibility routes", () => {
  expect(isMailboxSettingsPath("/mailboxes/settings")).toBe(true);
  expect(isMailboxSettingsPath("/accounts", "?view=graph-settings")).toBe(true);
  expect(isSiteKeysViewPath("/keys")).toBe(true);
  expect(isSiteKeysViewPath("/chatgpt", "?view=keys")).toBe(true);
  expect(getMailboxAccountIdFromLocation("/mailboxes", "?accountId=12")).toBe(12);
  expect(getMailboxAccountIdFromLocation("/accounts", "?mailboxAccountId=34")).toBe(34);
  expect(getMailboxAccountIdFromLocation("/accounts")).toBeNull();
});
