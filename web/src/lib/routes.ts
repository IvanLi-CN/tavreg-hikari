import type { PageKey } from "@/lib/app-types";

export function normalizeAppPath(pathname: string): string {
  const value = String(pathname || "").trim() || "/";
  if (value === "/") return "/";
  return value.replace(/\/+$/, "") || "/";
}

function isSupportedKeysSite(value: string | null): value is "tavily" | "grok" | "chatgpt" {
  return value === "tavily" || value === "grok" || value === "chatgpt";
}

export function isKeysCompatPath(pathname: string): boolean {
  const normalized = normalizeAppPath(pathname);
  return normalized === "/keys" || normalized === "/api-keys";
}

export function getPageFromPathname(pathname: string, search = ""): PageKey {
  const normalized = normalizeAppPath(pathname);
  const params = new URLSearchParams(search);
  if (normalized === "/grok") return "grok";
  if (normalized === "/chatgpt") return "chatgpt";
  if (normalized === "/tavily" || normalized === "/dashboard") return "tavily";
  if (normalized === "/accounts" || normalized === "/mailboxes" || normalized.startsWith("/mailboxes/")) return "accounts";
  if (isKeysCompatPath(normalized)) {
    const site = params.get("site");
    return isSupportedKeysSite(site) ? site : "tavily";
  }
  if (normalized === "/proxies") return "proxies";
  return "tavily";
}

export function isMailboxSettingsPath(pathname: string, search = ""): boolean {
  return normalizeAppPath(pathname) === "/mailboxes/settings" || new URLSearchParams(search).get("view") === "graph-settings";
}

export function isAccountsMailboxSurfacePath(pathname: string, search = ""): boolean {
  return getPageFromPathname(pathname, search) === "accounts" && !isMailboxSettingsPath(pathname, search);
}

export function isSiteKeysViewPath(pathname: string, search = ""): boolean {
  return isKeysCompatPath(pathname) || new URLSearchParams(search).get("view") === "keys";
}

export function getMailboxAccountIdFromLocation(pathname: string, search = ""): number | null {
  const normalized = normalizeAppPath(pathname);
  const params = new URLSearchParams(search);
  const rawValue =
    normalized === "/mailboxes" || normalized === "/mailboxes/settings"
      ? params.get("accountId") || params.get("mailboxAccountId")
      : params.get("mailboxAccountId") || params.get("accountId");
  const accountId = Number(rawValue || 0);
  return Number.isInteger(accountId) && accountId > 0 ? accountId : null;
}

export function buildAccountsPath(mailboxAccountId?: number | null): string {
  if (mailboxAccountId != null && Number.isInteger(mailboxAccountId) && mailboxAccountId > 0) {
    return `/accounts?mailboxAccountId=${mailboxAccountId}`;
  }
  return "/accounts";
}

export function buildMailboxSettingsPath(mailboxAccountId?: number | null): string {
  const params = new URLSearchParams();
  params.set("view", "graph-settings");
  if (mailboxAccountId != null && Number.isInteger(mailboxAccountId) && mailboxAccountId > 0) {
    params.set("mailboxAccountId", String(mailboxAccountId));
  }
  return `/accounts?${params.toString()}`;
}
