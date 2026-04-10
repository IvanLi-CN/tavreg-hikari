import type { PageKey } from "@/lib/app-types";

export function normalizeAppPath(pathname: string): string {
  const value = String(pathname || "").trim() || "/";
  if (value === "/") return "/";
  return value.replace(/\/+$/, "") || "/";
}

export function getPageFromPathname(pathname: string): PageKey {
  const normalized = normalizeAppPath(pathname);
  if (normalized === "/chatgpt") return "chatgpt";
  if (normalized === "/tavily" || normalized === "/dashboard") return "tavily";
  if (normalized === "/accounts") return "accounts";
  if (normalized === "/mailboxes" || normalized.startsWith("/mailboxes/")) return "mailboxes";
  if (normalized === "/keys" || normalized === "/api-keys") return "keys";
  if (normalized === "/proxies") return "proxies";
  return "tavily";
}

export function isMailboxSettingsPath(pathname: string): boolean {
  return normalizeAppPath(pathname) === "/mailboxes/settings";
}
