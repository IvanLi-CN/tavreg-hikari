import type { PageKey } from "@/lib/app-types";

export function normalizeAppPath(pathname: string): string {
  const value = String(pathname || "").trim() || "/";
  if (value === "/") return "/";
  return value.replace(/\/+$/, "") || "/";
}

export function getPageFromPathname(pathname: string): PageKey {
  const normalized = normalizeAppPath(pathname);
  if (normalized === "/accounts") return "accounts";
  if (normalized === "/api-keys") return "apiKeys";
  if (normalized === "/proxies") return "proxies";
  return "dashboard";
}
