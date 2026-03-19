import type { ProxyNode } from "@/lib/app-types";

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function formatLocation(node: Pick<ProxyNode, "lastCountry" | "lastCity" | "lastOrg">): string {
  return [node.lastCountry, node.lastCity, node.lastOrg].filter(Boolean).join(" / ") || "—";
}
