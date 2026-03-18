import { Badge } from "@/components/ui/badge";

function normalizeVariant(status: string | null | undefined): "neutral" | "success" | "warning" | "danger" | "info" {
  if (!status) return "neutral";
  if (["completed", "succeeded", "active", "ready"].includes(status)) return "success";
  if (["running", "completing", "unknown"].includes(status)) return "info";
  if (["paused", "warning", "revoked"].includes(status)) return "warning";
  if (["failed", "error", "disabled"].includes(status)) return "danger";
  return "neutral";
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  return <Badge variant={normalizeVariant(status)}>{status || "unknown"}</Badge>;
}
