import { Badge } from "@/components/ui/badge";

export function normalizeStatusBadgeVariant(status: string | null | undefined): "neutral" | "success" | "warning" | "danger" | "info" {
  if (!status) return "neutral";
  if (["completed", "succeeded", "active", "ready", "ok", "available"].includes(status)) return "success";
  if (["running", "completing", "unknown", "preparing", "bootstrapping"].includes(status)) return "info";
  if (["paused", "stopping", "force_stopping", "stopped", "warning", "revoked"].includes(status)) return "warning";
  if (["failed", "error", "disabled", "fail", "invalidated", "locked", "blocked"].includes(status)) return "danger";
  return "neutral";
}

export function formatStatusBadgeLabel(status: string | null | undefined) {
  if (!status) return "unknown";

  const labels: Record<string, string> = {
    "no-key": "no key",
    skipped_has_key: "linked",
    extract_api_key: "extract api key",
    ok: "ok",
    fail: "fail",
    stopping: "停止中",
    force_stopping: "强停中",
    stopped: "已停止",
    preparing: "preparing",
    available: "available",
    invalidated: "invalidated",
    locked: "locked",
    bootstrapping: "bootstrapping",
    blocked: "blocked",
  };

  return labels[status] ?? status;
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  return (
    <Badge variant={normalizeStatusBadgeVariant(status)} className="min-w-fit shrink-0">
      {formatStatusBadgeLabel(status)}
    </Badge>
  );
}
