import { Badge } from "@/components/ui/badge";

function normalizeVariant(status: string | null | undefined): "neutral" | "success" | "warning" | "danger" | "info" {
  if (!status) return "neutral";
  if (["completed", "succeeded", "active", "ready"].includes(status)) return "success";
  if (["running", "completing", "unknown"].includes(status)) return "info";
  if (["paused", "warning", "revoked"].includes(status)) return "warning";
  if (["failed", "error", "disabled"].includes(status)) return "danger";
  return "neutral";
}

function formatLabel(status: string | null | undefined) {
  if (!status) return "unknown";

  const labels: Record<string, string> = {
    "no-key": "no key",
    skipped_has_key: "linked",
    extract_api_key: "extract api key",
  };

  return labels[status] ?? status;
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  return (
    <Badge variant={normalizeVariant(status)} className="min-w-fit shrink-0">
      {formatLabel(status)}
    </Badge>
  );
}
