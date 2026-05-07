import { Badge } from "@/components/ui/badge";

export type FailureTooltipDetails = {
  heading?: string | null;
  stage?: string | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  fallbackMessage?: string | null;
};

function cleanDetail(value: string | null | undefined): string | null {
  const trimmed = String(value || "").trim();
  return trimmed || null;
}

export function formatFailureTooltip(details: FailureTooltipDetails): string | null {
  const stage = cleanDetail(details.stage);
  const errorCode = cleanDetail(details.errorCode);
  const errorMessage = cleanDetail(details.errorMessage) || cleanDetail(details.fallbackMessage);
  if (!stage && !errorCode && !errorMessage) return null;
  return [
    cleanDetail(details.heading),
    stage ? `阶段：${stage}` : null,
    errorCode ? `错误代码：${errorCode}` : null,
    errorMessage ? `失败原因：${errorMessage}` : null,
  ].filter(Boolean).join("\n");
}

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

export function StatusBadge({ status, title }: { status: string | null | undefined; title?: string | null }) {
  return (
    <Badge variant={normalizeStatusBadgeVariant(status)} className="min-w-fit shrink-0" title={title || undefined} aria-label={title || undefined}>
      {formatStatusBadgeLabel(status)}
    </Badge>
  );
}
