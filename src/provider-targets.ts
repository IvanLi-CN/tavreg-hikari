export type ProviderTarget = "tavily" | "chatgpt";

export type TargetArtifactType = "api_key" | "access_token";

export type TargetRunStatus = "succeeded" | "failed" | "skipped_has_artifact";

export const TARGET_ORDER: ProviderTarget[] = ["tavily", "chatgpt"];

export const DEFAULT_TARGETS: ProviderTarget[] = ["tavily"];

export function isProviderTarget(value: string): value is ProviderTarget {
  return value === "tavily" || value === "chatgpt";
}

export function normalizeProviderTargets(input: Iterable<string | ProviderTarget> | null | undefined): ProviderTarget[] {
  const values = new Set<ProviderTarget>();
  for (const item of input || []) {
    const normalized = String(item || "").trim().toLowerCase();
    if (!isProviderTarget(normalized)) continue;
    values.add(normalized);
  }
  const ordered = TARGET_ORDER.filter((target) => values.has(target));
  return ordered.length > 0 ? ordered : [...DEFAULT_TARGETS];
}

export function parseProviderTargetsCsv(raw: string | undefined | null): ProviderTarget[] {
  if (!raw || !String(raw).trim()) return [...DEFAULT_TARGETS];
  return normalizeProviderTargets(String(raw).split(","));
}

export function providerTargetsToCsv(targets: Iterable<ProviderTarget>): string {
  return normalizeProviderTargets(targets).join(",");
}

export function defaultArtifactTypeForTarget(target: ProviderTarget): TargetArtifactType {
  return target === "chatgpt" ? "access_token" : "api_key";
}

export function hasArtifactCompatibleStatus(status: string | null | undefined): boolean {
  return status === "succeeded" || status === "skipped_has_artifact";
}
