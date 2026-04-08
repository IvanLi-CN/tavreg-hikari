import { accessSync, constants as fsConstants, statSync } from "node:fs";
import path from "node:path";

const FINGERPRINT_BROWSER_PATH_MARKERS = ["/fingerprint-browser/", "/chromium.app/"] as const;

export function resolveExplicitChromeExecutablePath(raw: string | undefined | null): string | undefined {
  const trimmed = String(raw || "").trim();
  return trimmed ? trimmed : undefined;
}

export function isFingerprintChromiumExecutable(executablePath: string | undefined | null): boolean {
  const normalized = String(executablePath || "").trim().toLowerCase().replaceAll("\\", "/");
  if (!normalized) return false;
  if (FINGERPRINT_BROWSER_PATH_MARKERS.some((marker) => normalized.includes(marker))) {
    return true;
  }
  return normalized.endsWith("/chromium") && (normalized.includes("/.tools/") || normalized.includes("fingerprint"));
}

export function requireFingerprintChromiumExecutablePath(executablePath: string | undefined | null): string {
  const resolved = resolveExplicitChromeExecutablePath(executablePath);
  if (!resolved) {
    throw new Error("fingerprint browser executable path is not configured");
  }
  if (!isFingerprintChromiumExecutable(resolved)) {
    throw new Error(`Unsupported CHROME_EXECUTABLE_PATH: ${resolved}. Only the provided fingerprint browser is allowed.`);
  }
  return resolved;
}

export function assertUsableFingerprintChromiumExecutablePath(executablePath: string | undefined | null): string {
  const resolved = requireFingerprintChromiumExecutablePath(executablePath);
  const normalized = path.resolve(resolved);
  let stats;
  try {
    stats = statSync(normalized);
  } catch {
    throw new Error(`fingerprint browser executable does not exist: ${normalized}`);
  }
  if (!stats.isFile()) {
    throw new Error(`fingerprint browser executable is not a file: ${normalized}`);
  }
  try {
    accessSync(normalized, fsConstants.X_OK);
  } catch {
    throw new Error(`fingerprint browser executable is not executable: ${normalized}`);
  }
  return normalized;
}
