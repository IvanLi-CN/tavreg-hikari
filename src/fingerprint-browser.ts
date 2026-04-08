import { accessSync, constants as fsConstants, readFileSync, statSync } from "node:fs";
import path from "node:path";

const MACOS_FINGERPRINT_BROWSER_PATTERN = /\/chromium\.app\/contents\/macos\/chromium$/i;
const FINGERPRINT_BROWSER_CHROME_PATTERN = /\/fingerprint-browser\/(?:linux\/)?(?:[\w.+-]+\/)?chrome$/i;
const FINGERPRINT_BROWSER_INSTALL_MARKER = ".fingerprint-browser-install.json";
const FINGERPRINT_BROWSER_INSTALLER_ID = "install-fingerprint-browser.sh";

function isOfficialFingerprintBrowserInstall(executablePath: string): boolean {
  const resolved = path.resolve(executablePath);
  const normalized = resolved.replaceAll("\\", "/").toLowerCase();
  if (!normalized.endsWith("/chrome")) return false;
  const candidateDirs: string[] = [];
  let currentDir = path.dirname(resolved);
  for (let depth = 0; depth < 4; depth += 1) {
    if (candidateDirs.includes(currentDir)) break;
    candidateDirs.push(currentDir);
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }
  for (const dir of candidateDirs) {
    try {
      const markerPath = path.join(dir, FINGERPRINT_BROWSER_INSTALL_MARKER);
      if (!statSync(markerPath).isFile()) continue;
      const marker = JSON.parse(readFileSync(markerPath, "utf8")) as {
        schemaVersion?: number;
        installer?: string;
        platform?: string;
      };
      if (marker.schemaVersion === 1 && marker.installer === FINGERPRINT_BROWSER_INSTALLER_ID && marker.platform === "linux") {
        return true;
      }
    } catch {
      // ignore missing / malformed markers and continue walking parents
    }
  }
  return false;
}

export function resolveExplicitChromeExecutablePath(raw: string | undefined | null): string | undefined {
  const trimmed = String(raw || "").trim();
  return trimmed ? trimmed : undefined;
}

export function isFingerprintChromiumExecutable(executablePath: string | undefined | null): boolean {
  const normalized = String(executablePath || "").trim().toLowerCase().replaceAll("\\", "/");
  if (!normalized) return false;
  return (
    MACOS_FINGERPRINT_BROWSER_PATTERN.test(normalized)
    || FINGERPRINT_BROWSER_CHROME_PATTERN.test(normalized)
    || isOfficialFingerprintBrowserInstall(String(executablePath || "").trim())
  );
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
