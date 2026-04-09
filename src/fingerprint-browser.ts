import { createHash } from "node:crypto";
import { accessSync, closeSync, constants as fsConstants, openSync, readFileSync, readSync, statSync } from "node:fs";
import path from "node:path";

const MACOS_FINGERPRINT_BROWSER_PATTERN = /\/chromium\.app\/contents\/macos\/chromium$/i;
const FINGERPRINT_BROWSER_INSTALL_MARKER = ".fingerprint-browser-install.json";
const FINGERPRINT_BROWSER_INSTALLER_ID = "install-fingerprint-browser.sh";
const FINGERPRINT_BROWSER_DIGEST_CACHE = new Map<string, boolean>();

type FingerprintBrowserInstallMarker = {
  schemaVersion?: number;
  installer?: string;
  platform?: string;
  version?: string;
  binaryRelativePath?: string;
  binarySha256?: string;
};

type OfficialFingerprintBrowserCandidate = {
  platform: "linux" | "macos";
  resolvedPath: string;
};

function computeFileSha256(filePath: string): string {
  const fd = openSync(filePath, "r");
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    while (true) {
      const bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

function resolveOfficialFingerprintBrowserCandidate(executablePath: string): OfficialFingerprintBrowserCandidate | undefined {
  const resolvedPath = path.resolve(executablePath);
  const normalized = resolvedPath.replaceAll("\\", "/").toLowerCase();
  if (MACOS_FINGERPRINT_BROWSER_PATTERN.test(normalized)) {
    return { platform: "macos", resolvedPath };
  }
  if (normalized.endsWith("/chrome")) {
    return { platform: "linux", resolvedPath };
  }
  return undefined;
}

function buildInstallDigestCacheKey(markerPath: string, executablePath: string, binarySha256: string): string | undefined {
  try {
    const markerStats = statSync(markerPath);
    const executableStats = statSync(executablePath);
    if (!markerStats.isFile() || !executableStats.isFile()) return undefined;
    return [
      markerPath,
      executablePath,
      binarySha256,
      String(markerStats.size),
      String(markerStats.mtimeMs),
      String(executableStats.size),
      String(executableStats.mtimeMs),
    ].join(":");
  } catch {
    return undefined;
  }
}

function isOfficialFingerprintBrowserInstall(executablePath: string): boolean {
  const candidate = resolveOfficialFingerprintBrowserCandidate(executablePath);
  if (!candidate) return false;
  const { platform, resolvedPath } = candidate;
  const candidateDirs: string[] = [];
  let currentDir = path.dirname(resolvedPath);
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
      const marker = JSON.parse(readFileSync(markerPath, "utf8")) as FingerprintBrowserInstallMarker;
      if (marker.schemaVersion !== 1 || marker.installer !== FINGERPRINT_BROWSER_INSTALLER_ID || marker.platform !== platform) {
        continue;
      }
      if (typeof marker.binaryRelativePath !== "string" || marker.binaryRelativePath.trim() === "") {
        continue;
      }
      if (typeof marker.binarySha256 !== "string" || marker.binarySha256.trim() === "") {
        continue;
      }
      const expectedBinaryPath = path.resolve(dir, marker.binaryRelativePath);
      if (expectedBinaryPath !== resolvedPath) {
        continue;
      }
      const cacheKey = buildInstallDigestCacheKey(markerPath, resolvedPath, marker.binarySha256);
      if (!cacheKey) {
        continue;
      }
      const cached = FINGERPRINT_BROWSER_DIGEST_CACHE.get(cacheKey);
      if (cached !== undefined) {
        if (cached) return true;
        continue;
      }
      const matches = computeFileSha256(resolvedPath) === marker.binarySha256;
      FINGERPRINT_BROWSER_DIGEST_CACHE.set(cacheKey, matches);
      if (matches) {
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
  const resolved = resolveExplicitChromeExecutablePath(executablePath);
  if (!resolved) return false;
  return isOfficialFingerprintBrowserInstall(resolved);
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
