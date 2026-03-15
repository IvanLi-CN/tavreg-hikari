import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import process from "node:process";

export type VirtualDisplayBackend = "system" | "xvfb";

export interface FingerprintChromiumOptions {
  platform: NodeJS.Platform | string;
  executablePath?: string;
  profileDir: string;
  proxyServer: string;
  locale: string;
  acceptLanguage: string;
  timezoneId?: string;
}

export interface VirtualDisplayConfig {
  enabled: boolean;
  executablePath?: string;
  displayNum: string;
  screen: string;
  startupTimeoutMs: number;
}

export interface VirtualDisplayDecisionInput {
  platform: NodeJS.Platform | string;
  mode: "headed" | "headless";
  browserEngine: string;
  displayEnv?: string;
  waylandDisplayEnv?: string;
  enabled: boolean;
}

export interface VirtualDisplaySession {
  backend: VirtualDisplayBackend;
  display?: string;
  env: NodeJS.ProcessEnv;
  stop: () => Promise<void>;
}

const AUTO_DISPLAY = "auto";
const AUTO_DISPLAY_START = 99;
const AUTO_DISPLAY_END = 140;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeDisplaySetting(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === AUTO_DISPLAY) return AUTO_DISPLAY;
  if (/^:\d+$/.test(trimmed)) return trimmed;
  if (/^\d+$/.test(trimmed)) return `:${trimmed}`;
  throw new Error(`invalid virtual display number: ${raw}`);
}

function displayArtifacts(display: string): { lockPath: string; socketPath: string } {
  const displayId = display.replace(/^:/, "");
  return {
    lockPath: `/tmp/.X${displayId}-lock`,
    socketPath: `/tmp/.X11-unix/X${displayId}`,
  };
}

function displayLooksBusy(display: string): boolean {
  const { lockPath, socketPath } = displayArtifacts(display);
  return existsSync(lockPath) || existsSync(socketPath);
}

function resolveManagedDisplay(displaySetting: string): string {
  const normalized = normalizeDisplaySetting(displaySetting);
  if (normalized !== AUTO_DISPLAY) return normalized;
  for (let num = AUTO_DISPLAY_START; num <= AUTO_DISPLAY_END; num += 1) {
    const candidate = `:${num}`;
    if (!displayLooksBusy(candidate)) return candidate;
  }
  throw new Error("no free Xvfb display found in auto range");
}

function signalChildProcess(child: ChildProcess, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (!pid) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-pid, signal);
      return;
    } catch {
      // fall through to direct child kill
    }
  }
  try {
    child.kill(signal);
  } catch {
    // ignore shutdown races
  }
}

function createChildStopper(child: ChildProcess): () => Promise<void> {
  let stopping = false;
  return async () => {
    if (stopping) return;
    stopping = true;
    if (child.exitCode != null) return;
    signalChildProcess(child, "SIGTERM");
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      if (child.exitCode != null) return;
      await delay(120);
    }
    signalChildProcess(child, "SIGKILL");
  };
}

async function waitForXvfbReady(
  display: string,
  child: ChildProcess,
  timeoutMs: number,
  getSpawnError: () => Error | null,
): Promise<void> {
  const { socketPath } = displayArtifacts(display);
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (existsSync(socketPath)) return;
    const spawnError = getSpawnError();
    if (spawnError) {
      throw spawnError;
    }
    if (child.exitCode != null) {
      throw new Error(`xvfb exited early: ${child.exitCode}`);
    }
    await delay(100);
  }
  throw new Error(`xvfb startup timed out after ${timeoutMs}ms`);
}

export function shouldUseVirtualDisplay(input: VirtualDisplayDecisionInput): boolean {
  return (
    input.platform === "linux" &&
    input.mode === "headed" &&
    input.browserEngine === "chrome" &&
    !input.displayEnv?.trim() &&
    !input.waylandDisplayEnv?.trim() &&
    input.enabled
  );
}

export async function ensureVirtualDisplaySession(
  cfg: VirtualDisplayConfig,
  input: Omit<VirtualDisplayDecisionInput, "enabled">,
): Promise<VirtualDisplaySession> {
  const baseEnv: NodeJS.ProcessEnv = { ...process.env };
  if (
    !shouldUseVirtualDisplay({
      ...input,
      enabled: cfg.enabled,
    })
  ) {
    return {
      backend: "system",
      display: baseEnv.DISPLAY,
      env: baseEnv,
      stop: async () => {},
    };
  }

  const executablePath = cfg.executablePath?.trim() || "Xvfb";
  const display = resolveManagedDisplay(cfg.displayNum);
  const env: NodeJS.ProcessEnv = {
    ...baseEnv,
    DISPLAY: display,
  };
  delete env.WAYLAND_DISPLAY;

  const args = [
    display,
    "-screen",
    "0",
    cfg.screen,
    "-nolisten",
    "tcp",
    "-ac",
  ];
  const child = spawn(executablePath, args, {
    stdio: "ignore",
    detached: true,
    env: baseEnv,
  });
  child.unref();
  let spawnError: Error | null = null;
  child.once("error", (error) => {
    spawnError = error;
  });
  const stop = createChildStopper(child);
  try {
    await waitForXvfbReady(display, child, cfg.startupTimeoutMs, () => spawnError);
  } catch (error) {
    await stop().catch(() => {});
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`virtual_display_unavailable:${reason}`);
  }

  return {
    backend: "xvfb",
    display,
    env,
    stop,
  };
}

export function isFingerprintChromiumExecutable(executablePath: string | undefined): boolean {
  const normalized = (executablePath || "").trim().toLowerCase();
  return normalized.endsWith("/chromium") || normalized.includes("/chromium.app/");
}

export function resolveFingerprintChromiumPlatform(platform: NodeJS.Platform | string): "linux" | "macos" | null {
  if (platform === "linux") return "linux";
  if (platform === "darwin") return "macos";
  return null;
}

function buildFingerprintSeed(profileDir: string, proxyServer: string, locale: string): string {
  const digest = createHash("sha256").update(`${profileDir}|${proxyServer}|${locale}`).digest("hex");
  return String(parseInt(digest.slice(0, 8), 16) || 1000);
}

export function getFingerprintChromiumArgs(options: FingerprintChromiumOptions): string[] {
  if (!isFingerprintChromiumExecutable(options.executablePath)) return [];
  const seed = buildFingerprintSeed(options.profileDir, options.proxyServer, options.locale);
  const args = [
    `--fingerprint=${seed}`,
    "--fingerprint-brand=Chrome",
    `--lang=${options.locale}`,
    `--accept-lang=${options.acceptLanguage}`,
    "--disable-non-proxied-udp",
  ];
  const platform = resolveFingerprintChromiumPlatform(options.platform);
  if (platform) {
    args.push(`--fingerprint-platform=${platform}`);
  }
  if (options.timezoneId?.trim()) {
    args.push(`--timezone=${options.timezoneId.trim()}`);
  }
  return args;
}

export function shouldFallbackToPersistentBrowser(
  browserEngine: string,
  mode: "headed" | "headless",
  nativeAutomationEnabled: boolean,
): boolean {
  return browserEngine === "chrome" && mode === "headed" && nativeAutomationEnabled;
}
