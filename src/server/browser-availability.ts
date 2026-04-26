import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright-core";
import {
  assertUsableFingerprintChromiumExecutablePath,
  resolveExplicitChromeExecutablePath,
} from "../fingerprint-browser.js";

export type BrowserRunModeAvailability = {
  headed: boolean;
  headless: true;
  headedReason: string | null;
};

export type AccountBusinessFlowAvailability = {
  headless: true;
  headed: boolean;
  fingerprint: boolean;
  headedReason: string | null;
  fingerprintReason: string | null;
  deAvailable: boolean;
};

type BrowserAvailabilitySnapshot = {
  runModeAvailability: BrowserRunModeAvailability;
  businessFlowAvailability: AccountBusinessFlowAvailability;
  checkedAt: string | null;
  executablePath: string | null;
};

type HeadedBrowserLaunchProbe = (input: { executablePath: string; cwd: string }) => Promise<void>;

const PENDING_REASON = "正在检测当前环境的浏览器能力。";
const DEFAULT_TTL_MS = 30_000;

function nowIso(): string {
  return new Date().toISOString();
}

function createPendingSnapshot(): BrowserAvailabilitySnapshot {
  return {
    runModeAvailability: {
      headed: false,
      headless: true,
      headedReason: PENDING_REASON,
    },
    businessFlowAvailability: {
      headless: true,
      headed: false,
      fingerprint: false,
      headedReason: PENDING_REASON,
      fingerprintReason: PENDING_REASON,
      deAvailable: false,
    },
    checkedAt: null,
    executablePath: null,
  };
}

function createUnavailableSnapshot(reason: { headed: string; fingerprint: string }, executablePath: string | null): BrowserAvailabilitySnapshot {
  return {
    runModeAvailability: {
      headed: false,
      headless: true,
      headedReason: reason.headed,
    },
    businessFlowAvailability: {
      headless: true,
      headed: false,
      fingerprint: false,
      headedReason: reason.headed,
      fingerprintReason: reason.fingerprint,
      deAvailable: false,
    },
    checkedAt: nowIso(),
    executablePath,
  };
}

function createAvailableSnapshot(executablePath: string): BrowserAvailabilitySnapshot {
  return {
    runModeAvailability: {
      headed: true,
      headless: true,
      headedReason: null,
    },
    businessFlowAvailability: {
      headless: true,
      headed: true,
      fingerprint: true,
      headedReason: null,
      fingerprintReason: null,
      deAvailable: true,
    },
    checkedAt: nowIso(),
    executablePath,
  };
}

function normalizeProbeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error || "unknown_error");
  const firstLine = raw
    .split("\n")
    .map((line) => line.trim())
    .find(Boolean);
  return firstLine || "未知错误";
}

function buildExecutableUnavailableReason(message: string): { headed: string; fingerprint: string } {
  return {
    headed: `当前环境缺少可用的指纹浏览器，无法启动有头浏览器。${message ? ` ${message}` : ""}`.trim(),
    fingerprint: `当前环境缺少可用的指纹浏览器，无法启动指纹浏览器。${message ? ` ${message}` : ""}`.trim(),
  };
}

function buildLaunchFailureReason(message: string): { headed: string; fingerprint: string } {
  return {
    headed: `当前环境无法启动有头浏览器：${message}`,
    fingerprint: `当前环境无法启动指纹浏览器：${message}`,
  };
}

function buildProbeSignature(cwd: string, env: NodeJS.ProcessEnv): string {
  const payload = JSON.stringify({
    cwd,
    platform: process.platform,
    chromeExecutablePath: String(env.CHROME_EXECUTABLE_PATH || "").trim(),
  });
  return createHash("sha256").update(payload, "utf8").digest("hex");
}

function resolveProbeExecutablePath(cwd: string, env: NodeJS.ProcessEnv): { executablePath: string } | { reason: { headed: string; fingerprint: string }; executablePath: string | null } {
  const explicitExecutablePath = resolveExplicitChromeExecutablePath(env.CHROME_EXECUTABLE_PATH, cwd);
  if (!explicitExecutablePath) {
    return {
      executablePath: null,
      reason: buildExecutableUnavailableReason("fingerprint browser executable path is not configured"),
    };
  }
  try {
    return {
      executablePath: assertUsableFingerprintChromiumExecutablePath(explicitExecutablePath),
    };
  } catch (error) {
    const message = normalizeProbeErrorMessage(error);
    return {
      executablePath: explicitExecutablePath ? path.resolve(explicitExecutablePath) : null,
      reason: buildExecutableUnavailableReason(message),
    };
  }
}

async function defaultHeadedBrowserLaunchProbe(input: { executablePath: string; cwd: string }): Promise<void> {
  const probeRoot = path.join(input.cwd, "tmp", "browser-availability-probe");
  await mkdir(probeRoot, { recursive: true });
  const userDataDir = await mkdtemp(path.join(probeRoot, "profile-"));
  let context: Awaited<ReturnType<typeof chromium.launchPersistentContext>> | null = null;
  try {
    context = await chromium.launchPersistentContext(userDataDir, {
      executablePath: input.executablePath,
      headless: false,
      timeout: 20_000,
      args: ["--no-first-run", "--no-default-browser-check"],
    });
    const page = context.pages()[0] || await context.newPage();
    await page.goto("about:blank", { waitUntil: "domcontentloaded", timeout: 5_000 });
  } finally {
    await context?.close().catch(() => {});
    await rm(userDataDir, { recursive: true, force: true }).catch(() => {});
  }
}

export class BrowserAvailabilityService {
  private snapshot: BrowserAvailabilitySnapshot = createPendingSnapshot();
  private inflight: Promise<void> | null = null;
  private lastProbeAtMs = 0;
  private lastProbeSignature: string | null = null;

  constructor(
    private readonly options: {
      cwd?: string;
      env?: NodeJS.ProcessEnv;
      ttlMs?: number;
      launchProbe?: HeadedBrowserLaunchProbe;
    } = {},
  ) {}

  getRunModeAvailability(): BrowserRunModeAvailability {
    return this.snapshot.runModeAvailability;
  }

  getAccountBusinessFlowAvailability(): AccountBusinessFlowAvailability {
    return this.snapshot.businessFlowAvailability;
  }

  getSnapshot(): BrowserAvailabilitySnapshot {
    return this.snapshot;
  }

  async ensureFresh(force = false): Promise<void> {
    const cwd = this.options.cwd || process.cwd();
    const env = this.options.env || process.env;
    const ttlMs = this.options.ttlMs ?? DEFAULT_TTL_MS;
    const signature = buildProbeSignature(cwd, env);
    const now = Date.now();
    if (!force && this.inflight) {
      await this.inflight;
      return;
    }
    if (!force && this.lastProbeSignature === signature && now - this.lastProbeAtMs < ttlMs) {
      return;
    }
    const task = this.refresh(signature, cwd, env);
    this.inflight = task;
    try {
      await task;
    } finally {
      if (this.inflight === task) {
        this.inflight = null;
      }
    }
  }

  private async refresh(signature: string, cwd: string, env: NodeJS.ProcessEnv): Promise<void> {
    const resolved = resolveProbeExecutablePath(cwd, env);
    if ("reason" in resolved) {
      this.snapshot = createUnavailableSnapshot(resolved.reason, resolved.executablePath);
      this.lastProbeSignature = signature;
      this.lastProbeAtMs = Date.now();
      return;
    }

    try {
      await (this.options.launchProbe || defaultHeadedBrowserLaunchProbe)({
        executablePath: resolved.executablePath,
        cwd,
      });
      this.snapshot = createAvailableSnapshot(resolved.executablePath);
    } catch (error) {
      this.snapshot = createUnavailableSnapshot(
        buildLaunchFailureReason(normalizeProbeErrorMessage(error)),
        resolved.executablePath,
      );
    }

    this.lastProbeSignature = signature;
    this.lastProbeAtMs = Date.now();
  }
}
