import { config as loadDotenv } from "dotenv";
import { Camoufox } from "camoufox-js";
import { Resvg } from "@resvg/resvg-js";
import { Impit } from "impit";
import { chromium, type Browser, type BrowserContextOptions, type LaunchOptions } from "playwright-core";
import { randomBytes, randomInt } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import path from "node:path";
import process from "node:process";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { startMihomo, type MihomoConfig } from "./proxy/mihomo.js";
import { checkNode, resolveLocalEgressIp, type NodeCheckResult } from "./proxy/check.js";
import { buildAcceptLanguage, deriveLocale, type GeoInfo } from "./proxy/geo.js";
import { TaskLedger, type SignupTaskRecord, type TaskLedgerConfig } from "./storage/task-ledger.js";

type JsonRecord = Record<string, unknown>;
type RunMode = "headed" | "headless" | "both";
type BrowserEngine = "camoufox" | "chrome";

interface CliArgs {
  proxyNode?: string;
  mode?: RunMode;
  browserEngine?: BrowserEngine;
  skipPrecheck: boolean;
  inspectSites: boolean;
}

interface AppConfig {
  openaiBaseUrl: string;
  openaiKey: string;
  preferredModel: string;
  runMode: RunMode;
  browserEngine: BrowserEngine;
  inspectBrowserEngine: BrowserEngine;
  chromeExecutablePath?: string;
  chromeNativeAutomation: boolean;
  chromeStealthJsEnabled: boolean;
  chromeWebrtcHardened: boolean;
  chromeProfileDir: string;
  chromeRemoteDebuggingPort: number;
  slowMoMs: number;
  maxCaptchaRounds: number;
  ocrRetryWindowMs: number;
  ocrInitialCooldownMs: number;
  ocrMaxCooldownMs: number;
  ocrRequestTimeoutMs: number;
  humanConfirmBeforeSignup: boolean;
  humanConfirmText: string;
  duckmailBaseUrl: string;
  duckmailApiKey?: string;
  duckmailDomain?: string;
  duckmailPollMs: number;
  emailWaitMs: number;
  keyName: string;
  keyLimit: number;
  existingEmail?: string;
  existingPassword?: string;
  mihomoSubscriptionUrl: string;
  mihomoApiPort: number;
  mihomoMixedPort: number;
  proxyCheckUrl: string;
  proxyCheckTimeoutMs: number;
  proxyLatencyMaxMs: number;
  ipinfoToken?: string;
  browserPrecheckEnabled: boolean;
  browserPrecheckStrict: boolean;
  browserPrecheckCheckHostingProvider: boolean;
  requireWebrtcVisible: boolean;
  verifyHostAllowlist: string[];
  modeRetryMax: number;
  browserLaunchRetryMax: number;
  nodeReuseCooldownMs: number;
  nodeRecentWindow: number;
  nodeCheckCacheTtlMs: number;
  nodeScanMaxChecks: number;
  nodeScanMaxMs: number;
  nodeDeferLogMax: number;
  allowSameEgressIpFallback: boolean;
  cfProbeEnabled: boolean;
  cfProbeUrl: string;
  cfProbeTimeoutMs: number;
  cfProbeCacheTtlMs: number;
  inspectKeepOpenMs: number;
  inspectChromeNative: boolean;
  inspectChromeProfileDir: string;
  taskLedger: TaskLedgerConfig;
}

interface DuckmailSession {
  baseUrl: string;
  address: string;
  accountId: string;
  token: string;
}

interface ResultPayload {
  mode: "headed" | "headless";
  email: string;
  password: string;
  verificationLink: string | null;
  apiKey: string | null;
  model: string;
  precheckPassed: boolean;
  verifyPassed: boolean;
  failureStage?: string;
  notes: string[];
}

interface RequestDiagRecord {
  url: string;
  method: string;
  contentType?: string;
  bodyLength?: number;
  postKeys?: string[];
  captchaLength?: number;
  captchaTokenLength?: number;
  stateLength?: number;
  passwordLength?: number;
  emailHint?: string;
  responseStatus?: number;
  responseErrorCodes?: string[];
  suspiciousSnippet?: string;
}

interface NetworkDiagRecord {
  url: string;
  status: number;
  contentType: string;
  bodyPreview?: string;
  responseErrorCodes?: string[];
  suspiciousSnippet?: string;
}

interface RiskSignalSummary {
  hasIpRateLimit: boolean;
  hasSuspiciousActivity: boolean;
  hasExtensibilityError: boolean;
  hasInvalidCaptcha: boolean;
  requestCount: number;
  suspiciousHitCount: number;
  captchaSubmitCount: number;
  maxCaptchaLength?: number;
  snippets: string[];
}

interface ModeRunContext {
  batchId: string;
  modeAttempt: number;
  taskLedger: TaskLedger | null;
}

interface BrowserIdentityProfile {
  userAgent: string;
  navigatorPlatform: string;
  cdpPlatform: string;
  acceptLanguage: string;
  languages: string[];
}

interface ProxyNodeUsageEntry {
  count: number;
  successCount?: number;
  failCount?: number;
  consecutiveFailCount?: number;
  lastIp?: string;
  lastGeo?: GeoInfo;
  lastUsedAt?: string;
  lastCheckedAt?: string;
  lastOutcome?: "ok" | "fallback" | "fail";
  lastLatencyMs?: number | null;
  lastCfProbeAt?: string;
  lastCfProbePassed?: boolean;
  lastCfProbeUrl?: string;
}

interface ProxyNodeUsageState {
  version: 1;
  recentSelected: string[];
  recentSelectedIps: string[];
  nodes: Record<string, ProxyNodeUsageEntry>;
}

loadDotenv({ path: ".env.local", quiet: true });

const OUTPUT_DIR = new URL("../output/", import.meta.url);
const OUTPUT_PATH = fileURLToPath(OUTPUT_DIR);
const PROXY_NODE_USAGE_PATH = new URL("proxy/node-usage.json", OUTPUT_DIR);

function ts(): string {
  return new Date().toISOString();
}

function log(message: string): void {
  console.log(`[${ts()}] ${message}`);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function mustEnv(name: string): string {
  const value = (process.env[name] || "").trim();
  if (!value) {
    throw new Error(`Missing env: ${name}`);
  }
  return value;
}

function toBool(raw: string | undefined, fallback: boolean): boolean {
  if (!raw || !raw.trim()) return fallback;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

function toInt(raw: string | undefined, fallback: number): number {
  if (!raw || !raw.trim()) return fallback;
  const value = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(value) ? value : fallback;
}

function parseRunMode(raw: string | undefined): RunMode | null {
  if (!raw) return null;
  const value = raw.trim().toLowerCase();
  if (value === "headed" || value === "headless" || value === "both") {
    return value;
  }
  return null;
}

function parseBrowserEngine(raw: string | undefined): BrowserEngine | null {
  if (!raw) return null;
  const value = raw.trim().toLowerCase();
  if (value === "camoufox" || value === "chrome") return value;
  return null;
}

function parseArgs(argv: string[]): CliArgs {
  let proxyNode: string | undefined;
  let mode: RunMode | undefined;
  let browserEngine: BrowserEngine | undefined;
  let skipPrecheck = false;
  let inspectSites = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--proxy-node" && argv[i + 1]) {
      proxyNode = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith("--proxy-node=")) {
      proxyNode = arg.slice("--proxy-node=".length);
      continue;
    }
    if (arg === "--mode" && argv[i + 1]) {
      const parsed = parseRunMode(argv[i + 1]);
      if (!parsed) {
        throw new Error(`invalid --mode value: ${argv[i + 1]}`);
      }
      mode = parsed;
      i += 1;
      continue;
    }
    if (arg.startsWith("--mode=")) {
      const parsed = parseRunMode(arg.slice("--mode=".length));
      if (!parsed) {
        throw new Error(`invalid --mode value: ${arg.slice("--mode=".length)}`);
      }
      mode = parsed;
      continue;
    }
    if (arg === "--skip-precheck") {
      skipPrecheck = true;
      continue;
    }
    if (arg === "--browser-engine" && argv[i + 1]) {
      const parsed = parseBrowserEngine(argv[i + 1]);
      if (!parsed) {
        throw new Error(`invalid --browser-engine value: ${argv[i + 1]}`);
      }
      browserEngine = parsed;
      i += 1;
      continue;
    }
    if (arg.startsWith("--browser-engine=")) {
      const parsed = parseBrowserEngine(arg.slice("--browser-engine=".length));
      if (!parsed) {
        throw new Error(`invalid --browser-engine value: ${arg.slice("--browser-engine=".length)}`);
      }
      browserEngine = parsed;
      continue;
    }
    if (arg === "--inspect-sites") {
      inspectSites = true;
      continue;
    }
  }
  return { proxyNode: proxyNode?.trim() || undefined, mode, browserEngine, skipPrecheck, inspectSites };
}

function defaultProxyNodeUsageState(): ProxyNodeUsageState {
  return {
    version: 1,
    recentSelected: [],
    recentSelectedIps: [],
    nodes: {},
  };
}

function normalizeProxyNodeUsageEntry(entry: unknown): ProxyNodeUsageEntry {
  const record = entry && typeof entry === "object" ? (entry as JsonRecord) : {};
  const intOrZero = (value: unknown): number => {
    return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
  };
  const dateOrUndefined = (value: unknown): string | undefined => {
    if (typeof value !== "string" || !value.trim()) return undefined;
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
  };
  const outcome =
    record.lastOutcome === "ok" || record.lastOutcome === "fallback" || record.lastOutcome === "fail"
      ? record.lastOutcome
      : undefined;
  const lastIp = normalizeIp(typeof record.lastIp === "string" ? record.lastIp : "");
  const geoRaw = record.lastGeo && typeof record.lastGeo === "object" ? (record.lastGeo as JsonRecord) : null;
  const lat =
    geoRaw && typeof geoRaw.latitude === "number" && Number.isFinite(geoRaw.latitude) ? geoRaw.latitude : undefined;
  const lon =
    geoRaw && typeof geoRaw.longitude === "number" && Number.isFinite(geoRaw.longitude) ? geoRaw.longitude : undefined;
  const geoIp = normalizeIp(geoRaw && typeof geoRaw.ip === "string" ? geoRaw.ip : "") || lastIp;
  const lastGeo: GeoInfo | undefined = geoIp
    ? {
        ip: geoIp,
        country: geoRaw && typeof geoRaw.country === "string" ? geoRaw.country : undefined,
        region: geoRaw && typeof geoRaw.region === "string" ? geoRaw.region : undefined,
        city: geoRaw && typeof geoRaw.city === "string" ? geoRaw.city : undefined,
        org: geoRaw && typeof geoRaw.org === "string" ? geoRaw.org : undefined,
        timezone: geoRaw && typeof geoRaw.timezone === "string" ? geoRaw.timezone : undefined,
        latitude: lat,
        longitude: lon,
      }
    : undefined;
  const latency =
    typeof record.lastLatencyMs === "number" && Number.isFinite(record.lastLatencyMs) && record.lastLatencyMs >= 0
      ? record.lastLatencyMs
      : null;
  const lastCfProbePassed = typeof record.lastCfProbePassed === "boolean" ? record.lastCfProbePassed : undefined;
  const lastCfProbeUrl = typeof record.lastCfProbeUrl === "string" && record.lastCfProbeUrl.trim() ? record.lastCfProbeUrl : undefined;

  return {
    count: intOrZero(record.count),
    successCount: intOrZero(record.successCount),
    failCount: intOrZero(record.failCount),
    consecutiveFailCount: intOrZero(record.consecutiveFailCount),
    lastIp,
    lastGeo,
    lastUsedAt: dateOrUndefined(record.lastUsedAt),
    lastCheckedAt: dateOrUndefined(record.lastCheckedAt),
    lastOutcome: outcome,
    lastLatencyMs: latency,
    lastCfProbeAt: dateOrUndefined(record.lastCfProbeAt),
    lastCfProbePassed,
    lastCfProbeUrl,
  };
}

async function readProxyNodeUsageState(): Promise<ProxyNodeUsageState> {
  try {
    const raw = await readFile(PROXY_NODE_USAGE_PATH, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") {
      return defaultProxyNodeUsageState();
    }
    const parsedRecord = parsed as JsonRecord;
    if (parsedRecord.version !== 1) {
      return defaultProxyNodeUsageState();
    }
    const normalizedNodes: Record<string, ProxyNodeUsageEntry> = {};
    if (parsedRecord.nodes && typeof parsedRecord.nodes === "object") {
      for (const [name, entry] of Object.entries(parsedRecord.nodes as JsonRecord)) {
        if (typeof name === "string" && name.trim()) {
          normalizedNodes[name] = normalizeProxyNodeUsageEntry(entry);
        }
      }
    }
    return {
      version: 1,
      recentSelected: Array.isArray(parsedRecord.recentSelected)
        ? (parsedRecord.recentSelected as unknown[]).filter((item): item is string => typeof item === "string")
        : [],
      recentSelectedIps: Array.isArray(parsedRecord.recentSelectedIps)
        ? (parsedRecord.recentSelectedIps as unknown[]).filter(
            (item): item is string => typeof item === "string" && item.trim().length > 0,
          )
        : [],
      nodes: normalizedNodes,
    };
  } catch {
    return defaultProxyNodeUsageState();
  }
}

async function writeProxyNodeUsageState(state: ProxyNodeUsageState): Promise<void> {
  await writeJson(PROXY_NODE_USAGE_PATH, state);
}

function pushRecentUnique(values: string[], value: string | undefined, limit: number): string[] {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) return values.slice(0, limit);
  return [normalized, ...values.filter((item) => item !== normalized)].slice(0, limit);
}

function isUsageEntryFresh(entry: ProxyNodeUsageEntry | undefined, nowMs: number, ttlMs: number): boolean {
  if (!entry?.lastCheckedAt) return false;
  const checkedAtMs = Date.parse(entry.lastCheckedAt);
  if (!Number.isFinite(checkedAtMs)) return false;
  return nowMs - checkedAtMs <= ttlMs;
}

function isCfProbeFresh(
  entry: ProxyNodeUsageEntry | undefined,
  nowMs: number,
  ttlMs: number,
  targetUrl: string,
): boolean {
  if (!entry?.lastCfProbeAt || !entry.lastCfProbeUrl || !entry.lastCfProbePassed && entry.lastCfProbePassed !== false) {
    return false;
  }
  if (entry.lastCfProbeUrl !== targetUrl) return false;
  const checkedAtMs = Date.parse(entry.lastCfProbeAt);
  if (!Number.isFinite(checkedAtMs)) return false;
  return nowMs - checkedAtMs <= ttlMs;
}

function compactGeo(geo: GeoInfo | undefined): GeoInfo | undefined {
  if (!geo?.ip) return undefined;
  return {
    ip: normalizeIp(geo.ip) || geo.ip,
    country: geo.country,
    region: geo.region,
    city: geo.city,
    org: geo.org,
    timezone: geo.timezone,
    latitude: typeof geo.latitude === "number" && Number.isFinite(geo.latitude) ? geo.latitude : undefined,
    longitude: typeof geo.longitude === "number" && Number.isFinite(geo.longitude) ? geo.longitude : undefined,
  };
}

function detectCfChallenge(title: string, body: string, url: string): string | null {
  const haystack = `${title}\n${body}`.toLowerCase();
  if (haystack.includes("__cf_chl_rt_tk")) return "cf_token";
  if (/captcha\s*\|\s*sukka/i.test(title) || /captcha\s*\|\s*sukka/i.test(body)) return "sukka_captcha";
  if (haystack.includes("just a moment")) return "just_a_moment";
  if (haystack.includes("attention required")) return "attention_required";
  if (haystack.includes("cloudflare")) {
    if (haystack.includes("challenge") || haystack.includes("verify")) return "cloudflare_challenge";
  }
  if (/\?__cf_chl_rt_tk=/i.test(url)) return "cf_query_token";
  return null;
}

async function probeCfViaProxy(
  proxyUrl: string,
  targetUrl: string,
  timeoutMs: number,
): Promise<{ passed: boolean; reason?: string }> {
  try {
    const impit = new Impit({ proxyUrl, timeout: timeoutMs });
    const resp = await impit.fetch(targetUrl, {
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    const body = await resp.text();
    const title = body.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.trim() || "";
    if (!resp.ok) {
      return { passed: false, reason: `status_${resp.status}` };
    }
    const challengeReason = detectCfChallenge(title, body, targetUrl);
    if (challengeReason) {
      return { passed: false, reason: `cf_${challengeReason}` };
    }
    return { passed: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { passed: false, reason: `probe_error:${message.slice(0, 120)}` };
  }
}

async function resolveProxyEgressIp(proxyUrl: string, timeoutMs: number, ipinfoToken?: string): Promise<string | undefined> {
  try {
    const url = new URL("https://ipinfo.io/json");
    if (ipinfoToken && ipinfoToken.trim()) {
      url.searchParams.set("token", ipinfoToken.trim());
    }
    const impit = new Impit({ proxyUrl, timeout: timeoutMs });
    const resp = await impit.fetch(url.toString());
    if (!resp.ok) return undefined;
    const payload = (await resp.json()) as JsonRecord;
    return normalizeIp(typeof payload.ip === "string" ? payload.ip : undefined);
  } catch {
    return undefined;
  }
}

async function waitForProxyEgressIp(
  proxyUrl: string,
  expectedIp: string | undefined,
  timeoutMs: number,
  ipinfoToken?: string,
): Promise<void> {
  const targetIp = normalizeIp(expectedIp);
  if (!targetIp) return;
  const deadline = Date.now() + Math.max(timeoutMs * 2, 8_000);
  let lastObserved: string | undefined;
  while (Date.now() < deadline) {
    lastObserved = await resolveProxyEgressIp(proxyUrl, timeoutMs, ipinfoToken);
    if (lastObserved && sameIp(lastObserved, targetIp)) {
      return;
    }
    await delay(300);
  }
  throw new Error(`proxy_egress_not_switched: expected=${targetIp} observed=${lastObserved || "unknown"}`);
}

function nodeSelectionScore(
  name: string,
  usage: ProxyNodeUsageState,
  nowMs: number,
  cfg: AppConfig,
): number {
  const entry = usage.nodes[name];
  if (!entry) {
    return 180 + Math.random() * 16;
  }

  const countPenalty = 0;
  const recentPenalty = 0;
  const hottestPenalty = 0;
  const recentIpPenalty = entry.lastIp && usage.recentSelectedIps.includes(entry.lastIp) ? 1200 : 0;
  const hottestIpPenalty = entry.lastIp && usage.recentSelectedIps[0] === entry.lastIp ? 480 : 0;
  const lastUsedMs = entry.lastUsedAt ? Date.parse(entry.lastUsedAt) : NaN;
  const cooldownRemaining = Number.isFinite(lastUsedMs) ? cfg.nodeReuseCooldownMs - (nowMs - lastUsedMs) : 0;
  const cooldownPenalty =
    cooldownRemaining > 0 ? Math.round((cooldownRemaining / Math.max(1, cfg.nodeReuseCooldownMs)) * 700) : 0;
  const successCount = entry.successCount || 0;
  const failCount = entry.failCount || 0;
  const checkedCount = successCount + failCount;
  const successRate = checkedCount > 0 ? successCount / checkedCount : null;
  const reliabilityPenalty = successRate == null ? 0 : Math.round((1 - successRate) * 260);
  const failPenalty = (entry.lastOutcome === "fail" ? 120 : 0) + (entry.consecutiveFailCount || 0) * 220 + failCount * 18;
  const latencyPenalty = typeof entry.lastLatencyMs === "number" && entry.lastLatencyMs > 0 ? entry.lastLatencyMs / 70 : 0;
  const org = (entry.lastGeo?.org || "").toLowerCase();
  const hostingPenalty =
    /colocrossing|colo crossing|hostpapa|zmto|digitalocean|linode|vultr|ovh|hetzner|contabo|amazon|aws|google cloud|azure|oracle cloud|hosting|datacenter|data center|vps|server/i.test(
      org,
    )
      ? 2400
      : 0;
  const outcomeBonus = entry.lastOutcome === "ok" ? -140 : entry.lastOutcome === "fallback" ? -40 : 0;
  return (
    countPenalty +
    recentPenalty +
    hottestPenalty +
    recentIpPenalty +
    hottestIpPenalty +
    cooldownPenalty +
    reliabilityPenalty +
    failPenalty +
    latencyPenalty +
    hostingPenalty +
    outcomeBonus +
    Math.random() * 0.01
  );
}

function buildMihomoConfig(cfg: AppConfig): MihomoConfig {
  return {
    subscriptionUrl: cfg.mihomoSubscriptionUrl,
    apiPort: cfg.mihomoApiPort,
    mixedPort: cfg.mihomoMixedPort,
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: cfg.proxyCheckUrl,
    workDir: path.join(OUTPUT_PATH, "mihomo"),
    downloadDir: path.resolve("downloads", "mihomo"),
  };
}

async function selectProxyNode(
  controller: Awaited<ReturnType<typeof startMihomo>>,
  cfg: AppConfig,
  overrideName?: string,
  blockedEgressIps: Set<string> = new Set(),
): Promise<NodeCheckResult> {
  const options = {
    checkUrl: cfg.proxyCheckUrl,
    timeoutMs: cfg.proxyCheckTimeoutMs,
    maxLatencyMs: cfg.proxyLatencyMaxMs,
    ipinfoToken: cfg.ipinfoToken,
  };
  const usage = await readProxyNodeUsageState();
  const nowMs = Date.now();
  const nowIso = new Date().toISOString();
  const blockedIps = new Set(
    Array.from(blockedEgressIps)
      .map((item) => normalizeIp(item))
      .filter((item): item is string => typeof item === "string" && item.length > 0),
  );
  const isBlockedByRisk = (ip: string | undefined): boolean => {
    const normalized = normalizeIp(ip);
    if (!normalized) return false;
    if (cfg.taskLedger.allowRateLimitedIpFallback) return false;
    return blockedIps.has(normalized);
  };
  const localEgressIp = normalizeIp(await resolveLocalEgressIp(options.timeoutMs));
  if (localEgressIp) {
    log(`proxy local direct egress IP: ${localEgressIp}`);
  }
  if (blockedIps.size > 0) {
    const preview = Array.from(blockedIps).slice(0, 8).join(", ");
    log(`proxy ip blocked by recent rate-limit events: ${preview}${blockedIps.size > 8 ? " ..." : ""}`);
  }
  const emptyUsageEntry: ProxyNodeUsageEntry = { count: 0, successCount: 0, failCount: 0, consecutiveFailCount: 0 };
  const ensureGroupSelected = async (name: string, expectedIp?: string): Promise<void> => {
    await controller.setGroupProxy(name);
    const selected = await controller.getGroupSelection().catch(() => null);
    if (selected && selected !== name) {
      throw new Error(`proxy_group_mismatch:${name}->${selected}`);
    }
    await waitForProxyEgressIp(controller.proxyServer, expectedIp, options.timeoutMs, options.ipinfoToken);
  };
  const runCfProbeForNode = async (name: string): Promise<{ passed: boolean; reason?: string; cached: boolean }> => {
    if (!cfg.cfProbeEnabled) {
      return { passed: true, cached: false };
    }
    const entry = usage.nodes[name];
    if (isCfProbeFresh(entry, nowMs, cfg.cfProbeCacheTtlMs, cfg.cfProbeUrl)) {
      const passed = entry?.lastCfProbePassed !== false;
      return { passed, reason: passed ? undefined : "cached_cf_probe_failed", cached: true };
    }
    await ensureGroupSelected(name);
    const probe = await probeCfViaProxy(controller.proxyServer, cfg.cfProbeUrl, cfg.cfProbeTimeoutMs);
    const previous = usage.nodes[name] || emptyUsageEntry;
    usage.nodes[name] = {
      ...previous,
      lastCfProbeAt: nowIso,
      lastCfProbePassed: probe.passed,
      lastCfProbeUrl: cfg.cfProbeUrl,
      lastOutcome: probe.passed ? previous.lastOutcome : "fail",
      failCount: probe.passed ? previous.failCount : (previous.failCount || 0) + 1,
      consecutiveFailCount: probe.passed ? previous.consecutiveFailCount : (previous.consecutiveFailCount || 0) + 1,
    };
    return { passed: probe.passed, reason: probe.reason, cached: false };
  };

  if (overrideName) {
    const result = await checkNode(controller, overrideName, options);
    const previous = usage.nodes[overrideName] || emptyUsageEntry;
    if (result.error) {
      usage.nodes[overrideName] = {
        ...previous,
        lastCheckedAt: nowIso,
        lastOutcome: "fail",
        lastLatencyMs: result.latencyMs ?? null,
        lastGeo: compactGeo(result.geo),
        failCount: (previous.failCount || 0) + 1,
        consecutiveFailCount: (previous.consecutiveFailCount || 0) + 1,
      };
      await writeProxyNodeUsageState(usage);
      throw new Error(`proxy_node_unavailable:${overrideName}:${result.error}`);
    }
    const cfProbe = await runCfProbeForNode(overrideName);
    if (!cfProbe.passed) {
      await writeProxyNodeUsageState(usage);
      throw new Error(`proxy_cf_probe_failed:${overrideName}:${cfProbe.reason || "unknown"}`);
    }
    await ensureGroupSelected(overrideName, normalizeIp(result.geo?.ip));
    usage.nodes[overrideName] = {
      ...previous,
      count: (previous.count || 0) + 1,
      lastUsedAt: nowIso,
      lastCheckedAt: nowIso,
      lastOutcome: result.ok ? "ok" : "fallback",
      lastLatencyMs: result.latencyMs ?? null,
      successCount: (previous.successCount || 0) + 1,
      consecutiveFailCount: 0,
      lastIp: normalizeIp(result.geo?.ip),
      lastGeo: compactGeo(result.geo),
    };
    usage.recentSelected = pushRecentUnique(usage.recentSelected, overrideName, cfg.nodeRecentWindow);
    usage.recentSelectedIps = pushRecentUnique(usage.recentSelectedIps, normalizeIp(result.geo?.ip), cfg.nodeRecentWindow);
    await writeProxyNodeUsageState(usage);
    log(
      `proxy override selected: ${overrideName} latency=${result.latencyMs ?? "n/a"}ms egress_ip=${
        normalizeIp(result.geo?.ip) || "?"
      }`,
    );
    return result;
  }

  const nodes = await controller.listGroupNodes();
  const names = nodes.map((node) => node.name).filter((name) => name.trim().length > 0);
  let deferredLogTotal = 0;
  let deferredLogSuppressed = 0;
  const logDeferred = (
    prefix: "proxy cached candidate deferred" | "proxy candidate deferred",
    name: string,
    latencyMs: number | null | undefined,
    ip: string | undefined,
  ): void => {
    deferredLogTotal += 1;
    if (deferredLogTotal <= cfg.nodeDeferLogMax) {
      log(`${prefix} (duplicate egress IP): ${name} latency=${latencyMs ?? "n/a"}ms egress_ip=${ip || "?"}`);
      return;
    }
    deferredLogSuppressed += 1;
  };
  const flushDeferredLogSummary = (): void => {
    if (deferredLogSuppressed > 0) {
      log(`proxy deferred logs suppressed: ${deferredLogSuppressed} more candidates (NODE_DEFER_LOG_MAX=${cfg.nodeDeferLogMax})`);
      deferredLogSuppressed = 0;
    }
  };
  const scoreByNode = new Map<string, number>();
  for (const name of names) {
    scoreByNode.set(name, nodeSelectionScore(name, usage, nowMs, cfg));
  }
  const prioritized = [...names].sort((a, b) => {
    const diff = (scoreByNode.get(a) || 0) - (scoreByNode.get(b) || 0);
    return diff !== 0 ? diff : a.localeCompare(b);
  });
  const orderPreview = prioritized
    .slice(0, 8)
    .map((name) => `${name}(${(scoreByNode.get(name) || 0).toFixed(1)})`)
    .join(", ");
  log(`proxy node order: ${orderPreview}${prioritized.length > 8 ? " ..." : ""}`);
  log(`proxy recent egress IPs: ${usage.recentSelectedIps.length > 0 ? usage.recentSelectedIps.join(", ") : "(none)"}`);

  const cachedFreshCandidates = prioritized
    .map((name) => ({ name, entry: usage.nodes[name] }))
    .filter((item) => isUsageEntryFresh(item.entry, nowMs, cfg.nodeCheckCacheTtlMs));
  const cachedFreshNameSet = new Set(cachedFreshCandidates.map((item) => item.name));
  log(
    `proxy cache status: fresh=${cachedFreshCandidates.length}/${prioritized.length} ttl=${cfg.nodeCheckCacheTtlMs}ms`,
  );

  const cachedDeferredSameIp: NodeCheckResult[] = [];
  const blockedByRiskDeferred: NodeCheckResult[] = [];
  for (const cached of cachedFreshCandidates) {
    const entry = cached.entry;
    if (!entry) continue;
    if (entry.lastOutcome === "fail") continue;
    const cachedGeo = compactGeo(entry.lastGeo);
    const cachedIp = normalizeIp(cachedGeo?.ip || entry.lastIp);
    if (!cachedGeo?.ip && !cachedIp) continue;
    const cachedResult: NodeCheckResult = {
      name: cached.name,
      latencyMs: entry.lastLatencyMs ?? null,
      geo: cachedGeo || (cachedIp ? ({ ip: cachedIp } as GeoInfo) : undefined),
      ok: true,
    };
    const sameAsLocalIp = !!(localEgressIp && cachedIp && sameIp(cachedIp, localEgressIp));
    if (sameAsLocalIp) {
      usage.nodes[cached.name] = {
        ...entry,
        lastCheckedAt: nowIso,
        lastOutcome: "fail",
        lastLatencyMs: entry.lastLatencyMs ?? null,
        lastIp: cachedIp,
        lastGeo: compactGeo(cachedResult.geo),
        failCount: (entry.failCount || 0) + 1,
        consecutiveFailCount: (entry.consecutiveFailCount || 0) + 1,
      };
      log(
        `proxy cached candidate rejected (same as local egress): ${cached.name} latency=${
          cachedResult.latencyMs ?? "n/a"
        }ms egress_ip=${cachedIp || "?"}`,
      );
      continue;
    }
    if (isBlockedByRisk(cachedIp)) {
      blockedByRiskDeferred.push(cachedResult);
      log(`proxy cached candidate deferred (recent ip rate-limit): ${cached.name} egress_ip=${cachedIp || "?"}`);
      continue;
    }
    const hitsRecentIp = cachedIp ? usage.recentSelectedIps.includes(cachedIp) : false;
    if (hitsRecentIp) {
      logDeferred("proxy cached candidate deferred", cached.name, cachedResult.latencyMs, cachedIp);
      cachedDeferredSameIp.push(cachedResult);
      continue;
    }
    const cfProbe = await runCfProbeForNode(cached.name);
    if (!cfProbe.passed) {
      log(`proxy cached candidate rejected (cf probe failed): ${cached.name} reason=${cfProbe.reason || "unknown"}`);
      continue;
    }
    await ensureGroupSelected(cached.name, cachedIp);
    usage.nodes[cached.name] = {
      ...entry,
      count: (entry.count || 0) + 1,
      lastUsedAt: nowIso,
      lastCheckedAt: entry.lastCheckedAt,
      lastOutcome: "ok",
      lastLatencyMs: entry.lastLatencyMs ?? null,
      lastIp: cachedIp,
      lastGeo: compactGeo(cachedResult.geo),
      consecutiveFailCount: 0,
    };
    usage.recentSelected = pushRecentUnique(usage.recentSelected, cached.name, cfg.nodeRecentWindow);
    usage.recentSelectedIps = pushRecentUnique(usage.recentSelectedIps, cachedIp, cfg.nodeRecentWindow);
    await writeProxyNodeUsageState(usage);
    flushDeferredLogSummary();
    log(
      `proxy selected from cache: ${cached.name} latency=${cachedResult.latencyMs ?? "n/a"}ms egress_ip=${cachedIp || "?"}`,
    );
    return cachedResult;
  }

  const checked: NodeCheckResult[] = [];
  const sameIpDeferred: NodeCheckResult[] = [];
  const scanStartedMs = Date.now();
  for (const name of prioritized) {
    if (cachedFreshNameSet.has(name)) {
      continue;
    }
    if (checked.length >= cfg.nodeScanMaxChecks) {
      log(`proxy scan capped by node count: checked=${checked.length} max=${cfg.nodeScanMaxChecks}`);
      break;
    }
    if (Date.now() - scanStartedMs >= cfg.nodeScanMaxMs) {
      log(`proxy scan capped by elapsed time: elapsed=${Date.now() - scanStartedMs}ms max=${cfg.nodeScanMaxMs}ms`);
      break;
    }
    const result = await checkNode(controller, name, options);
    checked.push(result);
    const nodeIp = normalizeIp(result.geo?.ip);
    const previous = usage.nodes[name] || { count: 0, successCount: 0, failCount: 0, consecutiveFailCount: 0 };
    usage.nodes[name] = {
      ...previous,
      lastCheckedAt: nowIso,
      lastOutcome: result.ok ? "ok" : "fail",
      lastLatencyMs: result.latencyMs ?? null,
      lastIp: nodeIp,
      lastGeo: compactGeo(result.geo),
      successCount: result.ok ? (previous.successCount || 0) + 1 : previous.successCount,
      failCount: result.ok ? previous.failCount : (previous.failCount || 0) + 1,
      consecutiveFailCount: result.ok ? 0 : (previous.consecutiveFailCount || 0) + 1,
    };
    if (!result.ok) {
      log(
        `proxy candidate failed: ${name} latency=${result.latencyMs ?? "n/a"}ms error=${result.error || "threshold_miss"} egress_ip=${
          nodeIp || "?"
        }`,
      );
    }
    if (result.ok) {
      if (isBlockedByRisk(nodeIp)) {
        blockedByRiskDeferred.push(result);
        log(`proxy candidate deferred (recent ip rate-limit): ${name} latency=${result.latencyMs ?? "n/a"}ms ip=${nodeIp || "?"}`);
        continue;
      }
      const hitsRecentIp = nodeIp ? usage.recentSelectedIps.includes(nodeIp) : false;
      const hasUncheckedCandidate = checked.length < prioritized.length;
      if (hitsRecentIp && hasUncheckedCandidate) {
        logDeferred("proxy candidate deferred", name, result.latencyMs, nodeIp);
        sameIpDeferred.push(result);
        continue;
      }
      const cfProbe = await runCfProbeForNode(name);
      if (!cfProbe.passed) {
        log(`proxy candidate rejected (cf probe failed): ${name} reason=${cfProbe.reason || "unknown"}`);
        continue;
      }
      await ensureGroupSelected(name, nodeIp);
      usage.nodes[name] = {
        ...usage.nodes[name],
        count: (previous.count || 0) + 1,
        lastUsedAt: nowIso,
        lastCheckedAt: nowIso,
        lastOutcome: "ok",
        lastIp: nodeIp,
        lastGeo: compactGeo(result.geo),
        consecutiveFailCount: 0,
      };
      usage.recentSelected = pushRecentUnique(usage.recentSelected, name, cfg.nodeRecentWindow);
      usage.recentSelectedIps = pushRecentUnique(usage.recentSelectedIps, nodeIp, cfg.nodeRecentWindow);
      await writeProxyNodeUsageState(usage);
      flushDeferredLogSummary();
      log(`proxy selected: ${name} latency=${result.latencyMs ?? "n/a"}ms egress_ip=${nodeIp || "?"}`);
      return result;
    }
  }

  const combinedDeferred = [...cachedDeferredSameIp, ...sameIpDeferred];
  if (combinedDeferred.length > 0) {
    if (!cfg.allowSameEgressIpFallback) {
      const deferredIps = Array.from(
        new Set(
          combinedDeferred
            .map((item) => normalizeIp(item.geo?.ip))
            .filter((item): item is string => typeof item === "string" && item.length > 0),
        ),
      );
      flushDeferredLogSummary();
      throw new Error(
        `proxy_no_distinct_egress_ip: all available candidates share repeated egress IPs (${deferredIps.join(",") || "unknown"})`,
      );
    }
    const sortedDeferred = [...combinedDeferred].sort(
      (a, b) => (a.latencyMs || Number.MAX_SAFE_INTEGER) - (b.latencyMs || Number.MAX_SAFE_INTEGER),
    );
    for (const deferred of sortedDeferred) {
      const cfProbe = await runCfProbeForNode(deferred.name);
      if (!cfProbe.passed) {
        log(`proxy deferred candidate rejected (cf probe failed): ${deferred.name} reason=${cfProbe.reason || "unknown"}`);
        continue;
      }
      const previous = usage.nodes[deferred.name] || emptyUsageEntry;
      const deferredIp = normalizeIp(deferred.geo?.ip);
      await ensureGroupSelected(deferred.name, deferredIp);
      usage.nodes[deferred.name] = {
        ...previous,
        count: (previous.count || 0) + 1,
        successCount: previous.successCount || 0,
        failCount: previous.failCount || 0,
        lastUsedAt: nowIso,
        lastCheckedAt: nowIso,
        lastOutcome: "ok",
        lastLatencyMs: deferred.latencyMs ?? null,
        lastIp: deferredIp,
        lastGeo: compactGeo(deferred.geo),
        consecutiveFailCount: 0,
      };
      usage.recentSelected = pushRecentUnique(usage.recentSelected, deferred.name, cfg.nodeRecentWindow);
      usage.recentSelectedIps = pushRecentUnique(usage.recentSelectedIps, deferredIp, cfg.nodeRecentWindow);
      await writeProxyNodeUsageState(usage);
      flushDeferredLogSummary();
      log(
        `proxy selected from deferred same-ip pool: ${deferred.name} latency=${deferred.latencyMs}ms ip=${
          deferredIp || "?"
        }`,
      );
      return deferred;
    }
  }

  const fallbackPool = checked.filter(
    (item) => !item.error && item.geo?.ip && typeof item.latencyMs === "number",
  );
  const fallbackNoRiskPool = fallbackPool.filter((item) => !isBlockedByRisk(item.geo?.ip));
  if (fallbackNoRiskPool.length === 0 && blockedByRiskDeferred.length > 0 && !cfg.taskLedger.allowRateLimitedIpFallback) {
    await writeProxyNodeUsageState(usage);
    flushDeferredLogSummary();
    const blockedPreview = Array.from(
      new Set(
        blockedByRiskDeferred
          .map((item) => normalizeIp(item.geo?.ip))
          .filter((item): item is string => typeof item === "string" && item.length > 0),
      ),
    )
      .slice(0, 10)
      .join(",");
    throw new Error(`proxy_node_blocked_by_recent_ip_rate_limit:${blockedPreview || "unknown"}`);
  }
  const fallbackFreshIpPool = fallbackPool.filter((item) => {
    const ip = normalizeIp(item.geo?.ip);
    return ip ? !usage.recentSelectedIps.includes(ip) : false;
  });
  const fallbackCandidates = (
    fallbackFreshIpPool.length > 0
      ? fallbackFreshIpPool.filter((item) => !isBlockedByRisk(item.geo?.ip))
      : fallbackNoRiskPool
  ).sort(
    (a, b) => (a.latencyMs || Number.MAX_SAFE_INTEGER) - (b.latencyMs || Number.MAX_SAFE_INTEGER),
  );
  for (const fallback of fallbackCandidates) {
    const cfProbe = await runCfProbeForNode(fallback.name);
    if (!cfProbe.passed) {
      log(`proxy fallback candidate rejected (cf probe failed): ${fallback.name} reason=${cfProbe.reason || "unknown"}`);
      continue;
    }
    const previous = usage.nodes[fallback.name] || emptyUsageEntry;
    const fallbackIp = normalizeIp(fallback.geo?.ip);
    await ensureGroupSelected(fallback.name, fallbackIp);
    usage.nodes[fallback.name] = {
      ...previous,
      count: (previous.count || 0) + 1,
      lastUsedAt: nowIso,
      lastCheckedAt: nowIso,
      lastOutcome: "fallback",
      lastLatencyMs: fallback.latencyMs ?? null,
      successCount: (previous.successCount || 0) + 1,
      lastIp: fallbackIp,
      lastGeo: compactGeo(fallback.geo),
      consecutiveFailCount: 0,
    };
    usage.recentSelected = pushRecentUnique(usage.recentSelected, fallback.name, cfg.nodeRecentWindow);
    usage.recentSelectedIps = pushRecentUnique(usage.recentSelectedIps, fallbackIp, cfg.nodeRecentWindow);
    await writeProxyNodeUsageState(usage);
    flushDeferredLogSummary();
    log(
      `proxy fallback selected due to threshold miss: ${fallback.name} latency=${fallback.latencyMs}ms ip=${fallback.geo?.ip || "?"}`,
    );
    return fallback;
  }

  await writeProxyNodeUsageState(usage);
  flushDeferredLogSummary();
  throw new Error(`proxy_node_unavailable:all checked=${checked.length}`);
}

function shuffleChars(values: string[]): string[] {
  const items = [...values];
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = randomInt(0, i + 1);
    [items[i], items[j]] = [items[j]!, items[i]!];
  }
  return items;
}

function pickChar(alphabet: string): string {
  return alphabet[randomInt(0, alphabet.length)] || alphabet[0] || "a";
}

function randomPassword(): string {
  const lowers = "abcdefghijklmnopqrstuvwxyz";
  const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const specials = "!@#$%^&*_-+=";
  const all = `${lowers}${uppers}${digits}${specials}`;
  const length = randomInt(14, 19);
  const chars = [
    pickChar(lowers),
    pickChar(uppers),
    pickChar(digits),
    pickChar(specials),
  ];
  while (chars.length < length) {
    chars.push(pickChar(all));
  }
  return shuffleChars(chars).join("");
}

function pickRandom<T>(values: T[]): T {
  return values[randomInt(0, values.length)]!;
}

const MAILBOX_NAME_PREFIXES = [
  "alex",
  "sam",
  "jordan",
  "taylor",
  "kai",
  "mika",
  "ren",
  "haru",
  "noa",
  "niko",
  "rei",
  "yuna",
  "mina",
  "leo",
  "luna",
];

const MAILBOX_NAME_SUFFIXES = [
  "lin",
  "park",
  "chen",
  "wong",
  "tan",
  "mori",
  "sato",
  "kato",
  "ito",
  "kim",
  "li",
  "ng",
  "choi",
  "song",
];

function randomMailboxLocalPart(): string {
  const sep = pickRandom(["", "", ".", "_"]);
  const digits = String(randomInt(10, 9999));
  const raw = `${pickRandom(MAILBOX_NAME_PREFIXES)}${sep}${pickRandom(MAILBOX_NAME_SUFFIXES)}${digits}`;
  return raw.replace(/[^a-z0-9._-]/gi, "").toLowerCase();
}

function sanitizeCaptchaText(value: string): string {
  return (value || "").replace(/[^A-Za-z0-9]/g, "").trim();
}

function normalizeCaptchaForSubmit(raw: string, expectedLength = 6): string {
  const cleaned = sanitizeCaptchaText(raw);
  if (cleaned.length <= expectedLength) return cleaned;
  return cleaned.slice(0, expectedLength);
}

function parseFormEncoded(raw: string): Record<string, string> {
  const parsed: Record<string, string> = {};
  const params = new URLSearchParams(raw);
  for (const [key, value] of params.entries()) {
    parsed[key] = value;
  }
  return parsed;
}

function flattenJsonForLengths(value: unknown, prefix = "", out: Record<string, string> = {}): Record<string, string> {
  if (value == null) return out;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    out[prefix || "value"] = String(value);
    return out;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      flattenJsonForLengths(item, prefix ? `${prefix}.${index}` : String(index), out);
    });
    return out;
  }
  if (typeof value === "object") {
    for (const [key, nested] of Object.entries(value as JsonRecord)) {
      flattenJsonForLengths(nested, prefix ? `${prefix}.${key}` : key, out);
    }
  }
  return out;
}

function parseRequestPayload(raw: string, contentType: string): Record<string, string> {
  const normalizedType = contentType.toLowerCase();
  if (!raw) return {};
  if (normalizedType.includes("application/json")) {
    try {
      return flattenJsonForLengths(JSON.parse(raw));
    } catch {
      return {};
    }
  }
  if (normalizedType.includes("application/x-www-form-urlencoded")) {
    return parseFormEncoded(raw);
  }
  // Auth0 form submissions can occasionally omit the content-type header in intercepted requests.
  if (raw.includes("=") && raw.includes("&")) {
    return parseFormEncoded(raw);
  }
  return {};
}

function maskEmailHint(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  const at = trimmed.indexOf("@");
  if (at <= 0) return undefined;
  const local = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1);
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}***@${domain} (localLen=${local.length})`;
}

function splitEmail(email: string): { domain?: string; localLen?: number } {
  const trimmed = (email || "").trim();
  const at = trimmed.indexOf("@");
  if (at <= 0 || at >= trimmed.length - 1) return {};
  return {
    domain: trimmed.slice(at + 1).toLowerCase(),
    localLen: at,
  };
}

function summarizeRiskSignals(requestLog: RequestDiagRecord[], networkLog: NetworkDiagRecord[]): RiskSignalSummary {
  let hasIpRateLimit = false;
  let hasSuspiciousActivity = false;
  let hasExtensibilityError = false;
  let hasInvalidCaptcha = false;
  let suspiciousHitCount = 0;
  let captchaSubmitCount = 0;
  let maxCaptchaLength = 0;
  const snippets = new Set<string>();

  const inspectText = (value: string | undefined): void => {
    const text = (value || "").trim();
    if (!text) return;
    if (/too many signups from the same ip/i.test(text)) hasIpRateLimit = true;
    if (/suspicious activity detected/i.test(text)) hasSuspiciousActivity = true;
    if (/(suspicious activity detected|too many signups from the same ip)/i.test(text)) {
      suspiciousHitCount += 1;
      snippets.add(text.slice(0, 220));
    }
  };

  for (const item of requestLog) {
    if (item.captchaLength != null) {
      captchaSubmitCount += 1;
      maxCaptchaLength = Math.max(maxCaptchaLength, item.captchaLength);
    }
    for (const code of item.responseErrorCodes || []) {
      if (/custom-script-error-code_extensibility_error/i.test(code)) hasExtensibilityError = true;
      if (/invalid-captcha/i.test(code)) hasInvalidCaptcha = true;
    }
    inspectText(item.suspiciousSnippet);
  }

  for (const item of networkLog) {
    for (const code of item.responseErrorCodes || []) {
      if (/custom-script-error-code_extensibility_error/i.test(code)) hasExtensibilityError = true;
      if (/invalid-captcha/i.test(code)) hasInvalidCaptcha = true;
    }
    inspectText(item.suspiciousSnippet);
  }

  return {
    hasIpRateLimit,
    hasSuspiciousActivity,
    hasExtensibilityError,
    hasInvalidCaptcha,
    requestCount: requestLog.length,
    suspiciousHitCount,
    captchaSubmitCount,
    maxCaptchaLength: maxCaptchaLength > 0 ? maxCaptchaLength : undefined,
    snippets: Array.from(snippets).slice(0, 6),
  };
}

function deriveErrorCode(message: string, stage: string, risk: RiskSignalSummary): string {
  const normalized = (message || "").toLowerCase();
  if (risk.hasIpRateLimit) return "too_many_signups_same_ip";
  if (/risk_control_suspicious_activity/i.test(message) || risk.hasSuspiciousActivity) {
    return "risk_control_suspicious_activity";
  }
  if (risk.hasExtensibilityError || /extensibility_error|custom-script-error-code_extensibility_error/i.test(message)) {
    return "auth0_extensibility_error";
  }
  if (risk.hasInvalidCaptcha || /invalid-captcha|captcha failed/i.test(message)) {
    return "invalid_captcha";
  }
  if (/proxy_node_blocked_by_recent_ip_rate_limit/i.test(message)) {
    return "proxy_ip_rate_limit_block";
  }
  if (/timeout/i.test(normalized)) return "timeout";
  if (/network/i.test(normalized)) return "network";
  if (/browser precheck failed/i.test(normalized)) return "browser_precheck_failed";
  if (/verification email not found/i.test(normalized)) return "verification_email_missing";
  if (/signup password step failed/i.test(normalized)) return "signup_password_step_failed";
  if (stage) return `stage_${stage}`;
  return "unknown";
}

function safeJsonStringify(payload: unknown): string {
  try {
    return JSON.stringify(payload);
  } catch {
    return "";
  }
}

function isLikelyTavilyKey(value: string): boolean {
  return /^tvly-[A-Za-z0-9_-]{8,}$/i.test(value.trim());
}

function extractTavilyKeyDeep(node: unknown): string | null {
  if (node == null) return null;
  if (typeof node === "string") {
    return isLikelyTavilyKey(node) ? node.trim() : null;
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = extractTavilyKeyDeep(item);
      if (found) return found;
    }
    return null;
  }
  if (typeof node === "object") {
    const record = node as JsonRecord;
    for (const keyName of ["key", "api_key", "apiKey", "token", "secret", "value"]) {
      const value = record[keyName];
      if (typeof value === "string" && isLikelyTavilyKey(value)) return value.trim();
    }
    for (const value of Object.values(record)) {
      const found = extractTavilyKeyDeep(value);
      if (found) return found;
    }
  }
  return null;
}

async function writeJson(path: URL, payload: unknown): Promise<void> {
  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

type IpProbeScope = "domestic" | "global";

interface IpProbeSnapshot {
  name: string;
  scope: IpProbeScope;
  url: string;
  ip?: string;
  ipCandidates: string[];
  loaded: boolean;
  error?: string;
}

interface IpProbeTarget {
  name: string;
  scope: IpProbeScope;
  url: string;
}

interface GoldenSnapshot {
  url: string;
  rawText?: string;
  ipAddress?: string;
  location?: string;
  timezone?: string;
  isp?: string;
  connection?: string;
  botDetection?: string;
  webRtc?: string;
  navigatorLanguage?: string;
  navigatorLanguages?: string[];
  navigatorUserAgent?: string;
  navigatorPlatform?: string;
  browserTimeZone?: string;
  webdriver?: boolean;
}

interface WebRtcProbeSnapshot {
  candidateCount: number;
  publicIps: string[];
  rawCandidates: string[];
}

interface BrowserPrecheckReport {
  mode: "headed" | "headless";
  checkedAt: string;
  expected: {
    ip?: string;
    locale: string;
    timezone?: string;
    country?: string;
    city?: string;
    proxyNode: string;
  };
  domesticIps: IpProbeSnapshot[];
  globalIps: IpProbeSnapshot[];
  golden: GoldenSnapshot;
  webRtcProbe: WebRtcProbeSnapshot;
  issues: string[];
  passed: boolean;
}

const DOMESTIC_IP_PROBE_TARGETS: IpProbeTarget[] = [
  { name: "ipip", scope: "domestic", url: "https://myip.ipip.net" },
  { name: "cip", scope: "domestic", url: "https://cip.cc" },
  { name: "3322", scope: "domestic", url: "https://ip.3322.net" },
];

const GLOBAL_IP_PROBE_TARGETS: IpProbeTarget[] = [
  { name: "ip_sb", scope: "global", url: "https://api.ip.sb/geoip" },
  { name: "ipinfo", scope: "global", url: "https://ipinfo.io/json" },
];

function parseCsvList(raw: string | undefined): string[] {
  if (!raw || !raw.trim()) return [];
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function normalizeIp(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const cleaned = value.trim().replace(/^\[|\]$/g, "");
  if (!cleaned) return undefined;
  const matchedV4 = cleaned.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (matchedV4?.[0]) return matchedV4[0];
  const matchedV6 = cleaned.match(/\b[0-9a-fA-F:]{2,}\b/);
  if (matchedV6?.[0]) return matchedV6[0];
  return cleaned;
}

function sameIp(a: string | undefined, b: string | undefined): boolean {
  return !!a && !!b && a.trim() === b.trim();
}

function isPublicIpv4(ip: string): boolean {
  const parts = ip.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isFinite(part) || part < 0 || part > 255)) return false;
  const a = parts[0] ?? -1;
  const b = parts[1] ?? -1;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a >= 224) return false;
  return true;
}

function extractPublicIpv4List(text: string): string[] {
  const found = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const unique: string[] = [];
  for (const raw of found) {
    const normalized = normalizeIp(raw);
    if (!normalized || !isPublicIpv4(normalized)) continue;
    if (!unique.includes(normalized)) {
      unique.push(normalized);
    }
  }
  return unique;
}

async function collectIpProbeSnapshot(page: any, target: IpProbeTarget, waitMs = 6500): Promise<IpProbeSnapshot> {
  const expectedHost = new URL(target.url).hostname.toLowerCase();
  await safeGoto(page, target.url);
  await page.waitForLoadState("domcontentloaded", { timeout: 60000 });
  await page.waitForTimeout(waitMs);

  const payload = await page.evaluate(() => {
    const text = document.body?.innerText || "";
    return {
      text,
      url: window.location.href,
    };
  });
  const text = typeof payload.text === "string" ? payload.text : "";
  const ipCandidates = extractPublicIpv4List(text);
  const observedUrl = typeof payload.url === "string" ? payload.url : target.url;
  let observedHost = "";
  try {
    observedHost = new URL(observedUrl).hostname.toLowerCase();
  } catch {
    observedHost = "";
  }
  const onExpectedHost =
    !!observedHost && (observedHost === expectedHost || observedHost.endsWith(`.${expectedHost}`) || expectedHost.endsWith(`.${observedHost}`));

  return {
    name: target.name,
    scope: target.scope,
    url: observedUrl,
    ip: ipCandidates[0],
    ipCandidates: ipCandidates.slice(0, 8),
    loaded: onExpectedHost && (ipCandidates.length > 0 || text.trim().length > 20),
  };
}

async function safeCollectIpProbeSnapshot(page: any, target: IpProbeTarget, waitMs = 6500): Promise<IpProbeSnapshot> {
  try {
    return await collectIpProbeSnapshot(page, target, waitMs);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      name: target.name,
      scope: target.scope,
      url: target.url,
      ipCandidates: [],
      loaded: false,
      error: message,
    };
  }
}

async function collectIpProbeSnapshotInContext(context: any, target: IpProbeTarget, waitMs = 6500): Promise<IpProbeSnapshot> {
  const probePage = await context.newPage();
  try {
    return await safeCollectIpProbeSnapshot(probePage, target, waitMs);
  } finally {
    await probePage.close().catch(() => {});
  }
}

async function collectGoldenSnapshot(page: any): Promise<GoldenSnapshot> {
  await safeGoto(page, "https://fingerprint.goldenowl.ai/");
  await page.waitForLoadState("domcontentloaded", { timeout: 60000 });
  await page.waitForTimeout(9000);

  const payload = await page.evaluate(() => {
    const text = document.body?.innerText || "";
    const lines = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    const normalize = (line: string) => line.toLowerCase().replace(/[:\s]+$/g, "");
    const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const findAfter = (label: string): string => {
      const target = normalize(label);
      for (let i = 0; i < lines.length - 1; i += 1) {
        if (normalize(lines[i] || "") === target) {
          return lines[i + 1] || "";
        }
      }
      return "";
    };
    const findInline = (label: string): string => {
      const escaped = escapeRegex(label);
      const patterns = [
        new RegExp(`${escaped}\\s*[:：]\\s*([^\\n]+)`, "i"),
        new RegExp(`${escaped}\\s+([^\\n]+)`, "i"),
      ];
      for (const pattern of patterns) {
        const matched = text.match(pattern);
        if (matched?.[1]) {
          return matched[1].trim();
        }
      }
      return "";
    };
    const pick = (label: string): string => findAfter(label) || findInline(label);

    return {
      url: window.location.href,
      text,
      ipAddress: pick("IP Address"),
      location: pick("Location"),
      timezone: pick("Timezone"),
      isp: pick("ISP"),
      connection: pick("Connection"),
      botDetection: pick("Bot Detection"),
      webRtc: pick("WebRTC"),
      navigatorLanguage: navigator.language,
      navigatorLanguages: Array.isArray(navigator.languages) ? navigator.languages : [],
      navigatorUserAgent: navigator.userAgent,
      navigatorPlatform: navigator.platform,
      browserTimeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      webdriver: Boolean((navigator as Navigator & { webdriver?: boolean }).webdriver),
    };
  });
  const text = typeof payload.text === "string" ? payload.text : "";
  const ipCandidates = extractPublicIpv4List(text);
  const labeledIp = normalizeIp(typeof payload.ipAddress === "string" ? payload.ipAddress : "");
  const ipAddress = labeledIp && isPublicIpv4(labeledIp) ? labeledIp : ipCandidates[0];

  return {
    url: typeof payload.url === "string" ? payload.url : "https://fingerprint.goldenowl.ai/",
    rawText: text,
    ipAddress,
    location: typeof payload.location === "string" ? payload.location : undefined,
    timezone: typeof payload.timezone === "string" ? payload.timezone : undefined,
    isp: typeof payload.isp === "string" ? payload.isp : undefined,
    connection: typeof payload.connection === "string" ? payload.connection : undefined,
    botDetection: typeof payload.botDetection === "string" ? payload.botDetection : undefined,
    webRtc: typeof payload.webRtc === "string" ? payload.webRtc : undefined,
    navigatorLanguage: typeof payload.navigatorLanguage === "string" ? payload.navigatorLanguage : undefined,
    navigatorLanguages: Array.isArray(payload.navigatorLanguages)
      ? (payload.navigatorLanguages as unknown[]).filter((item: unknown): item is string => typeof item === "string")
      : undefined,
    navigatorUserAgent: typeof payload.navigatorUserAgent === "string" ? payload.navigatorUserAgent : undefined,
    navigatorPlatform: typeof payload.navigatorPlatform === "string" ? payload.navigatorPlatform : undefined,
    browserTimeZone: typeof payload.browserTimeZone === "string" ? payload.browserTimeZone : undefined,
    webdriver: typeof payload.webdriver === "boolean" ? payload.webdriver : undefined,
  };
}

async function collectGoldenAndWebRtc(page: any): Promise<{ golden: GoldenSnapshot; webRtcProbe: WebRtcProbeSnapshot }> {
  const golden = await collectGoldenSnapshot(page);
  const webRtcProbe = await probeWebRtc(page);
  return { golden, webRtcProbe };
}

async function probeWebRtc(page: any): Promise<WebRtcProbeSnapshot> {
  const payload = await page.evaluate(async () => {
    const RTCPeer =
      (window as Window & { RTCPeerConnection?: any }).RTCPeerConnection ||
      (window as Window & { webkitRTCPeerConnection?: any }).webkitRTCPeerConnection;
    if (!RTCPeer) {
      return { rawCandidates: [] as string[] };
    }

    const pc = new RTCPeer({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    const candidates: string[] = [];

    pc.onicecandidate = (event: any) => {
      const candidate = event?.candidate?.candidate;
      if (typeof candidate === "string" && candidate.trim()) {
        candidates.push(candidate.trim());
      }
    };

    pc.createDataChannel("probe");
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await new Promise((resolve) => setTimeout(resolve, 4500));
    pc.close();

    return { rawCandidates: candidates };
  });

  const rawCandidates =
    payload && typeof payload === "object" && Array.isArray((payload as JsonRecord).rawCandidates)
      ? ((payload as JsonRecord).rawCandidates as unknown[]).filter((item): item is string => typeof item === "string")
      : [];

  const publicIps = new Set<string>();
  for (const candidate of rawCandidates) {
    const v4 = candidate.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (const ip of v4) {
      const normalized = normalizeIp(ip);
      if (normalized) publicIps.add(normalized);
    }
  }

  return {
    candidateCount: rawCandidates.length,
    publicIps: Array.from(publicIps),
    rawCandidates: rawCandidates.slice(0, 8),
  };
}

async function runBrowserPrecheck(
  page: any,
  cfg: AppConfig,
  mode: "headed" | "headless",
  selectedProxy: NodeCheckResult,
  locale: string,
): Promise<BrowserPrecheckReport> {
  const expectedGeo: GeoInfo | undefined = selectedProxy.geo;
  const expectedIp = normalizeIp(expectedGeo?.ip);
  const expectedTimezone = expectedGeo?.timezone;
  const expectedLangPrefix = locale.split("-")[0]?.toLowerCase() || "en";
  const context = typeof page?.context === "function" ? page.context() : null;
  const allProbeTargets = [...DOMESTIC_IP_PROBE_TARGETS, ...GLOBAL_IP_PROBE_TARGETS];

  const collectProbeSnapshots = async (): Promise<IpProbeSnapshot[]> => {
    if (context && typeof context.newPage === "function") {
      return await Promise.all(allProbeTargets.map((target) => collectIpProbeSnapshotInContext(context, target, 5500)));
    }
    const snapshots: IpProbeSnapshot[] = [];
    for (const target of allProbeTargets) {
      snapshots.push(await safeCollectIpProbeSnapshot(page, target, 5500));
    }
    return snapshots;
  };

  const collectGoldenBundle = async (): Promise<{ golden: GoldenSnapshot; webRtcProbe: WebRtcProbeSnapshot }> => {
    if (context && typeof context.newPage === "function") {
      const goldenPage = await context.newPage();
      try {
        return await collectGoldenAndWebRtc(goldenPage);
      } finally {
        await goldenPage.close().catch(() => {});
      }
    }
    return await collectGoldenAndWebRtc(page);
  };

  const [probeSnapshots, goldenBundle] = await Promise.all([collectProbeSnapshots(), collectGoldenBundle()]);
  const domesticIps = probeSnapshots.filter((item) => item.scope === "domestic");
  const globalIps = probeSnapshots.filter((item) => item.scope === "global");
  const { golden, webRtcProbe } = goldenBundle;

  const issues: string[] = [];
  const probeIps = [...domesticIps, ...globalIps]
    .map((probe) => probe.ip)
    .filter((ip): ip is string => typeof ip === "string" && ip.length > 0);
  const observedIps = [...probeIps, golden.ipAddress].filter((ip): ip is string => typeof ip === "string" && ip.length > 0);

  for (const probe of [...domesticIps, ...globalIps]) {
    if (!probe.loaded) {
      issues.push(
        `${probe.scope} ip site(${probe.name}) content not loaded${probe.error ? `: ${probe.error}` : ""}`,
      );
    }
    if (!probe.ip) {
      issues.push(`${probe.scope} ip site(${probe.name}) did not expose an IP address`);
    }
  }

  if (!/:\/\/(?:www\.)?fingerprint\.goldenowl\.ai(?:\/|$)/i.test(golden.url)) {
    issues.push(`golden unexpected URL: ${golden.url}`);
  }

  if (probeIps.length > 0) {
    const uniqueObservedProbeIps = Array.from(new Set(probeIps));
    if (uniqueObservedProbeIps.length !== 1) {
      issues.push(`probe IP mismatch across 3 domestic + 2 global sites: ${uniqueObservedProbeIps.join(",")}`);
    }
  }

  if (observedIps.length === 0 && cfg.browserPrecheckStrict) {
    issues.push("precheck could not extract any public IP");
  }
  if (expectedIp) {
    for (const probe of [...domesticIps, ...globalIps]) {
      if (probe.ip && !sameIp(probe.ip, expectedIp)) {
        issues.push(`${probe.scope} ip mismatch(${probe.name}): expected=${expectedIp} got=${probe.ip}`);
      }
    }
    if (golden.ipAddress && !sameIp(golden.ipAddress, expectedIp)) {
      issues.push(`golden ip mismatch: expected=${expectedIp} got=${golden.ipAddress}`);
    }
    if (!observedIps.every((ip) => sameIp(ip, expectedIp))) {
      issues.push(`expected proxy IP not observed in browser precheck: ${expectedIp}`);
    }
  }
  const uniqueObservedIps = Array.from(new Set(observedIps));
  if (uniqueObservedIps.length > 1) {
    issues.push(`cross-site IP mismatch: ${uniqueObservedIps.join(",")}`);
  }

  if (golden.navigatorLanguage && !golden.navigatorLanguage.toLowerCase().startsWith(expectedLangPrefix)) {
    issues.push(`navigator.language mismatch: expected-prefix=${expectedLangPrefix} got=${golden.navigatorLanguage}`);
  }
  if (cfg.browserPrecheckStrict) {
    const firstLang = golden.navigatorLanguages?.[0];
    if (firstLang && !firstLang.toLowerCase().startsWith(expectedLangPrefix)) {
      issues.push(`navigator.languages[0] mismatch: expected-prefix=${expectedLangPrefix} got=${firstLang}`);
    }
  }

  if (golden.botDetection && !/clean/i.test(golden.botDetection)) {
    issues.push(`bot detection is not clean: ${golden.botDetection}`);
  } else if (!golden.botDetection && cfg.browserPrecheckStrict) {
    issues.push("bot detection field missing on goldenowl");
  }
  if (cfg.browserPrecheckCheckHostingProvider && /hosting provider detected/i.test(golden.rawText || "")) {
    issues.push("hosting provider detected on goldenowl");
  }

  if (cfg.requireWebrtcVisible) {
    const webRtc = (golden.webRtc || "").trim();
    if (!webRtc) {
      issues.push("webrtc field missing on goldenowl");
    } else {
      const webRtcDisabled = /disabled|blocked|unavailable/i.test(webRtc);
      if (expectedIp && webRtcProbe.candidateCount > 0 && !webRtcProbe.publicIps.some((ip) => sameIp(ip, expectedIp))) {
        issues.push(
          `webrtc probe candidates do not include expected proxy IP: expected=${expectedIp} probe=${webRtcProbe.publicIps.join(",") || "none"}`,
        );
      }
      if (!webRtcDisabled && cfg.browserPrecheckStrict && webRtcProbe.candidateCount <= 0) {
        issues.push(`webrtc appears enabled but ICE candidates are empty: ${webRtc}`);
      }
    }
  }

  if (golden.webdriver) {
    issues.push("navigator.webdriver is true");
  }

  return {
    mode,
    checkedAt: new Date().toISOString(),
    expected: {
      ip: expectedIp,
      locale,
      timezone: expectedTimezone,
      country: expectedGeo?.country,
      city: expectedGeo?.city,
      proxyNode: selectedProxy.name,
    },
    domesticIps,
    globalIps,
    golden,
    webRtcProbe,
    issues,
    passed: issues.length === 0,
  };
}

function parseBody(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function trunc(value: unknown, max = 240): string {
  try {
    return JSON.stringify(value).slice(0, max);
  } catch {
    return String(value).slice(0, max);
  }
}

async function httpJson<T = unknown>(
  method: string,
  url: string,
  options?: { headers?: Record<string, string>; body?: unknown; timeoutMs?: number },
): Promise<T> {
  const timeoutMs = options?.timeoutMs ?? 25000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    body = JSON.stringify(options.body);
  }

  const headers: Record<string, string> = { ...(options?.headers || {}) };
  if (options?.body !== undefined && typeof options.body !== "string") {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }

  try {
    const resp = await fetch(url, {
      method: method.toUpperCase(),
      headers,
      body,
      signal: controller.signal,
    });

    const text = await resp.text();
    const parsed = parseBody(text);

    if (!resp.ok) {
      throw new Error(`http_failed:${resp.status}:${trunc(parsed)}`);
    }
    return parsed as T;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("http_failed:network:timeout");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function collectStrings(value: unknown, bucket: string[], depth = 0): void {
  if (depth > 8 || value == null) return;
  if (typeof value === "string") {
    bucket.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, bucket, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value as JsonRecord)) collectStrings(item, bucket, depth + 1);
  }
}

function isAllowedVerificationUrl(candidate: string, allowlist: string[]): boolean {
  try {
    const parsed = new URL(candidate);
    const hostname = parsed.hostname.toLowerCase();
    if (!allowlist.some((allowed) => hostname === allowed || hostname.endsWith(`.${allowed}`))) {
      return false;
    }
    return /(verify|verification|email|callback|auth|confirm)/i.test(candidate);
  } catch {
    return false;
  }
}

function extractVerificationLinkFromPayload(payload: unknown, allowlist: string[]): string | null {
  const texts: string[] = [];
  collectStrings(payload, texts);

  for (const text of texts) {
    const normalized = text
      .replaceAll("\\/", "/")
      .replaceAll("&amp;", "&")
      .replaceAll("\\u003d", "=")
      .replaceAll("\\u0026", "&");

    const matches = normalized.match(/https?:\/\/[^\s"'<>`\\)]+/gi) || [];
    for (const raw of matches) {
      const candidate = raw.replace(/[),.;\s]+$/, "");
      if (isAllowedVerificationUrl(candidate, allowlist)) {
        return candidate;
      }
    }

    const hrefMatches = normalized.match(/href=['"]([^'"]+)['"]/gi) || [];
    for (const rawHref of hrefMatches) {
      const match = rawHref.match(/href=['"]([^'"]+)['"]/i);
      const candidate = (match?.[1] || "").trim();
      if (candidate.startsWith("http") && isAllowedVerificationUrl(candidate, allowlist)) {
        return candidate;
      }
    }
  }

  return null;
}

function normalizeModelName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isVisionLikeModel(name: string): boolean {
  return /(vl|vision|ocr)/i.test(name);
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i += 1) dp[i]![0] = i;
  for (let j = 0; j <= n; j += 1) dp[0]![j] = j;

  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + cost);
    }
  }

  return dp[m]![n]!;
}

async function listModels(cfg: AppConfig): Promise<string[]> {
  let payload: { data?: Array<{ id?: string }> } | null = null;
  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      payload = await httpJson<{ data?: Array<{ id?: string }> }>("GET", `${cfg.openaiBaseUrl.replace(/\/+$/, "")}/models`, {
        headers: { Authorization: `Bearer ${cfg.openaiKey}` },
        timeoutMs: 25000,
      });
      break;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const transient = /:429:|:5\d\d:|network|timeout/i.test(message);
      if (!transient || attempt === 5) {
        lastError = error instanceof Error ? error : new Error(message);
        break;
      }
      const waitMs = 1200 * attempt;
      log(`models endpoint transient error, retry in ${waitMs}ms (attempt=${attempt})`);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }
  if (!payload) {
    throw lastError || new Error("failed to load models");
  }

  const models: string[] = [];
  for (const item of payload.data || []) {
    if (item && typeof item.id === "string" && item.id.trim()) {
      models.push(item.id.trim());
    }
  }
  return models;
}

function resolveModelName(preferred: string, allModels: string[]): string {
  if (allModels.includes(preferred)) {
    return preferred;
  }

  const lowerPreferred = preferred.toLowerCase();
  const caseInsensitive = allModels.find((name) => name.toLowerCase() === lowerPreferred);
  if (caseInsensitive) {
    return caseInsensitive;
  }

  const visionModels = allModels.filter(isVisionLikeModel);
  if (visionModels.length === 0) {
    throw new Error("No vision/OCR models found in /models response");
  }

  const normalizedPreferred = normalizeModelName(preferred);
  const normalizedExact = visionModels.find((name) => normalizeModelName(name) === normalizedPreferred);
  if (normalizedExact) {
    return normalizedExact;
  }

  let best: { name: string; dist: number } | null = null;
  for (const name of visionModels) {
    const dist = levenshtein(normalizedPreferred, normalizeModelName(name));
    if (!best || dist < best.dist) {
      best = { name, dist };
    }
  }

  const maxAllowedDist = Math.max(2, Math.floor(normalizedPreferred.length * 0.25));
  if (best && best.dist <= maxAllowedDist) {
    return best.name;
  }

  throw new Error(
    `MODEL_NAME not found in related vision/OCR models: requested=${preferred}, candidates=${visionModels.join(", ")}`,
  );
}

class CaptchaSolver {
  private readonly cfg: AppConfig;

  private readonly model: string;

  constructor(cfg: AppConfig, model: string) {
    this.cfg = cfg;
    this.model = model;
  }

  private readonly promptVariants = [
    "OCR captcha text from this image. Return only visible letters and digits, no explanation.",
    "Read this captcha exactly (case-sensitive). Reply with only the letters and numbers.",
    "Return only the captcha code from this image, no spaces, no punctuation.",
  ];

  private extractTextFromResponses(payload: unknown): string {
    if (!payload || typeof payload !== "object") return "";
    const record = payload as JsonRecord;

    const outputText = record.output_text;
    if (typeof outputText === "string" && outputText.trim()) {
      return outputText;
    }

    const output = record.output;
    if (!Array.isArray(output)) return "";

    for (const item of output) {
      if (!item || typeof item !== "object") continue;
      const content = (item as JsonRecord).content;
      if (!Array.isArray(content)) continue;
      for (const piece of content) {
        if (!piece || typeof piece !== "object") continue;
        const text = (piece as JsonRecord).text;
        if (typeof text === "string" && text.trim()) {
          return text;
        }
      }
    }

    return "";
  }

  private pickBestCandidate(candidates: string[]): string {
    const cleaned = candidates.map((v) => sanitizeCaptchaText(v)).filter((v) => v.length > 0);
    if (cleaned.length === 0) return "";

    const inRange = cleaned.filter((v) => v.length >= 4 && v.length <= 10);
    if (inRange.length === 0) return "";

    const exactSix = inRange.filter((v) => v.length === 6);
    const pool = exactSix.length > 0 ? exactSix : inRange;

    const counts = new Map<string, number>();
    for (const item of pool) counts.set(item, (counts.get(item) || 0) + 1);

    let best = pool[0]!;
    let bestCount = counts.get(best) || 0;
    for (const item of pool) {
      const current = counts.get(item) || 0;
      if (current > bestCount) {
        best = item;
        bestCount = current;
      }
    }
    return best;
  }

  private async callResponsesWithPrompt(pngData: Buffer, prompt: string): Promise<string> {
    const dataUrl = `data:image/png;base64,${pngData.toString("base64")}`;
    const payload = {
      model: this.model,
      temperature: 0,
      input: [
        {
          role: "user",
          content: [
            { type: "input_text", text: prompt },
            { type: "input_image", image_url: dataUrl },
          ],
        },
      ],
    };

    const response = await httpJson("POST", `${this.cfg.openaiBaseUrl.replace(/\/+$/, "")}/responses`, {
      headers: {
        Authorization: `Bearer ${this.cfg.openaiKey}`,
        "Content-Type": "application/json",
      },
      body: payload,
      timeoutMs: Math.max(10000, this.cfg.ocrRequestTimeoutMs),
    });

    return sanitizeCaptchaText(this.extractTextFromResponses(response));
  }

  private async callResponses(pngData: Buffer): Promise<string> {
    const results: string[] = [];
    let lastError: Error | null = null;

    for (const prompt of this.promptVariants) {
      try {
        const text = await this.callResponsesWithPrompt(pngData, prompt);
        if (text) results.push(text);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, 120));
    }

    const picked = this.pickBestCandidate(results);
    if (picked) {
      log(`captcha OCR candidates (${this.model}): ${results.join(", ")} -> ${picked}`);
      return picked;
    }

    if (lastError) {
      throw lastError;
    }
    return "";
  }

  private isTransient(reason: string): boolean {
    const lower = reason.toLowerCase();
    return [":429:", ":500:", ":502:", ":503:", ":504:", ":520:", ":521:", ":522:", "timeout", "network", "temporarily unavailable", "rate limit"].some((k) =>
      lower.includes(k),
    );
  }

  private isPermanentModelError(reason: string): boolean {
    const lower = reason.toLowerCase();
    return [":400:", ":401:", ":403:", ":422:", "model_not_found", "invalid_model_error", "forbidden", "bad request"].some(
      (k) => lower.includes(k),
    );
  }

  async solve(pngData: Buffer): Promise<string> {
    const deadline = Date.now() + this.cfg.ocrRetryWindowMs;
    let cooldownMs = this.cfg.ocrInitialCooldownMs;
    const errors: string[] = [];
    let blocked = false;
    let round = 0;

    while (Date.now() < deadline) {
      round += 1;
      let transientSeen = false;

      try {
        const solved = await this.callResponses(pngData);
        if (solved.length >= 4 && solved.length <= 10) {
          log(`captcha solved by ${this.model}: ${solved}`);
          return solved;
        }
        errors.push(`${this.model}:invalid_result:${solved}`);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        errors.push(`${this.model}:${reason}`);

        if (this.isPermanentModelError(reason)) {
          blocked = true;
        }
        if (this.isTransient(reason)) {
          transientSeen = true;
        }
      }

      if (blocked) break;
      if (!transientSeen) break;

      const waitMs = Math.min(cooldownMs, Math.max(0, deadline - Date.now()));
      if (waitMs <= 0) break;
      log(`captcha OCR throttled/upstream unstable (round=${round}), wait ${waitMs}ms`);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      cooldownMs = Math.min(Math.floor(cooldownMs * 1.7), this.cfg.ocrMaxCooldownMs);
    }

    throw new Error(
      `captcha OCR failed within retry window. models=1 blocked=${blocked ? 1 : 0} last_errors=${errors
        .slice(-8)
        .join(" | ")}`,
    );
  }
}

async function createDuckmailSession(cfg: AppConfig): Promise<DuckmailSession> {
  const baseUrl = cfg.duckmailBaseUrl.replace(/\/+$/, "");
  const headers: Record<string, string> = {};
  if (cfg.duckmailApiKey) {
    headers.Authorization = `Bearer ${cfg.duckmailApiKey}`;
  }

  const domainsResp = await httpJson<{ "hydra:member"?: Array<{ domain?: string }> }>("GET", `${baseUrl}/domains`, {
    headers,
  });

  const domains = (domainsResp["hydra:member"] || [])
    .map((item) => (item?.domain || "").trim())
    .filter((domain) => domain.length > 0);

  if (domains.length === 0) {
    throw new Error("duckmail returned empty domain list");
  }

  let pickedDomain = cfg.duckmailDomain;
  if (pickedDomain) {
    const matched = domains.find((item) => item.toLowerCase() === pickedDomain!.toLowerCase());
    if (!matched) {
      throw new Error(`duckmail requested domain not found: ${pickedDomain}`);
    }
    pickedDomain = matched;
  } else {
    pickedDomain = pickRandom(domains);
  }

  const localPart = randomMailboxLocalPart();
  const address = `${localPart}@${pickedDomain}`;
  const mailboxPassword = randomPassword();

  const created = await httpJson<JsonRecord>("POST", `${baseUrl}/accounts`, {
    headers: { ...headers, "Content-Type": "application/json" },
    body: { address, password: mailboxPassword },
  });

  let accountId = typeof created.id === "string" ? created.id : "";

  const tokenResp = await httpJson<JsonRecord>("POST", `${baseUrl}/token`, {
    headers: { "Content-Type": "application/json" },
    body: { address, password: mailboxPassword },
  });

  const token = typeof tokenResp.token === "string" ? tokenResp.token : "";
  if (!accountId && typeof tokenResp.id === "string") {
    accountId = tokenResp.id;
  }

  if (!token) throw new Error("duckmail token response missing token");
  if (!accountId) throw new Error("duckmail account id missing");

  return {
    baseUrl,
    address,
    accountId,
    token,
  };
}

async function waitForVerificationLink(
  mailbox: DuckmailSession,
  timeoutMs: number,
  pollMs: number,
  allowlist: string[],
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  const seen = new Set<string>();

  while (Date.now() < deadline) {
    const messages = await httpJson<JsonRecord>("GET", `${mailbox.baseUrl}/messages`, {
      headers: { Authorization: `Bearer ${mailbox.token}` },
    });

    const items = (messages["hydra:member"] as unknown[]) || [];

    for (const item of items) {
      const fromSummary = extractVerificationLinkFromPayload(item, allowlist);
      if (fromSummary) return fromSummary;

      if (!item || typeof item !== "object") continue;
      const messageId = String((item as JsonRecord).id || "").trim();
      if (!messageId || seen.has(messageId)) continue;
      seen.add(messageId);

      const detail = await httpJson("GET", `${mailbox.baseUrl}/messages/${encodeURIComponent(messageId)}`, {
        headers: { Authorization: `Bearer ${mailbox.token}` },
      });

      const fromDetail = extractVerificationLinkFromPayload(detail, allowlist);
      if (fromDetail) return fromDetail;
    }

    await new Promise((resolve) => setTimeout(resolve, Math.max(200, pollMs)));
  }

  return null;
}

async function verifyVerificationLanding(page: any): Promise<boolean> {
  await page.waitForTimeout(2200);
  const url = page.url();
  if (/auth\.tavily\.com|app\.tavily\.com/i.test(url) && !/\/u\/signup\/identifier/i.test(url)) {
    return true;
  }

  const text = await page.evaluate(() => (document.body?.innerText || "").slice(0, 5000));
  return /(email|account).{0,30}(verified|confirmed|activated)|verification.{0,20}(complete|success)/i.test(text);
}

async function fillInput(page: any, selector: string, value: string): Promise<void> {
  await page.waitForSelector(selector, { timeout: 30000 });
  const input = page.locator(selector).first();
  await input.fill("");
  await input.type(value, { delay: randomInt(55, 135) });
}

async function safeGoto(page: any, url: string, timeout = 90000): Promise<void> {
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/NS_BINDING_ABORTED|interrupted by another navigation|frame was detached/i.test(message)) {
      log(`safeGoto transient (${url}): ${message.split("\n")[0]}`);
      await page.waitForTimeout(900);
      return;
    }
    throw error;
  }
}

async function waitHomeStable(page: any, stableMs = 6000): Promise<boolean> {
  const step = 800;
  const rounds = Math.max(1, Math.floor(stableMs / step));
  for (let i = 0; i < rounds; i += 1) {
    const url = page.url();
    if (!/app\.tavily\.com\/home/i.test(url) || /auth\.tavily\.com/i.test(url)) {
      return false;
    }
    await page.waitForTimeout(step);
  }
  return true;
}

async function getProcessedCaptchaPng(page: any): Promise<Buffer> {
  await page.waitForSelector('img[alt="captcha"]', { timeout: 30000 });
  const src = await page.$eval('img[alt="captcha"]', (el: any) => String(el.src || ""));
  const match = src.match(/^data:image\/svg\+xml;base64,(.+)$/i);
  if (match && match[1]) {
    try {
      const svgBinary = Buffer.from(match[1], "base64");
      const rendered = new Resvg(svgBinary, {
        fitTo: { mode: "width", value: 900 },
        background: "white",
      }).render();
      return Buffer.from(rendered.asPng());
    } catch {
      // fallback to screenshot path
    }
  }

  const image = page.locator('img[alt="captcha"]').first();
  const screenshot = await image.screenshot({ type: "png" });
  return Buffer.from(screenshot);
}

async function clickSubmit(page: any): Promise<void> {
  await page.waitForTimeout(randomInt(220, 780));
  const btn = page.locator('button[type="submit"], input[type="submit"]').first();
  try {
    await btn.click({ timeout: 10000 });
    return;
  } catch {
    await page.evaluate(() => {
      const form = document.querySelector('form[data-form-primary="true"], form') as HTMLFormElement | null;
      const submitEl = form?.querySelector('button[type="submit"], input[type="submit"]') as
        | HTMLButtonElement
        | HTMLInputElement
        | null;
      if (submitEl) {
        submitEl.click();
      } else if (form?.requestSubmit) {
        form.requestSubmit();
      } else if (form) {
        form.submit();
      }
    });
  }
}

async function clickSignUp(page: any): Promise<void> {
  const direct = page.locator('a[href*="/u/signup/identifier"]').first();
  if ((await direct.count()) > 0) {
    await direct.click();
    return;
  }

  const clicked = await page.evaluate(() => {
    const links = Array.from(document.querySelectorAll("a"));
    const target = links.find((el) => /sign up/i.test(el.textContent || ""));
    if (!target) return false;
    (target as HTMLAnchorElement).click();
    return true;
  });

  if (!clicked) {
    throw new Error("Sign up entry not found");
  }
}

async function solveCaptchaForm(
  page: any,
  solver: CaptchaSolver,
  formKind: "signup" | "login",
  email: string,
  maxRounds: number,
): Promise<void> {
  const emailSelector = formKind === "signup" ? 'input[name="email"]' : 'input[name="username"]';
  const successUrlPattern =
    formKind === "signup"
      ? /\/u\/signup\/password|app\.tavily\.com\/home/i
      : /\/u\/login\/password|app\.tavily\.com\/home/i;

  for (let attempt = 1; attempt <= maxRounds; attempt += 1) {
    let hasCaptcha = (await page.locator('img[alt="captcha"]').count()) > 0;
    if (!hasCaptcha) {
      try {
        await page.waitForSelector('img[alt="captcha"]', { timeout: 2500 });
        hasCaptcha = true;
      } catch {
        hasCaptcha = false;
      }
    }

    let previousCaptchaSrc = "";
    if (hasCaptcha) {
      previousCaptchaSrc = await page.$eval('img[alt="captcha"]', (el: any) => String(el.src || ""));
      const pngData = await getProcessedCaptchaPng(page);
      const solved = await solver.solve(pngData);
      const captchaCode = normalizeCaptchaForSubmit(solved);
      if (solved.length !== captchaCode.length) {
        log(`${formKind} captcha normalized from len=${solved.length} to len=${captchaCode.length}`);
      }
      if ((await page.locator('input[name="captcha"]').count()) > 0) {
        await fillInput(page, 'input[name="captcha"]', captchaCode);
      }
    }

    await fillInput(page, emailSelector, email);

    const previousUrl = page.url();
    await clickSubmit(page);

    try {
      await page.waitForURL(successUrlPattern, { timeout: 10000 });
      return;
    } catch {
      // continue with explicit checks
    }

    await page.waitForTimeout(2200);
    const currentUrl = page.url();
    if (successUrlPattern.test(currentUrl)) {
      return;
    }
    if (currentUrl !== previousUrl) {
      log(`${formKind} flow moved to ${currentUrl} after captcha submit`);
      return;
    }

    const currentCaptchaSrc = hasCaptcha
      ? ((await page
          .$eval('img[alt="captcha"]', (el: any) => String(el.src || ""))
          .catch(() => "")) || "")
      : "";

    if (hasCaptcha && currentCaptchaSrc && currentCaptchaSrc !== previousCaptchaSrc) {
      log(`${formKind} captcha refreshed after attempt ${attempt}, retrying`);
      continue;
    }

    log(`${formKind} captcha rejected on attempt ${attempt}, retrying`);
  }

  throw new Error(`${formKind} captcha failed after ${maxRounds} rounds`);
}

async function completeSignup(page: any, solver: CaptchaSolver, email: string, password: string, cfg: AppConfig): Promise<void> {
  await safeGoto(page, "https://app.tavily.com/api/auth/login");
  await page.waitForURL(/auth\.tavily\.com/i, { timeout: 90000 });

  if (!/\/u\/signup\/identifier|\/u\/signup\/password/i.test(page.url())) {
    if (/\/u\/login\/identifier/i.test(page.url())) {
      await clickSignUp(page);
    } else {
      await safeGoto(page, "https://auth.tavily.com/u/signup/identifier");
    }
  }

  await page.waitForURL(/\/u\/signup\/identifier|\/u\/signup\/password/i, { timeout: 90000 });
  if (/\/u\/signup\/identifier/i.test(page.url())) {
    await solveCaptchaForm(page, solver, "signup", email, cfg.maxCaptchaRounds);
    await page.waitForTimeout(1200);
  }

  if (/app\.tavily\.com\/home/i.test(page.url())) {
    return;
  }
  if (!/\/u\/signup\/password/i.test(page.url())) {
    throw new Error(`signup did not reach password step, current=${page.url()}`);
  }

  if (/\/u\/signup\/password/i.test(page.url())) {
    for (let attempt = 1; attempt <= cfg.maxCaptchaRounds; attempt += 1) {
      let previousCaptchaSrc = "";
      if (attempt === 1) {
        await writeFile(new URL("signup_password_before.html", OUTPUT_DIR), await page.content(), "utf8");
        const snap = await page.screenshot({ fullPage: true });
        await writeFile(new URL("signup_password_before.png", OUTPUT_DIR), snap);
      }

      const passwordInputs = page.locator('input[type="password"]');
      const pwdCount = await passwordInputs.count();
      if (pwdCount === 0) {
        await fillInput(page, 'input[name="password"]', password);
      } else {
        for (let i = 0; i < pwdCount; i += 1) {
          const input = passwordInputs.nth(i);
          await input.fill("");
          await input.type(password, { delay: randomInt(55, 135) });
        }
      }

      let hasCaptchaInput = (await page.locator('input[name="captcha"]').count()) > 0;
      if (!hasCaptchaInput) {
        const waitTimeout = attempt === 1 ? 4200 : 1600;
        await page.waitForSelector('input[name="captcha"]', { timeout: waitTimeout }).catch(() => {});
        hasCaptchaInput = (await page.locator('input[name="captcha"]').count()) > 0;
      }

      if (hasCaptchaInput) {
        previousCaptchaSrc = await page
          .$eval('img[alt="captcha"]', (el: any) => String(el.src || ""))
          .catch(() => "");
        const pngData = await getProcessedCaptchaPng(page);
        const solved = await solver.solve(pngData);
        const code = normalizeCaptchaForSubmit(solved);
        if (solved.length !== code.length) {
          log(`signup password captcha normalized from len=${solved.length} to len=${code.length}`);
        }
        await fillInput(page, 'input[name="captcha"]', code);
      } else if (attempt === 1) {
        // Avoid a blind first submit before captcha widget hydration has settled.
        log("signup password captcha input missing on first attempt, retrying after wait");
        await page.waitForTimeout(1200);
        continue;
      }

      const passwordDiag = await page.evaluate(() => {
        const value = (document.querySelector('input[name="password"]') as HTMLInputElement | null)?.value || "";
        return {
          len: value.length,
          lower: /[a-z]/.test(value),
          upper: /[A-Z]/.test(value),
          digit: /\d/.test(value),
          special: /[^A-Za-z0-9]/.test(value),
        };
      });
      log(`signup password diag attempt=${attempt} ${JSON.stringify(passwordDiag)}`);

      await clickSubmit(page);
      await page.waitForTimeout(2200);

      if (attempt === 1) {
        await writeFile(new URL("signup_password_after1.html", OUTPUT_DIR), await page.content(), "utf8");
        const snap = await page.screenshot({ fullPage: true });
        await writeFile(new URL("signup_password_after1.png", OUTPUT_DIR), snap);
      }

      if (!/\/u\/signup\/password/i.test(page.url())) {
        return;
      }

      const currentCaptchaSrc =
        (await page
          .$eval('img[alt="captcha"]', (el: any) => String(el.src || ""))
          .catch(() => "")) || "";
      const captchaRefreshed = !!previousCaptchaSrc && !!currentCaptchaSrc && currentCaptchaSrc !== previousCaptchaSrc;
      if (captchaRefreshed) {
        log(`signup password captcha refreshed after attempt ${attempt}, retrying`);
      }

      const formErrors: string[] = await page.evaluate(() => {
        const visible = (el: Element): boolean => {
          const style = window.getComputedStyle(el as HTMLElement);
          return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
        };
        const nodes = Array.from(
          document.querySelectorAll(
            '.ulp-error-info,[data-error-code],#error-element-captcha,[role="alert"],.error,[class*="error"]',
          ),
        );
        const texts = nodes
          .filter(visible)
          .map((el) => (el.textContent || "").trim())
          .filter((t) => t.length > 0)
          .slice(0, 6);
        return texts;
      });
      log(`signup password step still present after submit (attempt=${attempt}) errors=${formErrors.join(" | ") || "n/a"}`);
      const hasSuspiciousMarker = formErrors.some((text) => /Suspicious activity detected/i.test(text));
      if (hasSuspiciousMarker) {
        if (attempt >= cfg.maxCaptchaRounds) {
          throw new Error("risk_control_suspicious_activity");
        }
        log(`signup suspicious marker observed on attempt ${attempt}, retrying`);
        continue;
      }
      if (captchaRefreshed) {
        continue;
      }
      if (attempt < cfg.maxCaptchaRounds) {
        log(`signup password submission not accepted on attempt ${attempt}, retrying`);
        continue;
      }
    }
    throw new Error(`signup password step failed after ${cfg.maxCaptchaRounds} attempts`);
  }
}

async function loginAndReachHome(page: any, solver: CaptchaSolver, email: string, password: string, cfg: AppConfig): Promise<void> {
  for (let cycle = 1; cycle <= 5; cycle += 1) {
    await safeGoto(page, "https://app.tavily.com/home");
    await page.waitForTimeout(1200);

    if (/app\.tavily\.com\/home/i.test(page.url()) && !/auth\.tavily\.com/i.test(page.url())) {
      if (await waitHomeStable(page, 6500)) {
        return;
      }
    }

    await safeGoto(page, "https://app.tavily.com/api/auth/login");
    await page.waitForTimeout(900);

    if (/\/u\/login\/identifier/i.test(page.url())) {
      await solveCaptchaForm(page, solver, "login", email, cfg.maxCaptchaRounds);
    }

    if ((await page.locator('input[name="password"]').count()) > 0) {
      await fillInput(page, 'input[name="password"]', password);
      await clickSubmit(page);
      await page.waitForTimeout(1400);
    }

    const current = page.url();
    if (/app\.tavily\.com\/home/i.test(current) && !/auth\.tavily\.com/i.test(current)) {
      if (await waitHomeStable(page, 5000)) {
        return;
      }
    }

    log(`login cycle ${cycle} not yet on home, current=${current}`);
  }

  throw new Error(`login flow did not reach home, last_url=${page.url()}`);
}

async function getDefaultApiKey(page: any, cfg: AppConfig): Promise<string | null> {
  await page.waitForLoadState("domcontentloaded", { timeout: 30000 });

  for (let round = 1; round <= 6; round += 1) {
    await page.waitForTimeout(1200);

    const fromDom = await page.evaluate(() => {
      const pick = (value: unknown): string | null => {
        if (typeof value !== "string") return null;
        const match = value.match(/tvly-[A-Za-z0-9_-]{8,}/i);
        return match ? match[0] : null;
      };

      const selectOption = Array.from(document.querySelectorAll("option"))
        .map((el) => (el as HTMLOptionElement).value || "")
        .map((v) => pick(v))
        .find((v) => !!v);
      if (selectOption) return { key: selectOption, source: "dom-option" };

      const inputVal = Array.from(document.querySelectorAll("input,textarea"))
        .map((el) => {
          const node = el as HTMLInputElement | HTMLTextAreaElement;
          return [node.value, node.getAttribute("value"), node.getAttribute("placeholder")];
        })
        .flat()
        .map((v) => pick(v))
        .find((v) => !!v);
      if (inputVal) return { key: inputVal, source: "dom-input" };

      const textMatch = pick(document.body?.innerText || "");
      if (textMatch) return { key: textMatch, source: "dom-text" };
      return { key: null, source: "none" };
    });

    if (fromDom?.key && isLikelyTavilyKey(fromDom.key)) {
      log(`default api key found from ${fromDom.source}`);
      return fromDom.key;
    }

    const pageResult = await page.evaluate(
      async ({ keyName, keyLimit }: { keyName: string; keyLimit: number }) => {
        const isLikelyKey = (value: string): boolean => /^tvly-[A-Za-z0-9_-]{8,}$/i.test((value || "").trim());
        const extractKey = (node: any): string | null => {
          if (!node) return null;
          if (typeof node === "string") return isLikelyKey(node) ? node.trim() : null;
          if (Array.isArray(node)) {
            for (const item of node) {
              const key = extractKey(item);
              if (key) return key;
            }
            return null;
          }
          if (typeof node === "object") {
            for (const k of ["key", "api_key", "apiKey", "token", "secret", "value"]) {
              const v = node[k];
              if (typeof v === "string" && isLikelyKey(v)) return v.trim();
            }
            for (const v of Object.values(node)) {
              const key = extractKey(v);
              if (key) return key;
            }
          }
          return null;
        };

        const parse = async (res: Response) => {
          const text = await res.text();
          let body: unknown;
          try {
            body = JSON.parse(text);
          } catch {
            body = text;
          }
          return { ok: res.ok, status: res.status, body };
        };

        const safeFetch = async (url: string, init?: RequestInit) => {
          try {
            const resp = await fetch(url, { credentials: "include", ...(init || {}) });
            return await parse(resp);
          } catch (error) {
            return { ok: false, status: 0, body: { error: String(error) } };
          }
        };

        const oidCandidates = new Set<string>();
        const collectOidFromNode = (node: any) => {
          if (!node) return;
          if (Array.isArray(node)) {
            node.forEach(collectOidFromNode);
            return;
          }
          if (typeof node !== "object") return;
          for (const [k, v] of Object.entries(node)) {
            if (typeof v === "string" && /(^|_)oid$|organization.?id|org.?id|selected.?oid/i.test(k) && v.trim()) {
              oidCandidates.add(v.trim());
            } else {
              collectOidFromNode(v);
            }
          }
        };

        const fromStorage = [localStorage.getItem("selected_oid"), sessionStorage.getItem("selected_oid")];
        for (const oid of fromStorage) {
          if (oid && oid.trim()) oidCandidates.add(oid.trim());
        }

        const account = await safeFetch("/api/account");
        collectOidFromNode(account.body);

        const endpoints: string[] = [];
        for (const oid of oidCandidates) endpoints.push(`/api/keys?oid=${encodeURIComponent(oid)}`);
        endpoints.push("/api/keys?oid=");
        endpoints.push("/api/keys");

        const debug: Array<{ step: string; status: number }> = [];
        for (const endpoint of endpoints) {
          const listed = await safeFetch(endpoint);
          debug.push({ step: `list:${endpoint}`, status: listed.status });
          const existing = extractKey(listed.body);
          if (existing) return { key: existing, debug };

          const createPayload = {
            name: keyName,
            limit: keyLimit > 0 ? keyLimit : 2147483647,
            key_type: "development",
            search_egress_policy: "allow_external",
          };
          const created = await safeFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(createPayload),
          });
          debug.push({ step: `create:${endpoint}`, status: created.status });
          const createdKey = extractKey(created.body);
          if (createdKey) return { key: createdKey, debug };

          const listedAgain = await safeFetch(endpoint);
          debug.push({ step: `list2:${endpoint}`, status: listedAgain.status });
          const listedAgainKey = extractKey(listedAgain.body);
          if (listedAgainKey) return { key: listedAgainKey, debug };
        }

        return { key: null, debug };
      },
      { keyName: cfg.keyName, keyLimit: cfg.keyLimit },
    );

    const debugInfo = pageResult && typeof pageResult === "object" ? (pageResult as JsonRecord).debug : null;
    if (debugInfo) {
      log(`api key page-flow debug round=${round} ${trunc(debugInfo, 600)}`);
    }

    if (pageResult && typeof pageResult === "object") {
      const key = (pageResult as JsonRecord).key;
      if (typeof key === "string" && isLikelyTavilyKey(key)) {
        return key;
      }
    }
  }

  return null;
}

async function confirmHumanControl(cfg: AppConfig, email: string, stage: string): Promise<void> {
  if (!cfg.humanConfirmBeforeSignup) return;

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("human confirmation requires an interactive terminal (TTY)");
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (
      await rl.question(
        `Manual check ${stage}. Type "${cfg.humanConfirmText}" to continue for ${email}, or anything else to abort: `,
      )
    ).trim();

    if (answer !== cfg.humanConfirmText) {
      throw new Error(`human confirmation rejected (expected "${cfg.humanConfirmText}")`);
    }
  } finally {
    rl.close();
  }
}

function resolveChromeExecutablePath(raw: string | undefined): string | undefined {
  const trimmed = (raw || "").trim();
  if (trimmed) return trimmed;
  if (process.platform === "darwin") {
    return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  }
  return undefined;
}

function loadConfig(): AppConfig {
  const envRunMode = parseRunMode(process.env.RUN_MODE);
  const envBrowserEngine = parseBrowserEngine(process.env.BROWSER_ENGINE) || "camoufox";
  const envInspectBrowserEngine = parseBrowserEngine(process.env.INSPECT_BROWSER_ENGINE) || "chrome";
  const fallbackRunMode: RunMode = toBool(process.env.HEADLESS, false) ? "headless" : "headed";
  const verifyHostAllowlist = parseCsvList(process.env.VERIFY_HOST_ALLOWLIST).map((host) => host.toLowerCase());
  const defaultApiPort = 39090 + randomInt(0, 2000);
  const defaultMixedPort = 49090 + randomInt(0, 2000);

  return {
    openaiBaseUrl: mustEnv("OPENAI_BASE_URL"),
    openaiKey: mustEnv("OPENAI_KEY"),
    preferredModel: mustEnv("MODEL_NAME"),
    runMode: envRunMode || fallbackRunMode,
    browserEngine: envBrowserEngine,
    inspectBrowserEngine: envInspectBrowserEngine,
    chromeExecutablePath: resolveChromeExecutablePath(process.env.CHROME_EXECUTABLE_PATH),
    chromeNativeAutomation: toBool(process.env.CHROME_NATIVE_AUTOMATION, true),
    chromeStealthJsEnabled: toBool(process.env.CHROME_STEALTH_JS_ENABLED, false),
    chromeWebrtcHardened: toBool(process.env.CHROME_WEBRTC_HARDENED, true),
    chromeProfileDir: path.resolve(process.env.CHROME_PROFILE_DIR || path.join(OUTPUT_PATH, "chrome-profile")),
    chromeRemoteDebuggingPort: Math.max(0, toInt(process.env.CHROME_REMOTE_DEBUGGING_PORT, 0)),
    slowMoMs: toInt(process.env.SLOWMO_MS, 50),
    maxCaptchaRounds: toInt(process.env.MAX_CAPTCHA_ROUNDS, 30),
    ocrRetryWindowMs: toInt(process.env.OCR_RETRY_WINDOW_MS, 300_000),
    ocrInitialCooldownMs: toInt(process.env.OCR_INITIAL_COOLDOWN_MS, 12_000),
    ocrMaxCooldownMs: toInt(process.env.OCR_MAX_COOLDOWN_MS, 120_000),
    ocrRequestTimeoutMs: toInt(process.env.OCR_REQUEST_TIMEOUT_MS, 25_000),
    humanConfirmBeforeSignup: toBool(process.env.HUMAN_CONFIRM_BEFORE_SIGNUP, false),
    humanConfirmText: (process.env.HUMAN_CONFIRM_TEXT || "CONFIRM").trim() || "CONFIRM",
    duckmailBaseUrl: (process.env.DUCKMAIL_BASE_URL || "https://mail-api.example.invalid").trim(),
    duckmailApiKey: (process.env.DUCKMAIL_API_KEY || "").trim() || undefined,
    duckmailDomain: (process.env.DUCKMAIL_DOMAIN || "").trim() || undefined,
    duckmailPollMs: toInt(process.env.DUCKMAIL_POLL_MS, 2500),
    emailWaitMs: toInt(process.env.EMAIL_WAIT_MS, 180_000),
    keyName: (process.env.KEY_NAME || "").trim() || `reg-key-${String(Date.now()).slice(-6)}`,
    keyLimit: toInt(process.env.KEY_LIMIT, 1000),
    existingEmail: (process.env.EXISTING_EMAIL || "").trim() || undefined,
    existingPassword: (process.env.EXISTING_PASSWORD || "").trim() || undefined,
    mihomoSubscriptionUrl: mustEnv("MIHOMO_SUBSCRIPTION_URL"),
    mihomoApiPort: toInt(process.env.MIHOMO_API_PORT, defaultApiPort),
    mihomoMixedPort: toInt(process.env.MIHOMO_MIXED_PORT, defaultMixedPort),
    proxyCheckUrl: (process.env.PROXY_CHECK_URL || "https://www.cloudflare.com/cdn-cgi/trace").trim(),
    proxyCheckTimeoutMs: toInt(process.env.PROXY_CHECK_TIMEOUT_MS, 8000),
    proxyLatencyMaxMs: toInt(process.env.PROXY_LATENCY_MAX_MS, 3000),
    ipinfoToken: (process.env.IPINFO_TOKEN || "").trim() || undefined,
    browserPrecheckEnabled: toBool(process.env.BROWSER_PRECHECK_ENABLED, true),
    browserPrecheckStrict: toBool(process.env.BROWSER_PRECHECK_STRICT, true),
    browserPrecheckCheckHostingProvider: toBool(process.env.BROWSER_PRECHECK_CHECK_HOSTING_PROVIDER, false),
    requireWebrtcVisible: toBool(process.env.REQUIRE_WEBRTC_VISIBLE, true),
    verifyHostAllowlist:
      verifyHostAllowlist.length > 0
        ? verifyHostAllowlist
        : ["tavily.com", "auth.tavily.com", "app.tavily.com"],
    modeRetryMax: Math.max(1, toInt(process.env.MODE_RETRY_MAX, 3)),
    browserLaunchRetryMax: Math.max(1, toInt(process.env.BROWSER_LAUNCH_RETRY_MAX, 3)),
    nodeReuseCooldownMs: Math.max(60_000, toInt(process.env.NODE_REUSE_COOLDOWN_MS, 30 * 60_000)),
    nodeRecentWindow: Math.max(1, toInt(process.env.NODE_RECENT_WINDOW, 4)),
    nodeCheckCacheTtlMs: Math.max(30_000, toInt(process.env.NODE_CHECK_CACHE_TTL_MS, 10 * 60_000)),
    nodeScanMaxChecks: Math.max(5, toInt(process.env.NODE_SCAN_MAX_CHECKS, 40)),
    nodeScanMaxMs: Math.max(15_000, toInt(process.env.NODE_SCAN_MAX_MS, 180_000)),
    nodeDeferLogMax: Math.max(1, toInt(process.env.NODE_DEFER_LOG_MAX, 12)),
    allowSameEgressIpFallback: toBool(process.env.ALLOW_SAME_EGRESS_IP_FALLBACK, false),
    cfProbeEnabled: toBool(process.env.CF_PROBE_ENABLED, false),
    cfProbeUrl: (process.env.CF_PROBE_URL || "https://ip.skk.moe/").trim(),
    cfProbeTimeoutMs: Math.max(3000, toInt(process.env.CF_PROBE_TIMEOUT_MS, 12000)),
    cfProbeCacheTtlMs: Math.max(60_000, toInt(process.env.CF_PROBE_CACHE_TTL_MS, 30 * 60_000)),
    inspectKeepOpenMs: Math.max(30_000, toInt(process.env.INSPECT_KEEP_OPEN_MS, 15 * 60_000)),
    inspectChromeNative: toBool(process.env.INSPECT_CHROME_NATIVE, true),
    inspectChromeProfileDir: path.resolve(process.env.INSPECT_CHROME_PROFILE_DIR || path.join(OUTPUT_PATH, "chrome-inspect-profile")),
    taskLedger: {
      enabled: toBool(process.env.TASK_LEDGER_ENABLED, true),
      dbPath: path.resolve(process.env.TASK_LEDGER_DB_PATH || path.join(OUTPUT_PATH, "registry", "signup-tasks.sqlite")),
      busyTimeoutMs: Math.max(500, toInt(process.env.TASK_LEDGER_BUSY_TIMEOUT_MS, 5000)),
      ipRateLimitCooldownMs: Math.max(
        60_000,
        toInt(process.env.TASK_LEDGER_IP_RATE_LIMIT_COOLDOWN_MS, 12 * 60 * 60 * 1000),
      ),
      ipRateLimitMax: Math.max(1, toInt(process.env.TASK_LEDGER_IP_RATE_LIMIT_MAX, 64)),
      allowRateLimitedIpFallback: toBool(process.env.ALLOW_RATE_LIMITED_IP_FALLBACK, false),
    },
  };
}

function isRecoverableBrowserError(reason: string): boolean {
  return /Execution context was destroyed|Target closed|Navigation|Cannot find context|page has been closed|context has been closed/i.test(
    reason,
  );
}

function resolveModeList(mode: RunMode): Array<"headed" | "headless"> {
  if (mode === "both") return ["headed", "headless"];
  return [mode];
}

function shouldRetryModeFailure(message: string): boolean {
  return /proxy_node_unavailable|proxy_no_distinct_egress_ip|browser precheck failed|ip\.skk did not expose an IP address|expected proxy IP not observed|cross-site IP mismatch|golden ip mismatch|webrtc probe candidates do not include expected proxy IP|captcha failed|timeout|network|Target closed|context has been closed|Failed to launch the browser process|browser has been closed/i.test(
    message,
  );
}

function getChromeWebRtcPolicyArgs(cfg: AppConfig): string[] {
  if (!cfg.chromeWebrtcHardened) return [];
  return [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--enforce-webrtc-ip-permission-check",
  ];
}

function getChromeVisualArgs(): string[] {
  return [
    "--window-size=1512,982",
    "--force-device-scale-factor=2",
  ];
}

function normalizeChromeVersion(raw: string): string {
  const trimmed = (raw || "").trim();
  const full = trimmed.match(/\d+\.\d+\.\d+\.\d+/)?.[0];
  if (full) return full;
  const major = trimmed.match(/\d+/)?.[0];
  if (major) return `${major}.0.0.0`;
  return "145.0.0.0";
}

function buildBrowserIdentityProfile(locale: string, browserVersion: string): BrowserIdentityProfile {
  const normalizedLocale = locale || "en-US";
  const langPrefix = (normalizedLocale.split("-")[0] || "en").toLowerCase();
  const languages = [normalizedLocale, `${langPrefix}-${normalizedLocale.split("-")[1] || "US"}`, langPrefix]
    .map((item) => item.trim())
    .filter((item, index, all) => item.length > 0 && all.indexOf(item) === index)
    .slice(0, 3);
  const acceptLanguage = `${languages[0]},${langPrefix};q=0.9,en;q=0.8`;
  const chromeVersion = normalizeChromeVersion(browserVersion);
  const userAgent =
    `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ` +
    `AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} Safari/537.36`;
  return {
    userAgent,
    navigatorPlatform: "MacIntel",
    cdpPlatform: "macOS",
    acceptLanguage,
    languages,
  };
}

const IDENTITY_BOUND_CONTEXTS = new WeakSet<object>();

async function applyPageIdentityOverrides(
  context: any,
  page: any,
  identity: BrowserIdentityProfile,
  timezoneId?: string,
): Promise<void> {
  let cdp: any = null;
  try {
    cdp = await context.newCDPSession(page);
  } catch {
    cdp = null;
  }
  if (!cdp) return;

  await cdp.send("Network.enable").catch(() => {});
  await cdp
    .send("Network.setExtraHTTPHeaders", {
      headers: {
        "Accept-Language": identity.acceptLanguage,
        "User-Agent": identity.userAgent,
      },
    })
    .catch(() => {});
  await cdp
    .send("Emulation.setUserAgentOverride", {
      userAgent: identity.userAgent,
      acceptLanguage: identity.languages[0] || "en-US",
      platform: identity.cdpPlatform,
    })
    .catch(() => {});
  if (timezoneId) {
    await cdp.send("Emulation.setTimezoneOverride", { timezoneId }).catch(() => {});
  }
}

async function applyBrowserIdentityToContext(
  context: any,
  identity: BrowserIdentityProfile,
  timezoneId?: string,
): Promise<void> {
  await context
    .setExtraHTTPHeaders({
      "Accept-Language": identity.acceptLanguage,
      "User-Agent": identity.userAgent,
    })
    .catch(() => {});
  await context
    .addInitScript((profile: BrowserIdentityProfile) => {
      const defineReadonly = (target: any, key: string, value: unknown): void => {
        try {
          Object.defineProperty(target, key, { get: () => value });
        } catch {
          // ignore sealed properties
        }
      };
      const firstLanguage = profile.languages[0] || "en-US";
      defineReadonly(navigator, "userAgent", profile.userAgent);
      defineReadonly(navigator, "appVersion", profile.userAgent.replace(/^Mozilla\//, ""));
      defineReadonly(navigator, "platform", profile.navigatorPlatform);
      defineReadonly(navigator, "language", firstLanguage);
      defineReadonly(navigator, "languages", profile.languages);
    }, identity)
    .catch(() => {});

  const applyToPage = async (page: any): Promise<void> => {
    await applyPageIdentityOverrides(context, page, identity, timezoneId);
  };

  const pages = typeof context.pages === "function" ? context.pages() : [];
  for (const page of pages) {
    await applyToPage(page);
  }

  const contextObj = context as object;
  if (!IDENTITY_BOUND_CONTEXTS.has(contextObj) && typeof context.on === "function") {
    context.on("page", (newPage: any) => {
      void applyToPage(newPage);
    });
    IDENTITY_BOUND_CONTEXTS.add(contextObj);
  }
}

async function launchBrowserWithEngine(
  engine: BrowserEngine,
  cfg: AppConfig,
  mode: "headed" | "headless",
  proxyServer: string,
  locale: string,
  geoIp: string,
): Promise<Browser> {
  if (engine === "chrome") {
    const options: LaunchOptions = {
      headless: mode === "headless",
      slowMo: Math.max(0, cfg.slowMoMs),
      proxy: { server: proxyServer },
      ignoreDefaultArgs: ["--enable-automation"],
      args: [
        "--disable-blink-features=AutomationControlled",
        `--lang=${locale}`,
        ...getChromeVisualArgs(),
        ...getChromeWebRtcPolicyArgs(cfg),
      ],
      timeout: 180_000,
    };
    if (cfg.chromeExecutablePath) {
      options.executablePath = cfg.chromeExecutablePath;
    }
    return await chromium.launch(options);
  }

  return (await Camoufox({
    headless: mode === "headless",
    humanize: 1.2,
    debug: false,
    proxy: { server: proxyServer },
    locale,
    geoip: geoIp,
    block_webrtc: false,
    enable_cache: true,
  })) as Browser;
}

function createChildProcessStopper(child: ReturnType<typeof spawn>): () => Promise<void> {
  let stopping = false;
  return async () => {
    if (stopping) return;
    stopping = true;
    if (child.exitCode != null) return;
    child.kill("SIGTERM");
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      if (child.exitCode != null) return;
      await delay(150);
    }
    child.kill("SIGKILL");
  };
}

function buildChromeProfileCandidates(baseDir: string): string[] {
  const runProfile = path.join(baseDir, `run-${Date.now()}-${randomInt(1000, 9999)}`);
  return [runProfile, baseDir];
}

async function resolveDebuggingPort(preferredPort: number): Promise<number> {
  if (preferredPort > 0) return preferredPort;
  return await new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        if (!port || port <= 0) {
          reject(new Error("failed to reserve chrome debugging port"));
          return;
        }
        resolve(port);
      });
    });
  });
}

async function waitForChromeWsEndpoint(port: number, timeoutMs = 20_000): Promise<string> {
  const endpoint = `http://127.0.0.1:${port}/json/version`;
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const resp = await fetch(endpoint);
      if (resp.ok) {
        const payload = (await resp.json()) as JsonRecord;
        const ws = typeof payload.webSocketDebuggerUrl === "string" ? payload.webSocketDebuggerUrl.trim() : "";
        if (ws) return ws;
      }
    } catch {
      // retry until timeout
    }
    await delay(250);
  }
  throw new Error(`native chrome debugger endpoint timeout on port ${port}`);
}

async function launchNativeChromeCdp(
  cfg: AppConfig,
  proxyServer: string,
  locale: string,
): Promise<{
  browser: Browser;
  context: any;
  stop: () => Promise<void>;
  details: { executablePath: string; profileDir: string; debugPort: number };
}> {
  if (!cfg.chromeExecutablePath) {
    throw new Error("chrome executable path is not configured");
  }

  const profileCandidates = buildChromeProfileCandidates(cfg.chromeProfileDir);
  let lastError: Error | null = null;

  for (let i = 0; i < profileCandidates.length; i += 1) {
    const profileDir = profileCandidates[i]!;
    const usingBaseProfile = i > 0;
    await mkdir(profileDir, { recursive: true });
    const debugPort = await resolveDebuggingPort(cfg.chromeRemoteDebuggingPort);
    const args = [
      `--remote-debugging-port=${debugPort}`,
      "--remote-debugging-address=127.0.0.1",
      "--remote-allow-origins=*",
      `--user-data-dir=${profileDir}`,
      `--proxy-server=${proxyServer}`,
      `--lang=${locale}`,
      "--no-first-run",
      "--no-default-browser-check",
      ...getChromeVisualArgs(),
      ...getChromeWebRtcPolicyArgs(cfg),
      "--new-window",
      "about:blank",
    ];

    const child = spawn(cfg.chromeExecutablePath, args, { stdio: "ignore" });
    const stop = createChildProcessStopper(child);
    await delay(1000);
    if (child.exitCode != null) {
      lastError = new Error(
        `native chrome exited early: ${child.exitCode}${usingBaseProfile ? " (base profile fallback)" : ""}`,
      );
      continue;
    }

    try {
      const wsEndpoint = await waitForChromeWsEndpoint(debugPort);
      const browser = await chromium.connectOverCDP(wsEndpoint, { timeout: 25_000 });
      const context = browser.contexts()[0];
      if (!context) {
        await browser.close().catch(() => {});
        throw new Error("native chrome did not expose a default browser context");
      }

      return {
        browser,
        context,
        stop,
        details: {
          executablePath: cfg.chromeExecutablePath,
          profileDir,
          debugPort,
        },
      };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      await stop().catch(() => {});
    }
  }

  throw lastError || new Error("failed to start native chrome cdp session");
}

async function launchChromePersistent(
  cfg: AppConfig,
  mode: "headed" | "headless",
  proxyServer: string,
  locale: string,
  contextOptions: BrowserContextOptions,
): Promise<{
  browser: Browser;
  context: any;
  details: { executablePath: string; profileDir: string };
}> {
  const profileCandidates = buildChromeProfileCandidates(cfg.chromeProfileDir);
  let lastError: Error | null = null;

  for (const profileDir of profileCandidates) {
    try {
      await mkdir(profileDir, { recursive: true });
      const launchOptions: any = {
        headless: mode === "headless",
        slowMo: Math.max(0, cfg.slowMoMs),
        proxy: { server: proxyServer },
        ignoreDefaultArgs: ["--enable-automation"],
        args: [
          "--disable-blink-features=AutomationControlled",
          "--no-first-run",
          "--no-default-browser-check",
          `--lang=${locale}`,
          ...getChromeVisualArgs(),
          ...getChromeWebRtcPolicyArgs(cfg),
        ],
        locale: contextOptions.locale,
        timezoneId: contextOptions.timezoneId,
        viewport: contextOptions.viewport,
        screen: contextOptions.screen,
        deviceScaleFactor: contextOptions.deviceScaleFactor,
        geolocation: contextOptions.geolocation,
        permissions: contextOptions.permissions,
        extraHTTPHeaders: contextOptions.extraHTTPHeaders,
        timeout: 180_000,
      };
      if (cfg.chromeExecutablePath) {
        launchOptions.executablePath = cfg.chromeExecutablePath;
      }
      const context = await chromium.launchPersistentContext(profileDir, launchOptions);
      const browser = context.browser();
      if (!browser) {
        await context.close().catch(() => {});
        throw new Error("persistent chrome context has no browser handle");
      }
      return {
        browser,
        context,
        details: {
          executablePath: cfg.chromeExecutablePath || "playwright chromium",
          profileDir,
        },
      };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }

  throw lastError || new Error("failed to launch chrome persistent context");
}

async function configureNativeChromePage(
  context: any,
  page: any,
  identity: BrowserIdentityProfile,
  timezoneId?: string,
): Promise<void> {
  await applyPageIdentityOverrides(context, page, identity, timezoneId);

  await context
    .setExtraHTTPHeaders({
      "Accept-Language": identity.acceptLanguage,
      "User-Agent": identity.userAgent,
    })
    .catch(() => {});

  let cdp: any = null;
  try {
    cdp = await context.newCDPSession(page);
  } catch {
    cdp = null;
  }
  if (!cdp) return;

  await cdp.send("Network.enable").catch(() => {});
  await cdp
    .send("Network.setExtraHTTPHeaders", {
      headers: {
        "Accept-Language": identity.acceptLanguage,
        "User-Agent": identity.userAgent,
      },
    })
    .catch(() => {});
  await cdp
    .send("Emulation.setDeviceMetricsOverride", {
      width: 1512,
      height: 982,
      deviceScaleFactor: 2,
      mobile: false,
      screenWidth: 1512,
      screenHeight: 982,
    })
    .catch(() => {});

  if (timezoneId) {
    await cdp.send("Emulation.setTimezoneOverride", { timezoneId }).catch(() => {});
  }
}

async function launchNativeChromeInspect(
  cfg: AppConfig,
  proxyServer: string,
  locale: string,
): Promise<{
  stop: () => Promise<void>;
  details: { executablePath: string; profileDir: string; targets: string[] };
}> {
  if (!cfg.chromeExecutablePath) {
    throw new Error("chrome executable path is not configured");
  }
  const targets = ["https://fingerprint.goldenowl.ai/", "https://ip.skk.moe/"];
  await mkdir(cfg.inspectChromeProfileDir, { recursive: true });

  const args = [
    `--user-data-dir=${cfg.inspectChromeProfileDir}`,
    `--proxy-server=${proxyServer}`,
    `--lang=${locale}`,
    ...getChromeVisualArgs(),
    ...getChromeWebRtcPolicyArgs(cfg),
    "--new-window",
    ...targets,
  ];
  const child = spawn(cfg.chromeExecutablePath, args, {
    stdio: "ignore",
  });
  const stop = createChildProcessStopper(child);
  await delay(1200);
  if (child.exitCode != null) {
    throw new Error(`native chrome exited early: ${child.exitCode}`);
  }
  return {
    stop,
    details: {
      executablePath: cfg.chromeExecutablePath,
      profileDir: cfg.inspectChromeProfileDir,
      targets,
    },
  };
}

async function applyEngineStealth(
  context: any,
  engine: BrowserEngine,
  locale: string,
  enabled: boolean,
): Promise<void> {
  if (engine !== "chrome" || !enabled) return;
  const lang = locale || "en-US";
  await context.addInitScript((preferredLang: string) => {
    const langPrefix = preferredLang.split("-")[0] || "en";
    const languages = [preferredLang, langPrefix];
    Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    Object.defineProperty(navigator, "languages", { get: () => languages });
    (window as any).chrome = (window as any).chrome || { runtime: {} };
    const permissions = navigator.permissions as any;
    if (permissions && typeof permissions.query === "function") {
      const originalQuery = permissions.query.bind(permissions);
      permissions.query = (parameters: any) => {
        if (parameters && parameters.name === "notifications") {
          return Promise.resolve({ state: Notification.permission });
        }
        return originalQuery(parameters);
      };
    }
  }, lang);
}

async function runSingleMode(
  cfg: AppConfig,
  args: CliArgs,
  solver: CaptchaSolver,
  resolvedModel: string,
  mode: "headed" | "headless",
  ctx: ModeRunContext,
): Promise<ResultPayload> {
  const notes: string[] = [];
  let failureStage = "init";
  const runId = `signup-${Date.now()}-${randomBytes(4).toString("hex")}`;
  const startedAt = new Date().toISOString();
  const ledger = ctx.taskLedger;

  let mailbox: DuckmailSession | null = null;
  let email = cfg.existingEmail || "";
  let password = cfg.existingPassword || "";
  let verificationLink: string | null = null;
  let apiKey: string | null = null;
  let verifyPassed = false;
  let precheckPassed = !cfg.browserPrecheckEnabled || args.skipPrecheck;

  if (email && password) {
    log(`[${mode}] existing account mode: ${email}`);
    notes.push("existing account mode enabled");
  } else {
    mailbox = await createDuckmailSession(cfg);
    email = mailbox.address;
    password = randomPassword();
    log(`[${mode}] duckmail mailbox: ${email}`);
    notes.push(`duckmail mailbox created (${mailbox.accountId})`);
  }

  const mihomoController = await startMihomo(buildMihomoConfig(cfg));
  const browserEngine = args.browserEngine || cfg.browserEngine;
  const useNativeChrome = browserEngine === "chrome" && mode === "headed" && cfg.chromeNativeAutomation;
  let browser: Browser | null = null;
  let context: any = null;
  let page: any = null;
  let nativeChromeStop: (() => Promise<void>) | null = null;
  let nativeChromeContext: any = null;
  let nativeChromeMode: "cdp" | "persistent" | null = null;
  const observedApiKeys = new Set<string>();
  const networkLog: NetworkDiagRecord[] = [];
  const requestLog: RequestDiagRecord[] = [];
  let identity: BrowserIdentityProfile | null = null;
  let selectedProxy: NodeCheckResult | null = null;
  let selectedGeo: GeoInfo | undefined;
  let localErrorCode = "";
  let localErrorMessage = "";

  const { domain: initialEmailDomain, localLen: initialEmailLocalLen } = splitEmail(email);
  const ledgerRecord: SignupTaskRecord = {
    runId,
    batchId: ctx.batchId,
    mode,
    attemptIndex: ctx.modeAttempt,
    modeRetryMax: cfg.modeRetryMax,
    status: "running",
    startedAt,
    modelName: resolvedModel,
    browserEngine,
    browserMode: useNativeChrome ? "chrome-native" : browserEngine,
    emailAddress: email || undefined,
    emailDomain: initialEmailDomain,
    emailLocalLen: initialEmailLocalLen,
    notesJson: safeJsonStringify(notes),
  };
  const persistLedgerRecord = (reason: string): void => {
    if (!ledger) return;
    try {
      ledger.upsertTask(ledgerRecord);
    } catch (error) {
      log(`task ledger write skipped (${reason}): ${error instanceof Error ? error.message : String(error)}`);
    }
  };
  persistLedgerRecord("start");

  const bindPageEvents = (targetPage: any): void => {
    targetPage.on("request", (req: any) => {
      try {
        const url = String(req.url?.() || "");
        const method = String(req.method?.() || "GET").toUpperCase();
        if (method !== "POST") return;
        if (!/https?:\/\/auth\.tavily\.com\/u\/(signup|login)\//i.test(url)) return;

        const headers = (req.headers?.() || {}) as Record<string, string>;
        const contentType = String(headers["content-type"] || "");
        const postData = String(req.postData?.() || "");
        const payload = parseRequestPayload(postData, contentType);
        const postKeys = Object.keys(payload).slice(0, 18);

        requestLog.push({
          url,
          method,
          contentType: contentType || undefined,
          bodyLength: postData.length || undefined,
          postKeys: postKeys.length ? postKeys : undefined,
          captchaLength: payload["captcha"]?.length,
          captchaTokenLength: payload["cf-turnstile-response"]?.length || payload["g-recaptcha-response"]?.length,
          stateLength: payload["state"]?.length,
          passwordLength: payload["password"]?.length,
          emailHint: maskEmailHint(payload["email"]),
        });
        if (requestLog.length > 200) requestLog.shift();
      } catch {
        // ignore request sampling errors
      }
    });

    targetPage.on("response", async (resp: any) => {
      try {
        const url = String(resp.url?.() || "");
        if (!/https?:\/\/(app|auth)\.tavily\.com/i.test(url)) return;
        if (/\.(?:css|js|png|jpg|jpeg|webp|gif|svg|woff2?|ttf|ico)(?:\?|$)/i.test(url)) return;

        const status = Number(resp.status?.() || 0);
        const headers = resp.headers?.() || {};
        const contentType = String(headers["content-type"] || "");
        const shouldSampleBody = /\/api\/|json|text\//i.test(`${url} ${contentType}`);
        let bodyText = "";
        if (shouldSampleBody) {
          bodyText = await resp.text();
        }

        let responseErrorCodes: string[] | undefined;
        let suspiciousSnippet: string | undefined;
        if (bodyText) {
          const matchedCodes = Array.from(bodyText.matchAll(/data-error-code=\"([^\"]+)\"/g))
            .map((entry) => entry[1])
            .filter((entry): entry is string => typeof entry === "string" && /^[a-z0-9_-]{3,80}$/i.test(entry));
          if (matchedCodes.length > 0) {
            responseErrorCodes = Array.from(new Set(matchedCodes)).slice(0, 10);
          }

          const riskPatterns: RegExp[] = [
            /Suspicious activity detected[\s\S]{0,180}/i,
            /Too many signups from the same IP[\s\S]{0,180}/i,
          ];
          for (const pattern of riskPatterns) {
            const match = bodyText.match(pattern);
            if (match?.[0]) {
              suspiciousSnippet = match[0].replace(/\s+/g, " ").trim();
              break;
            }
          }
        }

        networkLog.push({
          url,
          status,
          contentType,
          bodyPreview: bodyText ? bodyText.slice(0, 600) : undefined,
          responseErrorCodes,
          suspiciousSnippet,
        });
        if (networkLog.length > 240) networkLog.shift();

        if (responseErrorCodes || suspiciousSnippet) {
          const normalizedUrl = url.toLowerCase();
          for (let idx = requestLog.length - 1; idx >= 0; idx -= 1) {
            const reqEntry = requestLog[idx];
            if (!reqEntry) continue;
            if (reqEntry.responseStatus != null) continue;
            if (!normalizedUrl.startsWith(reqEntry.url.toLowerCase())) continue;
            reqEntry.responseStatus = status;
            reqEntry.responseErrorCodes = responseErrorCodes;
            reqEntry.suspiciousSnippet = suspiciousSnippet;
            break;
          }
        }

        if (status >= 400 && !/\/api\//i.test(url)) return;
        if (!shouldSampleBody) return;
        const matches = bodyText.match(/tvly-[A-Za-z0-9_-]{8,}/g) || [];
        for (const matched of matches) observedApiKeys.add(matched);
      } catch {
        // ignore response sampling errors
      }
    });
  };

  try {
    failureStage = "proxy_select";
    const blockedIpsFromLedger = new Set<string>();
    if (ledger) {
      try {
        for (const ip of ledger.listRecentRateLimitedIps()) {
          blockedIpsFromLedger.add(ip);
        }
      } catch (error) {
        log(`task ledger read skipped (recent blocked ips): ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    selectedProxy = await selectProxyNode(mihomoController, cfg, args.proxyNode, blockedIpsFromLedger);
    const geo = selectedProxy.geo;
    selectedGeo = geo;
    if (!geo || !geo.ip) {
      throw new Error("proxy_geo_missing");
    }

    const locale = deriveLocale(geo.country);
    const acceptLanguage = buildAcceptLanguage(locale);
    notes.push(`proxy node: ${selectedProxy.name}`);
    notes.push(`proxy ip: ${geo.ip}`);
    notes.push(`browser engine: ${useNativeChrome ? "chrome-native-cdp" : browserEngine}`);
    ledgerRecord.proxyNode = selectedProxy.name;
    ledgerRecord.proxyIp = normalizeIp(geo.ip);
    ledgerRecord.proxyCountry = geo.country;
    ledgerRecord.proxyCity = geo.city;
    ledgerRecord.proxyTimezone = geo.timezone;
    ledgerRecord.emailAddress = email;
    const split = splitEmail(email);
    ledgerRecord.emailDomain = split.domain;
    ledgerRecord.emailLocalLen = split.localLen;
    ledgerRecord.notesJson = safeJsonStringify(notes);
    persistLedgerRecord("after-proxy-select");

    const contextOptions: BrowserContextOptions = {
      locale,
      viewport: { width: 1512, height: 982 },
      screen: { width: 1512, height: 982 },
      deviceScaleFactor: 2,
      extraHTTPHeaders: {
        "Accept-Language": acceptLanguage,
      },
    };
    if (geo.timezone) {
      contextOptions.timezoneId = geo.timezone;
    }

    failureStage = "browser_launch";
    const launchBrowser = async (): Promise<Browser> => {
      if (useNativeChrome) {
        try {
          const launched = await launchNativeChromeCdp(cfg, mihomoController.proxyServer, locale);
          nativeChromeMode = "cdp";
          nativeChromeStop = launched.stop;
          nativeChromeContext = launched.context;
          notes.push(`native chrome executable: ${launched.details.executablePath}`);
          notes.push(`native chrome profile: ${launched.details.profileDir}`);
          notes.push(`native chrome debug port: ${launched.details.debugPort}`);
          return launched.browser;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          notes.push(`native chrome cdp fallback: ${message.split("\n")[0]}`);
          const persistent = await launchChromePersistent(
            cfg,
            mode,
            mihomoController.proxyServer,
            locale,
            contextOptions,
          );
          nativeChromeMode = "persistent";
          nativeChromeStop = null;
          nativeChromeContext = persistent.context;
          notes.push(`persistent chrome executable: ${persistent.details.executablePath}`);
          notes.push(`persistent chrome profile: ${persistent.details.profileDir}`);
          return persistent.browser;
        }
      }
      return await launchBrowserWithEngine(browserEngine, cfg, mode, mihomoController.proxyServer, locale, geo.ip);
    };

    const rebuildPage = async (): Promise<void> => {
      if (context && !useNativeChrome) {
        await context.close().catch(() => {});
      }
      if (useNativeChrome) {
        context = nativeChromeContext;
        if (!context) {
          throw new Error("native chrome context missing");
        }
        const pages = typeof context.pages === "function" ? context.pages() : [];
        for (const existing of pages) {
          await existing.close().catch(() => {});
        }
        if (identity) {
          await applyBrowserIdentityToContext(context, identity, geo.timezone);
        }
        await applyEngineStealth(context, "chrome", locale, cfg.chromeStealthJsEnabled);
        page = await context.newPage();
        if (nativeChromeMode === "cdp" && identity) {
          await configureNativeChromePage(
            context,
            page,
            identity,
            geo.timezone,
          );
        }
      } else {
        context = await browser!.newContext(contextOptions);
        if (identity) {
          await applyBrowserIdentityToContext(context, identity, geo.timezone);
        }
        await applyEngineStealth(context, browserEngine, locale, cfg.chromeStealthJsEnabled);
        page = await context.newPage();
      }
      bindPageEvents(page);
    };

    let browserReady = false;
    let launchErr: Error | null = null;
    for (let launchAttempt = 1; launchAttempt <= cfg.browserLaunchRetryMax; launchAttempt += 1) {
      try {
        const existingBrowser = browser;
        if (existingBrowser) {
          await existingBrowser.close().catch(() => {});
          browser = null;
        }
        browser = await launchBrowser();
        if (browserEngine === "chrome") {
          identity = buildBrowserIdentityProfile(locale, browser.version?.() || "");
          notes.push(`browser ua profile: ${identity.userAgent}`);
        } else {
          identity = null;
        }
        await rebuildPage();
        browserReady = true;
        if (launchAttempt > 1) {
          notes.push(`browser launch recovered on attempt ${launchAttempt}`);
        }
        break;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        launchErr = error instanceof Error ? error : new Error(message);
        log(`[${mode}] browser launch/context attempt ${launchAttempt} failed: ${message}`);
        if (context) {
          if (!useNativeChrome) {
            await context.close().catch(() => {});
          }
          context = null;
        }
        const launchedBrowser = browser;
        if (launchedBrowser) {
          await launchedBrowser.close().catch(() => {});
          browser = null;
        }
        if (nativeChromeStop != null) {
          await (nativeChromeStop as () => Promise<void>)().catch(() => {});
          nativeChromeStop = null;
        }
        nativeChromeContext = null;
        nativeChromeMode = null;
        if (launchAttempt >= cfg.browserLaunchRetryMax) {
          break;
        }
        await delay(Math.min(3000, 700 * launchAttempt));
      }
    }
    if (!browserReady) {
      throw launchErr || new Error("browser launch failed without details");
    }
    ledgerRecord.browserMode = useNativeChrome ? nativeChromeMode || "persistent" : browserEngine;
    ledgerRecord.browserUserAgent = identity?.userAgent;
    ledgerRecord.browserLocale = locale;
    ledgerRecord.browserTimezone = geo.timezone;
    ledgerRecord.notesJson = safeJsonStringify(notes);
    persistLedgerRecord("after-browser-launch");

    if (cfg.browserPrecheckEnabled && !args.skipPrecheck) {
      failureStage = "browser_precheck";
      const precheck = await runBrowserPrecheck(page, cfg, mode, selectedProxy, locale);
      precheckPassed = precheck.passed;
      await writeJson(new URL(`browser_precheck_${mode}.json`, OUTPUT_DIR), precheck);
      await writeJson(new URL("browser_precheck.json", OUTPUT_DIR), precheck);
      if (!precheck.passed) {
        throw new Error(`browser precheck failed: ${precheck.issues.join(" | ")}`);
      }
      notes.push("browser precheck passed");
      ledgerRecord.precheckPassed = true;
      ledgerRecord.notesJson = safeJsonStringify(notes);
      ledgerRecord.detailsJson = safeJsonStringify({
        precheck,
      });
      persistLedgerRecord("after-precheck");
    }

    if (cfg.existingEmail && cfg.existingPassword) {
      notes.push("skip signup (existing account)");
    } else {
      failureStage = "signup";
      if (cfg.humanConfirmBeforeSignup) {
        await confirmHumanControl(cfg, email, "before signup");
        notes.push("human confirmation accepted before signup");
      }

      for (let attempt = 1; attempt <= 2; attempt += 1) {
        try {
          await completeSignup(page, solver, email, password, cfg);
          notes.push("signup flow submitted");
          ledgerRecord.signupSubmitted = true;
          ledgerRecord.notesJson = safeJsonStringify(notes);
          persistLedgerRecord("after-signup-submit");
          break;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (!isRecoverableBrowserError(message) || attempt === 2) {
            throw error;
          }
          log(`[${mode}] signup retry after browser reset (attempt=${attempt})`);
          await rebuildPage();
        }
      }

      failureStage = "email_verify_wait";
      verificationLink = await waitForVerificationLink(mailbox!, cfg.emailWaitMs, cfg.duckmailPollMs, cfg.verifyHostAllowlist);
      if (!verificationLink) {
        throw new Error("verification email not found within timeout");
      }

      failureStage = "email_verify_open";
      await safeGoto(page, verificationLink, 120000);
      verifyPassed = await verifyVerificationLanding(page);
      if (!verifyPassed) {
        throw new Error(`verification link opened but success signal missing, current=${page.url()}`);
      }
      notes.push("email verification confirmed");
    }

    failureStage = "login_home";
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        await loginAndReachHome(page, solver, email, password, cfg);
        notes.push("reached app home");
        break;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!isRecoverableBrowserError(message) || attempt === 2) {
          throw error;
        }
        log(`[${mode}] login retry after browser reset (attempt=${attempt})`);
        await rebuildPage();
      }
    }

    failureStage = "api_key";
    let lastKeyError: Error | null = null;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      try {
        const sampled = Array.from(observedApiKeys).find((key) => isLikelyTavilyKey(key));
        if (sampled) {
          apiKey = sampled;
          break;
        }

        await loginAndReachHome(page, solver, email, password, cfg);
        await page.waitForTimeout(1500);
        if (attempt === 1) {
          await writeFile(new URL(`home_${mode}.html`, OUTPUT_DIR), await page.content(), "utf8");
          await writeJson(new URL(`network_${mode}.json`, OUTPUT_DIR), networkLog.slice(-120));
        }

        apiKey = await getDefaultApiKey(page, cfg);
        if (apiKey) break;

        const sampledAfter = Array.from(observedApiKeys).find((key) => isLikelyTavilyKey(key));
        if (sampledAfter) {
          apiKey = sampledAfter;
          break;
        }

        log(`[${mode}] api key not found on attempt ${attempt}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (isRecoverableBrowserError(message) && attempt < 5) {
          log(`[${mode}] api-key retry after browser reset (attempt=${attempt})`);
          await rebuildPage();
          continue;
        }
        lastKeyError = error instanceof Error ? error : new Error(message);
        break;
      }
    }

    if (lastKeyError) {
      throw lastKeyError;
    }
    if (!apiKey) {
      throw new Error("default api key missing from app responses");
    }
    notes.push("default api key fetched");

    const successRisk = summarizeRiskSignals(requestLog, networkLog);
    ledgerRecord.status = "succeeded";
    ledgerRecord.completedAt = new Date().toISOString();
    ledgerRecord.durationMs = Date.parse(ledgerRecord.completedAt) - Date.parse(ledgerRecord.startedAt);
    ledgerRecord.failureStage = undefined;
    ledgerRecord.errorCode = undefined;
    ledgerRecord.errorMessage = undefined;
    ledgerRecord.verifyPassed = verifyPassed || !!cfg.existingEmail;
    ledgerRecord.precheckPassed = precheckPassed;
    ledgerRecord.hasIpRateLimit = successRisk.hasIpRateLimit;
    ledgerRecord.hasSuspiciousActivity = successRisk.hasSuspiciousActivity;
    ledgerRecord.hasExtensibilityError = successRisk.hasExtensibilityError;
    ledgerRecord.hasInvalidCaptcha = successRisk.hasInvalidCaptcha;
    ledgerRecord.requestCount = successRisk.requestCount;
    ledgerRecord.suspiciousHitCount = successRisk.suspiciousHitCount;
    ledgerRecord.captchaSubmitCount = successRisk.captchaSubmitCount;
    ledgerRecord.maxCaptchaLength = successRisk.maxCaptchaLength;
    ledgerRecord.apiKeyPrefix = apiKey.slice(0, Math.min(apiKey.length, 12));
    ledgerRecord.notesJson = safeJsonStringify(notes);
    ledgerRecord.detailsJson = safeJsonStringify({
      risk: successRisk,
      snippets: successRisk.snippets,
      verificationLink,
      selectedProxy: selectedProxy
        ? {
            name: selectedProxy.name,
            ip: normalizeIp(selectedProxy.geo?.ip),
            country: selectedGeo?.country,
            city: selectedGeo?.city,
            timezone: selectedGeo?.timezone,
          }
        : null,
      requestLog: requestLog.slice(-80),
      networkLog: networkLog.slice(-80),
      notes,
    });
    persistLedgerRecord("success");

    return {
      mode,
      email,
      password,
      verificationLink,
      apiKey,
      model: resolvedModel,
      precheckPassed,
      verifyPassed: verifyPassed || !!cfg.existingEmail,
      notes,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const risk = summarizeRiskSignals(requestLog, networkLog);
    localErrorCode = deriveErrorCode(message, failureStage, risk);
    localErrorMessage = message;
    try {
      await writeJson(new URL(`network_fail_${mode}.json`, OUTPUT_DIR), networkLog.slice(-180));
      await writeJson(new URL(`request_fail_${mode}.json`, OUTPUT_DIR), requestLog.slice(-180));
      await writeJson(new URL(`failure_context_${mode}.json`, OUTPUT_DIR), {
        failedAt: new Date().toISOString(),
        stage: failureStage,
        url: page ? page.url() : null,
        email,
        browserEngine,
        notes,
      });
      if (page) {
        await writeFile(new URL(`failure_page_${mode}.html`, OUTPUT_DIR), await page.content(), "utf8");
      }
    } catch {
      // best effort diagnostics only
    }
    ledgerRecord.status = "failed";
    ledgerRecord.completedAt = new Date().toISOString();
    ledgerRecord.durationMs = Date.parse(ledgerRecord.completedAt) - Date.parse(ledgerRecord.startedAt);
    ledgerRecord.failureStage = failureStage;
    ledgerRecord.errorCode = localErrorCode;
    ledgerRecord.errorMessage = message;
    ledgerRecord.verifyPassed = verifyPassed;
    ledgerRecord.precheckPassed = precheckPassed;
    ledgerRecord.hasIpRateLimit = risk.hasIpRateLimit;
    ledgerRecord.hasSuspiciousActivity = risk.hasSuspiciousActivity;
    ledgerRecord.hasExtensibilityError = risk.hasExtensibilityError;
    ledgerRecord.hasInvalidCaptcha = risk.hasInvalidCaptcha;
    ledgerRecord.requestCount = risk.requestCount;
    ledgerRecord.suspiciousHitCount = risk.suspiciousHitCount;
    ledgerRecord.captchaSubmitCount = risk.captchaSubmitCount;
    ledgerRecord.maxCaptchaLength = risk.maxCaptchaLength;
    ledgerRecord.notesJson = safeJsonStringify(notes);
    ledgerRecord.detailsJson = safeJsonStringify({
      failureStage,
      errorCode: localErrorCode,
      errorMessage: message,
      risk,
      snippets: risk.snippets,
      selectedProxy: selectedProxy
        ? {
            name: selectedProxy.name,
            ip: normalizeIp(selectedProxy.geo?.ip),
            country: selectedGeo?.country,
            city: selectedGeo?.city,
            timezone: selectedGeo?.timezone,
          }
        : null,
      requestLog: requestLog.slice(-120),
      networkLog: networkLog.slice(-120),
      notes,
    });
    persistLedgerRecord("failure");
    throw new Error(`mode=${mode} stage=${failureStage}: ${message}`);
  } finally {
    if (context && !useNativeChrome) {
      await context.close().catch(() => {});
    }
    if (browser) {
      await browser.close().catch(() => {});
    }
    if (nativeChromeStop != null) {
      await (nativeChromeStop as () => Promise<void>)().catch(() => {});
    }
    await mihomoController.stop();
  }
}

async function runInspectSites(cfg: AppConfig, args: CliArgs): Promise<void> {
  const mode: "headed" = "headed";
  const notes: string[] = [];
  const mihomoController = await startMihomo(buildMihomoConfig(cfg));
  const browserEngine = args.browserEngine || cfg.inspectBrowserEngine;
  const useNativeChrome = browserEngine === "chrome" && cfg.inspectChromeNative;
  let browser: Browser | null = null;
  let context: any = null;
  let nativeChromeStop: (() => Promise<void>) | null = null;

  try {
    const selectedProxy = await selectProxyNode(mihomoController, cfg, args.proxyNode);
    const geo = selectedProxy.geo;
    if (!geo || !geo.ip) {
      throw new Error("proxy_geo_missing");
    }

    const locale = deriveLocale(geo.country);
    const acceptLanguage = buildAcceptLanguage(locale);
    notes.push(`proxy node: ${selectedProxy.name}`);
    notes.push(`proxy ip: ${geo.ip}`);
    notes.push(`browser engine: ${browserEngine}`);

    if (useNativeChrome) {
      const nativeChrome = await launchNativeChromeInspect(cfg, mihomoController.proxyServer, locale);
      nativeChromeStop = nativeChrome.stop;
      notes.push(`native chrome executable: ${nativeChrome.details.executablePath}`);
      notes.push(`native chrome profile: ${nativeChrome.details.profileDir}`);
      notes.push("opened fingerprint.goldenowl.ai");
      notes.push("opened ip.skk.moe");

      await writeJson(new URL("inspect_sites.json", OUTPUT_DIR), {
        mode: "inspect-sites-native-chrome",
        openedAt: new Date().toISOString(),
        proxy: {
          node: selectedProxy.name,
          ip: geo.ip,
          country: geo.country,
          city: geo.city,
          timezone: geo.timezone,
        },
        pages: nativeChrome.details.targets.map((url) => ({ url })),
        notes,
      });
    } else {
      browser = await launchBrowserWithEngine(browserEngine, cfg, mode, mihomoController.proxyServer, locale, geo.ip);

      const contextOptions: BrowserContextOptions = {
        locale,
        viewport: { width: 1512, height: 982 },
        screen: { width: 1512, height: 982 },
        deviceScaleFactor: 2,
        extraHTTPHeaders: {
          "Accept-Language": acceptLanguage,
        },
      };
      if (geo.timezone) {
        contextOptions.timezoneId = geo.timezone;
      }

      context = await browser.newContext(contextOptions);
      await applyEngineStealth(context, browserEngine, locale, cfg.chromeStealthJsEnabled);

      const fingerprintPage = await context.newPage();
      await safeGoto(fingerprintPage, "https://fingerprint.goldenowl.ai/", 120000);
      await fingerprintPage.waitForLoadState("domcontentloaded", { timeout: 60000 });
      await writeFile(new URL("inspect_fingerprint.png", OUTPUT_DIR), await fingerprintPage.screenshot({ fullPage: true }));
      notes.push("opened fingerprint.goldenowl.ai");

      const ipSkkPage = await context.newPage();
      await safeGoto(ipSkkPage, "https://ip.skk.moe/", 120000);
      await ipSkkPage.waitForLoadState("domcontentloaded", { timeout: 60000 });
      await writeFile(new URL("inspect_ip_skk.png", OUTPUT_DIR), await ipSkkPage.screenshot({ fullPage: true }));
      await ipSkkPage.bringToFront();
      notes.push("opened ip.skk.moe");

      await writeJson(new URL("inspect_sites.json", OUTPUT_DIR), {
        mode: "inspect-sites",
        openedAt: new Date().toISOString(),
        proxy: {
          node: selectedProxy.name,
          ip: geo.ip,
          country: geo.country,
          city: geo.city,
          timezone: geo.timezone,
        },
        pages: [
          { url: await fingerprintPage.url(), title: await fingerprintPage.title().catch(() => "") },
          { url: await ipSkkPage.url(), title: await ipSkkPage.title().catch(() => "") },
        ],
        notes,
      });
    }

    if (process.stdin.isTTY && process.stdout.isTTY) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      try {
        await rl.question(
          `Inspect mode ready. Browser opened with proxy node ${selectedProxy.name} (${geo.ip}) using ${
            useNativeChrome ? "native chrome" : browserEngine
          }. Press Enter to close: `,
        );
      } finally {
        rl.close();
      }
    } else {
      log(`inspect mode no TTY, keep browser open for ${cfg.inspectKeepOpenMs}ms`);
      await delay(cfg.inspectKeepOpenMs);
    }
  } finally {
    if (context) {
      await context.close().catch(() => {});
    }
    if (browser) {
      await browser.close().catch(() => {});
    }
    if (nativeChromeStop) {
      await nativeChromeStop().catch(() => {});
    }
    await mihomoController.stop();
  }
}

async function run(): Promise<void> {
  const cfg = loadConfig();
  const args = parseArgs(process.argv.slice(2));
  if (args.inspectSites) {
    log("start inspect-sites mode (headed)");
    await runInspectSites(cfg, args);
    await writeJson(new URL("result.json", OUTPUT_DIR), {
      mode: "inspect-sites",
      completedAt: new Date().toISOString(),
      ok: true,
    });
    log("inspect-sites mode completed");
    return;
  }
  const batchId = `batch-${Date.now()}-${randomBytes(3).toString("hex")}`;
  const taskLedger = await TaskLedger.open(cfg.taskLedger);
  if (taskLedger) {
    log(`task ledger enabled: ${taskLedger.dbPath()}`);
  } else {
    log("task ledger disabled");
  }

  try {
    const requestedMode = args.mode || cfg.runMode;
    const modes = resolveModeList(requestedMode);
    log(`start modes=${modes.join(",")} precheck=${cfg.browserPrecheckEnabled && !args.skipPrecheck ? "on" : "off"}`);

    const allModels = await listModels(cfg);
    const resolvedModel = resolveModelName(cfg.preferredModel, allModels);
    log(`captcha model selected: ${resolvedModel}`);
    const solver = new CaptchaSolver(cfg, resolvedModel);

    const results: ResultPayload[] = [];
    for (const mode of modes) {
      let result: ResultPayload | null = null;
      let lastError: Error | null = null;

      for (let attempt = 1; attempt <= cfg.modeRetryMax; attempt += 1) {
        try {
          result = await runSingleMode(cfg, args, solver, resolvedModel, mode, {
            batchId,
            modeAttempt: attempt,
            taskLedger,
          });
          if (attempt > 1) {
            result.notes.push(`mode retry succeeded on attempt ${attempt}`);
          }
          break;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          lastError = error instanceof Error ? error : new Error(message);
          if (attempt < cfg.modeRetryMax && shouldRetryModeFailure(message)) {
            log(`[${mode}] run attempt ${attempt} failed, retrying: ${message}`);
            continue;
          }
          break;
        }
      }

      if (!result) {
        throw lastError || new Error(`[${mode}] run failed without result`);
      }

      results.push(result);
      log(`[${mode}] finished account=${result.email}`);
    }

    const summaryPayload = {
      batchId,
      requestedMode,
      completedAt: new Date().toISOString(),
      model: resolvedModel,
      results,
    };
    await writeJson(new URL("run_summary.json", OUTPUT_DIR), summaryPayload);

    const resultOutput: unknown = results.length === 1 ? results[0] : summaryPayload;
    await writeJson(new URL("result.json", OUTPUT_DIR), resultOutput);
    log("saved output/result.json");

    if (results.length === 1) {
      const only = results[0]!;
      console.log(`ACCOUNT=${only.email}`);
      console.log(`PASSWORD=${only.password}`);
      console.log(`DEFAULT_API_KEY=${only.apiKey}`);
    } else {
      for (const item of results) {
        console.log(`[${item.mode}] ACCOUNT=${item.email}`);
        console.log(`[${item.mode}] PASSWORD=${item.password}`);
        console.log(`[${item.mode}] DEFAULT_API_KEY=${item.apiKey}`);
      }
    }
  } finally {
    taskLedger?.close();
  }
}

async function main(): Promise<void> {
  try {
    await run();
  } catch (error) {
    const message = error instanceof Error ? error.stack || error.message : String(error);
    console.error(`[${ts()}] fatal: ${message}`);
    await writeJson(new URL("error.json", OUTPUT_DIR), {
      failedAt: new Date().toISOString(),
      error: message,
    });
    process.exitCode = 1;
  }
}

await main();
