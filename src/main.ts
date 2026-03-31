import { config as loadDotenv } from "dotenv";
import { Resvg } from "@resvg/resvg-js";
import { Impit } from "impit";
import { chromium, type Browser, type BrowserContextOptions, type LaunchOptions } from "playwright-core";
import { createHash, randomBytes, randomInt } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { sep as pathSep } from "node:path";
import { existsSync, openSync } from "node:fs";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, isIP } from "node:net";
import { release as osRelease } from "node:os";
import path from "node:path";
import process from "node:process";
import readline from "node:readline/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  buildMoeMailAuthHeaders,
  extractFreshMicrosoftProofCodeFromMoeMailResponse,
  normalizeMoeMailBaseUrl,
  provisionMoeMailMailbox,
  resolveMoeMailMailboxId as resolveMoeMailMailboxIdViaOpenApi,
} from "./moemail-openapi.js";
import {
  classifyMicrosoftFlowInterrupt,
  buildMicrosoftPasswordSurfaceKey,
  classifyMicrosoftPasswordError,
  isMicrosoftAuthorizeShellUnready,
  shouldClassifyMicrosoftUnknownRecoveryEmail,
  shouldAttemptMicrosoftProofPasswordFallback,
  shouldRecoverMicrosoftPasskeyToProofCode,
} from "./microsoft-login-state.js";
import { isMicrosoftPasskeyInterruptUrl } from "./microsoft-passkey.js";
import { startMihomo, type MihomoConfig } from "./proxy/mihomo.js";
import { resolveLocalEgressIp, type NodeCheckResult } from "./proxy/check.js";
import { buildAcceptLanguage, deriveLocale, lookupIpInfo, type GeoInfo } from "./proxy/geo.js";
import { resolveTaskLedgerDbPath } from "./storage/db-paths.js";
import { TaskLedger, type SignupTaskRecord, type TaskLedgerConfig } from "./storage/task-ledger.js";

type JsonRecord = Record<string, unknown>;
type RunMode = "headed" | "headless";
type BrowserEngine = "chrome";
type MailProvider = "duckmail" | "gptmail" | "vmail";
type MailboxSessionProvider = MailProvider | "moemail";
type AuthLoginProvider = "password" | "microsoft";

interface GptmailAuthPayload {
  token: string;
  email?: string;
  expiresAt?: number;
}

interface CliArgs {
  proxyNode?: string;
  mode?: RunMode;
  browserEngine?: BrowserEngine;
  skipPrecheck: boolean;
  inspectSites: boolean;
  printSecrets: boolean;
  parallel: number;
  need: number;
}

export interface AppConfig {
  runMode: RunMode;
  browserEngine: BrowserEngine;
  inspectBrowserEngine: BrowserEngine;
  chromeExecutablePath?: string;
  chromeNativeAutomation: boolean;
  chromeActivateOnLaunch: boolean;
  chromeIdentityOverride: boolean;
  chromeStealthJsEnabled: boolean;
  chromeWebrtcHardened: boolean;
  chromeProfileDir: string;
  chromeRemoteDebuggingPort: number;
  slowMoMs: number;
  maxCaptchaRounds: number;
  allowPasswordSubmitWithoutCaptcha: boolean;
  humanConfirmBeforeSignup: boolean;
  humanConfirmText: string;
  mailProvider: MailProvider;
  blockedMailboxDomains: string[];
  mailPollMs: number;
  gptmailBaseUrl: string;
  vmailBaseUrl: string;
  vmailApiKey?: string;
  vmailDomain?: string;
  moemailBaseUrl: string;
  moemailApiKey?: string;
  duckmailBaseUrl: string;
  duckmailApiKey?: string;
  duckmailDomain?: string;
  emailWaitMs: number;
  keyName: string;
  keyLimit: number;
  existingEmail?: string;
  existingPassword?: string;
  microsoftAccountEmail?: string;
  microsoftAccountPassword?: string;
  microsoftProofMailboxProvider?: "moemail";
  microsoftProofMailboxAddress?: string;
  microsoftProofMailboxId?: string;
  microsoftKeepSignedIn: boolean;
  mihomoSubscriptionUrl: string;
  mihomoGroupName: string;
  mihomoRouteGroupName: string;
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
  taskAttemptTimeoutMs: number;
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

interface MailboxSession {
  provider: MailboxSessionProvider;
  baseUrl: string;
  address: string;
  accountId: string;
  headers: Record<string, string>;
}

function isBlockedMailboxAddress(blockedDomains: ReadonlySet<string>, address: string): boolean {
  const { domain } = splitEmail(address);
  return !!domain && blockedDomains.has(domain);
}

function computeMailboxPreloadTarget(need: number): number {
  if (need <= 0) return 0;
  return Math.max(1, Math.ceil(need * 0.25));
}

function getConfiguredLoginProvider(cfg: Pick<AppConfig, "existingEmail" | "existingPassword" | "microsoftAccountEmail" | "microsoftAccountPassword">): AuthLoginProvider | null {
  if (cfg.microsoftAccountEmail && cfg.microsoftAccountPassword) {
    return "microsoft";
  }
  if (cfg.existingEmail && cfg.existingPassword) {
    return "password";
  }
  return null;
}

function hasConfiguredLoginAccount(cfg: Pick<AppConfig, "existingEmail" | "existingPassword" | "microsoftAccountEmail" | "microsoftAccountPassword">): boolean {
  return getConfiguredLoginProvider(cfg) !== null;
}

function getConfiguredLoginEmail(cfg: Pick<AppConfig, "existingEmail" | "microsoftAccountEmail">): string | undefined {
  return cfg.microsoftAccountEmail || cfg.existingEmail;
}

function getConfiguredLoginPassword(cfg: Pick<AppConfig, "existingPassword" | "microsoftAccountPassword">): string | undefined {
  return cfg.microsoftAccountPassword || cfg.existingPassword;
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

interface ResourceDiagRecord {
  phase: "request" | "response" | "requestfailed";
  url: string;
  method?: string;
  resourceType?: string;
  status?: number;
  contentType?: string;
  bodyPreview?: string;
  failureText?: string;
  startedAt: string;
}

interface PasswordStepSnapshot {
  collectedAt: string;
  url: string;
  hasCaptchaInput: boolean;
  hasCaptchaImage: boolean;
  hasCaptchaContainer: boolean;
  captchaProvider?: string;
  captchaSiteKeyHint?: string;
  hasTurnstileResponseInput: boolean;
  hasRecaptchaResponseInput: boolean;
  hasHcaptchaResponseInput: boolean;
  challengeHint: boolean;
  formInputNames: string[];
  visibleErrors: string[];
}

interface PasswordStrengthSnapshot {
  len: number;
  lower: boolean;
  upper: boolean;
  digit: boolean;
  special: boolean;
  tooWeak: boolean;
  visiblePolicyErrors: string[];
}

interface AuthChallengeSnapshot {
  collectedAt: string;
  url: string;
  hasCaptchaInput: boolean;
  captchaValueLength: number;
  turnstileValueLength: number;
  recaptchaValueLength: number;
  hcaptchaValueLength: number;
  hasCaptchaImage: boolean;
  hasCaptchaContainer: boolean;
  hasChallengeFrame: boolean;
  hasTurnstileApi: boolean;
  hasChallengeCheckbox: boolean;
  challengeCheckboxChecked?: boolean;
  challengeFrameUrl?: string;
  captchaProvider?: string;
  captchaSiteKeyHint?: string;
  challengeHint: boolean;
  challengeSuccessVisible: boolean;
  visibleErrors: string[];
  visibleErrorCodes: string[];
}

interface ChallengeBoxRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface ManagedChallengeCdpSnapshot {
  frameUrl?: string;
  iframeBox?: ChallengeBoxRect;
  checkboxBox?: ChallengeBoxRect;
  refreshBox?: ChallengeBoxRect;
  checkboxChecked?: boolean;
  hasCheckbox: boolean;
  statusText?: string;
  successVisible?: boolean;
}

interface BrowserFingerprintSnapshot {
  collectedAt: string;
  url: string;
  navigatorUserAgent?: string;
  navigatorPlatform?: string;
  navigatorLanguage?: string;
  navigatorLanguages?: string[];
  timezone?: string;
  webdriver?: boolean;
  hardwareConcurrency?: number;
  deviceMemory?: number;
  pluginsLength?: number;
  permissionNotification?: string;
  permissionNotificationViaQuery?: string;
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

const authSubmitFieldCache = new WeakMap<
  object,
  { captcha?: string; challengeToken?: string; email?: string; password?: string; code?: string; state?: string }
>();

interface ModeRunContext {
  batchId: string;
  modeAttempt: number;
  keepBrowserOpenOnFailure: boolean;
  taskLedger: TaskLedger | null;
  runtimeRecentProxyIps: string[];
  ipEmailUsage: Map<string, Set<string>>;
  activeProxyIps: Set<string>;
  blockedMailboxDomains: Set<string>;
}

interface PreparedSignupTask {
  taskId: string;
  email: string;
  password: string;
  mailbox: MailboxSession | null;
  mailboxPromise?: Promise<{ ok: true; mailbox: MailboxSession } | { ok: false; error: unknown }> | null;
  proxyName: string;
  proxyIp?: string;
  proxyGeo?: GeoInfo;
  ipEmailOrdinal: number;
}

interface BrowserIdentityProfile {
  userAgent: string;
  navigatorPlatform: string;
  cdpPlatform: string;
  cdpPlatformVersion: string;
  cdpArchitecture: string;
  cdpBitness: string;
  acceptLanguage: string;
  languages: string[];
  vendor: string;
  hardwareConcurrency: number;
  deviceMemory: number;
  maxTouchPoints: number;
  webglVendor?: string;
  webglRenderer?: string;
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

const DEFAULT_OUTPUT_PATH = fileURLToPath(new URL("../output/", import.meta.url));
const OUTPUT_PATH = path.resolve(process.env.OUTPUT_ROOT_DIR || DEFAULT_OUTPUT_PATH);
const OUTPUT_DIR = pathToFileURL(`${OUTPUT_PATH}${pathSep}`);
const PROXY_NODE_USAGE_PATH = new URL("proxy/node-usage.json", OUTPUT_DIR);
const AUTH_CHALLENGE_RESOURCE_RE =
  /(?:challenges\.cloudflare\.com|arkoselabs\.com|funcaptcha|hcaptcha\.com|recaptcha(?:\.net|\.com)|friendly-challenge|cdn\.auth0\.com\/ulp)/i;

function ts(): string {
  return new Date().toISOString();
}

function log(message: string): void {
  console.log(`[${ts()}] ${message}`);
}

function renderAccountSummaryLine(index: number, result: ResultPayload, includeSecrets: boolean): string {
  if (includeSecrets) {
    return `ACCOUNT_${index}=${JSON.stringify({
      email: result.email,
      password: result.password,
      apiKey: result.apiKey,
    })}`;
  }
  return `ACCOUNT_${index}=${JSON.stringify({ email: result.email })}`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(100, timeoutMs));
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function connectOverCdpWithTimeout(endpoint: string, timeoutMs: number): Promise<Browser> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`overCDP: Timeout ${timeoutMs}ms exceeded.`));
    }, Math.max(1000, timeoutMs));
    // Avoid holding the Node.js event loop if the caller already completed.
    if (typeof (timer as any).unref === "function") {
      (timer as any).unref();
    }
  });
  return (await Promise.race([chromium.connectOverCDP(endpoint, { timeout: timeoutMs }), timeoutPromise])) as Browser;
}

function toAbortError(signal: AbortSignal | undefined, fallbackMessage: string): Error {
  const reason = signal?.reason;
  if (reason instanceof Error) return reason;
  if (typeof reason === "string" && reason.trim()) return new Error(reason.trim());
  return new Error(fallbackMessage);
}

function throwIfAborted(signal: AbortSignal | undefined, fallbackMessage: string): void {
  if (!signal?.aborted) return;
  throw toAbortError(signal, fallbackMessage);
}

async function raceWithAbort<T>(
  task: Promise<T>,
  signal: AbortSignal | undefined,
  fallbackMessage: string,
): Promise<T> {
  if (!signal) {
    return await task;
  }
  if (signal.aborted) {
    throw toAbortError(signal, fallbackMessage);
  }
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const onAbort = () => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      reject(toAbortError(signal, fallbackMessage));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    task.then(
      (value) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
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
  if (value === "headed" || value === "headless") {
    return value;
  }
  return null;
}

function parseBrowserEngine(raw: string | undefined): BrowserEngine | null {
  if (!raw) return null;
  const value = raw.trim().toLowerCase();
  if (value === "chrome") return "chrome";
  return null;
}

function parseMailProvider(raw: string | undefined): MailProvider | null {
  if (!raw) return null;
  const value = raw.trim().toLowerCase();
  if (value === "duckmail" || value === "gptmail" || value === "vmail") return value;
  return null;
}

function parsePositiveInt(raw: string | undefined): number | null {
  if (!raw) return null;
  const normalized = raw.trim();
  if (!normalized) return null;
  const num = Number(normalized);
  if (!Number.isFinite(num) || !Number.isInteger(num)) return null;
  if (num < 1) return null;
  return num;
}

function parseArgs(argv: string[]): CliArgs {
  let proxyNode: string | undefined;
  let mode: RunMode | undefined;
  let browserEngine: BrowserEngine | undefined;
  let skipPrecheck = false;
  let inspectSites = false;
  let printSecrets = false;
  let parallel = 1;
  let need = 1;
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
    if (arg === "--print-secrets") {
      printSecrets = true;
      continue;
    }
    if (arg === "--parallel" && argv[i + 1]) {
      const parsed = parsePositiveInt(argv[i + 1]);
      if (!parsed) {
        throw new Error(`invalid --parallel value: ${argv[i + 1]}`);
      }
      parallel = parsed;
      i += 1;
      continue;
    }
    if (arg.startsWith("--parallel=")) {
      const parsed = parsePositiveInt(arg.slice("--parallel=".length));
      if (!parsed) {
        throw new Error(`invalid --parallel value: ${arg.slice("--parallel=".length)}`);
      }
      parallel = parsed;
      continue;
    }
    if (arg === "--need" && argv[i + 1]) {
      const parsed = parsePositiveInt(argv[i + 1]);
      if (!parsed) {
        throw new Error(`invalid --need value: ${argv[i + 1]}`);
      }
      need = parsed;
      i += 1;
      continue;
    }
    if (arg.startsWith("--need=")) {
      const parsed = parsePositiveInt(arg.slice("--need=".length));
      if (!parsed) {
        throw new Error(`invalid --need value: ${arg.slice("--need=".length)}`);
      }
      need = parsed;
      continue;
    }
  }
  return {
    proxyNode: proxyNode?.trim() || undefined,
    mode,
    browserEngine,
    skipPrecheck,
    inspectSites,
    printSecrets,
    parallel,
    need,
  };
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

async function recordProxyNodeTaskOutcome(
  name: string,
  geo: GeoInfo | undefined,
  outcome: "ok" | "fail",
  nowIso = new Date().toISOString(),
): Promise<void> {
  const usage = await readProxyNodeUsageState();
  const previous = usage.nodes[name] || { count: 0, successCount: 0, failCount: 0, consecutiveFailCount: 0 };
  const nodeIp = normalizeIp(geo?.ip) || previous.lastIp;
  usage.nodes[name] = {
    ...previous,
    lastCheckedAt: nowIso,
    lastUsedAt: nowIso,
    lastOutcome: outcome,
    lastIp: nodeIp,
    lastGeo: compactGeo(geo) || previous.lastGeo,
    successCount: outcome === "ok" ? (previous.successCount || 0) + 1 : previous.successCount,
    failCount: outcome === "fail" ? (previous.failCount || 0) + 1 : previous.failCount,
    consecutiveFailCount: outcome === "fail" ? (previous.consecutiveFailCount || 0) + 1 : 0,
  };
  await writeProxyNodeUsageState(usage);
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

function resolveBrowserLocale(country?: string): string {
  const derived = deriveLocale(country);
  return /^(zh|ja|ko|ar|he|ru|uk|tr|th|vi|ms|id)\b/i.test(derived) ? "en-US" : derived;
}

function mergeGeoInfo(primary: GeoInfo | undefined, fallback: GeoInfo | undefined): GeoInfo | undefined {
  const ip = normalizeIp(primary?.ip) || normalizeIp(fallback?.ip);
  if (!ip) return undefined;
  return {
    ...(fallback || {}),
    ...(primary || {}),
    ip,
    country: primary?.country || fallback?.country,
    region: primary?.region || fallback?.region,
    city: primary?.city || fallback?.city,
    org: primary?.org || fallback?.org,
    timezone: primary?.timezone || fallback?.timezone,
    latitude: primary?.latitude ?? fallback?.latitude,
    longitude: primary?.longitude ?? fallback?.longitude,
    raw: primary?.raw ?? fallback?.raw,
  };
}

function needsGeoEnrichment(geo: GeoInfo | undefined): boolean {
  return Boolean(geo?.ip) && (!geo?.country || !geo?.timezone || !geo?.city);
}

async function enrichGeoInfo(geo: GeoInfo | undefined, ipinfoToken?: string): Promise<GeoInfo | undefined> {
  if (!needsGeoEnrichment(geo) || !geo?.ip) return geo;
  try {
    return mergeGeoInfo(geo, await lookupIpInfo(geo.ip, ipinfoToken));
  } catch {
    return geo;
  }
}

let proxyBootstrapQueue: Promise<void> = Promise.resolve();

function withProxyBootstrapLock<T>(task: () => Promise<T>): Promise<T> {
  const previous = proxyBootstrapQueue;
  let release!: () => void;
  proxyBootstrapQueue = new Promise<void>((resolve) => {
    release = resolve;
  });
  return (async () => {
    await previous;
    try {
      return await task();
    } finally {
      release();
    }
  })();
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

interface ProxyIpUsageEntry {
  ip: string;
  lastUsedMs: number | null;
  lastOutcome?: "ok" | "fallback" | "fail";
  consecutiveFailCount: number;
  failCount: number;
}

function buildProxyIpUsageIndex(usage: ProxyNodeUsageState): Map<string, ProxyIpUsageEntry> {
  const byIp = new Map<string, ProxyIpUsageEntry>();
  for (const entry of Object.values(usage.nodes)) {
    const ip = normalizeIp(entry.lastIp || entry.lastGeo?.ip);
    if (!ip) continue;
    const lastUsedMs = entry.lastUsedAt ? Date.parse(entry.lastUsedAt) : NaN;
    const normalizedLastUsedMs = Number.isFinite(lastUsedMs) ? lastUsedMs : null;
    const current = byIp.get(ip);
    if (!current) {
      byIp.set(ip, {
        ip,
        lastUsedMs: normalizedLastUsedMs,
        lastOutcome: entry.lastOutcome,
        consecutiveFailCount: entry.consecutiveFailCount || 0,
        failCount: entry.failCount || 0,
      });
      continue;
    }
    const currentMs = current.lastUsedMs ?? Number.NEGATIVE_INFINITY;
    const nextMs = normalizedLastUsedMs ?? Number.NEGATIVE_INFINITY;
    if (nextMs >= currentMs) {
      current.lastUsedMs = normalizedLastUsedMs;
      current.lastOutcome = entry.lastOutcome;
      current.consecutiveFailCount = entry.consecutiveFailCount || 0;
      current.failCount = entry.failCount || 0;
    } else {
      current.consecutiveFailCount = Math.max(current.consecutiveFailCount, entry.consecutiveFailCount || 0);
      current.failCount = Math.max(current.failCount, entry.failCount || 0);
    }
  }
  return byIp;
}

function resolveKnownNodeIp(
  entry: ProxyNodeUsageEntry | undefined,
  nowMs?: number,
  ttlMs?: number,
): string | undefined {
  if (Number.isFinite(nowMs) && Number.isFinite(ttlMs) && !isUsageEntryFresh(entry, nowMs as number, ttlMs as number)) {
    return undefined;
  }
  return normalizeIp(entry?.lastIp || entry?.lastGeo?.ip);
}

function computeHistoricalNodeReliabilityPenalty(successCount: number | undefined, failCount: number | undefined): number {
  const success = Math.max(0, Number(successCount) || 0);
  const fail = Math.max(0, Number(failCount) || 0);
  const total = success + fail;
  if (total <= 0) return 0;

  const failureRatioPenalty = Math.round((fail / total) * 1_600);
  const accumulatedFailPenalty = Math.min(1_800, fail * 4);
  const successCredit = Math.min(900, success * 28);
  return Math.max(0, failureRatioPenalty + accumulatedFailPenalty - successCredit);
}

function nodeSelectionScore(
  name: string,
  usage: ProxyNodeUsageState,
  recentSelectedIps: string[],
  nowMs: number,
  cfg: AppConfig,
  ipUsageByIp: Map<string, ProxyIpUsageEntry>,
): number {
  const entry = usage.nodes[name];
  const nodeIp = normalizeIp(entry?.lastIp || entry?.lastGeo?.ip);
  const historicalReliabilityPenalty = computeHistoricalNodeReliabilityPenalty(entry?.successCount, entry?.failCount);
  const unknownIpFailPenalty =
    (entry?.lastOutcome === "fail" ? 180 : 0) + (entry?.consecutiveFailCount || 0) * 260 + historicalReliabilityPenalty;
  const unknownIpLatencyPenalty = typeof entry?.lastLatencyMs === "number" && entry.lastLatencyMs > 0 ? entry.lastLatencyMs / 90 : 0;
  const unknownIpOrg = (entry?.lastGeo?.org || "").toLowerCase();
  const unknownIpHostingPenalty =
    /colocrossing|colo crossing|hostpapa|zmto|digitalocean|linode|vultr|ovh|hetzner|contabo|amazon|aws|google cloud|azure|oracle cloud|hosting|datacenter|data center|vps|server/i.test(
      unknownIpOrg,
    )
      ? 2400
      : 0;
  if (!nodeIp) {
    return 15_000 + unknownIpFailPenalty + unknownIpLatencyPenalty + unknownIpHostingPenalty + Math.random() * 16;
  }

  const ipUsage = ipUsageByIp.get(nodeIp);
  const recentIpPenalty = recentSelectedIps.includes(nodeIp) ? 1800 : 0;
  const hottestIpPenalty = recentSelectedIps[0] === nodeIp ? 900 : 0;
  const lastUsedMs = ipUsage?.lastUsedMs ?? NaN;
  const neverUsedPenalty = Number.isFinite(lastUsedMs) ? 0 : 8_000;
  const idleMinutes = Number.isFinite(lastUsedMs) ? Math.max(0, (nowMs - lastUsedMs) / 60_000) : 0;
  const longUnusedBonus = -Math.min(7_200, Math.round(idleMinutes * 2));
  const cooldownRemaining = Number.isFinite(lastUsedMs) ? cfg.nodeReuseCooldownMs - (nowMs - lastUsedMs) : 0;
  const cooldownPenalty =
    cooldownRemaining > 0 ? Math.round((cooldownRemaining / Math.max(1, cfg.nodeReuseCooldownMs)) * 900) : 0;
  const failPenalty = ((ipUsage?.lastOutcome === "fail" ? 180 : 0) + (ipUsage?.consecutiveFailCount || 0) * 260);
  const reliabilityPenalty = computeHistoricalNodeReliabilityPenalty(entry?.successCount, entry?.failCount);
  const latencyPenalty = typeof entry?.lastLatencyMs === "number" && entry.lastLatencyMs > 0 ? entry.lastLatencyMs / 90 : 0;
  const org = (entry?.lastGeo?.org || "").toLowerCase();
  const hostingPenalty =
    /colocrossing|colo crossing|hostpapa|zmto|digitalocean|linode|vultr|ovh|hetzner|contabo|amazon|aws|google cloud|azure|oracle cloud|hosting|datacenter|data center|vps|server/i.test(
      org,
    )
      ? 2400
      : 0;
  return (
    neverUsedPenalty +
    longUnusedBonus +
    recentIpPenalty +
    hottestIpPenalty +
    cooldownPenalty +
    failPenalty +
    reliabilityPenalty +
    latencyPenalty +
    hostingPenalty +
    Math.random() * 0.01
  );
}

function buildMihomoConfig(
  cfg: AppConfig,
  overrides?: { apiPort?: number; mixedPort?: number; workDir?: string },
): MihomoConfig {
  return {
    subscriptionUrl: cfg.mihomoSubscriptionUrl,
    apiPort: overrides?.apiPort ?? cfg.mihomoApiPort,
    mixedPort: overrides?.mixedPort ?? cfg.mihomoMixedPort,
    groupName: cfg.mihomoGroupName,
    routeGroupName: cfg.mihomoRouteGroupName,
    checkUrl: cfg.proxyCheckUrl,
    workDir: overrides?.workDir ?? path.join(OUTPUT_PATH, "mihomo"),
    downloadDir: path.resolve("downloads", "mihomo"),
  };
}

async function switchProxyGroup(controller: Awaited<ReturnType<typeof startMihomo>>, name: string): Promise<void> {
  await controller.setGroupProxy(name);
  const selected = await controller.getGroupSelection().catch(() => null);
  if (selected && selected !== name) {
    throw new Error(`proxy_group_mismatch:${name}->${selected}`);
  }
  // Mihomo needs a short settle window after switching groups, otherwise Chrome hits ERR_CONNECTION_CLOSED on the old tunnel.
  await delay(5_000);
}

async function selectProxyNode(
  controller: Awaited<ReturnType<typeof startMihomo>>,
  cfg: AppConfig,
  overrideName?: string,
  blockedEgressIps: Set<string> = new Set(),
  runtimeRecentSelectedIps: string[] = [],
  overrideExpectedIp?: string,
  busyProxyNames: Set<string> = new Set(),
  busyProxyIps: Set<string> = new Set(),
): Promise<NodeCheckResult> {
  const usage = await readProxyNodeUsageState();
  const nowMs = Date.now();
  const nowIso = new Date().toISOString();
  const emptyUsageEntry: ProxyNodeUsageEntry = { count: 0, successCount: 0, failCount: 0, consecutiveFailCount: 0 };

  const persistSelection = async (name: string, result: NodeCheckResult, outcome: "ok" | "fallback"): Promise<void> => {
    const previous = usage.nodes[name] || emptyUsageEntry;
    const nodeIp = normalizeIp(result.geo?.ip);
    usage.nodes[name] = {
      ...previous,
      count: (previous.count || 0) + 1,
      lastUsedAt: nowIso,
      lastCheckedAt: nowIso,
      lastOutcome: outcome,
      lastLatencyMs: result.latencyMs ?? previous.lastLatencyMs ?? null,
      lastIp: nodeIp || previous.lastIp,
      lastGeo: compactGeo(result.geo) || previous.lastGeo,
      consecutiveFailCount: previous.consecutiveFailCount || 0,
    };
    usage.recentSelected = pushRecentUnique(usage.recentSelected, name, cfg.nodeRecentWindow);
    if (nodeIp) {
      const updated = pushRecentUnique(runtimeRecentSelectedIps, nodeIp, cfg.nodeRecentWindow);
      runtimeRecentSelectedIps.splice(0, runtimeRecentSelectedIps.length, ...updated);
    }
    await writeProxyNodeUsageState(usage);
  };

  const buildResult = (name: string, previous: ProxyNodeUsageEntry, expectedIp?: string): NodeCheckResult => {
    const nodeIp = normalizeIp(expectedIp) || normalizeIp(previous.lastGeo?.ip) || normalizeIp(previous.lastIp);
    return {
      name,
      ok: true,
      latencyMs: previous.lastLatencyMs ?? null,
      geo: nodeIp ? ({ ...(compactGeo(previous.lastGeo) || {}), ip: nodeIp } as GeoInfo) : previous.lastGeo,
    };
  };

  if (overrideName) {
    const previous = usage.nodes[overrideName] || emptyUsageEntry;
    const currentSelection = await controller.getGroupSelection().catch(() => null);
    if (currentSelection !== overrideName) {
      await switchProxyGroup(controller, overrideName);
    }
    const result = buildResult(overrideName, previous, overrideExpectedIp);
    await persistSelection(overrideName, result, "ok");
    log(`proxy override selected: ${overrideName} latency=${result.latencyMs ?? "n/a"}ms egress_ip=${normalizeIp(result.geo?.ip) || "?"}`);
    return result;
  }

  const nodes = await controller.listGroupNodes();
  const allNames = nodes.map((node) => node.name).filter((name) => name.trim().length > 0);
  if (allNames.length === 0) {
    throw new Error("proxy_node_inventory_empty");
  }
  const names = allNames.filter((name) => !busyProxyNames.has(name));
  if (names.length === 0) {
    throw new Error("proxy_all_nodes_busy");
  }
  const ipUsageByIp = buildProxyIpUsageIndex(usage);
  const scoreByNode = new Map<string, number>();
  for (const name of names) {
    scoreByNode.set(name, nodeSelectionScore(name, usage, runtimeRecentSelectedIps, nowMs, cfg, ipUsageByIp));
  }
  const sorted = [...names].sort((a, b) => {
    const diff = (scoreByNode.get(a) || 0) - (scoreByNode.get(b) || 0);
    return diff !== 0 ? diff : a.localeCompare(b);
  });
  const seenKnownIps = new Set<string>();
  const prioritized: string[] = [];
  for (const name of sorted) {
    const knownIp = resolveKnownNodeIp(usage.nodes[name], nowMs, cfg.nodeCheckCacheTtlMs);
    if (!knownIp) {
      prioritized.push(name);
      continue;
    }
    if (seenKnownIps.has(knownIp)) {
      continue;
    }
    seenKnownIps.add(knownIp);
    prioritized.push(name);
  }
  const cooldownBlockedIps = new Set<string>();
  for (const item of ipUsageByIp.values()) {
    if (!Number.isFinite(item.lastUsedMs)) continue;
    if (nowMs - (item.lastUsedMs as number) < cfg.nodeReuseCooldownMs) {
      cooldownBlockedIps.add(item.ip);
    }
  }
  const orderPreview = prioritized
    .slice(0, 8)
    .map((name) => `${name}(${(scoreByNode.get(name) || 0).toFixed(1)})`)
    .join(", ");
  log(`proxy node order: ${orderPreview}${prioritized.length > 8 ? " ..." : ""}`);
  log(`proxy recent egress IPs: ${runtimeRecentSelectedIps.length > 0 ? runtimeRecentSelectedIps.join(", ") : "(none)"}`);
  if (cooldownBlockedIps.size > 0) {
    log(
      `proxy cooldown-blocked IPs (${Math.round(cfg.nodeReuseCooldownMs / 3_600_000)}h): ${Array.from(cooldownBlockedIps)
        .slice(0, 6)
        .join(", ")}${cooldownBlockedIps.size > 6 ? " ..." : ""}`,
    );
  }
  if (blockedEgressIps.size > 0) {
    log(`proxy blocked IPs: ${Array.from(blockedEgressIps).slice(0, 6).join(", ")}${blockedEgressIps.size > 6 ? " ..." : ""}`);
  }
  if (busyProxyNames.size > 0) {
    log(`proxy busy nodes: ${Array.from(busyProxyNames).slice(0, 6).join(", ")}${busyProxyNames.size > 6 ? " ..." : ""}`);
  }
  if (busyProxyIps.size > 0) {
    log(`proxy busy IPs: ${Array.from(busyProxyIps).slice(0, 6).join(", ")}${busyProxyIps.size > 6 ? " ..." : ""}`);
  }

  for (const name of prioritized) {
    const previous = usage.nodes[name] || emptyUsageEntry;
    const previousIp = resolveKnownNodeIp(previous, nowMs, cfg.nodeCheckCacheTtlMs);
    if (previousIp && cooldownBlockedIps.has(previousIp)) {
      continue;
    }
    if (previousIp && blockedEgressIps.has(previousIp)) {
      continue;
    }
    if (previousIp && busyProxyIps.has(previousIp)) {
      continue;
    }
    await switchProxyGroup(controller, name);
    const result = buildResult(name, previous);
    await persistSelection(name, result, "ok");
    log(`proxy selected by node rotation: ${name} latency=${result.latencyMs ?? "n/a"}ms egress_ip=${normalizeIp(result.geo?.ip) || "?"}`);
    return result;
  }

  throw new Error("proxy_no_available_node");
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

function countPasswordCategoryHits(password: string): number {
  let hits = 0;
  if (/[a-z]/.test(password)) hits += 1;
  if (/[A-Z]/.test(password)) hits += 1;
  if (/\d/.test(password)) hits += 1;
  if (/[^A-Za-z0-9]/.test(password)) hits += 1;
  return hits;
}

function hasTripleRepeatedChars(password: string): boolean {
  return /(.)\1\1/.test(password);
}

function isCompliantGeneratedPassword(password: string): boolean {
  return password.length >= 14 && countPasswordCategoryHits(password) >= 4 && !hasTripleRepeatedChars(password);
}

function randomPassword(): string {
  const lowers = "abcdefghijklmnopqrstuvwxyz";
  const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  // Keep the special-character set aligned with Tavily/Auth0's visible password policy hint.
  const specials = "!@#$%^&*";
  const all = `${lowers}${uppers}${digits}${specials}`;
  for (let attempt = 0; attempt < 32; attempt += 1) {
    // Bias toward higher-entropy passwords to reduce "too weak" server-side rejections.
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
    const candidate = shuffleChars(chars).join("");
    if (isCompliantGeneratedPassword(candidate)) {
      return candidate;
    }
  }
  return "Aa1!SecurePass97";
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

function normalizeCaptchaForSubmit(raw: string, maxLength = 6): string {
  const cleaned = sanitizeCaptchaText(raw);
  if (cleaned.length <= maxLength) return cleaned;
  return cleaned.slice(0, maxLength);
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
  if (/native_cdp_unavailable/i.test(message)) return "native_cdp_unavailable";
  if (/task_attempt_timeout/i.test(message)) return "task_attempt_timeout";
  if (/ERR_TIMED_OUT/i.test(message)) return "network_timeout";
  if (/ERR_CONNECTION_CLOSED/i.test(message)) return "network_connection_closed";
  if (/ERR_CONNECTION_RESET/i.test(message)) return "network_connection_reset";
  if (/auth_session_invalid_request/i.test(message)) return "auth_session_invalid_request";
  if (/challenge_unresponsive/i.test(message)) return "challenge_unresponsive";
  if (/risk_control_ip_rate_limit/i.test(message)) return "too_many_signups_same_ip";
  if (risk.hasIpRateLimit) return "too_many_signups_same_ip";
  if (/mailbox_rate_limited/i.test(message)) return "mailbox_rate_limited";
  if (/signup_password_captcha_missing/i.test(message)) return "signup_password_captcha_missing";
  if (/risk_control_suspicious_activity/i.test(message) || risk.hasSuspiciousActivity) {
    return "risk_control_suspicious_activity";
  }
  if (risk.hasExtensibilityError || /extensibility_error|custom-script-error-code_extensibility_error/i.test(message)) {
    return "auth0_extensibility_error";
  }
  if (risk.hasInvalidCaptcha || /invalid-captcha|captcha failed|captcha_ocr_unstable/i.test(message)) {
    return "invalid_captcha";
  }
  if (/proxy_node_blocked_by_recent_ip_rate_limit/i.test(message)) {
    return "proxy_ip_rate_limit_block";
  }
  if (/microsoft_proof_mailbox_missing/i.test(message)) return "microsoft_proof_mailbox_missing";
  if (/moemail_api_key_missing/i.test(message)) return "moemail_api_key_missing";
  if (/moemail_mailbox_not_found/i.test(message)) return "moemail_mailbox_not_found";
  if (/microsoft_unknown_recovery_email/i.test(message)) return "microsoft_unknown_recovery_email";
  if (/microsoft_password_fallback_unavailable/i.test(message)) return "microsoft_unknown_recovery_email";
  if (/microsoft_account_locked/i.test(message)) return "microsoft_account_locked";
  if (/microsoft_auth_try_again_later/i.test(message)) return "microsoft_auth_try_again_later";
  if (/microsoft_password_rate_limited/i.test(message)) return "microsoft_password_rate_limited";
  if (/microsoft_password_incorrect/i.test(message)) return "microsoft_password_incorrect";
  if (/microsoft_password_submit_stalled/i.test(message)) return "microsoft_password_submit_stalled";
  if (/microsoft_consent_accept_missing/i.test(message)) return "microsoft_consent_accept_missing";
  if (/microsoft_proof_add_email_input_missing/i.test(message)) return "microsoft_proof_add_email_input_missing";
  if (/microsoft_proof_add_submit_missing/i.test(message)) return "microsoft_proof_add_submit_missing";
  if (/microsoft_proof_code_timeout/i.test(message)) return "microsoft_proof_code_timeout";
  if (/microsoft_proof_submit_failed/i.test(message)) return "microsoft_proof_submit_failed";
  if (/timeout/i.test(normalized)) return "timeout";
  if (/network/i.test(normalized)) return "network";
  if (/browser precheck failed/i.test(normalized)) return "browser_precheck_failed";
  if (/verification email (not found|code not found)/i.test(normalized)) return "verification_email_missing";
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
  const dir = new URL(".", path);
  await mkdir(dir, { recursive: true });
  const content = `${JSON.stringify(payload, null, 2)}\n`;
  const targetPath = fileURLToPath(path);
  const tmpPath = `${targetPath}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tmpPath, content, "utf8");
  try {
    await rename(tmpPath, targetPath);
  } catch (error: any) {
    // Best-effort fallback for platforms where rename won't overwrite.
    const code = typeof error?.code === "string" ? error.code : "";
    if (code === "EEXIST" || code === "EPERM") {
      await rm(targetPath, { force: true }).catch(() => {});
      await rename(tmpPath, targetPath);
      return;
    }
    throw error;
  }
}

async function readJsonFile(path: URL): Promise<unknown | null> {
  try {
    const targetPath = fileURLToPath(path);
    const raw = await readFile(targetPath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

class CaptchaSolver {
  rotatePreferredModel(_reason: string): void {}

  async solve(_pngData: Buffer): Promise<string> {
    throw new Error("image_captcha_not_supported");
  }
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

const SINGLE_BROWSER_IP_PROBE_TARGET: IpProbeTarget = {
  name: "ifconfig",
  scope: "global",
  url: "https://ifconfig.me/ip",
};

const SINGLE_BROWSER_IP_PROBE_TARGETS: IpProbeTarget[] = [
  SINGLE_BROWSER_IP_PROBE_TARGET,
  ...GLOBAL_IP_PROBE_TARGETS,
  ...DOMESTIC_IP_PROBE_TARGETS,
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

function isChallengeResourceUrl(url: string): boolean {
  return AUTH_CHALLENGE_RESOURCE_RE.test(url);
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

function isPublicIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return isPublicIpv4(ip);
  if (family !== 6) return false;
  const normalized = ip.toLowerCase();
  if (normalized === "::1" || normalized === "::") return false;
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) {
    return false;
  }
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return false;
  if (normalized.startsWith("ff")) return false;
  return true;
}

function extractPublicIpList(text: string): string[] {
  const found = [
    ...(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []),
    ...(text.match(/\b(?:(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4})\b/g) || []),
  ];
  const unique: string[] = [];
  for (const raw of found) {
    const normalized = normalizeIp(raw);
    if (!normalized || !isPublicIp(normalized)) continue;
    if (!unique.includes(normalized)) {
      unique.push(normalized);
    }
  }
  return unique;
}

async function collectIpProbeSnapshot(page: any, target: IpProbeTarget, waitMs = 6500): Promise<IpProbeSnapshot> {
  const expectedHost = new URL(target.url).hostname.toLowerCase();
  const navigationTimeout = Math.max(6_000, Math.min(15_000, waitMs + 8_500));
  const loadStateTimeout = Math.max(10_000, Math.min(60_000, waitMs + 54_500));
  await safeGoto(page, target.url, navigationTimeout);
  await page.waitForLoadState("domcontentloaded", { timeout: loadStateTimeout });
  await page.waitForTimeout(waitMs);

  const payload = await page.evaluate(() => {
    const text = document.body?.innerText || "";
    return {
      text,
      url: window.location.href,
    };
  });
  const text = typeof payload.text === "string" ? payload.text : "";
  const ipCandidates = extractPublicIpList(text);
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

async function collectSingleBrowserIpProbe(page: any): Promise<IpProbeSnapshot> {
  let lastSnapshot: IpProbeSnapshot | null = null;
  for (const target of SINGLE_BROWSER_IP_PROBE_TARGETS) {
    const snapshot = await safeCollectIpProbeSnapshot(page, target, 4500);
    lastSnapshot = snapshot;
    if (normalizeIp(snapshot.ip || snapshot.ipCandidates?.[0])) {
      return snapshot;
    }
  }
  return (
    lastSnapshot || {
      name: SINGLE_BROWSER_IP_PROBE_TARGET.name,
      scope: SINGLE_BROWSER_IP_PROBE_TARGET.scope,
      url: SINGLE_BROWSER_IP_PROBE_TARGET.url,
      ipCandidates: [],
      loaded: false,
      error: "browser ip probe exhausted all targets",
    }
  );
}

async function collectSingleBrowserIpProbeWithMinimalContext(browser: Browser): Promise<IpProbeSnapshot> {
  const probeContext = await browser.newContext();
  try {
    const probePage = await probeContext.newPage();
    return await collectSingleBrowserIpProbe(probePage);
  } finally {
    await probeContext.close().catch(() => {});
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

  const payload = await page.evaluate(`(() => {
    const text = document.body ? document.body.innerText : "";
    const lines = text
      .split(/\\r?\\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    const normalize = (line) => line.toLowerCase().replace(/[:\\s]+$/g, "");
    const escapeRegex = (value) => {
      const specials = "\\\\^$.*+?()[]{}|";
      let out = "";
      for (const ch of value) {
        if (specials.indexOf(ch) >= 0) {
          out += "\\\\";
        }
        out += ch;
      }
      return out;
    };
    const findAfter = (label) => {
      const target = normalize(label);
      for (let i = 0; i < lines.length - 1; i += 1) {
        if (normalize(lines[i] || "") === target) {
          return lines[i + 1] || "";
        }
      }
      return "";
    };
    const findInline = (label) => {
      const escaped = escapeRegex(label);
      const patterns = [
        new RegExp(escaped + "\\\\s*[:：]\\\\s*([^\\\\n]+)", "i"),
        new RegExp(escaped + "\\\\s+([^\\\\n]+)", "i"),
      ];
      for (const pattern of patterns) {
        const matched = text.match(pattern);
        if (matched && matched[1]) {
          return matched[1].trim();
        }
      }
      return "";
    };
    const pick = (label) => findAfter(label) || findInline(label);

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
      webdriver: Boolean(navigator.webdriver),
    };
  })()`);
  const text = typeof payload.text === "string" ? payload.text : "";
  const ipCandidates = extractPublicIpList(text);
  const labeledIp = normalizeIp(typeof payload.ipAddress === "string" ? payload.ipAddress : "");
  const ipAddress = labeledIp && isPublicIp(labeledIp) ? labeledIp : ipCandidates[0];

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

  const domesticWithIp = domesticIps.filter((probe) => !!probe.ip);
  const globalWithIp = globalIps.filter((probe) => !!probe.ip);
  if (domesticWithIp.length === 0) {
    issues.push("domestic ip probes did not expose any IP address");
  }
  if (globalWithIp.length === 0) {
    issues.push("global ip probes did not expose any IP address");
  }
  if (cfg.browserPrecheckStrict && domesticWithIp.length + globalWithIp.length < 3) {
    issues.push(
      `insufficient ip probe coverage: domestic=${domesticWithIp.length}/${domesticIps.length} global=${globalWithIp.length}/${globalIps.length}`,
    );
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

interface HttpRequestOptions {
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
  proxyUrl?: string;
}

async function fetchWithOptionalProxy(
  method: string,
  url: string,
  options?: HttpRequestOptions,
): Promise<any> {
  const timeoutMs = options?.timeoutMs ?? 25_000;

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

  if (options?.proxyUrl) {
    const impit = new Impit({ proxyUrl: options.proxyUrl, timeout: timeoutMs });
    return await impit.fetch(url, {
      method: method.toUpperCase() as any,
      headers,
      body,
    });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method: method.toUpperCase(),
      headers,
      body,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("http_failed:network:timeout");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function httpJson<T = unknown>(method: string, url: string, options?: HttpRequestOptions): Promise<T> {
  try {
    const resp = await fetchWithOptionalProxy(method, url, options);
    const text = await resp.text();
    const parsed = parseBody(text);

    if (!resp.ok) {
      throw new Error(`http_failed:${resp.status}:${trunc(parsed)}`);
    }
    return parsed as T;
  } catch (error) {
    if (error instanceof Error && error.message === "http_failed:network:timeout") {
      throw error;
    }
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("http_failed:network:timeout");
    }
    throw error;
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

function extractEmailCodeFromPayload(payload: unknown): string | null {
  const texts: string[] = [];
  collectStrings(payload, texts);
  const seen = new Set<string>();

  for (const text of texts) {
    const normalized = text
      .replaceAll("\\/", "/")
      .replaceAll("&amp;", "&")
      .replaceAll("\\u003d", "=")
      .replaceAll("\\u0026", "&")
      .replace(/\s+/g, " ");
    const matches = Array.from(normalized.matchAll(/\b(\d{6})\b/g));
    for (const match of matches) {
      const code = match[1];
      if (!code || seen.has(code)) continue;
      seen.add(code);
      const start = Math.max(0, (match.index || 0) - 64);
      const end = Math.min(normalized.length, (match.index || 0) + code.length + 64);
      const context = normalized.slice(start, end);
      if (/(code|otp|one-time|one time|verification|verify|login|sign in|identity)/i.test(context)) {
        return code;
      }
    }
  }

  if (seen.size === 1) {
    return Array.from(seen)[0] || null;
  }

  return null;
}

function isMailboxTransientError(reason: string): boolean {
  const lower = reason.toLowerCase();
  return [
    ":500:",
    ":502:",
    ":503:",
    ":504:",
    "timeout",
    "network",
    "temporarily unavailable",
    "connection reset",
    "socket hang up",
    "econnreset",
    "fetch failed",
    "eai_again",
    "ecconn",
    "unexpectedeof",
    "tls handshake eof",
    "hyper_util::client::legacy::error",
  ].some((needle) => lower.includes(needle));
}

function isMailboxRateLimitError(reason: string): boolean {
  const lower = reason.toLowerCase();
  return [":429:", "too many requests", "rate limit"].some((needle) => lower.includes(needle));
}

function normalizeVmailBaseUrl(raw: string): string {
  const trimmed = raw.replace(/\/+$/, "");
  if (/\/api\/v1$/i.test(trimmed)) {
    return trimmed;
  }
  return `${trimmed}/api/v1`;
}

function normalizeGptmailBaseUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  return trimmed || "https://mail.chatgpt.org.uk";
}

function extractCookieValue(setCookieHeader: string | null, name: string): string | null {
  if (!setCookieHeader) return null;
  const match = setCookieHeader.match(new RegExp(`(?:^|,\\s*)${name}=([^;]+)`, "i"));
  return match?.[1]?.trim() || null;
}

function extractGptmailAuthPayload(payload: unknown): GptmailAuthPayload | null {
  if (!payload || typeof payload !== "object") return null;
  const record = payload as JsonRecord;
  const auth = record.auth;
  if (!auth || typeof auth !== "object") return null;
  const authRecord = auth as JsonRecord;
  const token = typeof authRecord.token === "string" ? authRecord.token.trim() : "";
  if (!token) return null;
  const email = typeof authRecord.email === "string" ? authRecord.email.trim() : undefined;
  const expiresAtRaw = authRecord.expires_at ?? authRecord.expiresAt;
  const expiresAt = typeof expiresAtRaw === "number" && Number.isFinite(expiresAtRaw) ? expiresAtRaw : undefined;
  return { token, email, expiresAt };
}

function extractGptmailBootstrapAuth(html: string): GptmailAuthPayload {
  const match = html.match(/window\.__BROWSER_AUTH\s*=\s*(\{[\s\S]*?\});/i);
  if (!match?.[1]) {
    throw new Error("gptmail bootstrap auth missing");
  }
  const parsed = parseBody(match[1]);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("gptmail bootstrap auth invalid");
  }
  const parsedRecord = parsed as JsonRecord;
  const token = typeof parsedRecord.token === "string" ? parsedRecord.token.trim() : "";
  if (!token) {
    throw new Error("gptmail bootstrap auth token missing");
  }
  const email = typeof parsedRecord.email === "string" ? parsedRecord.email.trim() : undefined;
  const expiresAtRaw = parsedRecord.expires_at ?? parsedRecord.expiresAt;
  const expiresAt = typeof expiresAtRaw === "number" && Number.isFinite(expiresAtRaw) ? expiresAtRaw : undefined;
  return { token, email, expiresAt };
}

function buildGptmailHeaders(cookieValue: string, authToken: string): Record<string, string> {
  return {
    Accept: "application/json",
    Cookie: `gm_sid=${cookieValue}`,
    "X-Inbox-Token": authToken,
  };
}

function syncGptmailMailboxAuth(mailbox: MailboxSession, payload: unknown): void {
  if (mailbox.provider !== "gptmail") return;
  const auth = extractGptmailAuthPayload(payload);
  if (auth?.token) {
    mailbox.headers["X-Inbox-Token"] = auth.token;
  }
}

function buildVmailAuthHeaders(apiKey: string): Record<string, string> {
  const key = apiKey.trim();
  return {
    "X-API-Key": key,
    Authorization: `Bearer ${key}`,
  };
}

async function createDuckmailSession(cfg: AppConfig, proxyUrl?: string): Promise<MailboxSession> {
  const baseUrl = cfg.duckmailBaseUrl.replace(/\/+$/, "");
  const headers: Record<string, string> = {};
  if (cfg.duckmailApiKey) {
    headers.Authorization = `Bearer ${cfg.duckmailApiKey}`;
  }
  const isTransient = (reason: string): boolean => isMailboxTransientError(reason);
  const isAddressConflict = (reason: string): boolean => {
    const lower = reason.toLowerCase();
    return [":409:", "already exists", "already used", "duplicate", "taken"].some((k) => lower.includes(k));
  };

  const domainsResp = await httpJson<{ "hydra:member"?: Array<{ domain?: string }> }>("GET", `${baseUrl}/domains`, {
    headers,
    proxyUrl,
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
    const sorted = [...domains].sort((a, b) => a.localeCompare(b));
    pickedDomain = sorted[0]!;
  }

  const mailboxPassword = randomPassword();
  let address = "";
  let accountId = "";
  let createdOk = false;
  const createAttempts = 5;
  for (let attempt = 1; attempt <= createAttempts; attempt += 1) {
    address = `${randomMailboxLocalPart()}@${pickedDomain}`;
    try {
      const created = await httpJson<JsonRecord>("POST", `${baseUrl}/accounts`, {
        headers: { ...headers, "Content-Type": "application/json" },
        body: { address, password: mailboxPassword },
        proxyUrl,
      });
      accountId = typeof created.id === "string" ? created.id : "";
      createdOk = true;
      break;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (isMailboxRateLimitError(message)) {
        throw new Error("mailbox_rate_limited");
      }
      const retryable = isTransient(message) || isAddressConflict(message);
      if (!retryable || attempt === createAttempts) {
        throw error;
      }
      const waitMs = 700 * attempt;
      log(`duckmail account create retry ${attempt}/${createAttempts} after ${waitMs}ms: ${message.split("\n")[0]}`);
      await delay(waitMs);
    }
  }
  if (!createdOk || !address) {
    throw new Error("duckmail account create failed");
  }

  let tokenResp: JsonRecord | null = null;
  const tokenAttempts = 5;
  for (let attempt = 1; attempt <= tokenAttempts; attempt += 1) {
    try {
      tokenResp = await httpJson<JsonRecord>("POST", `${baseUrl}/token`, {
        headers: { ...headers, "Content-Type": "application/json" },
        body: { address, password: mailboxPassword },
        proxyUrl,
      });
      break;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!isTransient(message) || attempt === tokenAttempts) {
        throw error;
      }
      const waitMs = 700 * attempt;
      log(`duckmail token retry ${attempt}/${tokenAttempts} after ${waitMs}ms: ${message.split("\n")[0]}`);
      await delay(waitMs);
    }
  }
  if (!tokenResp) {
    throw new Error("duckmail token request failed");
  }

  const token = typeof tokenResp.token === "string" ? tokenResp.token : "";
  if (!accountId && typeof tokenResp.id === "string") {
    accountId = tokenResp.id;
  }

  if (!token) throw new Error("duckmail token response missing token");
  if (!accountId) throw new Error("duckmail account id missing");

  return {
    provider: "duckmail",
    baseUrl,
    address,
    accountId,
    headers: { Authorization: `Bearer ${token}` },
  };
}

function parseVmailAllowedDomains(message: string): string[] {
  const matched = message.match(/available domains:\s*([^"}\n]+)/i);
  if (!matched?.[1]) return [];
  return matched[1]
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter((item) => /^[a-z0-9.-]+$/i.test(item));
}

async function createVmailSession(cfg: AppConfig, proxyUrl?: string): Promise<MailboxSession> {
  if (!cfg.vmailApiKey) {
    throw new Error("vmail api key missing (set VMAIL_API_KEY)");
  }
  const baseUrl = normalizeVmailBaseUrl(cfg.vmailBaseUrl);
  const authHeaders = buildVmailAuthHeaders(cfg.vmailApiKey);

  const configuredDomain = (cfg.vmailDomain || "").trim().toLowerCase() || null;
  let domainCandidates: Array<string | null> = [configuredDomain];
  if (domainCandidates.length === 0) {
    domainCandidates = [null];
  }
  let lastError: Error | null = null;

  const createAttempts = 8;
  for (let attempt = 1; attempt <= createAttempts; attempt += 1) {
    const domain = domainCandidates[(attempt - 1) % domainCandidates.length] || null;
    try {
      const body: Record<string, string> = {};
      if (domain) {
        body.domain = domain;
      }
      const created = await httpJson<JsonRecord>("POST", `${baseUrl}/mailboxes`, {
        headers: {
          ...authHeaders,
          "Content-Type": "application/json",
        },
        body,
        proxyUrl,
      });

      const data = (created.data && typeof created.data === "object" ? (created.data as JsonRecord) : created) as JsonRecord;
      const accountId = String(data.id || "").trim();
      const address = String(data.address || "").trim();
      if (!accountId) {
        throw new Error("vmail mailbox create response missing id");
      }
      if (!address) {
        throw new Error("vmail mailbox create response missing address");
      }
      return {
        provider: "vmail",
        baseUrl,
        address,
        accountId,
        headers: authHeaders,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (isMailboxRateLimitError(message)) {
        lastError = new Error("mailbox_rate_limited");
        break;
      }
      const allowedDomains = parseVmailAllowedDomains(message);
      if (allowedDomains.length > 0) {
        domainCandidates = allowedDomains.filter((item, index, arr) => arr.indexOf(item) === index);
      }

      const isValidationError = /validation_error/i.test(message);
      const retryable =
        isMailboxTransientError(message) ||
        isValidationError ||
        /service unavailable|internal server error|bad gateway/i.test(message);

      if (!retryable || attempt === createAttempts) {
        lastError = error instanceof Error ? error : new Error(message);
        break;
      }

      const waitMs = Math.min(1200 * attempt, 6000);
      log(`vmail mailbox create retry ${attempt}/${createAttempts} after ${waitMs}ms: ${message.split("\n")[0]}`);
      await delay(waitMs);
    }
  }

  throw lastError || new Error("vmail mailbox create failed");
}

async function createGptmailSession(cfg: AppConfig, proxyUrl?: string): Promise<MailboxSession> {
  const baseUrl = normalizeGptmailBaseUrl(cfg.gptmailBaseUrl);
  let landingHtml = "";
  let gmSid = "";
  try {
    const resp = await fetchWithOptionalProxy("GET", baseUrl, {
      headers: { "User-Agent": "Mozilla/5.0" },
      timeoutMs: 25_000,
      proxyUrl,
    });
    landingHtml = await resp.text();
    if (!resp.ok) {
      throw new Error(`http_failed:${resp.status}:${trunc(landingHtml, 240)}`);
    }
    gmSid = extractCookieValue(resp.headers.get("set-cookie"), "gm_sid") || "";
  } catch (error) {
    if (error instanceof Error && (error.name === "AbortError" || error.message === "http_failed:network:timeout")) {
      throw new Error("http_failed:network:timeout");
    }
    throw error;
  }

  if (!gmSid) {
    throw new Error("gptmail session cookie missing");
  }

  const bootstrapAuth = extractGptmailBootstrapAuth(landingHtml);
  let generated: JsonRecord;
  try {
    generated = await httpJson<JsonRecord>("GET", `${baseUrl}/api/generate-email`, {
      headers: buildGptmailHeaders(gmSid, bootstrapAuth.token),
      proxyUrl,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (isMailboxRateLimitError(message)) {
      throw new Error("mailbox_rate_limited");
    }
    throw error;
  }
  const generatedData =
    generated.data && typeof generated.data === "object" ? (generated.data as JsonRecord) : (generated as JsonRecord);
  const address = typeof generatedData.email === "string" ? generatedData.email.trim() : "";
  if (!address) {
    throw new Error("gptmail generate-email response missing address");
  }

  const auth = extractGptmailAuthPayload(generated) || bootstrapAuth;
  return {
    provider: "gptmail",
    baseUrl,
    address,
    accountId: address,
    headers: buildGptmailHeaders(gmSid, auth.token),
  };
}

async function createMailboxSession(cfg: AppConfig, blockedDomains: ReadonlySet<string>, proxyUrl?: string): Promise<MailboxSession> {
  const createRawSession = async (): Promise<MailboxSession> => {
    if (cfg.mailProvider === "gptmail") {
      return await createGptmailSession(cfg, proxyUrl);
    }
    if (cfg.mailProvider === "duckmail") {
      return await createDuckmailSession(cfg, proxyUrl);
    }
    return await createVmailSession(cfg, proxyUrl);
  };

  let lastBlockedDomain: string | undefined;
  for (let attempt = 1; attempt <= 8; attempt += 1) {
    const mailbox = await createRawSession();
    if (!isBlockedMailboxAddress(blockedDomains, mailbox.address)) {
      return mailbox;
    }
    const { domain } = splitEmail(mailbox.address);
    lastBlockedDomain = domain;
    log(`mailbox domain skipped by denylist (attempt=${attempt}): ${mailbox.address}`);
    await delay(Math.min(1200 * attempt, 4000));
  }

  throw new Error(`mailbox_domain_blocked:${lastBlockedDomain || "unknown"}`);
}

async function resolveMoeMailMailboxId(cfg: AppConfig, address: string, proxyUrl?: string): Promise<string | null> {
  return await resolveMoeMailMailboxIdViaOpenApi({
    baseUrl: cfg.moemailBaseUrl,
    apiKey: cfg.moemailApiKey || "",
    address,
    httpJson,
    proxyUrl,
  });
}

async function persistResolvedMicrosoftProofMailbox(cfg: AppConfig, address: string, mailboxId: string): Promise<void> {
  const envAccountId = Number.parseInt((process.env.TASK_LEDGER_ACCOUNT_ID || "").trim(), 10);
  if (!Number.isInteger(envAccountId) || envAccountId < 1) {
    return;
  }
  const { AppDatabase } = await import("./storage/app-db.js");
  const dbPath = path.resolve(process.env.TASK_LEDGER_DB_PATH || cfg.taskLedger.dbPath);
  const db = new AppDatabase(dbPath);
  try {
    db.updateAccountProofMailbox(envAccountId, {
      provider: "moemail",
      address,
      mailboxId,
    });
  } finally {
    db.close();
  }
}

async function syncLinkedMicrosoftAccountOutcome(
  cfg: AppConfig,
  outcome: { status: "succeeded"; apiKey: string } | { status: "failed"; errorCode?: string | null },
): Promise<void> {
  const envJobId = Number.parseInt((process.env.TASK_LEDGER_JOB_ID || "").trim(), 10);
  const envAccountId = Number.parseInt((process.env.TASK_LEDGER_ACCOUNT_ID || "").trim(), 10);
  if (!Number.isInteger(envAccountId) || envAccountId < 1) {
    return;
  }
  const isScheduledWorker = Number.isInteger(envJobId) && envJobId > 0;
  if (isScheduledWorker && outcome.status === "succeeded") {
    return;
  }
  const preserveLease = isScheduledWorker && outcome.status === "failed";
  const { AppDatabase } = await import("./storage/app-db.js");
  const dbPath = path.resolve(process.env.TASK_LEDGER_DB_PATH || cfg.taskLedger.dbPath);
  const db = new AppDatabase(dbPath);
  try {
    if (outcome.status === "succeeded") {
      db.recordApiKey(envAccountId, outcome.apiKey);
      db.markAccountDirectSuccess(envAccountId);
      return;
    }
    db.markAccountDirectFailure(envAccountId, outcome.errorCode ?? null, {
      releaseLease: !preserveLease,
    });
  } finally {
    db.close();
  }
}

async function provisionMicrosoftProofMailbox(cfg: AppConfig, proxyUrl?: string): Promise<{ address: string; mailboxId: string }> {
  if (!cfg.moemailApiKey) {
    throw new Error("moemail_api_key_missing");
  }
  const mailbox = await provisionMoeMailMailbox({
    baseUrl: cfg.moemailBaseUrl,
    apiKey: cfg.moemailApiKey,
    httpJson,
    proxyUrl,
    expiryTime: 0,
  });
  cfg.microsoftProofMailboxProvider = "moemail";
  cfg.microsoftProofMailboxAddress = mailbox.address;
  cfg.microsoftProofMailboxId = mailbox.id;
  try {
    await persistResolvedMicrosoftProofMailbox(cfg, mailbox.address, mailbox.id);
  } catch (error) {
    log(`proof mailbox provision cache skipped: ${error instanceof Error ? error.message : String(error)}`);
  }
  log(`login flow: provisioned Microsoft proof mailbox ${mailbox.address}`);
  return {
    address: mailbox.address,
    mailboxId: mailbox.id,
  };
}

async function resolveMicrosoftProofMailboxSession(
  cfg: AppConfig,
  proxyUrl?: string,
  options?: { allowProvision?: boolean },
): Promise<MailboxSession> {
  const provider = cfg.microsoftProofMailboxProvider || "moemail";
  if (provider !== "moemail") {
    throw new Error(`unsupported_microsoft_proof_mailbox_provider:${provider}`);
  }
  if (!cfg.moemailApiKey) {
    throw new Error("moemail_api_key_missing");
  }
  let address = cfg.microsoftProofMailboxAddress?.trim() || "";
  if (!address) {
    if (!options?.allowProvision) {
      const callerStack = new Error("microsoft_proof_mailbox_missing")
        .stack?.split("\n")
        .slice(1, 4)
        .map((line) => line.trim())
        .join(" | ");
      log(`login flow: configured Microsoft proof mailbox missing (${callerStack || "stack unavailable"})`);
      throw new Error("microsoft_proof_mailbox_missing");
    }
    const provisioned = await provisionMicrosoftProofMailbox(cfg, proxyUrl);
    address = provisioned.address;
  }
  let mailboxId = cfg.microsoftProofMailboxId?.trim() || "";
  if (!mailboxId) {
    mailboxId = (await resolveMoeMailMailboxId(cfg, address, proxyUrl)) || "";
    if (!mailboxId) {
      throw new Error(`moemail_mailbox_not_found:${address}`);
    }
    cfg.microsoftProofMailboxId = mailboxId;
    cfg.microsoftProofMailboxProvider = "moemail";
    try {
      await persistResolvedMicrosoftProofMailbox(cfg, address, mailboxId);
    } catch (error) {
      log(`proof mailbox id cache skipped: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return {
    provider: "moemail",
    baseUrl: normalizeMoeMailBaseUrl(cfg.moemailBaseUrl),
    address,
    accountId: mailboxId,
    headers: buildMoeMailAuthHeaders(cfg.moemailApiKey),
  };
}

async function waitForMicrosoftProofCode(
  mailbox: MailboxSession,
  timeoutMs: number,
  pollMs: number,
  proxyUrl?: string,
  notBeforeMs = Date.now() - 15_000,
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  let rateLimitHits = 0;
  let activeProxyUrl = proxyUrl;
  let directFallbackLogged = false;

  while (Date.now() < deadline) {
    try {
      const response = await httpJson<JsonRecord>("GET", `${mailbox.baseUrl}/api/emails/${encodeURIComponent(mailbox.accountId)}`, {
        headers: mailbox.headers,
        proxyUrl: activeProxyUrl,
      });
      const freshCode = extractFreshMicrosoftProofCodeFromMoeMailResponse(response, notBeforeMs);
      if (freshCode) return freshCode;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (isMailboxRateLimitError(message)) {
        if (activeProxyUrl && !directFallbackLogged) {
          activeProxyUrl = undefined;
          directFallbackLogged = true;
          log("microsoft proof mailbox rate limited via proxy, switch to direct polling");
          await delay(Math.max(1_200, pollMs));
          continue;
        }
        rateLimitHits += 1;
        const waitMs = Math.min(30_000, Math.max(4_000, pollMs * Math.min(rateLimitHits * 3, 12)));
        log(`microsoft proof mailbox rate limited, backoff ${waitMs}ms (hit=${rateLimitHits})`);
        await delay(waitMs);
        continue;
      }
      if (!isMailboxTransientError(message)) {
        throw error;
      }
      if (activeProxyUrl && !directFallbackLogged) {
        activeProxyUrl = undefined;
        directFallbackLogged = true;
        log(`microsoft proof mailbox transient via proxy, switch to direct polling: ${message.split("\n")[0]}`);
        await delay(Math.max(800, pollMs));
        continue;
      }
      log(`microsoft proof mailbox transient, retry after ${Math.max(400, pollMs)}ms: ${message.split("\n")[0]}`);
      await delay(Math.max(400, pollMs));
      continue;
    }
    await delay(Math.max(250, pollMs));
  }

  return null;
}

async function waitForVerificationLink(
  mailbox: MailboxSession,
  timeoutMs: number,
  pollMs: number,
  allowlist: string[],
  proxyUrl?: string,
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  const seen = new Set<string>();
  let rateLimitHits = 0;
  let activeProxyUrl = proxyUrl;
  let directFallbackLogged = false;

  while (Date.now() < deadline) {
    let items: unknown[] = [];
    try {
      if (mailbox.provider === "duckmail") {
        const messages = await httpJson<JsonRecord>("GET", `${mailbox.baseUrl}/messages`, {
          headers: mailbox.headers,
          proxyUrl: activeProxyUrl,
        });
        items = ((messages["hydra:member"] as unknown[]) || []).slice(0, 50);
      } else if (mailbox.provider === "gptmail") {
        const messages = await httpJson<JsonRecord>(
          "GET",
          `${mailbox.baseUrl}/api/emails?email=${encodeURIComponent(mailbox.address)}`,
          {
            headers: mailbox.headers,
            proxyUrl: activeProxyUrl,
          },
        );
        syncGptmailMailboxAuth(mailbox, messages);
        const data = messages.data;
        if (data && typeof data === "object" && Array.isArray((data as JsonRecord).emails)) {
          items = ((data as JsonRecord).emails as unknown[]).slice(0, 50);
        }
      } else {
        const messages = await httpJson<unknown>(
          "GET",
          `${mailbox.baseUrl}/mailboxes/${encodeURIComponent(mailbox.accountId)}/messages?limit=20`,
          {
            headers: mailbox.headers,
            proxyUrl: activeProxyUrl,
          },
        );
        if (messages && typeof messages === "object" && !Array.isArray(messages)) {
          const data = (messages as JsonRecord)["data"];
          if (Array.isArray(data)) {
            items = data.slice(0, 50);
          }
        } else if (Array.isArray(messages)) {
          items = messages.slice(0, 50);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (isMailboxRateLimitError(message)) {
        if (activeProxyUrl && !directFallbackLogged) {
          activeProxyUrl = undefined;
          directFallbackLogged = true;
          log("mailbox poll rate limited via proxy, switch to direct mailbox polling");
          await delay(Math.max(1_200, pollMs));
          continue;
        }
        rateLimitHits += 1;
        const waitMs = Math.min(30_000, Math.max(4_000, pollMs * Math.min(rateLimitHits * 3, 12)));
        log(`mailbox poll rate limited, backoff ${waitMs}ms (hit=${rateLimitHits})`);
        await delay(waitMs);
        continue;
      }
      if (!isMailboxTransientError(message)) {
        throw error;
      }
      if (activeProxyUrl && !directFallbackLogged) {
        activeProxyUrl = undefined;
        directFallbackLogged = true;
        log(`mailbox poll transient via proxy, switch to direct mailbox polling: ${message.split("\n")[0]}`);
        await delay(Math.max(800, pollMs));
        continue;
      }
      log(`mailbox poll transient, retry after ${Math.max(400, pollMs)}ms: ${message.split("\n")[0]}`);
      await delay(Math.max(400, pollMs));
      continue;
    }

    for (const item of items) {
      const fromSummary = extractVerificationLinkFromPayload(item, allowlist);
      if (fromSummary) return fromSummary;

      if (!item || typeof item !== "object") continue;
      const record = item as JsonRecord;
      const messageId = String(record.id || record.messageId || "").trim();
      if (!messageId || seen.has(messageId)) continue;
      seen.add(messageId);

      try {
        const detailUrl =
          mailbox.provider === "duckmail"
            ? `${mailbox.baseUrl}/messages/${encodeURIComponent(messageId)}`
            : mailbox.provider === "gptmail"
              ? `${mailbox.baseUrl}/api/email/${encodeURIComponent(messageId)}`
            : `${mailbox.baseUrl}/mailboxes/${encodeURIComponent(mailbox.accountId)}/messages/${encodeURIComponent(
                messageId,
              )}`;
        const detail = await httpJson<JsonRecord>("GET", detailUrl, {
          headers: mailbox.headers,
          proxyUrl: activeProxyUrl,
        });
        syncGptmailMailboxAuth(mailbox, detail);

        const payload =
          mailbox.provider !== "duckmail" && detail.data && typeof detail.data === "object"
            ? (detail.data as JsonRecord)
            : detail;
        const fromDetail = extractVerificationLinkFromPayload(payload, allowlist);
        if (fromDetail) return fromDetail;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (isMailboxRateLimitError(message)) {
          if (activeProxyUrl && !directFallbackLogged) {
            activeProxyUrl = undefined;
            directFallbackLogged = true;
            log("mailbox detail poll rate limited via proxy, switch to direct mailbox polling");
            await delay(Math.max(1_200, pollMs));
            continue;
          }
          rateLimitHits += 1;
          const waitMs = Math.min(30_000, Math.max(4_000, pollMs * Math.min(rateLimitHits * 3, 12)));
          log(`mailbox detail poll rate limited, backoff ${waitMs}ms (hit=${rateLimitHits})`);
          await delay(waitMs);
          continue;
        }
        if (!isMailboxTransientError(message)) {
          throw error;
        }
        if (activeProxyUrl && !directFallbackLogged) {
          activeProxyUrl = undefined;
          directFallbackLogged = true;
          log(`mailbox detail poll transient via proxy, switch to direct mailbox polling: ${message.split("\n")[0]}`);
          await delay(Math.max(800, pollMs));
          continue;
        }
      }
    }

    await new Promise((resolve) => setTimeout(resolve, Math.max(200, pollMs)));
  }

  return null;
}

async function waitForEmailCode(
  mailbox: MailboxSession,
  timeoutMs: number,
  pollMs: number,
  proxyUrl?: string,
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  const seen = new Set<string>();
  let rateLimitHits = 0;
  let activeProxyUrl = proxyUrl;
  let directFallbackLogged = false;

  while (Date.now() < deadline) {
    let items: unknown[] = [];
    try {
      if (mailbox.provider === "duckmail") {
        const messages = await httpJson<JsonRecord>("GET", `${mailbox.baseUrl}/messages`, {
          headers: mailbox.headers,
          proxyUrl: activeProxyUrl,
        });
        items = ((messages["hydra:member"] as unknown[]) || []).slice(0, 50);
      } else if (mailbox.provider === "gptmail") {
        const messages = await httpJson<JsonRecord>(
          "GET",
          `${mailbox.baseUrl}/api/emails?email=${encodeURIComponent(mailbox.address)}`,
          {
            headers: mailbox.headers,
            proxyUrl: activeProxyUrl,
          },
        );
        syncGptmailMailboxAuth(mailbox, messages);
        const data = messages.data;
        if (data && typeof data === "object" && Array.isArray((data as JsonRecord).emails)) {
          items = ((data as JsonRecord).emails as unknown[]).slice(0, 50);
        }
      } else {
        const messages = await httpJson<unknown>(
          "GET",
          `${mailbox.baseUrl}/mailboxes/${encodeURIComponent(mailbox.accountId)}/messages?limit=20`,
          {
            headers: mailbox.headers,
            proxyUrl: activeProxyUrl,
          },
        );
        if (messages && typeof messages === "object" && !Array.isArray(messages)) {
          const data = (messages as JsonRecord)["data"];
          if (Array.isArray(data)) {
            items = data.slice(0, 50);
          }
        } else if (Array.isArray(messages)) {
          items = messages.slice(0, 50);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (isMailboxRateLimitError(message)) {
        if (activeProxyUrl && !directFallbackLogged) {
          activeProxyUrl = undefined;
          directFallbackLogged = true;
          log("mailbox code poll rate limited via proxy, switch to direct mailbox polling");
          await delay(Math.max(1_200, pollMs));
          continue;
        }
        rateLimitHits += 1;
        const waitMs = Math.min(30_000, Math.max(4_000, pollMs * Math.min(rateLimitHits * 3, 12)));
        log(`mailbox code poll rate limited, backoff ${waitMs}ms (hit=${rateLimitHits})`);
        await delay(waitMs);
        continue;
      }
      if (!isMailboxTransientError(message)) {
        throw error;
      }
      if (activeProxyUrl && !directFallbackLogged) {
        activeProxyUrl = undefined;
        directFallbackLogged = true;
        log(`mailbox code poll transient via proxy, switch to direct mailbox polling: ${message.split("\n")[0]}`);
        await delay(Math.max(800, pollMs));
        continue;
      }
      log(`mailbox code poll transient, retry after ${Math.max(400, pollMs)}ms: ${message.split("\n")[0]}`);
      await delay(Math.max(400, pollMs));
      continue;
    }

    for (const item of items) {
      const fromSummary = extractEmailCodeFromPayload(item);
      if (fromSummary) return fromSummary;

      if (!item || typeof item !== "object") continue;
      const record = item as JsonRecord;
      const messageId = String(record.id || record.messageId || "").trim();
      if (!messageId || seen.has(messageId)) continue;
      seen.add(messageId);

      try {
        const detailUrl =
          mailbox.provider === "duckmail"
            ? `${mailbox.baseUrl}/messages/${encodeURIComponent(messageId)}`
            : mailbox.provider === "gptmail"
              ? `${mailbox.baseUrl}/api/email/${encodeURIComponent(messageId)}`
              : `${mailbox.baseUrl}/mailboxes/${encodeURIComponent(mailbox.accountId)}/messages/${encodeURIComponent(
                  messageId,
                )}`;
        const detail = await httpJson<JsonRecord>("GET", detailUrl, {
          headers: mailbox.headers,
          proxyUrl: activeProxyUrl,
        });
        syncGptmailMailboxAuth(mailbox, detail);

        const payload =
          mailbox.provider !== "duckmail" && detail.data && typeof detail.data === "object"
            ? (detail.data as JsonRecord)
            : detail;
        const fromDetail = extractEmailCodeFromPayload(payload);
        if (fromDetail) return fromDetail;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (isMailboxRateLimitError(message)) {
          if (activeProxyUrl && !directFallbackLogged) {
            activeProxyUrl = undefined;
            directFallbackLogged = true;
            log("mailbox code detail rate limited via proxy, switch to direct mailbox polling");
            await delay(Math.max(1_200, pollMs));
            continue;
          }
          rateLimitHits += 1;
          const waitMs = Math.min(30_000, Math.max(4_000, pollMs * Math.min(rateLimitHits * 3, 12)));
          log(`mailbox code detail rate limited, backoff ${waitMs}ms (hit=${rateLimitHits})`);
          await delay(waitMs);
          continue;
        }
        if (!isMailboxTransientError(message)) {
          throw error;
        }
        if (activeProxyUrl && !directFallbackLogged) {
          activeProxyUrl = undefined;
          directFallbackLogged = true;
          log(`mailbox code detail transient via proxy, switch to direct mailbox polling: ${message.split("\n")[0]}`);
          await delay(Math.max(800, pollMs));
          continue;
        }
      }
    }

    await delay(Math.max(200, pollMs));
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
  await input.click({ timeout: 5_000 }).catch(() => {});
  await input.fill("");
  await input.type(value, { delay: randomInt(55, 135) });
  const currentValue = await input.inputValue().catch(() => "");
  if (currentValue === value) {
    await input.dispatchEvent("input").catch(() => {});
    await input.dispatchEvent("change").catch(() => {});
    return;
  }
  await input.evaluate(
    (node: HTMLInputElement | HTMLTextAreaElement, nextValue: string) => {
      node.value = nextValue;
      node.dispatchEvent(new Event("input", { bubbles: true }));
      node.dispatchEvent(new Event("change", { bubbles: true }));
      node.dispatchEvent(new Event("blur", { bubbles: true }));
    },
    value,
  );
}

async function ensureInputValue(page: any, selector: string, value: string, label: string): Promise<void> {
  await page.waitForSelector(selector, { timeout: 30_000 });
  const input = page.locator(selector).first();
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await fillInput(page, selector, value);
    await page.waitForTimeout(randomInt(120, 260));
    const currentValue = await input.inputValue().catch(() => "");
    if (currentValue === value) {
      return;
    }
    await input.evaluate(
      (node: HTMLInputElement | HTMLTextAreaElement, nextValue: string) => {
        const proto =
          node instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
        descriptor?.set?.call(node, nextValue);
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        node.dispatchEvent(new Event("blur", { bubbles: true }));
      },
      value,
    );
    await page.waitForTimeout(randomInt(120, 260));
    const restoredValue = await input.inputValue().catch(() => "");
    if (restoredValue === value) {
      return;
    }
    log(`${label} input value did not persist (attempt=${attempt}, len=${restoredValue.length})`);
  }
  throw new Error(`${label}_input_not_persisted`);
}

async function waitForStableInputValue(
  page: any,
  selector: string,
  expected: string,
  settleMs = 500,
  timeoutMs = 6_000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  let stableSince = 0;
  while (Date.now() < deadline) {
    const currentValue = await page.locator(selector).first().inputValue().catch(() => "");
    if (currentValue === expected) {
      if (!stableSince) stableSince = Date.now();
      if (Date.now() - stableSince >= settleMs) {
        return true;
      }
    } else {
      stableSince = 0;
    }
    await page.waitForTimeout(120);
  }
  return false;
}

async function markBestVisibleControl(page: any, selector: string, hintPatterns: RegExp[], label: string): Promise<string | null> {
  const marker = `${label}-${Date.now()}-${randomBytes(3).toString("hex")}`;
  const matched = await page
    .evaluate(
      ({ selector: rawSelector, marker: rawMarker, hints }: { selector: string; marker: string; hints: string[] }) => {
        const isVisible = (node: Element): node is HTMLElement => {
          if (!(node instanceof HTMLElement)) return false;
          const rect = node.getBoundingClientRect();
          if (rect.width <= 0 || rect.height <= 0) return false;
          const style = window.getComputedStyle(node);
          return style.display !== "none" && style.visibility !== "hidden" && !node.hasAttribute("disabled");
        };
        const score = (node: HTMLElement): number => {
          const labelText =
            (node.getAttribute("aria-label") || "") +
            " " +
            (node.getAttribute("placeholder") || "") +
            " " +
            (node.getAttribute("name") || "") +
            " " +
            (node.getAttribute("id") || "") +
            " " +
            (node.textContent || "");
          let value = 0;
          if (node instanceof HTMLInputElement) {
            const type = (node.type || "").toLowerCase();
            if (type === "email") value += 14;
            if (type === "text" || type === "tel" || !type) value += 6;
            if (type === "number") value += 4;
          }
          for (const hint of hints) {
            try {
              if (new RegExp(hint, "i").test(labelText)) value += 25;
            } catch {
              // ignore invalid hint source
            }
          }
          return value;
        };
        const nodes = Array.from(document.querySelectorAll(rawSelector)).filter(isVisible);
        let best: HTMLElement | null = null;
        let bestScore = Number.NEGATIVE_INFINITY;
        for (const node of nodes) {
          const nextScore = score(node);
          if (best && nextScore < bestScore) continue;
          best = node;
          bestScore = nextScore;
        }
        if (!best) return false;
        for (const node of Array.from(document.querySelectorAll("[data-codex-visible-control]"))) {
          node.removeAttribute("data-codex-visible-control");
        }
        best.setAttribute("data-codex-visible-control", rawMarker);
        return true;
      },
      { selector, marker, hints: hintPatterns.map((pattern) => pattern.source) },
    )
    .catch(() => false);
  return matched ? `[data-codex-visible-control="${marker}"]` : null;
}

async function ensureDirectInputValue(page: any, selector: string, value: string, label: string): Promise<void> {
  await page.waitForSelector(selector, { timeout: 30_000 });
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    await page.locator(selector).first().evaluate(
      (node: HTMLInputElement | HTMLTextAreaElement, nextValue: string) => {
        node.focus();
        const proto =
          node instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
        descriptor?.set?.call(node, nextValue);
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
        node.dispatchEvent(new Event("blur", { bubbles: true }));
      },
      value,
    );
    const stable = await waitForStableInputValue(page, selector, value, 450, 3_500);
    if (stable) {
      return;
    }
    log(`${label} direct input value did not persist (attempt=${attempt})`);
    await page.waitForTimeout(180 * attempt);
  }
  throw new Error(`${label}_input_not_persisted`);
}

async function submitContainingFormDirectly(page: any, selector: string): Promise<boolean> {
  return await page
    .locator(selector)
    .first()
    .evaluate((node: Element) => {
      const form = node.closest("form") as HTMLFormElement | null;
      if (!form) return false;
      form.submit();
      return true;
    })
    .catch(() => false);
}

async function clearAuthFieldValidationState(page: any, selector: string): Promise<void> {
  try {
    await page.waitForSelector(selector, { timeout: 10_000 });
    await page.locator(selector).first().evaluate((node: HTMLInputElement | HTMLTextAreaElement) => {
      node.focus();
      if (typeof node.setCustomValidity === "function") {
        node.setCustomValidity("");
      }
      node.removeAttribute("aria-invalid");
      node.dispatchEvent(new Event("input", { bubbles: true }));
      node.dispatchEvent(new Event("change", { bubbles: true }));
    });
  } catch {
    // best effort
  }
}

async function collectBrowserNavigationErrorCode(page: any): Promise<string | null> {
  return await page
    .evaluate(() => {
      const currentUrl = String(window.location.href || "");
      if (!/^chrome-error:\/\//i.test(currentUrl)) {
        return null;
      }
      const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const match = text.match(/\b(ERR_[A-Z_]+)\b/i);
      return match?.[1] || "CHROME_ERROR_PAGE";
    })
    .catch(() => null);
}

async function safeGoto(page: any, url: string, timeout = 90000): Promise<void> {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout });
      const browserErrorCode = await collectBrowserNavigationErrorCode(page);
      if (browserErrorCode) {
        throw new Error(browserErrorCode);
      }
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const recoveredAfterTimeout = /Timeout \d+ms exceeded/i.test(message)
        ? await page
            .evaluate((targetUrl: string) => {
              const normalize = (value: string) => {
                try {
                  const parsed = new URL(value);
                  return `${parsed.origin}${parsed.pathname}${parsed.search}`;
                } catch {
                  return value.trim();
                }
              };
              const current = normalize(window.location.href);
              const target = normalize(targetUrl);
              const readyState = document.readyState || "";
              const bodyLength = (document.body?.innerText || document.body?.textContent || "").trim().length;
              return current === target && readyState !== "loading" && bodyLength > 0;
            }, url)
            .catch(() => false)
        : false;
      if (recoveredAfterTimeout) {
        const browserErrorCode = await collectBrowserNavigationErrorCode(page);
        if (!browserErrorCode) {
          log(`safeGoto recovered after timeout (${url}) via ready target document`);
          return;
        }
      }
      const transient = /NS_BINDING_ABORTED|ERR_ABORTED|ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET|interrupted by another navigation|frame was detached/i.test(
        message,
      );
      if (!transient || attempt >= 3) {
        throw error;
      }
      log(`safeGoto transient (${url}) attempt=${attempt}: ${message.split("\n")[0]}`);
      await page.waitForTimeout(700 * attempt);
    }
  }
}

async function fillMicrosoftProofOtpInputs(page: any, code: string): Promise<boolean> {
  const normalized = String(code || "").replace(/\D/g, "");
  if (normalized.length !== 6) {
    return false;
  }
  const firstSelector =
    (await firstVisibleSelector(page, ["#codeEntry-0", 'input[id^="codeEntry-"]', '[data-codex-otp-input="0"]'])) || null;
  if (!firstSelector) {
    const taggedGenericInputs = await page
      .evaluate((valueLength: number) => {
        const isVisible = (node: Element): node is HTMLInputElement => {
          if (!(node instanceof HTMLInputElement)) return false;
          const rect = node.getBoundingClientRect();
          if (rect.width <= 0 || rect.height <= 0) return false;
          const style = window.getComputedStyle(node);
          return style.display !== "none" && style.visibility !== "hidden" && !node.disabled;
        };
        const candidates = Array.from(
          document.querySelectorAll(
            'input[id^="codeEntry-"], input[autocomplete="one-time-code"], input[maxlength="1"], input[type="tel"], input[type="text"], input[type="number"], input[type="password"], input[inputmode="numeric"], input[inputmode="decimal"], input:not([type])',
          ),
        ).filter(isVisible);
        const otpInputs = candidates.filter((node) => {
          const maxLength = Number(node.getAttribute("maxlength") || "0");
          const autocomplete = (node.getAttribute("autocomplete") || "").toLowerCase();
          const hintText = [
            node.getAttribute("aria-label") || "",
            node.getAttribute("placeholder") || "",
            node.getAttribute("name") || "",
            node.getAttribute("id") || "",
            autocomplete,
          ]
            .join(" ")
            .toLowerCase();
          return maxLength === 1 || autocomplete === "one-time-code" || /code|digit|验证码|安全代码|one.?time/i.test(hintText);
        });
        if (otpInputs.length < valueLength) {
          return false;
        }
        for (const node of Array.from(document.querySelectorAll("[data-codex-otp-input]"))) {
          node.removeAttribute("data-codex-otp-input");
        }
        otpInputs.slice(0, valueLength).forEach((node, index) => {
          node.setAttribute("data-codex-otp-input", String(index));
        });
        return true;
      }, normalized.length)
      .catch(() => false);
    if (!taggedGenericInputs) {
      return false;
    }
  }

  const joinedValues = async (): Promise<string> =>
    await page
      .evaluate(() =>
        Array.from(document.querySelectorAll('input[id^="codeEntry-"], [data-codex-otp-input]'))
          .map((node) => ((node as HTMLInputElement | null)?.value || "").trim())
          .join(""),
      )
      .catch(() => "");

  try {
    const focusSelector = firstSelector || '[data-codex-otp-input="0"]';
    await page.locator(focusSelector).first().click({ timeout: 5_000 });
    await page.keyboard.type(normalized, { delay: 80 });
    await page.waitForTimeout(300);
    if ((await joinedValues()) === normalized) {
      return true;
    }
  } catch {
    // fall through to direct value injection
  }

  const directFilled = await page
    .evaluate((value: string) => {
      const inputs = Array.from(
        document.querySelectorAll('input[id^="codeEntry-"], [data-codex-otp-input]'),
      ) as HTMLInputElement[];
      if (inputs.length < value.length) {
        return false;
      }
      const firstInput = inputs[0];
      if (!firstInput) {
        return false;
      }
      const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
      const setter = descriptor?.set?.bind(firstInput);
      for (let index = 0; index < value.length; index += 1) {
        const input = inputs[index];
        if (!input) {
          return false;
        }
        const digit = value[index] || "";
        input.focus();
        if (typeof setter === "function") {
          setter.call(input, digit);
        } else {
          input.value = digit;
        }
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
      return inputs.slice(0, value.length).map((input) => (input.value || "").trim()).join("") === value;
    }, normalized)
    .catch(() => false);
  if (!directFilled) {
    return false;
  }
  await page.waitForTimeout(300);
  return (await joinedValues()) === normalized;
}

async function hasAuthSessionErrorPage(page: any): Promise<boolean> {
  try {
    return await page.evaluate(() => {
      const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      return /invalid_request/i.test(text) && /couldn't find your session|too many login dialogs|refreshed during login/i.test(text);
    });
  } catch {
    return false;
  }
}

async function hasAuthChallengeLoadErrorPage(page: any): Promise<boolean> {
  try {
    return await page.evaluate(() => {
      const isVisible = (el: Element | null): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        if (el.hidden) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
      };
      const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const visibleErrorText = Array.from(
        document.querySelectorAll(
          '#error-element-third-party-captcha, .ulp-captcha-client-error, [data-captcha-provider] ~ span, [data-captcha-provider] [id*="error"]',
        ),
      )
        .filter(isVisible)
        .map((el) => ((el as HTMLElement).innerText || el.textContent || "").replace(/\s+/g, " ").trim())
        .filter((value) => value.length > 0)
        .join(" ");
      const combinedText = `${text} ${visibleErrorText}`.trim();
      return (
        /couldn[’']t load the security challenge/i.test(combinedText) ||
        /we couldn[’']t load the security challenge/i.test(combinedText)
      );
    });
  } catch {
    return false;
  }
}

function buildAuthLoginSurfaceKey(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    const state = (url.searchParams.get("state") || "").trim();
    return `${url.origin}${url.pathname}?state=${state}`;
  } catch {
    return rawUrl;
  }
}

async function collectPageSurfaceSummary(page: any): Promise<string> {
  try {
    const payload = await page.evaluate(() => {
      const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      return {
        url: window.location.href,
        title: document.title || "",
        readyState: document.readyState,
        bodyLength: bodyText.length,
        bodySample: bodyText.slice(0, 200),
      };
    });
    return `url=${payload.url} title=${payload.title || "(empty)"} ready=${payload.readyState} body_len=${payload.bodyLength} body=${payload.bodySample || "(empty)"}`;
  } catch (error) {
    const message = error instanceof Error ? error.message.split("\n")[0] : String(error);
    return `surface-unavailable: ${message}`;
  }
}

async function detectChromiumNetErrorCode(page: any): Promise<string | null> {
  try {
    return await page.evaluate(() => {
      const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const title = (document.title || "").trim();
      const code =
        (document.querySelector(".error-code")?.textContent || "")
          .replace(/\s+/g, " ")
          .trim()
          .toUpperCase() ||
        (bodyText.match(/\bERR_[A-Z0-9_]+\b/)?.[0] || "").trim().toUpperCase();
      if (!code) return null;
      const hasInterstitial =
        window.location.href.startsWith("chrome-error://") ||
        !!document.querySelector("#main-frame-error, .neterror, .error-code");
      if (!hasInterstitial) return null;
      if (
        /(this site can.t be reached|can.t reach this page|无法访问此网站|意外终止了连接|took too long to respond)/i.test(
          `${title} ${bodyText}`,
        )
      ) {
        return code;
      }
      return null;
    });
  } catch {
    return null;
  }
}

async function hasRenderablePageSurface(page: any): Promise<boolean> {
  try {
    return await page.evaluate(() => {
      const title = (document.title || "").trim();
      const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const interactiveCount = document.querySelectorAll("a, button, input, form").length;
      return title.length > 0 || bodyText.length >= 80 || interactiveCount > 0;
    });
  } catch {
    return false;
  }
}

async function waitForAuthEntrySurface(page: any, kind: "signup" | "login", timeoutMs: number): Promise<void> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  while (Date.now() < deadline) {
    const url = page.url();
    if (/auth\.tavily\.com/i.test(url) || /\/u\/login\/identifier|\/u\/signup\/identifier|\/u\/signup\/password/i.test(url)) {
      return;
    }
    if (await hasAuthSessionErrorPage(page)) {
      return;
    }
    const hints = await collectActionEntryHints(page);
    if (hints.length > 0) {
      return;
    }
    const hasBodyText = await page
      .evaluate(() => Boolean((document.body?.innerText || "").replace(/\s+/g, "").length))
      .catch(() => false);
    if (hasBodyText) {
      return;
    }
    await page.waitForTimeout(500);
  }
  log(`${kind} entry surface still empty after wait: ${await collectPageSurfaceSummary(page)}`);
}

async function hasAuthenticatedHomeSignal(page: any): Promise<boolean> {
  if (await pageContainsAnyText(page, [/overview/i, /api keys/i, /billing/i, /settings/i, /\bdefault\b/i])) {
    return true;
  }
  return await page
    .evaluate(`async () => {
      const probeJsonText = async (url, matcher) => {
        try {
          const response = await fetch(url, { credentials: "include", cache: "no-store" });
          if (!response.ok) return false;
          const text = await response.text();
          return matcher.test(text);
        } catch {
          return false;
        }
      };

      try {
        if (await probeJsonText("/api/auth/me", /@|email|name|picture|user|sub|sid/i)) {
          return true;
        }
        if (await probeJsonText("/api/account", /@|email|name|uid|current_plan|plan_display_name/i)) {
          return true;
        }
        if (await probeJsonText("/api/keys", /tvly-[A-Za-z0-9_-]{8,}|\"name\"\\s*:\\s*\"default\"/i)) {
          return true;
        }
        return false;
      } catch {
        return false;
      }
    }`)
    .catch(() => false);
}

async function waitForSignUpEntryReady(page: any, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  while (Date.now() < deadline) {
    const directPoint = await findClickablePointBySelector(page, 'a[href*="/u/signup/identifier"], a[href*="signup"], a[href*="register"]');
    if (directPoint) {
      return true;
    }
    const textPoint =
      (await findClickablePointByLinkText(page, /sign up|create account|get started|start for free/i)) ||
      (await findClickablePointByActionText(page, [/sign up|create account|get started|start for free/i]));
    if (textPoint) {
      return true;
    }
    if (!(await hasAuthChallengeLoadErrorPage(page))) {
      const readyState = await page.evaluate(() => document.readyState).catch(() => "loading");
      if (readyState === "complete" || readyState === "interactive") {
        return false;
      }
    }
    await page.waitForTimeout(750);
  }
  return false;
}

async function navigateToSignupWithCurrentState(page: any): Promise<boolean> {
  try {
    const currentUrl = new URL(page.url());
    const state = currentUrl.searchParams.get("state");
    if (!state || !/\/u\/login\/identifier/i.test(currentUrl.pathname)) {
      return false;
    }
    const signupUrl = new URL("/u/signup/identifier", currentUrl.origin);
    signupUrl.searchParams.set("state", state);
    await safeGoto(page, signupUrl.toString(), 60_000);
    await page.waitForTimeout(800);
    return /\/u\/signup\/identifier|\/u\/signup\/password/i.test(page.url());
  } catch {
    return false;
  }
}

async function ensureAuthIdentifierFieldReady(page: any, selector: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  while (Date.now() < deadline) {
    const count = await page.locator(selector).count().catch(() => 0);
    if (count > 0) {
      return;
    }
    if (await hasAuthSessionErrorPage(page)) {
      throw new Error("auth_session_invalid_request");
    }
    await page.waitForTimeout(350);
  }
  await page.waitForSelector(selector, { timeout: 1_000 });
}

async function openAuthFlowEntry(
  page: any,
  kind: "signup" | "login",
): Promise<void> {
  const appRootUrl = "https://app.tavily.com/";
  const appHomeUrl = "https://app.tavily.com/home";
  const entryUrls = [
    { label: "app-root", url: appRootUrl },
    { label: "app-home", url: appHomeUrl },
  ];
  const successPattern =
    kind === "signup"
      ? /\/u\/login\/identifier|\/u\/signup\/identifier|\/u\/signup\/password/i
      : /\/u\/login\/identifier|\/u\/login\/password/i;
  let lastError: Error | null = null;

  const tryNavigation = async (label: string, url: string): Promise<boolean> => {
    try {
      await safeGoto(page, url, 60_000);
      await page.waitForTimeout(900);
      await waitForAuthEntrySurface(page, kind, 12_000);
      if (!(await hasRenderablePageSurface(page)) && !successPattern.test(page.url())) {
        log(`${kind} entry surface thin via ${label}, reloading once`);
        await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 }).catch(() => {});
        await page.waitForTimeout(1_200);
        await waitForAuthEntrySurface(page, kind, 10_000);
      }
      if (
        kind === "login" &&
        /app\.tavily\.com\/home/i.test(page.url()) &&
        !/auth\.tavily\.com/i.test(page.url()) &&
        (await hasAuthenticatedHomeSignal(page))
      ) {
        return true;
      }
      if (successPattern.test(page.url())) {
        return true;
      }
      return true;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      const message = lastError.message.split("\n")[0];
      log(`${kind} entry transient via ${label}: ${message}`);
      return false;
    }
  };

  for (const entry of entryUrls) {
    if (!(await tryNavigation(entry.label, entry.url))) {
      continue;
    }
    if (await hasAuthSessionErrorPage(page)) {
      log(`${kind} entry invalid_request page detected via ${entry.label}, retrying next entry`);
      await page.goto("about:blank", { waitUntil: "load", timeout: 10_000 }).catch(() => {});
      continue;
    }
    if (kind === "signup" && /\/u\/signup\/identifier|\/u\/signup\/password/i.test(page.url())) {
      return;
    }
    if (
      kind === "signup" &&
      (/\/u\/login\/identifier/i.test(page.url()) ||
        (/app\.tavily\.com/i.test(page.url()) && !/auth\.tavily\.com/i.test(page.url())))
    ) {
      const onLoginIdentifier = /\/u\/login\/identifier/i.test(page.url());
      const entryReady = await waitForSignUpEntryReady(page, 12_000);
      if (!entryReady && onLoginIdentifier && (await hasAuthChallengeLoadErrorPage(page))) {
        log(`${kind} entry challenge unavailable on login page, reloading once`);
        await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 }).catch(() => {});
        await page.waitForTimeout(1_200);
        await waitForAuthEntrySurface(page, kind, 10_000);
      }
      let switchedToSignup = false;
      try {
        await clickSignUp(page);
        await page.waitForURL(/\/u\/signup\/identifier|\/u\/signup\/password/i, { timeout: 30_000 });
        switchedToSignup = true;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (onLoginIdentifier && (/Sign up entry not found/i.test(message) || /forURL: Timeout/i.test(message))) {
          const navigated = await navigateToSignupWithCurrentState(page);
          if (navigated) {
            log(
              `${kind} entry switched via state-preserving signup URL${
                /forURL: Timeout/i.test(message) ? " after click timeout" : ""
              }`,
            );
            switchedToSignup = true;
          } else {
            throw error;
          }
        } else {
          throw error;
        }
      }
      if (!switchedToSignup) {
        throw new Error("Sign up entry not found");
      }
      if (await hasAuthSessionErrorPage(page)) {
        log(`${kind} entry invalid_request page detected after clickSignUp, retrying next entry`);
        await page.goto("about:blank", { waitUntil: "load", timeout: 10_000 }).catch(() => {});
        continue;
      }
      return;
    }
    if (successPattern.test(page.url())) {
      return;
    }
    try {
      await page.waitForURL(successPattern, { timeout: 10_000 });
      return;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      const message = lastError.message.split("\n")[0];
      log(`${kind} entry unresolved via ${entry.label}: ${message}`);
      await page.goto("about:blank", { waitUntil: "load", timeout: 10_000 }).catch(() => {});
      continue;
    }
  }

  throw lastError || new Error(`${kind} auth entry unavailable`);
}

async function waitHomeStable(page: any, stableMs = 6000): Promise<boolean> {
  const step = 800;
  const stableDeadline = Date.now() + Math.max(step, stableMs);
  const authGraceDeadline = Date.now() + Math.max(stableMs, 15_000);
  let sawAuthenticatedSignal = false;
  while (Date.now() < authGraceDeadline) {
    const url = page.url();
    if (!/app\.tavily\.com\/home/i.test(url) || /auth\.tavily\.com/i.test(url)) {
      return false;
    }
    if (await hasAuthenticatedHomeSignal(page)) {
      sawAuthenticatedSignal = true;
      if (Date.now() >= stableDeadline) {
        return true;
      }
    }
    await page.waitForTimeout(step);
  }
  return sawAuthenticatedSignal;
}

async function hasPostSignupConsentPrompt(page: any): Promise<boolean> {
  try {
    return await page.evaluate(() => {
      const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      return /receive marketing emails/i.test(text) && /privacy policy/i.test(text) && /website terms of use/i.test(text);
    });
  } catch {
    return false;
  }
}

async function acceptPostSignupConsent(page: any): Promise<boolean> {
  for (let round = 1; round <= 3; round += 1) {
    if (!(await hasPostSignupConsentPrompt(page))) {
      return round > 1;
    }
    const continuePoint =
      (await findClickablePointViaAxName(page, [/^continue$/i], ["button", "link"])) ||
      (await findClickablePointByActionText(page, [/^continue$/i])) ||
      (await findClickablePointBySelector(page, 'button[type="submit"], button'));
    if (continuePoint) {
      await dispatchMouseClickViaCdp(page, continuePoint.x, continuePoint.y);
    } else {
      const closePoint =
        (await findClickablePointBySelector(page, 'button[aria-label*="close" i], button[title*="close" i]')) ||
        (await findClickablePointViaAxName(page, [/^close$/i, /^dismiss$/i], ["button"])) ||
        (await findClickablePointByActionText(page, [/^close$/i, /^dismiss$/i]));
      if (!closePoint) {
        log(`post-signup consent action not found after round ${round}`);
        continue;
      }
      await dispatchMouseClickViaCdp(page, closePoint.x, closePoint.y);
    }
    const dismissDeadline = Date.now() + 8_000;
    while (Date.now() < dismissDeadline) {
      await page.waitForTimeout(350);
      if (!(await hasPostSignupConsentPrompt(page))) {
        break;
      }
    }
    if (!(await hasPostSignupConsentPrompt(page))) {
      log(`post-signup consent dismissed after round ${round}`);
      return true;
    }
  }
  return false;
}

async function dismissCookieBannerBestEffort(page: any): Promise<void> {
  for (let round = 1; round <= 2; round += 1) {
    const point =
      (await findClickablePointViaAxName(page, [/^reject all$/i], ["button"])) ||
      (await findClickablePointByActionText(page, [/^reject all$/i])) ||
      (await findClickablePointBySelector(page, 'button[aria-label*="close" i], button[title*="close" i]')) ||
      (await findClickablePointByActionText(page, [/^close$/i, /^dismiss$/i]));
    if (!point) return;
    await dispatchMouseClickViaCdp(page, point.x, point.y);
    await page.waitForTimeout(700 + round * 150);
    const stillVisible = await page
      .evaluate(() => {
        const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
        return /accept all cookies/i.test(text) || /reject all/i.test(text) || /cookie policy/i.test(text);
      })
      .catch(() => false);
    if (!stillVisible) {
      log(`cookie banner dismissed best-effort after round ${round}`);
      return;
    }
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

async function getNormalizedBodyText(page: any): Promise<string> {
  return await page
    .evaluate(() => (document.body?.innerText || "").replace(/\s+/g, " ").trim())
    .catch(() => "");
}

async function pageContainsAnyText(page: any, patterns: RegExp[]): Promise<boolean> {
  const text = await getNormalizedBodyText(page);
  if (!text) return false;
  return patterns.some((pattern) => pattern.test(text));
}

async function hasVisibleElement(page: any, selector: string): Promise<boolean> {
  return await page
    .locator(selector)
    .evaluateAll((nodes: Element[]) =>
      nodes.some((node: Element) => {
        if (!(node instanceof HTMLElement)) return false;
        const rect = node.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(node);
        return style.display !== "none" && style.visibility !== "hidden";
      }),
    )
    .catch(() => false);
}

async function firstVisibleSelector(page: any, selectors: string[]): Promise<string | null> {
  for (const selector of selectors) {
    if (await hasVisibleElement(page, selector)) {
      return selector;
    }
  }
  return null;
}

async function hasAnyElement(page: any, selector: string): Promise<boolean> {
  return await page
    .locator(selector)
    .count()
    .then((count: number) => count > 0)
    .catch(() => false);
}

async function clickMatchingAction(
  page: any,
  patterns: RegExp[],
  selector?: string,
  roles: string[] = ["button", "link"],
): Promise<boolean> {
  const point =
    (await findClickablePointByActionText(page, patterns)) ||
    (await findClickablePointViaAxName(page, patterns, roles)) ||
    (selector ? await findClickablePointBySelector(page, selector) : null);
  if (!point) return false;
  await dispatchMouseClickViaCdp(page, point.x, point.y);
  await page.waitForTimeout(1_000);
  return true;
}

async function clickMatchingActionDirectly(
  page: any,
  patterns: RegExp[],
  selector = 'a, button, [role="button"], input[type="button"], input[type="submit"]',
): Promise<boolean> {
  try {
    const patternPayload = patterns.map((pattern) => ({ source: pattern.source, flags: pattern.flags }));
    return await page.evaluate(
      (compiledPatterns: Array<{ source: string; flags: string }>, rawSelector: string) => {
        const matchers = compiledPatterns.map((item) => new RegExp(item.source, item.flags));
        const collectDeepElements = (root: ParentNode, targetSelector: string): Element[] => {
          const matches = Array.from(root.querySelectorAll(targetSelector));
          const descendants = Array.from(root.querySelectorAll("*"));
          for (const el of descendants) {
            const shadowRoot = (el as HTMLElement & { shadowRoot?: ShadowRoot | null }).shadowRoot;
            if (shadowRoot) {
              matches.push(...collectDeepElements(shadowRoot, targetSelector));
            }
          }
          return matches;
        };
        const isVisible = (el: Element): el is HTMLElement => {
          if (!(el instanceof HTMLElement)) return false;
          const rect = el.getBoundingClientRect();
          if (rect.width <= 0 || rect.height <= 0) return false;
          const style = window.getComputedStyle(el);
          return style.visibility !== "hidden" && style.display !== "none";
        };
        const normalize = (value: string): string => value.replace(/\s+/g, " ").trim();
        const candidates = collectDeepElements(document, rawSelector)
          .filter(isVisible)
          .map((el) => {
            const text = normalize(
              [
                el.textContent || "",
                el.getAttribute("aria-label") || "",
                el.getAttribute("title") || "",
                el.getAttribute("value") || "",
              ].join(" "),
            );
            const href = normalize(el.getAttribute("href") || "");
            return { el, text, href };
          });
        const winner = candidates.find((candidate) => matchers.some((matcher) => matcher.test(candidate.text) || matcher.test(candidate.href)));
        if (!winner) return false;
        winner.el.click();
        return true;
      },
      patternPayload,
      selector,
    );
  } catch {
    return false;
  }
}

async function clickMicrosoftPasswordFallbackAction(page: any): Promise<boolean> {
  const patterns = [/^use your password$/i, /^sign in with password$/i, /use.*password/i, /使用密码/i];
  const patternPayload = patterns.map((pattern) => ({ source: pattern.source, flags: pattern.flags }));
  const clickedDirectly = await page
    .evaluate((compiledPatterns: Array<{ source: string; flags: string }>) => {
      const matchers = compiledPatterns.map((item) => new RegExp(item.source, item.flags));
      const normalize = (value: string): string => value.replace(/\s+/g, " ").trim();
      const isVisible = (el: Element): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        return style.display !== "none" && style.visibility !== "hidden";
      };
      const readActionText = (el: Element): string =>
        normalize(
          [
            el.textContent || "",
            el.getAttribute("aria-label") || "",
            el.getAttribute("title") || "",
            el.getAttribute("value") || "",
          ].join(" "),
        );
      const baseCandidates = Array.from(
        document.querySelectorAll('a, button, [role="button"], input[type="button"], input[type="submit"]'),
      ).filter(isVisible);
      let target = baseCandidates.find((el) => matchers.some((matcher) => matcher.test(readActionText(el)))) as
        | HTMLElement
        | undefined;
      if (!target) {
        const fallbackNode = Array.from(document.querySelectorAll("span, div"))
          .filter(isVisible)
          .find((el) => {
            const text = normalize(el.textContent || "");
            return text.length > 0 && text.length <= 120 && matchers.some((matcher) => matcher.test(text));
          });
        if (fallbackNode instanceof HTMLElement) {
          target =
            fallbackNode.closest(
              'a, button, [role="button"], input[type="button"], input[type="submit"], [tabindex]:not([tabindex="-1"])',
            ) instanceof HTMLElement
              ? (fallbackNode.closest(
                  'a, button, [role="button"], input[type="button"], input[type="submit"], [tabindex]:not([tabindex="-1"])',
                ) as HTMLElement)
              : fallbackNode;
        }
      }
      if (!target) return false;
      target.click();
      return true;
    }, patternPayload)
    .catch(() => false);
  const clicked =
    clickedDirectly ||
    (await clickMatchingAction(page, patterns, 'button, [role="button"], a'));
  if (!clicked) {
    return false;
  }
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (await hasVisibleElement(page, 'input[type="password"], input[autocomplete="current-password"]')) {
      return true;
    }
    if (
      await pageContainsAnyText(page, [
        /enter your password/i,
        /输入你的密码/i,
        /stay signed in/i,
        /保持登录状态/i,
      ])
    ) {
      return true;
    }
    const currentUrl = page.url();
    if (!/login\.live\.com|account\.live\.com|login\.microsoft\.com/i.test(currentUrl)) {
      return true;
    }
    await page.waitForTimeout(250);
  }
  return false;
}

async function syncAuthProviderFormHiddenFields(page: any, provider: string): Promise<string[]> {
  try {
    return await page.evaluate((providerName: string) => {
      const touched: string[] = [];
      const globalState = window as Window & {
        __kohaLastAuthCaptcha?: string;
        __kohaLastChallengeToken?: string;
        __kohaReadAuthChallengeToken?: () => string;
      };
      const primaryForm =
        (document.querySelector('form[data-form-primary="true"]') as HTMLFormElement | null) ||
        (document.querySelector("form") as HTMLFormElement | null);
      const form = document.querySelector(`form[data-provider="${providerName}"]`) as HTMLFormElement | null;
      if (!(form instanceof HTMLFormElement)) {
        return touched;
      }
      const pageCaptcha = (document.querySelector('input[name="captcha"]') as HTMLInputElement | null)?.value?.trim() || "";
      const pageTurnstile =
        (document.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null)?.value?.trim() || "";
      const pageRecaptcha =
        (document.querySelector('input[name="g-recaptcha-response"]') as HTMLInputElement | null)?.value?.trim() || "";
      const pageHCaptcha =
        (
          document.querySelector('textarea[name="h-captcha-response"], input[name="h-captcha-response"]') as
            | HTMLInputElement
            | HTMLTextAreaElement
            | null
        )?.value?.trim() || "";
      const runtimeChallengeToken =
        typeof globalState.__kohaReadAuthChallengeToken === "function"
          ? String(globalState.__kohaReadAuthChallengeToken() || "").trim()
          : "";
      const challengeToken =
        pageTurnstile ||
        pageRecaptcha ||
        pageHCaptcha ||
        runtimeChallengeToken ||
        globalState.__kohaLastChallengeToken ||
        pageCaptcha ||
        "";
      const captchaToken = pageCaptcha || challengeToken || globalState.__kohaLastAuthCaptcha || "";
      if (challengeToken) {
        globalState.__kohaLastChallengeToken = challengeToken;
      }
      if (captchaToken) {
        globalState.__kohaLastAuthCaptcha = captchaToken;
      }

      const ensureHidden = (name: string, value: string) => {
        if (!value) return;
        let field = form.querySelector(`[name="${name}"]`) as HTMLInputElement | HTMLTextAreaElement | null;
        if (!field) {
          field = document.createElement("input");
          field.setAttribute("type", "hidden");
          field.setAttribute("name", name);
          form.appendChild(field);
          touched.push(`${name}:append`);
        }
        if ((field.value || "") !== value) {
          field.value = value;
          touched.push(`${name}:set`);
        }
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      };

      if (primaryForm instanceof HTMLFormElement) {
        const primaryHiddenFields = Array.from(primaryForm.querySelectorAll('input[type="hidden"][name], textarea[name]'));
        for (const sourceField of primaryHiddenFields) {
          const name = (sourceField.getAttribute("name") || "").trim();
          if (!name || name === "state" || name === "connection") continue;
          const value =
            sourceField instanceof HTMLInputElement || sourceField instanceof HTMLTextAreaElement
              ? sourceField.value.trim()
              : "";
          if (!value) continue;
          ensureHidden(name, value);
        }
      }
      ensureHidden("captcha", captchaToken);
      ensureHidden("cf-turnstile-response", challengeToken);
      return touched;
    }, provider);
  } catch {
    return [];
  }
}

async function submitAuthProviderForm(
  page: any,
  provider: string,
  buttonPatterns: RegExp[],
  submitPostPattern: RegExp,
  logLabel: string,
): Promise<boolean> {
  const baselineUrl = page.url();
  const authProviderSurfacePattern = /auth\.tavily\.com\/u\/(?:login|signup)\/identifier/i;
  const confirmProviderTransition = async (): Promise<boolean> => {
    const deadline = Date.now() + 8_000;
    while (Date.now() < deadline) {
      const currentUrl = page.url();
      if (currentUrl !== baselineUrl && !authProviderSurfacePattern.test(currentUrl)) {
        return true;
      }
      const stillShowingProvider = await page
        .evaluate(() => {
          const elements = Array.from(document.querySelectorAll("button, a, [role='button']"));
          return elements.some((el) => /continue with microsoft account/i.test((el.textContent || "").replace(/\s+/g, " ").trim()));
        })
        .catch(() => false);
      if (stillShowingProvider && authProviderSurfacePattern.test(currentUrl)) {
        await page.waitForTimeout(250);
        continue;
      }
      await page.waitForTimeout(250);
    }
    return page.url() !== baselineUrl && !authProviderSurfacePattern.test(page.url());
  };
  const syncedHiddenFields = await syncAuthFormHiddenFields(page);
  const syncedProviderFields = await syncAuthProviderFormHiddenFields(page, provider);
  const touchedChallengeFields = await dispatchChallengeResponseEvents(page);
  if (syncedHiddenFields.length > 0) {
    log(`${logLabel} synced auth fields: ${syncedHiddenFields.join(", ")}`);
  }
  if (syncedProviderFields.length > 0) {
    log(`${logLabel} synced provider fields: ${syncedProviderFields.join(", ")}`);
  }
  if (touchedChallengeFields.length > 0) {
    log(`${logLabel} refreshed challenge fields via events: ${touchedChallengeFields.join(", ")}`);
    await page.waitForTimeout(randomInt(120, 260));
  }

  const clickedDirectly = await clickMatchingActionDirectly(page, buttonPatterns, 'button, a, [role="button"]');
  if (clickedDirectly) {
    const submitSignal = await waitForAuthSubmitSignal(page, submitPostPattern, 3_500, baselineUrl);
    if (submitSignal !== "none") {
      const transitioned = submitSignal === "navigation" ? true : await confirmProviderTransition();
      if (!transitioned) {
        log(`${logLabel} direct provider click bounced back to login surface`);
        return false;
      }
      if (submitSignal === "navigation") {
        log(`${logLabel} navigation detected after direct provider click`);
      }
      log(`${logLabel} submit via direct provider click`);
      return true;
    }
  }

  const clicked = await clickMatchingAction(page, buttonPatterns, 'button, a, [role="button"]');
  if (clicked) {
    const submitSignal = await waitForAuthSubmitSignal(page, submitPostPattern, 3_500, baselineUrl);
    if (submitSignal !== "none") {
      const transitioned = submitSignal === "navigation" ? true : await confirmProviderTransition();
      if (!transitioned) {
        log(`${logLabel} provider click bounced back to login surface`);
        return false;
      }
      if (submitSignal === "navigation") {
        log(`${logLabel} navigation detected after provider click`);
      }
      log(`${logLabel} submit via provider click`);
      return true;
    }
  }

  try {
    const providerSubmitted = await page.evaluate((providerName: string) => {
      const form = document.querySelector(`form[data-provider="${providerName}"]`) as HTMLFormElement | null;
      if (!(form instanceof HTMLFormElement)) return false;
      const button =
        (form.querySelector('button[type="submit"], input[type="submit"], button[data-action-button-secondary="true"]') as
          | HTMLButtonElement
          | HTMLInputElement
          | null) || null;
      if (button instanceof HTMLElement) {
        button.click();
        return true;
      }
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
        return true;
      }
      form.submit();
      return true;
    }, provider);
    if (providerSubmitted) {
      const submitSignal = await waitForAuthSubmitSignal(page, submitPostPattern, 4_500, baselineUrl);
      if (submitSignal !== "none") {
        const transitioned = submitSignal === "navigation" ? true : await confirmProviderTransition();
        if (!transitioned) {
          log(`${logLabel} provider submit bounced back to login surface`);
          return false;
        }
        if (submitSignal === "navigation") {
          log(`${logLabel} navigation detected after provider form submit`);
        }
        log(`${logLabel} submit via provider form`);
        return true;
      }
      log(`${logLabel} provider form submit emitted no signal`);
    }
    return false;
  } catch {
    return clicked;
  }
}

async function clickMicrosoftProviderEntry(page: any): Promise<boolean> {
  const preSubmitManaged = await collectAuthChallengeSnapshot(page).catch(() => null);
  if (hasManagedAuthChallenge(preSubmitManaged)) {
    log("login provider microsoft: bypassing identifier challenge and submitting provider directly");
  }
  const clicked = await submitAuthProviderForm(
    page,
    "windowslive",
    [/^continue with microsoft account$/i, /^microsoft account$/i, /continue with microsoft/i, /microsoft/i],
    /\/u\/(?:login|signup)\/identifier/i,
    "login provider microsoft",
  );
  if (clicked) {
    log("login flow: selected Microsoft account provider");
  }
  return clicked;
}

async function waitForPassiveMicrosoftProviderReadiness(
  page: any,
  formKind: "signup" | "login",
  timeoutMs: number,
): Promise<"ready" | "skipped" | "wait"> {
  let latest = await collectAuthChallengeSnapshot(page).catch(() => null);
  if (!hasManagedAuthChallenge(latest)) {
    return "skipped";
  }
  const hasConcreteChallengeSurface = (snapshot: AuthChallengeSnapshot | null | undefined): boolean =>
    Boolean(snapshot?.hasChallengeFrame || snapshot?.hasChallengeCheckbox || getChallengeTokenLength(snapshot) > 0);
  if (!hasConcreteChallengeSurface(latest)) {
    return "ready";
  }
  if (isManagedChallengeStableForSubmit(latest)) {
    return "ready";
  }

  log(`${formKind} provider submit: waiting for passive managed challenge readiness`);
  const deadline = Date.now() + Math.max(1_500, timeoutMs);
  while (Date.now() < deadline) {
    latest = await collectAuthChallengeSnapshot(page).catch(() => latest);
    if (!hasManagedAuthChallenge(latest)) {
      return "skipped";
    }
    if (!hasConcreteChallengeSurface(latest)) {
      return "ready";
    }
    if (isManagedChallengeStableForSubmit(latest)) {
      log(
        `${formKind} provider submit: passive managed challenge became ready (captcha=${latest?.captchaValueLength || 0}, turnstile=${
          latest?.turnstileValueLength || 0
        }, frame=${latest?.hasChallengeFrame ? 1 : 0}, checkbox=${latest?.hasChallengeCheckbox ? 1 : 0})`,
      );
      return "ready";
    }
    await page.waitForTimeout(400);
  }

  if (latest && hasManagedAuthChallenge(latest)) {
    log(
      `${formKind} provider submit: passive managed challenge still not ready (captcha=${latest.captchaValueLength || 0}, turnstile=${
        latest.turnstileValueLength || 0
      }, frame=${latest.hasChallengeFrame ? 1 : 0}, checkbox=${latest.hasChallengeCheckbox ? 1 : 0})`,
    );
    if (canFallbackPassiveMicrosoftProviderSubmit(latest, formKind)) {
      log(`${formKind} provider submit: passive challenge timeout degraded to direct provider click`);
      return "ready";
    }
  }
  return "wait";
}

async function handleMicrosoftAccountPicker(page: any, email: string): Promise<boolean> {
  const currentUrl = page.url();
  if (
    /account\.live\.com\/username\/recover/i.test(currentUrl) ||
    /account\.live\.com\/identity\/confirm/i.test(currentUrl) ||
    /account\.live\.com\/proofs\//i.test(currentUrl) ||
    /login\.live\.com\/logout\.srf/i.test(currentUrl)
  ) {
    return false;
  }
  if (await hasVisibleElement(page, 'input[type="email"], input[autocomplete="username"], input[name="loginfmt"], input[name="fmt"]')) {
    return false;
  }
  const emailPattern = new RegExp(escapeRegExp(email), "i");
  const looksLikeAccountPicker = await pageContainsAnyText(page, [
    /pick an account/i,
    /choose an account/i,
    /select an account/i,
    /pick up where you left off/i,
    /选择帐户/i,
  ]);
  if (!looksLikeAccountPicker) {
    return false;
  }
  if (
    await clickMatchingAction(
      page,
      [/^use another account$/i, /^other account$/i, /使用其他帐户/i, /改用其他帐户/i],
      'button, a, [role="button"]',
    )
  ) {
    log("login flow: switched Microsoft picker to another account");
    return true;
  }
  if (looksLikeAccountPicker && (await clickMatchingAction(page, [emailPattern], 'button, a, [role="button"]'))) {
    log("login flow: selected remembered Microsoft account");
    return true;
  }
  return false;
}

async function isMicrosoftProofConfirmationSurface(page: any): Promise<boolean> {
  if (await isMicrosoftLikelyPasswordSurface(page)) {
    return false;
  }
  if (await firstVisibleSelector(page, ["#iProofEmail", '#proof-confirmation-email-input', 'input[name="proof"]'])) {
    return true;
  }
  if (!/account\.live\.com\/identity\/confirm|login\.live\.com\/oauth20_authorize\.srf|account\.live\.com\/proofs\//i.test(page.url())) {
    return false;
  }
  return await pageContainsAnyText(page, [
    /verify your email/i,
    /we[’']?ll send a code to/i,
    /already received a code/i,
    /use your password/i,
    /验证你的电子邮件/i,
  ]);
}

async function waitForMicrosoftPostEmailSurface(page: any, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  while (Date.now() < deadline) {
    if (await isMicrosoftLikelyPasswordSurface(page)) {
      return;
    }
    if (await hasVisibleMicrosoftPasswordShortcut(page)) {
      return;
    }
    if (await isMicrosoftProofConfirmationSurface(page)) {
      return;
    }
    if (
      /account\.live\.com\/proofs\/Add|account\.live\.com\/identity\/confirm|account\.live\.com\/proofs\/verify/i.test(
        page.url(),
      )
    ) {
      return;
    }
    if (
      await pageContainsAnyText(page, [
        /help us protect your account/i,
        /let.?s protect your account/i,
        /verify your email/i,
        /verify your identity/i,
        /stay signed in/i,
        /allow this app to access your info/i,
        /let this app access your info/i,
        /使用密码/i,
        /验证你的电子邮件/i,
        /验证你的身份/i,
        /保持登录状态/i,
      ])
    ) {
      return;
    }
    await page.waitForTimeout(250);
  }
}

async function handleMicrosoftEmailPrompt(
  page: any,
  email: string,
  proofState?: Pick<MicrosoftProofFlowState, "postEmailPasswordPriorityUntil">,
): Promise<boolean> {
  if (/account\.live\.com\/proofs\//i.test(page.url())) {
    return false;
  }
  if (await isMicrosoftProofConfirmationSurface(page)) {
    return false;
  }
  const selector = 'input[type="email"], input[autocomplete="username"]';
  if (!(await hasVisibleElement(page, selector))) return false;
  try {
    await clearAuthFieldValidationState(page, selector);
    await ensureDirectInputValue(page, selector, email, "microsoft_email");
  } catch (error) {
    if (await isMicrosoftProofConfirmationSurface(page)) {
      log("login flow: Microsoft email prompt yielded to proof confirmation surface");
      return false;
    }
    if (!(await hasVisibleElement(page, selector).catch(() => false))) {
      log("login flow: Microsoft email input advanced away during direct fill");
      return true;
    }
    throw error;
  }
  const submitted =
    (await clickMatchingAction(
      page,
      [/^next$/i, /^continue$/i, /^sign in$/i, /^login$/i, /^下一步$/i, /^继续$/i, /^登录$/i],
      'input[type="submit"], button[type="submit"]',
    )) || false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  if (proofState) {
    proofState.postEmailPasswordPriorityUntil = Date.now() + 6_000;
    log("login flow: armed Microsoft password-priority grace window after email submit");
  }
  await page.waitForLoadState("domcontentloaded", { timeout: 8_000 }).catch(() => {});
  await waitForMicrosoftPostEmailSurface(page, 6_000).catch(() => {});
  log("login flow: submitted Microsoft account email");
  return true;
}

async function collectMicrosoftPasswordErrors(page: any): Promise<string[]> {
  const visibleErrors = await collectVisibleFormErrors(page).catch(() => []);
  const bodySignals = await page
    .evaluate(() => {
      const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const patterns = [
        /you['’]ve tried to sign in too many times with an incorrect account or password\.?/i,
        /your account or password is incorrect\.?/i,
        /incorrect account or password\.?/i,
        /incorrect password\.?/i,
        /wrong password\.?/i,
        /invalid password\.?/i,
        /try again later\.?/i,
        /密码不正确。?/i,
        /帐户或密码不正确。?/i,
        /请稍后重试。?/i,
      ];
      return patterns.map((pattern) => bodyText.match(pattern)?.[0] || "").filter((text) => text.length > 0);
    })
    .catch(() => [] as string[]);
  return Array.from(new Set([...visibleErrors, ...bodySignals]));
}

async function collectMicrosoftPasswordPromptState(page: any): Promise<{
  hasVisibleInput: boolean;
  likelySurface: boolean;
}> {
  return await page
    .evaluate(() => {
      const isVisible = (node: Element | null): node is HTMLElement => {
        if (!(node instanceof HTMLElement)) return false;
        const rect = node.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(node);
        return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
      };
      const normalize = (value: string | null | undefined) =>
        String(value || "")
          .replace(/[\u200e\u200f\u202a-\u202e]/g, "")
          .replace(/\s+/g, " ")
          .trim()
          .toLowerCase();
      const visiblePasswordInput = Array.from(
        document.querySelectorAll('input[type="password"], input[autocomplete="current-password"], input[name="passwd"]'),
      ).some((node) => isVisible(node));
      const bodyText = normalize(document.body?.innerText || "");
      const titleText = normalize(document.title || "");
      const hasPasswordCopy =
        /enter your password|forgot your password|输入你的密码|忘记密码/i.test(bodyText) ||
        /enter your password|输入你的密码/i.test(titleText);
      const hasPasswordForm =
        !!document.querySelector('form[data-testid="passwordEntryForm"]') ||
        !!document.querySelector('input[name="passwd"]') ||
        !!document.querySelector("#passwordEntry");
      return {
        hasVisibleInput: visiblePasswordInput,
        likelySurface: visiblePasswordInput || (hasPasswordCopy && hasPasswordForm),
      };
    })
    .catch(() => ({
      hasVisibleInput: false,
      likelySurface: false,
    }));
}

async function isMicrosoftLikelyPasswordSurface(page: any): Promise<boolean> {
  const state = await collectMicrosoftPasswordPromptState(page);
  return state.likelySurface;
}

async function collectMicrosoftPasswordSurfaceKey(page: any): Promise<string> {
  const payload = await page
    .evaluate(() => {
      const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim();
      const emailMatch = bodyText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
      return {
        url: window.location.href,
        title: document.title || "",
        bodyText: bodyText.slice(0, 400),
        accountHint: emailMatch?.[0] || "",
      };
    })
    .catch(() => ({
      url: page.url(),
      title: "",
      bodyText: "",
      accountHint: "",
    }));
  return buildMicrosoftPasswordSurfaceKey(payload);
}

async function collectMicrosoftSurfaceSnapshot(page: any): Promise<{ url: string; title: string; bodyText: string }> {
  return await page
    .evaluate(() => ({
      url: window.location.href,
      title: document.title || "",
      bodyText: (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 1200),
    }))
    .catch(() => ({
      url: page.url(),
      title: "",
      bodyText: "",
    }));
}

async function classifyMicrosoftFlowInterruptFromPage(page: any) {
  const payload = await collectMicrosoftSurfaceSnapshot(page);
  return classifyMicrosoftFlowInterrupt(payload);
}

async function collectMicrosoftRecoveryChallengeState(
  page: any,
  configuredAddress: string | null,
): Promise<{
  hintedMaskedEmail: string;
  matchesConfiguredMailbox: boolean | null;
  hasMismatchError: boolean;
  hasPasswordFallback: boolean;
  surfaceKind: "verify_email" | "identity_confirm" | "unknown";
}> {
  const payload = await page
    .evaluate(({ configuredAddress: configuredAddressValue }: { configuredAddress: string | null }) => {
      const normalize = (value: string | null | undefined) =>
        String(value || "")
          .replace(/[\u200e\u200f\u202a-\u202e]/g, "")
          .replace(/\s+/g, " ")
          .trim()
          .toLowerCase();
      const parseMaskedEmail = (value: string | null | undefined) => {
        const match = normalize(value).match(/([a-z0-9._%+-]*)(\*+)?@([a-z0-9.-]+\.[a-z]{2,})/i);
        if (!match) return null;
        return {
          visibleLocal: (match[1] || "").toLowerCase(),
          hasMask: !!match[2],
          domain: (match[3] || "").toLowerCase(),
        };
      };
      const configured = parseMaskedEmail(configuredAddressValue);
      const textParts = [
        document.title || "",
        document.body?.innerText || "",
        ...Array.from(document.querySelectorAll("input, button, a, label, option")).map((node) =>
          [
            node.textContent || "",
            node.getAttribute("aria-label") || "",
            node.getAttribute("title") || "",
            node.getAttribute("value") || "",
            node.getAttribute("placeholder") || "",
          ].join(" "),
        ),
      ];
      const combinedText = normalize(textParts.join(" "));
      const matches = Array.from(combinedText.matchAll(/([a-z0-9._%+-]*)(\*+)?@([a-z0-9.-]+\.[a-z]{2,})/gi));
      let hinted: { visibleLocal: string; hasMask: boolean; domain: string } | null = null;
      for (const match of matches) {
        const candidate = {
          visibleLocal: (match[1] || "").toLowerCase(),
          hasMask: !!match[2],
          domain: (match[3] || "").toLowerCase(),
        };
        if (!hinted || candidate.hasMask) {
          hinted = candidate;
        }
        if (candidate.hasMask) {
          break;
        }
      }
      const hasMismatchError =
        /doesn[’']?t match the alternate email|correct email starts with|alternate email associated with your account|不匹配|正确的电子邮件|备用电子邮件/i.test(
          combinedText,
        );
      const matchesConfiguredMailbox =
        hinted && configured
          ? hinted.domain === configured.domain && configured.visibleLocal.startsWith(hinted.visibleLocal)
          : null;
      const hasPasswordFallback = /use\s+your\s+password|sign\s+in\s+with\s+password|使用密码/i.test(combinedText);
      const surfaceKind = /help us protect your account|verify online|i don[’']?t have these any more|我不再拥有这些信息/i.test(
        combinedText,
      )
        ? "identity_confirm"
        : /verify your email|we[’']?ll send a code to|already received a code|验证你的电子邮件/i.test(combinedText)
          ? "verify_email"
          : "unknown";
      return {
        hintedMaskedEmail: hinted ? `${hinted.visibleLocal}${hinted.hasMask ? "***" : ""}@${hinted.domain}` : "",
        matchesConfiguredMailbox: hasMismatchError ? false : matchesConfiguredMailbox,
        hasMismatchError,
        hasPasswordFallback,
        surfaceKind,
      };
    }, { configuredAddress })
    .catch(() => ({
      hintedMaskedEmail: "",
      matchesConfiguredMailbox: null,
      hasMismatchError: false,
      hasPasswordFallback: false,
      surfaceKind: "unknown" as const,
    }));
  return payload;
}

async function handleMicrosoftPasswordPrompt(
  page: any,
  password: string,
  state: { submissionKey: string | null; submittedAt: number | null; submittedCount: number },
): Promise<boolean> {
  const selector = '#passwordEntry, input[name="passwd"], input[type="password"], input[autocomplete="current-password"]';
  const promptState = await collectMicrosoftPasswordPromptState(page);
  const hasPasswordCopy =
    promptState.likelySurface ||
    (await pageContainsAnyText(page, [
      /enter your password/i,
      /forgot your password/i,
      /输入你的密码/i,
      /忘记密码/i,
    ]));
  if (!promptState.hasVisibleInput && !hasPasswordCopy) return false;
  await page.waitForSelector(selector, { timeout: hasPasswordCopy ? 8_000 : 2_000 }).catch(() => {});
  const hasPasswordField = (await page.locator(selector).count().catch(() => 0)) > 0;
  if (!hasPasswordField) return false;
  const surfaceKey = await collectMicrosoftPasswordSurfaceKey(page);
  const visibleErrors = await collectMicrosoftPasswordErrors(page);
  const classifiedError = classifyMicrosoftPasswordError(visibleErrors);
  if (classifiedError) {
    throw new Error(`${classifiedError.code}:${classifiedError.message}`);
  }
  const currentPasswordValue = await page.locator(selector).first().inputValue().catch(() => "");
  if (state.submissionKey !== surfaceKey) {
    state.submissionKey = surfaceKey;
    state.submittedAt = null;
    state.submittedCount = 0;
  }
  if (state.submissionKey === surfaceKey && state.submittedAt && state.submittedCount > 0) {
    if (!currentPasswordValue) {
      state.submittedAt = null;
      state.submittedCount = 0;
      log("login flow: reset stale Microsoft password submission state on empty field");
    } else {
      if (Date.now() - state.submittedAt >= 8_000) {
        throw new Error(`microsoft_password_submit_stalled:${surfaceKey}`);
      }
      await page.waitForTimeout(1_000);
      const followupErrors = await collectMicrosoftPasswordErrors(page);
      const followupClassifiedError = classifyMicrosoftPasswordError(followupErrors);
      if (followupClassifiedError) {
        throw new Error(`${followupClassifiedError.code}:${followupClassifiedError.message}`);
      }
      return true;
    }
  }
  await clearAuthFieldValidationState(page, selector);
  await ensureDirectInputValue(page, selector, password, "microsoft_password");
  const submitted =
    (await clickMatchingAction(
      page,
      [/^sign in$/i, /^login$/i, /^continue$/i, /^next$/i, /^登录$/i, /^继续$/i, /^下一步$/i],
      'input[type="submit"], button[type="submit"]',
    )) || false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  state.submittedAt = Date.now();
  state.submittedCount += 1;
  await page.waitForTimeout(1_500);
  const postSubmitErrors = await collectMicrosoftPasswordErrors(page);
  const postSubmitClassifiedError = classifyMicrosoftPasswordError(postSubmitErrors);
  if (postSubmitClassifiedError) {
    throw new Error(`${postSubmitClassifiedError.code}:${postSubmitClassifiedError.message}`);
  }
  log("login flow: submitted Microsoft account password");
  return true;
}

async function submitMicrosoftPasswordIfVisible(
  page: any,
  password: string,
  state: { submissionKey: string | null; submittedAt: number | null; submittedCount: number },
): Promise<void> {
  if (!(await hasVisibleElement(page, 'input[type="password"], input[autocomplete="current-password"]'))) {
    return;
  }
  state.submissionKey = null;
  state.submittedAt = null;
  state.submittedCount = 0;
  await handleMicrosoftPasswordPrompt(page, password, state);
}

async function collectMicrosoftPasswordShortcutSurfaceKey(page: any): Promise<string> {
  const payload = await page
    .evaluate(() => ({
      url: window.location.href,
      title: document.title || "",
      bodyText: (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 500),
    }))
    .catch(() => ({
      url: page.url(),
      title: "",
      bodyText: "",
    }));
  return `${payload.url}::${payload.title}::${payload.bodyText}`;
}

async function hasVisibleMicrosoftPasswordShortcut(page: any): Promise<boolean> {
  return await page
    .evaluate(() => {
      const matches = (value: string) => /use\s+your\s+password|sign\s+in\s+with\s+password|使用密码/i.test(value);
      const nodes = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]'));
      for (const node of nodes) {
        const text = ((node as HTMLElement).innerText || (node as HTMLInputElement).value || node.textContent || "")
          .replace(/\s+/g, " ")
          .trim();
        if (!matches(text)) continue;
        if (!(node instanceof HTMLElement)) continue;
        const rect = node.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) continue;
        const style = window.getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") continue;
        return true;
      }
      return false;
    })
    .catch(() => false);
}

async function handleMicrosoftUsePasswordShortcut(
  page: any,
  proofState: MicrosoftProofFlowState,
  password: string,
  passwordState: { submissionKey: string | null; submittedAt: number | null; submittedCount: number },
): Promise<boolean> {
  if (proofState.passwordFallbackBlocked) {
    proofState.passwordShortcutKey = null;
    proofState.passwordShortcutSubmittedAt = null;
    proofState.passwordShortcutSubmittedCount = 0;
    return false;
  }
  if (await hasVisibleElement(page, 'input[type="password"], input[autocomplete="current-password"]')) {
    proofState.passwordShortcutKey = null;
    proofState.passwordShortcutSubmittedAt = null;
    proofState.passwordShortcutSubmittedCount = 0;
    return false;
  }
  const hasShortcut = await hasVisibleMicrosoftPasswordShortcut(page);
  if (!hasShortcut) {
    proofState.passwordShortcutKey = null;
    proofState.passwordShortcutSubmittedAt = null;
    proofState.passwordShortcutSubmittedCount = 0;
    return false;
  }
  const surfaceKey = await collectMicrosoftPasswordShortcutSurfaceKey(page);
  if (
    proofState.passwordShortcutKey === surfaceKey &&
    proofState.passwordShortcutSubmittedAt &&
    proofState.passwordShortcutSubmittedCount > 0
  ) {
    if (Date.now() - proofState.passwordShortcutSubmittedAt >= 8_000) {
      throw new Error(`microsoft_password_shortcut_stalled:${surfaceKey}`);
    }
    await page.waitForTimeout(1_000);
    return true;
  }
  const clicked = await clickMicrosoftPasswordFallbackAction(page);
  if (!clicked) {
    throw new Error(`microsoft_password_shortcut_missing:${surfaceKey}`);
  }
  proofState.passwordShortcutKey = surfaceKey;
  proofState.passwordShortcutSubmittedAt = Date.now();
  proofState.passwordShortcutSubmittedCount += 1;
  proofState.passwordFallbackAttempted = true;
  proofState.passwordFallbackReturnUrl = page.url();
  log("login flow: switched Microsoft verify-email surface to password shortcut");
  await submitMicrosoftPasswordIfVisible(page, password, passwordState);
  return true;
}

interface MicrosoftProofFlowState {
  mailbox: MailboxSession | null;
  startedAt: number | null;
  codeRequestedAt: number | null;
  codeRecoveryCount: number;
  postEmailPasswordPriorityUntil: number | null;
  passwordFallbackAttempted: boolean;
  passwordFallbackBlocked: boolean;
  passwordFallbackReturnUrl: string | null;
  confirmationSubmissionKey: string | null;
  confirmationSubmittedAt: number | null;
  confirmationSubmittedCount: number;
  passwordShortcutKey: string | null;
  passwordShortcutSubmittedAt: number | null;
  passwordShortcutSubmittedCount: number;
}

interface MicrosoftPasskeyState {
  homeReturnAttempted: boolean;
  tavilyRelaunchCount: number;
  lastNonPasskeyUrl: string | null;
}

async function closeTransientPasskeyPopups(page: any): Promise<boolean> {
  const pageCdp = await createCdpSession(page);
  if (!pageCdp) return false;
  const targetInfos = await pageCdp
    .send("Target.getTargets")
    .then((result: { targetInfos?: Array<{ targetId?: string; type?: string; title?: string; url?: string }> }) =>
      Array.isArray(result?.targetInfos) ? result.targetInfos : [],
    )
    .catch(() => []);
  let closed = false;
  for (const info of targetInfos) {
    const targetId = String(info?.targetId || "");
    const type = String(info?.type || "");
    const title = String(info?.title || "");
    const url = String(info?.url || "");
    if (!targetId || type !== "page" || !/^chrome-extension:\/\//i.test(url)) {
      continue;
    }
    if (
      !/fido2|passkey|webauthn/i.test(url) &&
      !/(bitwarden|1password|dashlane|lastpass).*(passkey|fido|security key)/i.test(`${title} ${url}`)
    ) {
      continue;
    }
    const result = await pageCdp.send("Target.closeTarget", { targetId }).catch(() => null);
    if (result) {
      closed = true;
    }
  }
  if (closed) {
    await page.waitForTimeout(500);
  }
  return closed;
}

async function stabilizeMicrosoftSessionAfterPasskey(page: any): Promise<boolean> {
  const probeUrls = ["https://account.microsoft.com/", "https://outlook.live.com/mail/0/"];
  for (const probeUrl of probeUrls) {
    await safeGoto(page, probeUrl, 20_000).catch(() => {});
    await page.waitForLoadState("domcontentloaded", { timeout: 10_000 }).catch(() => {});
    await page.waitForTimeout(1_200);
    await handleMicrosoftKeepSignedInPrompt(page, true).catch(() => false);
    await page.waitForTimeout(800);
    const currentUrl = page.url();
    if (
      /account\.microsoft\.com|outlook\.live\.com/i.test(currentUrl) &&
      !/login\.live\.com|login\.microsoftonline\.com/i.test(currentUrl)
    ) {
      log(`login flow: Microsoft session stabilized via ${currentUrl}`);
      return true;
    }
  }
  return false;
}

async function handleMicrosoftPasskeyInterrupt(
  page: any,
  state?: MicrosoftPasskeyState,
  proofState?: MicrosoftProofFlowState,
  recoveryUrl?: string,
): Promise<boolean | any> {
  const MAX_TAVILY_RELAUNCHES = 1;
  const normalizedRecoveryUrl = String(recoveryUrl || "").trim() || "https://app.tavily.com/home";
  const onPasskeyInterruptRoute = isMicrosoftPasskeyInterruptUrl(page.url());
  const isPasskeySetupPrompt =
    onPasskeyInterruptRoute ||
    (await pageContainsAnyText(page, [
      /setting up your passkey/i,
      /opening a security window/i,
      /finish setting up your passkey/i,
      /设置通行密钥/i,
      /安全窗口/i,
    ]));
  const isPasskeyErrorPrompt =
    !isPasskeySetupPrompt &&
    (await pageContainsAnyText(page, [
      /unable to create a passkey/i,
      /can[’']?t create a passkey/i,
      /we couldn[’']?t create a passkey/i,
      /something went wrong trying to create a passkey/i,
      /无法创建通行密钥/i,
    ]));
  if (!isPasskeySetupPrompt && !isPasskeyErrorPrompt) {
    return false;
  }
  if (onPasskeyInterruptRoute && state && state.tavilyRelaunchCount < MAX_TAVILY_RELAUNCHES) {
    state.tavilyRelaunchCount += 1;
    const context = typeof page?.context === "function" ? page.context() : null;
    if (context) {
      await closeTransientPasskeyPopups(page).catch(() => false);
      const siblingPages =
        typeof context.pages === "function"
          ? context.pages().filter((candidate: any) => candidate && candidate !== page && isMicrosoftPasskeyInterruptUrl(candidate.url()))
          : [];
      for (const sibling of siblingPages) {
        await sibling.close().catch(() => {});
      }
      await page.close().catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 400));
      const recoveryPage = await context.newPage().catch(() => null);
      if (recoveryPage) {
        await stabilizeMicrosoftSessionAfterPasskey(recoveryPage).catch(() => false);
        await safeGoto(recoveryPage, normalizedRecoveryUrl, 20_000).catch(() => {});
        await recoveryPage.waitForLoadState("domcontentloaded", { timeout: 10_000 }).catch(() => {});
        await recoveryPage.bringToFront().catch(() => {});
        log(
          `login flow: recovered Microsoft passkey by closing interrupt page and reopening the login flow (${state.tavilyRelaunchCount}/${MAX_TAVILY_RELAUNCHES})`,
        );
        return recoveryPage;
      }
    }
  }
  if (onPasskeyInterruptRoute && proofState && shouldRecoverMicrosoftPasskeyToProofCode(proofState)) {
    proofState.passwordFallbackBlocked = true;
    await closeTransientPasskeyPopups(page).catch(() => false);
    const recoveryCandidates = [proofState.passwordFallbackReturnUrl, state?.lastNonPasskeyUrl].filter(
      (value, index, array): value is string => !!value && array.indexOf(value) === index,
    );
    await page.goBack({ waitUntil: "domcontentloaded", timeout: 15_000 }).catch(() => null);
    await page.waitForTimeout(1_000);
    if (!isMicrosoftPasskeyInterruptUrl(page.url())) {
      log("login flow: recovered Microsoft passkey redirect back to proof flow via history");
      return true;
    }
    for (const recoveryUrl of recoveryCandidates) {
      await safeGoto(page, recoveryUrl, 20_000).catch(() => {});
      await page.waitForLoadState("domcontentloaded", { timeout: 10_000 }).catch(() => {});
      if (!isMicrosoftPasskeyInterruptUrl(page.url())) {
        log(`login flow: recovered Microsoft passkey redirect back to proof flow via ${recoveryUrl}`);
        return true;
      }
    }
  }
  const dismissPatterns = [/^cancel$/i, /^not now$/i, /^skip for now$/i, /^skip$/i, /^取消$/i, /^暂不$/i];
  const tryDismissPasskeyPrompt = async (): Promise<boolean> => {
    const cdpClicked = await clickMatchingAction(page, dismissPatterns, "#idBtn_Back");
    if (cdpClicked) {
      await page.waitForTimeout(1_000);
      return true;
    }
    const domClicked = await page
      .evaluate(`(() => {
        const normalize = (value) => String(value || "").replace(/\\s+/g, " ").trim().toLowerCase();
        const matchesCancel = (value) => ["cancel", "not now", "skip for now", "skip", "取消", "暂不"].includes(normalize(value));
        const exact = document.querySelector("#idBtn_Back");
        if (exact instanceof HTMLElement) {
          exact.click();
          return true;
        }
        const candidates = Array.from(document.querySelectorAll('input[type="button"], button, [role="button"], a'));
        for (const candidate of candidates) {
          const text = normalize([
            candidate.textContent || "",
            candidate.getAttribute("aria-label") || "",
            candidate.getAttribute("title") || "",
            candidate.getAttribute("value") || "",
          ].join(" "));
          if (!matchesCancel(text)) continue;
          if (candidate instanceof HTMLElement) {
            candidate.click();
            return true;
          }
        }
        return false;
      })()`)
      .catch(() => false);
    if (domClicked) {
      await page.waitForTimeout(1_000);
      return true;
    }
    return false;
  };

  let dismissed = false;
  if (isPasskeySetupPrompt) {
    if (!state?.homeReturnAttempted) {
      if (state) {
        state.homeReturnAttempted = true;
      }
      await safeGoto(page, normalizedRecoveryUrl, 20_000).catch(() => {});
      await page.waitForLoadState("domcontentloaded", { timeout: 10_000 }).catch(() => {});
      if (!isMicrosoftPasskeyInterruptUrl(page.url())) {
        log(`login flow: bypassed Microsoft passkey setup via ${normalizedRecoveryUrl}`);
        return true;
      }
    }
    const deadline = Date.now() + 8_000;
    while (Date.now() < deadline) {
      await page.keyboard.press("Escape").catch(() => {});
      await dispatchEscapeViaCdp(page).catch(() => {});
      await page.waitForTimeout(300);
      if (!isMicrosoftPasskeyInterruptUrl(page.url())) {
        dismissed = true;
        break;
      }
      if (await tryDismissPasskeyPrompt()) {
        dismissed = true;
        break;
      }
      await page.waitForTimeout(400);
    }
    if (!dismissed) {
      throw new Error("microsoft_passkey_cancel_missing");
    }
  } else {
    dismissed = await tryDismissPasskeyPrompt();
    if (!dismissed) {
      await page.keyboard.press("Escape").catch(() => {});
      await page.waitForTimeout(600);
    }
    if (!dismissed) {
      await dispatchEnterViaCdp(page);
      await page.waitForTimeout(1_000);
    }
  }
  log(`login flow: dismissed Microsoft passkey ${isPasskeySetupPrompt ? "setup" : "error"} prompt`);
  return true;
}

async function handleMicrosoftKeepSignedInPrompt(page: any, keepSignedIn: boolean): Promise<boolean> {
  if (!(await pageContainsAnyText(page, [/stay signed in/i, /保持登录状态/i]))) {
    return false;
  }
  const patterns = keepSignedIn ? [/^yes$/i, /^是$/i] : [/^no$/i, /^否$/i];
  const clicked = await clickMatchingAction(page, patterns, 'input[type="submit"], button[type="submit"], button');
  if (!clicked) {
    throw new Error(`microsoft_keep_signed_in_action_missing:${keepSignedIn ? "yes" : "no"}`);
  }
  log(`login flow: selected Microsoft keep-signed-in=${keepSignedIn ? "yes" : "no"}`);
  return true;
}

async function handleMicrosoftConsentPrompt(page: any): Promise<boolean> {
  if (
    !(await pageContainsAnyText(page, [
      /allow this app to access your info/i,
      /allow this application to access your info/i,
      /let this app access your info/i,
      /needs your permission to/i,
      /allow this unverified app/i,
      /允许此应用访问你的信息/i,
    ])) &&
    !/account\.live\.com\/Consent\/Update/i.test(page.url())
  ) {
    return false;
  }
  const consentPatterns = [/^accept$/i, /^allow$/i, /^yes$/i, /^接受$/i, /^允许$/i, /^是$/i];
  const consentSelectors =
    '#idSIButton9, #acceptButton, #btnAccept, button[name="accept"], input[name="accept"], input[type="submit"], button[type="submit"], button';
  const clickConsentOnTarget = async (target: any): Promise<boolean> => {
    const clicked = await clickMatchingAction(target, consentPatterns, consentSelectors);
    if (clicked) {
      return true;
    }
    return target
      .evaluate(`(() => {
        const normalize = (value) => String(value || "").replace(/\\s+/g, " ").trim().toLowerCase();
        const candidates = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"], a'));
        for (const candidate of candidates) {
          const text = normalize([
            candidate.textContent || "",
            candidate.getAttribute("aria-label") || "",
            candidate.getAttribute("title") || "",
            candidate.getAttribute("value") || "",
            candidate.getAttribute("name") || "",
            candidate.getAttribute("id") || "",
            candidate.getAttribute("data-testid") || "",
          ].join(" "));
          if (!/^(accept|allow|yes|接受|允许|是)$/.test(text) && !/(accept|allow|允许|接受)/.test(text)) {
            continue;
          }
          if (candidate instanceof HTMLElement) {
            candidate.click();
            return true;
          }
        }
        const fallback = document.querySelector('#idSIButton9, #acceptButton, #btnAccept');
        if (fallback instanceof HTMLElement) {
          fallback.click();
          return true;
        }
        return false;
      })()`)
      .catch(() => false);
  };
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const targets = [page, ...((typeof page.frames === "function" ? page.frames() : []) || [])];
    for (const target of targets) {
      if (await clickConsentOnTarget(target)) {
        await page.waitForTimeout(1_000);
        log("login flow: accepted Microsoft OAuth consent");
        return true;
      }
    }
    await page.waitForLoadState("domcontentloaded", { timeout: 5_000 }).catch(() => {});
    await page.waitForTimeout(750);
  }
  throw new Error("microsoft_consent_accept_missing");
}

async function handleMicrosoftProofAddPrompt(
  page: any,
  cfg: AppConfig,
  proxyUrl: string | undefined,
  proofState: MicrosoftProofFlowState,
): Promise<boolean> {
  const onAddRoute = /account\.live\.com\/proofs\/Add/i.test(page.url());
  const hasProofOptionSelector = await hasVisibleElement(page, "#iProofOptions").catch(() => false);
  let emailSelector = (await firstVisibleSelector(page, ["#EmailAddress", 'input[name="EmailAddress"]'])) || null;
  if (!onAddRoute && !emailSelector) {
    return false;
  }
  if (!proofState.startedAt) {
    proofState.startedAt = Date.now();
  }

  if (onAddRoute && hasProofOptionSelector) {
    await page
      .evaluate(() => {
        const select = document.querySelector("#iProofOptions") as HTMLSelectElement | null;
        if (!select) return;
        if (select.value !== "Email") {
          select.value = "Email";
          select.dispatchEvent(new Event("input", { bubbles: true }));
          select.dispatchEvent(new Event("change", { bubbles: true }));
        }
      })
      .catch(() => {});
    await page.waitForTimeout(250);
    emailSelector = (await firstVisibleSelector(page, ["#EmailAddress", 'input[name="EmailAddress"]'])) || null;
  }

  if (!emailSelector) {
    return false;
  }

  const proofMailbox = proofState.mailbox || (await resolveMicrosoftProofMailboxSession(cfg, proxyUrl, { allowProvision: onAddRoute }));
  proofState.mailbox = proofMailbox;

  await clearAuthFieldValidationState(page, emailSelector);
  await ensureDirectInputValue(page, emailSelector, proofMailbox.address, "microsoft_proof_mailbox");
  const submitted =
    (await clickMatchingAction(
      page,
      [/^next$/i, /^continue$/i, /^send code$/i, /^verify$/i, /^下一步$/i, /^继续$/i, /^发送代码$/i, /^验证$/i],
      "#iNext",
    )) ||
    (await submitContainingFormDirectly(page, emailSelector)) ||
    (await clickMatchingAction(
      page,
      [/^next$/i, /^continue$/i, /^send code$/i, /^verify$/i, /^下一步$/i, /^继续$/i, /^发送代码$/i, /^验证$/i],
      'input[type="submit"], button[type="submit"], button',
    )) ||
    false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  proofState.codeRequestedAt = Date.now();
  log(`login flow: submitted Microsoft proof mailbox ${proofMailbox.address}`);
  return true;
}

async function handleMicrosoftProofMethodPrompt(
  page: any,
  proofState: MicrosoftProofFlowState,
): Promise<boolean> {
  if (await hasVisibleElement(page, "#iProofOptions")) {
    await page
      .evaluate(() => {
        const select = document.querySelector("#iProofOptions") as HTMLSelectElement | null;
        if (!select) return;
        if (select.value !== "Email") {
          select.value = "Email";
          select.dispatchEvent(new Event("input", { bubbles: true }));
          select.dispatchEvent(new Event("change", { bubbles: true }));
        }
      })
      .catch(() => {});
    log("login flow: selected Microsoft proof backup email method");
    return true;
  }
  if (!(await pageContainsAnyText(page, [/what security info would you like to add/i, /你想添加哪些安全信息/i]))) {
    return false;
  }
  if (!proofState.startedAt) {
    proofState.startedAt = Date.now();
  }
  const selected = await clickMatchingAction(page, [/backup email/i, /alternate email/i, /备用电子邮件地址/i, /电子邮件地址/i], undefined, [
    "button",
    "option",
    "link",
  ]);
  if (selected) {
    log("login flow: selected Microsoft proof backup email method");
  }
  return selected;
}

async function handleMicrosoftProofVerifyPrompt(
  page: any,
  cfg: AppConfig,
  proxyUrl: string | undefined,
  proofState: MicrosoftProofFlowState,
  password: string,
  passwordState: { submissionKey: string | null; submittedAt: number | null; submittedCount: number },
): Promise<boolean> {
  const onProofVerifyRoute = /account\.live\.com\/proofs\/verify/i.test(page.url());
  const proofOptionsCount = await page.locator('input[name="proof"][type="radio"]').count().catch(() => 0);
  if (!onProofVerifyRoute && proofOptionsCount === 0) {
    return false;
  }
  if (!proofState.startedAt) {
    proofState.startedAt = Date.now();
  }
  const configuredProofAddress = proofState.mailbox?.address || cfg.microsoftProofMailboxAddress?.trim() || "";

  const verifyState = await page.evaluate(`(() => {
    const address = ${JSON.stringify(configuredProofAddress)};
    const normalize = (value) =>
      String(value || "")
        .replace(/[\\u200e\\u200f\\u202a-\\u202e]/g, "")
        .replace(/\\s+/g, " ")
        .trim()
        .toLowerCase();
    const normalizedAddress = normalize(address);
    const [localPartRaw, domainRaw = ""] = normalizedAddress.split("@");
    const localPart = localPartRaw || "";
    const domainPart = domainRaw || "";
    const parseMaskedEmail = (value) => {
      const match = normalize(value).match(/([a-z0-9._%+-]*)(\\*+)?@([a-z0-9.-]+\\.[a-z]{2,})/i);
      if (!match) return null;
      return {
        visibleLocal: match[1] || "",
        hasMask: !!match[2],
        domain: match[3] || "",
      };
    };
    const optionInputs = Array.from(document.querySelectorAll('input[name="proof"][type="radio"]'));
    const optionStates = optionInputs.map((input) => {
      const optionId = input.id || "";
      const labelText =
        (optionId ? document.querySelector('label[for="' + CSS.escape(optionId) + '"]')?.textContent : "") ||
        input.closest("label, li, div, fieldset")?.textContent ||
        "";
      return {
        id: optionId,
        value: input.value || "",
        label: labelText,
        checked: !!input.checked,
      };
    });
    const hiddenSelect = document.querySelector("#iProofOptions");
    const hiddenValue = hiddenSelect && "value" in hiddenSelect ? hiddenSelect.value || "" : "";
    let checkedOption = optionStates.find((option) => option.checked) || null;
    if (!checkedOption) {
      checkedOption = optionStates.find((option) => normalize(option.value) === normalize(hiddenValue)) || null;
    }
    const bodyText = normalize(document.body?.innerText || "");
    const titleText = normalize(document.title || "");
    const codeInput = document.querySelector('#iOttText, input[name="iOttText"], input[aria-label*="code" i], input[placeholder*="code" i]');
    const emailCompletionInput = document.querySelector('#iProofEmail');
    let target = normalizedAddress ? optionStates.find((option) => normalize(option.value).includes(normalizedAddress)) || null : null;
    if (!target && normalizedAddress) {
      target = optionStates.find((option) => normalize(option.label).includes(normalizedAddress)) || null;
    }
    let matchedVisibleLocal = "";
    let hintedMaskedEmail = "";
    if (!target) {
      for (const option of optionStates) {
        const fromValue = parseMaskedEmail(option.value);
        const fromLabel = parseMaskedEmail(option.label);
        const candidate = fromValue || fromLabel;
        if (!candidate) continue;
        if (!hintedMaskedEmail) {
          hintedMaskedEmail = candidate.visibleLocal + (candidate.hasMask ? "***" : "") + "@" + candidate.domain;
        }
        if (candidate.domain !== domainPart) continue;
        if (!localPart.startsWith(candidate.visibleLocal)) continue;
        target = option;
        matchedVisibleLocal = candidate.visibleLocal;
        break;
      }
    }
    if (!matchedVisibleLocal && target) {
      const candidate = parseMaskedEmail(target.value) || parseMaskedEmail(target.label);
      matchedVisibleLocal = candidate?.visibleLocal || "";
      hintedMaskedEmail =
        hintedMaskedEmail || (candidate ? candidate.visibleLocal + (candidate.hasMask ? "***" : "") + "@" + candidate.domain : "");
    }
    const missingEmailPart =
      matchedVisibleLocal && localPart.startsWith(matchedVisibleLocal) ? localPart.slice(matchedVisibleLocal.length) : "";
    return {
      hasCodeInput: !!codeInput,
      codeInputValue: codeInput && "value" in codeInput ? codeInput.value || "" : "",
      options: optionStates,
      checkedValue: checkedOption?.value || "",
      checkedLabel: checkedOption?.label || "",
      titleText,
      bodyText,
      mentionsTarget:
        titleText.includes(normalizedAddress) ||
        bodyText.includes("enter the code we sent to " + normalizedAddress) ||
        bodyText.includes("we sent to " + normalizedAddress),
      targetId: target?.id || "",
      targetValue: target?.value || "",
      targetLabel: target?.label || "",
      hintedMaskedEmail,
      emailCompletionValue: missingEmailPart || localPart,
      missingEmailPart,
      hasEmailCompletionInput: !!emailCompletionInput,
    };
  })()`);

  if (verifyState.options.length === 0) {
    return false;
  }

  if (verifyState.mentionsTarget && verifyState.hasCodeInput) {
    return false;
  }

  if (!verifyState.targetId) {
    const challengeState = await collectMicrosoftRecoveryChallengeState(page, configuredProofAddress || null);
    if (
      shouldClassifyMicrosoftUnknownRecoveryEmail({
        surfaceKind: challengeState.surfaceKind,
        configuredMailboxMatchesChallenge: challengeState.matchesConfiguredMailbox,
        hasPasswordFallback: challengeState.hasPasswordFallback,
      })
    ) {
      throw new Error(
        `microsoft_unknown_recovery_email:${challengeState.hintedMaskedEmail || verifyState.hintedMaskedEmail || "unknown_recovery_email"}`,
      );
    }
    if (await clickMicrosoftPasswordFallbackAction(page)) {
      proofState.passwordFallbackAttempted = true;
      proofState.passwordFallbackReturnUrl = page.url();
      await submitMicrosoftPasswordIfVisible(page, password, passwordState);
      log("login flow: switched Microsoft proof verify prompt to password fallback");
      return true;
    }
    throw new Error(
      `microsoft_unknown_recovery_email:${verifyState.hintedMaskedEmail || "unknown_recovery_email"}`,
    );
  }
  const proofMailbox = proofState.mailbox || (await resolveMicrosoftProofMailboxSession(cfg, proxyUrl));
  proofState.mailbox = proofMailbox;

  await page.evaluate(
    (payload: { targetId: string; targetValue: string; missingEmailPart: string; emailCompletionValue: string }) => {
      const { targetId, targetValue, missingEmailPart, emailCompletionValue } = payload;
      const input = document.getElementById(targetId);
      if (!(input instanceof HTMLInputElement)) return;
      input.click();
      input.checked = true;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
      const hidden = document.querySelector("#iProofOptions");
      if (hidden instanceof HTMLInputElement || hidden instanceof HTMLSelectElement) {
        hidden.value = targetValue;
        hidden.dispatchEvent(new Event("input", { bubbles: true }));
        hidden.dispatchEvent(new Event("change", { bubbles: true }));
      }
      const emailCompletion = document.querySelector("#iProofEmail");
      if (emailCompletion instanceof HTMLInputElement && (emailCompletionValue || missingEmailPart)) {
        emailCompletion.value = emailCompletionValue || missingEmailPart;
        emailCompletion.dispatchEvent(new Event("input", { bubbles: true }));
        emailCompletion.dispatchEvent(new Event("change", { bubbles: true }));
      }
    },
    {
      targetId: verifyState.targetId,
      targetValue: verifyState.targetValue,
      emailCompletionValue: verifyState.emailCompletionValue || verifyState.missingEmailPart || "",
      missingEmailPart: verifyState.missingEmailPart || "",
    },
  );

  const submitted =
    (await clickMatchingAction(
      page,
      [/^next$/i, /^send code$/i, /^continue$/i, /^verify$/i, /^下一步$/i, /^发送代码$/i, /^继续$/i, /^验证$/i],
      'input[type="submit"], button[type="submit"], button',
    )) || false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  await page.waitForTimeout(1_200);
  const verifyErrors = await collectVisibleFormErrors(page).catch(() => []);
  if (
    verifyErrors.some((text) =>
      /doesn[’']?t match the alternate email|correct email starts with|alternate email associated with your account/i.test(
        text,
      ),
    )
  ) {
    throw new Error(`microsoft_proof_submit_failed:${verifyErrors.join(" | ")}`);
  }
  proofState.codeRequestedAt = Date.now();
  log(`login flow: requested Microsoft proof code via ${proofMailbox.address}`);
  return true;
}

async function handleMicrosoftProofEmailPrompt(
  page: any,
  cfg: AppConfig,
  proxyUrl: string | undefined,
  proofState: MicrosoftProofFlowState,
  password: string,
  passwordState: { submissionKey: string | null; submittedAt: number | null; submittedCount: number },
): Promise<boolean> {
  if (await isMicrosoftLikelyPasswordSurface(page)) {
    return false;
  }
  const confirmationSelectors = [
    '#proof-confirmation-email-input',
    'input[id*="proof-confirmation-email" i]',
    'input[data-testid*="proof-confirmation-email" i]',
  ];
  if (await firstVisibleSelector(page, confirmationSelectors)) {
    return false;
  }
  const onProofRoute = /account\.live\.com\/proofs\//i.test(page.url());
  const hasProofCopy = await pageContainsAnyText(page, [
    /protect your account/i,
    /let.?s protect your account/i,
    /let us protect your account/i,
    /让我们来保护你的帐户/i,
    /what security info would you like to add/i,
    /你想添加哪些安全信息/i,
    /verify your email/i,
    /验证你的电子邮件/i,
    /verify your identity/i,
    /验证你的身份/i,
  ]);
  if (!onProofRoute && !hasProofCopy) {
    return false;
  }
  let proofMailbox = proofState.mailbox;
  let proofMailboxError: Error | null = null;
  const configuredProofAddress = proofMailbox?.address || cfg.microsoftProofMailboxAddress?.trim() || null;
  const challengeState = await collectMicrosoftRecoveryChallengeState(page, configuredProofAddress);
  const shouldUsePasswordFallback = shouldAttemptMicrosoftProofPasswordFallback({
    hasConfiguredMailbox: !!configuredProofAddress,
    configuredMailboxMatchesChallenge: challengeState.matchesConfiguredMailbox,
    passwordFallbackAttempted: proofState.passwordFallbackAttempted,
    passwordFallbackBlocked: proofState.passwordFallbackBlocked,
  });
  if (
    shouldClassifyMicrosoftUnknownRecoveryEmail({
      surfaceKind: challengeState.surfaceKind,
      configuredMailboxMatchesChallenge: challengeState.matchesConfiguredMailbox,
      hasPasswordFallback: challengeState.hasPasswordFallback,
    })
  ) {
    throw new Error(`microsoft_unknown_recovery_email:${challengeState.hintedMaskedEmail || "unknown_recovery_email"}`);
  }
  if (shouldUsePasswordFallback) {
    if (await clickMicrosoftPasswordFallbackAction(page)) {
      proofState.passwordFallbackAttempted = true;
      proofState.passwordFallbackReturnUrl = page.url();
      await submitMicrosoftPasswordIfVisible(page, password, passwordState);
      log(
        `login flow: switched Microsoft proof email prompt to password fallback${
          challengeState.hintedMaskedEmail ? ` (hint=${challengeState.hintedMaskedEmail})` : ""
        }`,
      );
      return true;
    }
    if (challengeState.matchesConfiguredMailbox === false) {
      throw new Error(
        `microsoft_password_fallback_unavailable:${challengeState.hintedMaskedEmail || "challenge_mismatch"}`,
      );
    }
  }
  if (!proofState.startedAt) {
    proofState.startedAt = Date.now();
  }
  const selector =
    (await firstVisibleSelector(page, ["#EmailAddress"])) ||
    (await markBestVisibleControl(
      page,
      'input[type="email"], input[type="text"], input:not([type])',
      [/backup.*email/i, /alternate.*email/i, /备用电子邮件/i, /电子邮件地址/i, /example\.com/i, /email/i],
      "microsoft-proof-email",
    )) ||
    null;
  if (!selector) {
    return false;
  }
  if (!proofMailbox) {
    try {
      proofMailbox = await resolveMicrosoftProofMailboxSession(cfg, proxyUrl);
      proofState.mailbox = proofMailbox;
    } catch (error) {
      proofMailboxError = error instanceof Error ? error : new Error(String(error));
    }
  }
  if (!proofMailbox) {
    const surface = await collectMicrosoftSurfaceSnapshot(page).catch(() => ({
      url: page.url(),
      title: "",
      bodyText: "",
    }));
    log(
      `login flow: proof email prompt missing configured mailbox on surface title=${surface.title || "(empty)"} body=${surface.bodyText.slice(0, 160) || "(empty)"}`,
    );
    throw proofMailboxError || new Error("microsoft_proof_mailbox_missing");
  }
  if (/account\.live\.com\/proofs\/Add/i.test(page.url())) {
    await page
      .evaluate(() => {
        const select = document.querySelector("#iProofOptions") as HTMLSelectElement | null;
        if (!select) return;
        if (select.value !== "Email") {
          select.value = "Email";
          select.dispatchEvent(new Event("input", { bubbles: true }));
          select.dispatchEvent(new Event("change", { bubbles: true }));
        }
      })
      .catch(() => {});
  }
  await clearAuthFieldValidationState(page, selector);
  await ensureDirectInputValue(page, selector, proofMailbox.address, "microsoft_proof_mailbox");
  const submitted =
    (await submitContainingFormDirectly(page, selector)) ||
    (selector === "#EmailAddress" ? await clickMatchingAction(page, [/^next$/i, /^continue$/i, /^send code$/i], "#iNext") : false) ||
    (await clickMatchingAction(
      page,
      [/^next$/i, /^continue$/i, /^send code$/i, /^verify$/i, /^下一步$/i, /^继续$/i, /^发送代码$/i, /^验证$/i],
      'input[type="submit"], button[type="submit"], button',
    )) ||
    false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  const postSubmitErrors = await collectVisibleFormErrors(page).catch(() => []);
  if (
    postSubmitErrors.some((text) =>
      /doesn[’']?t match the alternate email|correct email starts with|alternate email associated with your account|不匹配|正确的电子邮件|备用电子邮件/i.test(
        text,
      ),
    )
  ) {
    if (challengeState.matchesConfiguredMailbox === false) {
      throw new Error(`microsoft_unknown_recovery_email:${challengeState.hintedMaskedEmail || "unknown_recovery_email"}`);
    }
    if (await clickMicrosoftPasswordFallbackAction(page)) {
      proofState.passwordFallbackAttempted = true;
      proofState.passwordFallbackReturnUrl = page.url();
      await submitMicrosoftPasswordIfVisible(page, password, passwordState);
      log("login flow: switched Microsoft proof email prompt to password fallback after mismatch");
      return true;
    }
    throw new Error(`microsoft_proof_submit_failed:${postSubmitErrors.join(" | ")}`);
  }
  proofState.codeRequestedAt = Date.now();
  log(`login flow: submitted Microsoft proof mailbox ${proofMailbox.address}`);
  return true;
}

async function handleMicrosoftProofConfirmationEmailPrompt(
  page: any,
  cfg: AppConfig,
  proxyUrl: string | undefined,
  proofState: MicrosoftProofFlowState,
  password: string,
  passwordState: { submissionKey: string | null; submittedAt: number | null; submittedCount: number },
): Promise<boolean> {
  if (await isMicrosoftLikelyPasswordSurface(page)) {
    return false;
  }
  const confirmationSelectors = [
    "#iProofEmail",
    '#proof-confirmation-email-input',
    'input[id*="proof-confirmation-email" i]',
    'input[data-testid*="proof-confirmation-email" i]',
  ];
  const confirmationSelector = confirmationSelectors.join(", ");
  const hasConfirmationInput = Boolean(await firstVisibleSelector(page, confirmationSelectors));
  const hasConfirmationCopy = await pageContainsAnyText(page, [
    /verify your email/i,
    /we'll send a code to/i,
    /we[’']?ll send a code to/i,
    /already received a code/i,
    /use your password/i,
    /验证你的电子邮件/i,
  ]);
  if (!hasConfirmationCopy && !hasConfirmationInput) {
    proofState.confirmationSubmissionKey = null;
    proofState.confirmationSubmittedAt = null;
    proofState.confirmationSubmittedCount = 0;
    return false;
  }
  const confirmationSurfaceKey = page.url();
  let proofMailbox = proofState.mailbox;
  let proofMailboxError: Error | null = null;
  const configuredProofAddress = proofMailbox?.address || cfg.microsoftProofMailboxAddress?.trim() || null;
  const confirmationState = await collectMicrosoftRecoveryChallengeState(page, configuredProofAddress);
  const shouldUsePasswordFallback = shouldAttemptMicrosoftProofPasswordFallback({
    hasConfiguredMailbox: !!configuredProofAddress,
    configuredMailboxMatchesChallenge: confirmationState.matchesConfiguredMailbox ?? null,
    passwordFallbackAttempted: proofState.passwordFallbackAttempted,
    passwordFallbackBlocked: proofState.passwordFallbackBlocked,
  });
  if (
    shouldClassifyMicrosoftUnknownRecoveryEmail({
      surfaceKind: confirmationState.surfaceKind,
      configuredMailboxMatchesChallenge: confirmationState.matchesConfiguredMailbox,
      hasPasswordFallback: confirmationState.hasPasswordFallback,
    })
  ) {
    throw new Error(`microsoft_unknown_recovery_email:${confirmationState.hintedMaskedEmail || "unknown_recovery_email"}`);
  }
  if (shouldUsePasswordFallback) {
    if (await clickMicrosoftPasswordFallbackAction(page)) {
      proofState.passwordFallbackAttempted = true;
      proofState.passwordFallbackReturnUrl = page.url();
      await submitMicrosoftPasswordIfVisible(page, password, passwordState);
      log(
        `login flow: switched Microsoft proof confirmation to password fallback${
          confirmationState.hintedMaskedEmail ? ` (hint=${confirmationState.hintedMaskedEmail})` : ""
        }`,
      );
      return true;
    }
    if (confirmationState.matchesConfiguredMailbox === false) {
      throw new Error(
        `microsoft_password_fallback_unavailable:${confirmationState.hintedMaskedEmail || "challenge_mismatch"}`,
      );
    }
  }
  const selector =
    (await markBestVisibleControl(
      page,
      confirmationSelector,
      [/email/i, /proof/i, /验证码/i, /电子邮件/i],
      "microsoft-proof-confirm-email",
    )) ||
    (await firstVisibleSelector(page, confirmationSelectors)) ||
    null;
  if (!selector && !proofMailboxError) {
    return false;
  }
  if (!proofState.startedAt) {
    proofState.startedAt = Date.now();
  }
  if (!proofMailbox) {
    try {
      proofMailbox = await resolveMicrosoftProofMailboxSession(cfg, proxyUrl);
      proofState.mailbox = proofMailbox;
    } catch (error) {
      proofMailboxError = error instanceof Error ? error : new Error(String(error));
    }
  }
  if (!selector) {
    throw proofMailboxError || new Error("microsoft_proof_add_email_input_missing");
  }
  if (!proofMailbox) {
    const surface = await collectMicrosoftSurfaceSnapshot(page).catch(() => ({
      url: page.url(),
      title: "",
      bodyText: "",
    }));
    log(
      `login flow: proof confirmation prompt missing configured mailbox on surface title=${surface.title || "(empty)"} body=${surface.bodyText.slice(0, 160) || "(empty)"}`,
    );
    throw proofMailboxError || new Error("microsoft_proof_mailbox_missing");
  }
  if (
    proofState.confirmationSubmissionKey === confirmationSurfaceKey &&
    proofState.confirmationSubmittedAt &&
    proofState.confirmationSubmittedCount > 0
  ) {
    const inlineCodeSelector = await firstVisibleSelector(page, [
      "#iOttText",
      'input[name="iOttText"]',
      'input[id^="codeEntry-"]',
      'input[autocomplete="one-time-code"]',
      'input[aria-label*="code" i]',
      'input[placeholder*="code" i]',
      'input[inputmode="numeric"]',
      'input[inputmode="decimal"]',
      'input[type="tel"]',
      'input[type="number"]',
    ]);
    if (inlineCodeSelector) {
      proofState.codeRequestedAt ||= proofState.confirmationSubmittedAt;
      return false;
    }
    const waitElapsedMs = Date.now() - proofState.confirmationSubmittedAt;
    const formErrors = await collectVisibleFormErrors(page).catch(() => []);
    if (
      formErrors.some((text) =>
        /doesn[’']?t match the alternate email|correct email starts with|alternate email associated with your account|不匹配|正确的电子邮件|备用电子邮件/i.test(
          text,
        ),
      )
    ) {
      throw new Error(`microsoft_unknown_recovery_email:${confirmationState.hintedMaskedEmail || "unknown_recovery_email"}`);
    }
    if (formErrors.some((text) => /invalid|incorrect|wrong|match|不正确|无效|匹配|重新输入/i.test(text))) {
      throw new Error(`microsoft_proof_submit_failed:${formErrors.join(" | ")}`);
    }
    if (waitElapsedMs >= 8_000) {
      throw new Error(`microsoft_proof_submit_failed:confirmation_stalled:${confirmationSurfaceKey}`);
    }
    await page.waitForTimeout(1_000);
    return true;
  }
  await clearAuthFieldValidationState(page, selector);
  await ensureDirectInputValue(page, selector, proofMailbox.address, "microsoft_proof_confirmation_mailbox");
  const submitted =
    (await clickMatchingAction(
      page,
      [/^send code$/i, /^next$/i, /^continue$/i, /^verify$/i, /^发送代码$/i, /^下一步$/i, /^继续$/i, /^验证$/i],
      'button[data-testid="primaryButton"], input[type="submit"], button[type="submit"], button',
    )) ||
    (await submitContainingFormDirectly(page, selector)) ||
    false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  proofState.confirmationSubmissionKey = confirmationSurfaceKey;
  proofState.confirmationSubmittedAt = Date.now();
  proofState.confirmationSubmittedCount += 1;
  proofState.codeRequestedAt = Date.now();
  const postSubmitErrors = await collectVisibleFormErrors(page).catch(() => []);
  if (
    postSubmitErrors.some((text) =>
      /doesn[’']?t match the alternate email|correct email starts with|alternate email associated with your account|不匹配|正确的电子邮件|备用电子邮件/i.test(
        text,
      ),
    )
  ) {
    throw new Error(`microsoft_unknown_recovery_email:${confirmationState.hintedMaskedEmail || "unknown_recovery_email"}`);
  }
  if (postSubmitErrors.some((text) => /invalid|incorrect|wrong|match|不正确|无效|匹配|重新输入/i.test(text))) {
    throw new Error(`microsoft_proof_submit_failed:${postSubmitErrors.join(" | ")}`);
  }
  log(`login flow: confirmed Microsoft proof mailbox ${proofMailbox.address}`);
  return true;
}

async function handleMicrosoftProofCodePrompt(
  page: any,
  cfg: AppConfig,
  proxyUrl: string | undefined,
  proofState: MicrosoftProofFlowState,
): Promise<boolean> {
  if (await isMicrosoftLikelyPasswordSurface(page)) {
    return false;
  }
  const isStillOnProofCodeSurface = async (): Promise<boolean> => {
    const currentUrl = page.url();
    if (/app\.tavily\.com\/home/i.test(currentUrl) || /account\.live\.com\/Consent\/Update/i.test(currentUrl)) {
      return false;
    }
    if (isMicrosoftPasskeyInterruptUrl(currentUrl)) {
      return false;
    }
    if (
      await pageContainsAnyText(page, [
        /security code/i,
        /enter (the|your) code/i,
        /verify your email/i,
        /verify your identity/i,
        /安全代码/i,
        /输入代码/i,
        /验证码/i,
        /验证你的电子邮件/i,
        /验证你的身份/i,
      ])
    ) {
      return true;
    }
    return Boolean(await firstVisibleSelector(page, codeInputSelectors));
  };
  const hasAdvancedPastProofCode = async (): Promise<boolean> => {
    const currentUrl = page.url();
    if (
      /app\.tavily\.com\/home/i.test(currentUrl) ||
      /account\.live\.com\/Consent\/Update/i.test(currentUrl) ||
      /login\.microsoft\.com\/consumers\/fido\/create/i.test(currentUrl)
    ) {
      return true;
    }
    return await pageContainsAnyText(page, [
      /stay signed in/i,
      /保持登录状态/i,
      /skip having to sign in every time/i,
      /让此应用访问你的信息/i,
      /allow this app to access your info/i,
      /let this app access your info/i,
      /needs your permission to/i,
      /setting up your passkey/i,
      /finish setting up your passkey/i,
    ]);
  };
  const attemptProofCodeRecovery = async (reason: string): Promise<boolean> => {
    if (proofState.codeRecoveryCount >= 1) {
      return false;
    }
    const wentBack =
      (await clickMatchingAction(page, [/^back$/i, /^返回$/i], '#back-button, button[aria-label*="Back" i], button[aria-label*="返回" i]')) ||
      false;
    if (!wentBack) {
      return false;
    }
    proofState.codeRecoveryCount += 1;
    proofState.codeRequestedAt = null;
    proofState.confirmationSubmissionKey = null;
    proofState.confirmationSubmittedAt = null;
    proofState.confirmationSubmittedCount = 0;
    await page.waitForTimeout(1_200);
    log(`login flow: retried Microsoft proof code by returning to resend surface (${reason})`);
    return true;
  };
  const codeInputSelectors = [
    '#iOttText',
    'input[name="iOttText"]',
    'input[id^="codeEntry-"]',
    'input[autocomplete="one-time-code"]',
    'input[maxlength="1"]',
    'input[aria-label*="code" i]',
    'input[placeholder*="code" i]',
    'input[inputmode="numeric"]',
    'input[inputmode="decimal"]',
    'input[type="tel"]',
    'input[type="number"]',
    'input[type="text"]',
    'input:not([type])',
  ];
  const visibleCodeSelector = await firstVisibleSelector(page, codeInputSelectors);
  if (
    !(await pageContainsAnyText(page, [
      /security code/i,
      /enter (the|your) code/i,
      /verify your email/i,
      /verify your identity/i,
      /安全代码/i,
      /输入代码/i,
      /验证码/i,
      /验证你的电子邮件/i,
      /验证你的身份/i,
    ])) &&
    !visibleCodeSelector
  ) {
    return false;
  }
  const selector = await markBestVisibleControl(
    page,
    'input[type="tel"], input[type="number"], input[inputmode="numeric"], input[type="text"], input:not([type])',
    [/code/i, /security/i, /验证码/i, /安全代码/i, /verify/i],
    "microsoft-proof-code",
  ) || visibleCodeSelector;
  if (!selector) {
    return false;
  }
  const proofMailbox = proofState.mailbox || (await resolveMicrosoftProofMailboxSession(cfg, proxyUrl));
  proofState.mailbox = proofMailbox;
  const notBeforeMs = (proofState.codeRequestedAt || proofState.startedAt || Date.now()) - 10_000;
  const code = await waitForMicrosoftProofCode(proofMailbox, cfg.emailWaitMs, cfg.mailPollMs, proxyUrl, notBeforeMs);
  if (!code) {
    if (await attemptProofCodeRecovery("timeout")) {
      return true;
    }
    throw new Error("microsoft_proof_code_timeout");
  }
  log(`login flow: received Microsoft proof code (${code.length} digits)`);
  const codeFilled = await fillMicrosoftProofOtpInputs(page, code);
  if (!codeFilled) {
    let activeSelector: string | null = selector;
    const selectorStillVisible = activeSelector ? await hasVisibleElement(page, activeSelector).catch(() => false) : false;
    if (!selectorStillVisible) {
      activeSelector =
        (await markBestVisibleControl(
          page,
          'input[type="tel"], input[type="number"], input[inputmode="numeric"], input[type="text"], input:not([type])',
          [/code/i, /security/i, /验证码/i, /安全代码/i, /verify/i],
          "microsoft-proof-code-fallback",
        )) ||
        (await firstVisibleSelector(page, codeInputSelectors)) ||
        null;
    }
    for (let round = 1; round <= 3; round += 1) {
      if (await hasAdvancedPastProofCode()) {
        log("login flow: Microsoft proof code surface advanced before direct code fill");
        return true;
      }
      if (activeSelector || (await isStillOnProofCodeSurface())) {
        break;
      }
      await page.waitForTimeout(400);
      activeSelector =
        activeSelector ||
        (await markBestVisibleControl(
          page,
          'input[type="tel"], input[type="number"], input[inputmode="numeric"], input[type="text"], input:not([type])',
          [/code/i, /security/i, /验证码/i, /安全代码/i, /verify/i],
          "microsoft-proof-code-recheck",
        )) ||
        (await firstVisibleSelector(page, codeInputSelectors)) ||
        null;
      if (round === 3 && !(await isStillOnProofCodeSurface())) {
        log("login flow: Microsoft proof code surface disappeared before code field became available");
        return true;
      }
    }
    if (!activeSelector) {
      throw new Error("microsoft_proof_code_input_missing");
    }
    await clearAuthFieldValidationState(page, activeSelector);
    try {
      await ensureDirectInputValue(page, activeSelector, code, "microsoft_proof_code");
    } catch (error) {
      if (await hasAdvancedPastProofCode()) {
        log("login flow: Microsoft proof code surface advanced while waiting for direct code input");
        return true;
      }
      throw error;
    }
  }
  await page.waitForTimeout(codeFilled ? 1_200 : 400);
  let formErrors = await collectVisibleFormErrors(page).catch(() => []);
  if (formErrors.some((text) => /invalid|incorrect|wrong|不正确|无效/i.test(text))) {
    if (await attemptProofCodeRecovery(`pre_submit_error:${formErrors.join(" | ")}`)) {
      return true;
    }
    throw new Error(`microsoft_proof_submit_failed:${formErrors.join(" | ")}`);
  }
  const submitted =
    (await clickMatchingAction(
      page,
      [/^next$/i, /^continue$/i, /^verify$/i, /^submit$/i, /^下一步$/i, /^继续$/i, /^验证$/i, /^提交$/i],
      'input[type="submit"], button[type="submit"], button',
    )) ||
    (!codeFilled ? (await submitContainingFormDirectly(page, selector || 'input[type="tel"], input[type="number"], input[inputmode="numeric"], input[type="text"], input:not([type])')) : false) ||
    false;
  if (!submitted) {
    await dispatchEnterViaCdp(page);
    await page.waitForTimeout(1_000);
  }
  await page.waitForTimeout(1_500);
  formErrors = await collectVisibleFormErrors(page).catch(() => []);
  if (formErrors.some((text) => /invalid|incorrect|wrong|不正确|无效/i.test(text))) {
    if (await attemptProofCodeRecovery(`post_submit_error:${formErrors.join(" | ")}`)) {
      return true;
    }
    throw new Error(`microsoft_proof_submit_failed:${formErrors.join(" | ")}`);
  }
  log("login flow: submitted Microsoft proof code");
  return true;
}

export interface MicrosoftLoginCompletionOptions {
  completionUrlPatterns?: RegExp[];
  passkeyRecoveryUrl?: string;
}

export async function completeMicrosoftLogin(
  page: any,
  cfg: AppConfig,
  proxyUrl?: string,
  options?: MicrosoftLoginCompletionOptions,
): Promise<any> {
  const email = cfg.microsoftAccountEmail;
  const password = cfg.microsoftAccountPassword;
  if (!email || !password) {
    throw new Error("microsoft_account_credentials_missing");
  }
  const proofState: MicrosoftProofFlowState = {
    mailbox: null as MailboxSession | null,
    startedAt: null as number | null,
    codeRequestedAt: null as number | null,
    codeRecoveryCount: 0,
    postEmailPasswordPriorityUntil: null as number | null,
    passwordFallbackAttempted: false,
    passwordFallbackBlocked: false,
    passwordFallbackReturnUrl: null,
    confirmationSubmissionKey: null,
    confirmationSubmittedAt: null,
    confirmationSubmittedCount: 0,
    passwordShortcutKey: null,
    passwordShortcutSubmittedAt: null,
    passwordShortcutSubmittedCount: 0,
  };
  const passwordState = {
    submissionKey: null as string | null,
    submittedAt: null as number | null,
    submittedCount: 0,
  };
  const providerState = {
    submissionKey: null as string | null,
    submittedAt: null as number | null,
    submittedCount: 0,
    challengeRecoveryKey: null as string | null,
  };
  const passkeyState: MicrosoftPasskeyState = {
    homeReturnAttempted: false,
    tavilyRelaunchCount: 0,
    lastNonPasskeyUrl: null,
  };
  const dialogHandler = async (dialog: any) => {
    const message = `${String(dialog?.message?.() || "")} ${String(dialog?.defaultValue?.() || "")}`.trim();
    if (/must provide prefix|break into debugger/i.test(message)) {
      log(`login flow: dismissed Microsoft proof dialog: ${message}`);
      await dialog.dismiss().catch(() => dialog.accept().catch(() => {}));
      return;
    }
    await dialog.dismiss().catch(() => {});
  };

  page.on("dialog", dialogHandler);
  const completionUrlPatterns = Array.isArray(options?.completionUrlPatterns) ? options.completionUrlPatterns : [];
  const passkeyRecoveryUrl = String(options?.passkeyRecoveryUrl || "").trim() || "https://app.tavily.com/home";
  const hasCompleted = (url: string): boolean => completionUrlPatterns.some((pattern) => pattern.test(url));

  try {
    const authProviderSurfacePattern = /auth\.tavily\.com\/u\/(?:login|signup)\/identifier/i;
    const socialSignupContinuationPattern = /auth\.tavily\.com\/u\/(?:signup\/identifier|signup\/password|email-identifier\/challenge)/i;
    let lastMicrosoftSurface = "";
    let lastFlowSurfaceUrl = "";
    let networkRecoveryCount = 0;
    let authorizeShellRecoveryKey: string | null = null;
    let authorizeShellRecoveryCount = 0;
    let visitedMicrosoftAccountSurface = false;
    const microsoftLoginDeadline = Date.now() + 120_000;
    for (let step = 1; Date.now() < microsoftLoginDeadline; step += 1) {
      const currentUrl = page.url();
      if (currentUrl && currentUrl !== lastFlowSurfaceUrl) {
        lastFlowSurfaceUrl = currentUrl;
        log(`login flow: main surface -> ${currentUrl}`);
      }
      const chromiumNetErrorCode = await detectChromiumNetErrorCode(page);
      if (chromiumNetErrorCode) {
        const canRecoverNetwork =
          networkRecoveryCount < 1 &&
          /ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET|ERR_ABORTED|ERR_TIMED_OUT/i.test(chromiumNetErrorCode) &&
          (/^chrome-error:\/\//i.test(currentUrl) || /login\.live\.com|account\.live\.com|login\.microsoft\.com/i.test(currentUrl));
        if (canRecoverNetwork) {
          networkRecoveryCount += 1;
          log(`login flow: recovering transient Microsoft network error ${chromiumNetErrorCode}`);
          await safeGoto(page, "https://app.tavily.com/home", 120_000).catch(() => {});
          await page.waitForTimeout(1_200);
          continue;
        }
        throw new Error(`chromium_net_error:${chromiumNetErrorCode}:url=${currentUrl}`);
      }
      if (/login\.live\.com|account\.live\.com|login\.microsoft\.com/i.test(currentUrl)) {
        visitedMicrosoftAccountSurface = true;
        const microsoftSurface = await collectMicrosoftSurfaceSnapshot(page);
        const interrupt = classifyMicrosoftFlowInterrupt(microsoftSurface);
        if (interrupt) {
          throw new Error(`${interrupt.code}:${interrupt.message}`);
        }
        if (isMicrosoftAuthorizeShellUnready(microsoftSurface)) {
          const surfaceKey = `${microsoftSurface.url}|${microsoftSurface.title}`;
          if (authorizeShellRecoveryKey !== surfaceKey) {
            authorizeShellRecoveryKey = surfaceKey;
            authorizeShellRecoveryCount = 0;
          }
          if (authorizeShellRecoveryCount < 2) {
            authorizeShellRecoveryCount += 1;
            log(
              `login flow: reloading blank Microsoft authorize shell (${authorizeShellRecoveryCount}/2) at ${microsoftSurface.url}`,
            );
            await page.reload({ waitUntil: "domcontentloaded", timeout: 60_000 }).catch(async () => {
              await safeGoto(page, microsoftSurface.url, 60_000).catch(() => {});
            });
            await page.waitForTimeout(1_500);
            continue;
          }
        } else {
          authorizeShellRecoveryKey = null;
          authorizeShellRecoveryCount = 0;
        }
      }
      if (!isMicrosoftPasskeyInterruptUrl(currentUrl)) {
        passkeyState.lastNonPasskeyUrl = currentUrl;
        if (!completionUrlPatterns.length && /app\.tavily\.com\/home/i.test(currentUrl) && !/auth\.tavily\.com/i.test(currentUrl)) {
          passkeyState.tavilyRelaunchCount = 0;
          passkeyState.homeReturnAttempted = false;
        }
      }
      if (!(await isMicrosoftLikelyPasswordSurface(page))) {
        passwordState.submissionKey = null;
        passwordState.submittedAt = null;
        passwordState.submittedCount = 0;
      }
      if (!authProviderSurfacePattern.test(currentUrl)) {
        providerState.submissionKey = null;
        providerState.submittedAt = null;
        providerState.submittedCount = 0;
        providerState.challengeRecoveryKey = null;
      }
      if (!completionUrlPatterns.length && /app\.tavily\.com\/home/i.test(currentUrl) && !/auth\.tavily\.com/i.test(currentUrl)) {
        return page;
      }
      if (hasCompleted(currentUrl)) {
        return page;
      }
      if (visitedMicrosoftAccountSurface && socialSignupContinuationPattern.test(currentUrl)) {
        log(`login flow: returned to Tavily social signup continuation ${currentUrl}`);
        return page;
      }

      if (authProviderSurfacePattern.test(currentUrl)) {
        const authSurfaceKey = buildAuthLoginSurfaceKey(currentUrl);
        const formErrors = await collectVisibleFormErrors(page).catch(() => []);
        const errorCodes = await collectVisibleErrorCodes(page).catch(() => []);
        const explicitRejection = detectExplicitFormRejection(formErrors, errorCodes);
        if (explicitRejection && explicitRejection !== "invalid_captcha" && explicitRejection !== "challenge_unresponsive") {
          throw new Error(`${explicitRejection}:${authSurfaceKey}`);
        }
        if (await hasAuthChallengeLoadErrorPage(page)) {
          log("login flow: auth security challenge warning present, ignored for Microsoft provider");
        }
        if (providerState.submissionKey === authSurfaceKey && providerState.submittedAt && providerState.submittedCount > 0) {
          if (Date.now() - providerState.submittedAt >= 8_000) {
            throw new Error(`microsoft_provider_submit_stalled:${authSurfaceKey}`);
          }
          await page.waitForTimeout(1_000);
          continue;
        }
        if (/\/u\/(?:login|signup)\/identifier/i.test(currentUrl)) {
          const providerReady = await waitForPassiveMicrosoftProviderReadiness(
            page,
            /\/u\/signup\/identifier/i.test(currentUrl) ? "signup" : "login",
            12_000,
          );
          if (providerReady === "wait") {
            providerState.challengeRecoveryKey = authSurfaceKey;
            await page.waitForTimeout(1_000);
            continue;
          }
          providerState.challengeRecoveryKey = null;
        }
        if (await clickMicrosoftProviderEntry(page)) {
          providerState.submissionKey = authSurfaceKey;
          providerState.submittedAt = Date.now();
          providerState.submittedCount += 1;
          providerState.challengeRecoveryKey = null;
          continue;
        }
      }

      if (await handleMicrosoftUsePasswordShortcut(page, proofState, password, passwordState)) {
        proofState.postEmailPasswordPriorityUntil = null;
        continue;
      }
      if (await handleMicrosoftPasswordPrompt(page, password, passwordState)) {
        proofState.postEmailPasswordPriorityUntil = null;
        continue;
      }
      if (
        proofState.postEmailPasswordPriorityUntil &&
        Date.now() < proofState.postEmailPasswordPriorityUntil
      ) {
        log(
          `login flow: waiting for password-priority grace window (${proofState.postEmailPasswordPriorityUntil - Date.now()}ms remaining)`,
        );
        await page.waitForLoadState("domcontentloaded", { timeout: 1_500 }).catch(() => {});
        await page.waitForTimeout(300);
        continue;
      }
      proofState.postEmailPasswordPriorityUntil = null;
      if (await handleMicrosoftAccountPicker(page, email)) continue;
      if (await handleMicrosoftProofAddPrompt(page, cfg, proxyUrl, proofState)) continue;
      if (await handleMicrosoftProofMethodPrompt(page, proofState)) continue;
      if (await handleMicrosoftProofVerifyPrompt(page, cfg, proxyUrl, proofState, password, passwordState)) continue;
      if (await handleMicrosoftProofAddPrompt(page, cfg, proxyUrl, proofState)) continue;
      if (await handleMicrosoftProofConfirmationEmailPrompt(page, cfg, proxyUrl, proofState, password, passwordState)) continue;
      if (await handleMicrosoftProofEmailPrompt(page, cfg, proxyUrl, proofState, password, passwordState)) continue;
      if (await handleMicrosoftProofCodePrompt(page, cfg, proxyUrl, proofState)) continue;
      if (await handleMicrosoftEmailPrompt(page, email, proofState)) continue;
      const passkeyResult = await handleMicrosoftPasskeyInterrupt(page, passkeyState, proofState, passkeyRecoveryUrl);
      if (passkeyResult) {
        if (passkeyResult !== true) {
          page = passkeyResult;
        }
        continue;
      }
      if (await handleMicrosoftKeepSignedInPrompt(page, cfg.microsoftKeepSignedIn)) continue;
      if (await handleMicrosoftConsentPrompt(page)) continue;

      if (/login\.live\.com|account\.live\.com/i.test(currentUrl) && step % 4 === 0) {
        const summary = await collectPageSurfaceSummary(page);
        if (summary !== lastMicrosoftSurface) {
          lastMicrosoftSurface = summary;
          log(`login flow: waiting on unhandled Microsoft surface (${step}/40): ${summary}`);
        }
      }

      await page.waitForTimeout(1_000);
    }
  } finally {
    page.off("dialog", dialogHandler);
  }

  const terminalChromiumNetErrorCode = await detectChromiumNetErrorCode(page);
  if (terminalChromiumNetErrorCode) {
    throw new Error(`chromium_net_error:${terminalChromiumNetErrorCode}:url=${page.url()}`);
  }
  throw new Error(`microsoft login flow did not reach home, last_url=${page.url()}`);
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

async function refreshCaptchaImage(page: any, previousSrc: string): Promise<boolean> {
  const point = await findClickablePointBySelector(page, 'img[alt="captcha"]');
  if (!point) return false;

  try {
    await dispatchMouseClickViaCdp(page, point.x, point.y);
  } catch {
    return false;
  }

  const deadline = Date.now() + 4200;
  while (Date.now() < deadline) {
    const current = await page
      .$eval('img[alt="captcha"]', (el: any) => String(el.src || ""))
      .catch(() => "");
    if (current && current !== previousSrc) {
      return true;
    }
    await page.waitForTimeout(220);
  }
  return false;
}

async function collectVisibleFormErrors(page: any): Promise<string[]> {
  return await page.evaluate(`(() => {
    const nodes = Array.from(
      document.querySelectorAll('.ulp-error-info,[data-error-code],#error-element-captcha,[role="alert"],.error,[class*="error"],.fui-Field__validationMessage,[id$="__validationMessage"],[data-testid*="validationMessage" i]'),
    );
    const values = [];
    for (const el of nodes) {
      const style = window.getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") continue;
      const text = (el.textContent || "").trim();
      if (text) values.push(text);
      if (values.length >= 10) break;
    }
    return values;
  })()`);
}

function isIgnorableErrorCode(code: string): boolean {
  return /^password-policy-/i.test(code);
}

async function collectVisibleErrorCodes(page: any): Promise<string[]> {
  return await page.evaluate(`(() => {
    const nodes = Array.from(document.querySelectorAll("[data-error-code]"));
    const seen = new Set();
    const values = [];
    for (const el of nodes) {
      const style = window.getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") continue;
      const code = (el.getAttribute("data-error-code") || "").trim();
      if (!/^[a-z0-9_-]{3,120}$/i.test(code)) continue;
      if (/^password-policy-/i.test(code)) continue;
      if (seen.has(code)) continue;
      seen.add(code);
      values.push(code);
      if (values.length >= 12) break;
    }
    return values;
  })()`);
}

async function collectPasswordStrengthSnapshot(page: any): Promise<PasswordStrengthSnapshot> {
  return await page.evaluate(() => {
    const input = document.querySelector('input[name="password"], input[type="password"]') as HTMLInputElement | null;
    const value = input?.value || "";
    const isVisible = (el: Element): el is HTMLElement => {
      if (!(el instanceof HTMLElement)) return false;
      const rect = el.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return false;
      const style = window.getComputedStyle(el);
      return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
    };
    const policyErrors = Array.from(
      document.querySelectorAll('[id*="password-too-weak"], .ulp-error-info, [data-error-code^="password-policy-"]'),
    )
      .filter(isVisible)
      .map((el) => (el.textContent || "").replace(/\s+/g, " ").trim())
      .filter(Boolean)
      .slice(0, 10);
    const normalized = policyErrors.join(" | ");
    return {
      len: value.length,
      lower: /[a-z]/.test(value),
      upper: /[A-Z]/.test(value),
      digit: /\d/.test(value),
      special: /[^A-Za-z0-9]/.test(value),
      tooWeak: /too weak/i.test(normalized),
      visiblePolicyErrors: policyErrors,
    };
  });
}

async function writePageArtifactsBestEffort(page: any, outputDir: URL, stem: string): Promise<void> {
  try {
    const html = await page.content();
    await writeFile(new URL(`${stem}.html`, outputDir), html, "utf8");
  } catch {
    // Navigation races during Auth0 transitions should not fail the task.
  }
  try {
    const snap = await page.screenshot({ fullPage: true });
    await writeFile(new URL(`${stem}.png`, outputDir), snap);
  } catch {
    // Best-effort diagnostics only.
  }
}

function detectExplicitFormRejection(formErrors: string[], errorCodes: string[]): string | null {
  if (errorCodes.some((code) => /ip-signup-blocked/i.test(code))) {
    return "risk_control_ip_rate_limit";
  }
  if (formErrors.some((text) => /Too many signups from the same IP/i.test(text))) {
    return "risk_control_ip_rate_limit";
  }
  if (errorCodes.some((code) => /custom-script-error-code_extensibility_error/i.test(code))) {
    return "auth0_extensibility_error";
  }
  if (
    errorCodes.some((code) => /suspicious/i.test(code)) ||
    formErrors.some((text) => /Suspicious activity detected/i.test(text))
  ) {
    return "risk_control_suspicious_activity";
  }
  if (errorCodes.some((code) => /invalid-captcha/i.test(code))) {
    return "invalid_captcha";
  }
  if (
    formErrors.some((text) =>
      /couldn[’']t load the security challenge|we couldn[’']t load the security challenge|security challenge/i.test(text),
    )
  ) {
    return "challenge_unresponsive";
  }
  return null;
}

async function collectPasswordStepSnapshot(page: any): Promise<PasswordStepSnapshot> {
  const payload = await page.evaluate(() => {
    const captchaContainer = document.querySelector("div[data-captcha-sitekey]");
    const form = document.querySelector('form[data-form-primary="true"], form');
    const formInputNames = form
      ? Array.from(form.querySelectorAll("input[name]"))
          .map((el) => (el.getAttribute("name") || "").trim())
          .filter((name) => name.length > 0)
          .slice(0, 20)
      : [];
    const sitekey = (captchaContainer?.getAttribute("data-captcha-sitekey") || "").trim();
    const bodyText = document.body?.innerText || "";
    return {
      url: window.location.href,
      hasCaptchaInput: !!document.querySelector('input[name="captcha"]'),
      hasCaptchaImage: !!document.querySelector('img[alt="captcha"]'),
      hasCaptchaContainer: !!captchaContainer,
      captchaProvider: (captchaContainer?.getAttribute("data-captcha-provider") || "").trim(),
      captchaSiteKeyHint:
        sitekey.length >= 10 ? `${sitekey.slice(0, 8)}...${sitekey.slice(-4)}` : sitekey || undefined,
      hasTurnstileResponseInput: !!document.querySelector('input[name="cf-turnstile-response"]'),
      hasRecaptchaResponseInput: !!document.querySelector('input[name="g-recaptcha-response"]'),
      hasHcaptchaResponseInput: !!document.querySelector('input[name="h-captcha-response"]'),
      challengeHint: /challenge|captcha|robot|verify/i.test(bodyText),
      formInputNames,
    };
  });

  const visibleErrors = await collectVisibleFormErrors(page).catch(() => []);
  return {
    collectedAt: new Date().toISOString(),
    url: typeof payload.url === "string" ? payload.url : page.url(),
    hasCaptchaInput: Boolean(payload.hasCaptchaInput),
    hasCaptchaImage: Boolean(payload.hasCaptchaImage),
    hasCaptchaContainer: Boolean(payload.hasCaptchaContainer),
    captchaProvider: typeof payload.captchaProvider === "string" && payload.captchaProvider ? payload.captchaProvider : undefined,
    captchaSiteKeyHint:
      typeof payload.captchaSiteKeyHint === "string" && payload.captchaSiteKeyHint ? payload.captchaSiteKeyHint : undefined,
    hasTurnstileResponseInput: Boolean(payload.hasTurnstileResponseInput),
    hasRecaptchaResponseInput: Boolean(payload.hasRecaptchaResponseInput),
    hasHcaptchaResponseInput: Boolean(payload.hasHcaptchaResponseInput),
    challengeHint: Boolean(payload.challengeHint),
    formInputNames: Array.isArray(payload.formInputNames)
      ? (payload.formInputNames as unknown[]).filter((item): item is string => typeof item === "string").slice(0, 20)
      : [],
    visibleErrors,
  };
}

async function collectAuthChallengeSnapshot(page: any): Promise<AuthChallengeSnapshot> {
  const payload = await page.evaluate(() => {
    const readRuntimeToken =
      typeof (globalThis as any).__kohaReadAuthChallengeToken === "function"
        ? String((globalThis as any).__kohaReadAuthChallengeToken() || "").trim()
        : "";
    const captchaContainer = document.querySelector("div[data-captcha-sitekey]");
    const sitekey = (captchaContainer?.getAttribute("data-captcha-sitekey") || "").trim();
    const captchaInput = document.querySelector('input[name="captcha"]') as HTMLInputElement | null;
    const turnstileInput = document.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null;
    const recaptchaInput = document.querySelector('input[name="g-recaptcha-response"]') as HTMLInputElement | null;
    const hcaptchaInput = document.querySelector('textarea[name="h-captcha-response"], input[name="h-captcha-response"]') as HTMLInputElement | null;
    const bodyText = document.body?.innerText || "";
    const hasChallengeFrame = !!document.querySelector(
      'iframe[src*="challenges.cloudflare.com"], iframe[title*="challenge" i], iframe[title*="turnstile" i]',
    );
    return {
      url: window.location.href,
      hasCaptchaInput: !!captchaInput,
      captchaValueLength: captchaInput?.value?.length || 0,
      turnstileValueLength: Math.max(turnstileInput?.value?.length || 0, readRuntimeToken.length),
      recaptchaValueLength: recaptchaInput?.value?.length || 0,
      hcaptchaValueLength: hcaptchaInput?.value?.length || 0,
      hasCaptchaImage: !!document.querySelector('img[alt="captcha"]'),
      hasCaptchaContainer: !!captchaContainer,
      hasChallengeFrame,
      hasTurnstileApi:
        typeof (window as Window & { turnstile?: { render?: unknown; execute?: unknown; reset?: unknown } }).turnstile
          ?.render === "function",
      captchaProvider: (captchaContainer?.getAttribute("data-captcha-provider") || "").trim(),
      captchaSiteKeyHint:
        sitekey.length >= 10 ? `${sitekey.slice(0, 8)}...${sitekey.slice(-4)}` : sitekey || undefined,
      challengeHint: /challenge|captcha|robot|verify/i.test(bodyText),
      challengeSuccessVisible: /\bsuccess!?\b/i.test(bodyText),
    };
  });

  const challengeFrame = (typeof page.frames === "function"
    ? page.frames().find((frame: any) => /challenges\.cloudflare\.com/i.test(String(frame?.url?.() || "")))
    : null) || null;
  const cdpSnapshot = await collectManagedChallengeCdpSnapshot(page).catch(() => null);
  const visibleErrors = await collectVisibleFormErrors(page).catch(() => []);
  const visibleErrorCodes = await collectVisibleErrorCodes(page).catch(() => []);
  return {
    collectedAt: new Date().toISOString(),
    url: typeof payload.url === "string" ? payload.url : page.url(),
    hasCaptchaInput: Boolean(payload.hasCaptchaInput),
    captchaValueLength:
      typeof payload.captchaValueLength === "number" && Number.isFinite(payload.captchaValueLength)
        ? Math.max(0, payload.captchaValueLength)
        : 0,
    turnstileValueLength:
      typeof payload.turnstileValueLength === "number" && Number.isFinite(payload.turnstileValueLength)
        ? Math.max(0, payload.turnstileValueLength)
        : 0,
    recaptchaValueLength:
      typeof payload.recaptchaValueLength === "number" && Number.isFinite(payload.recaptchaValueLength)
        ? Math.max(0, payload.recaptchaValueLength)
        : 0,
    hcaptchaValueLength:
      typeof payload.hcaptchaValueLength === "number" && Number.isFinite(payload.hcaptchaValueLength)
        ? Math.max(0, payload.hcaptchaValueLength)
        : 0,
    hasCaptchaImage: Boolean(payload.hasCaptchaImage),
    hasCaptchaContainer: Boolean(payload.hasCaptchaContainer),
    hasChallengeFrame: Boolean(payload.hasChallengeFrame || challengeFrame || cdpSnapshot?.frameUrl),
    hasTurnstileApi: Boolean(payload.hasTurnstileApi),
    hasChallengeCheckbox: Boolean(cdpSnapshot?.hasCheckbox),
    challengeCheckboxChecked:
      typeof cdpSnapshot?.checkboxChecked === "boolean" ? cdpSnapshot.checkboxChecked : undefined,
    challengeFrameUrl:
      typeof cdpSnapshot?.frameUrl === "string" && cdpSnapshot.frameUrl ? cdpSnapshot.frameUrl : undefined,
    captchaProvider: typeof payload.captchaProvider === "string" && payload.captchaProvider ? payload.captchaProvider : undefined,
    captchaSiteKeyHint:
      typeof payload.captchaSiteKeyHint === "string" && payload.captchaSiteKeyHint ? payload.captchaSiteKeyHint : undefined,
    challengeHint: Boolean(payload.challengeHint),
    challengeSuccessVisible: Boolean(payload.challengeSuccessVisible || cdpSnapshot?.successVisible),
    visibleErrors,
    visibleErrorCodes,
  };
}

function hasManagedAuthChallenge(snapshot: AuthChallengeSnapshot | null | undefined): boolean {
  if (!snapshot) return false;
  return (
    snapshot.hasCaptchaContainer ||
    snapshot.hasCaptchaInput ||
    snapshot.hasChallengeFrame ||
    snapshot.hasChallengeCheckbox ||
    snapshot.hasTurnstileApi ||
    snapshot.captchaProvider === "auth0_v2"
  );
}

function getChallengeTokenLength(snapshot: AuthChallengeSnapshot | null | undefined): number {
  if (!snapshot) return 0;
  return Math.max(
    snapshot.captchaValueLength || 0,
    snapshot.turnstileValueLength || 0,
    snapshot.recaptchaValueLength || 0,
    snapshot.hcaptchaValueLength || 0,
  );
}

function canSubmitManagedChallengeWithoutVisibleToken(snapshot: AuthChallengeSnapshot | null | undefined): boolean {
  if (!snapshot) return false;
  if (snapshot.challengeSuccessVisible) return true;
  if (getChallengeTokenLength(snapshot) > 0) {
    return isManagedChallengeStableForSubmit(snapshot);
  }
  if (snapshot.hasChallengeCheckbox) {
    return snapshot.challengeCheckboxChecked === true;
  }
  return false;
}

function canFallbackPassiveMicrosoftProviderSubmit(
  snapshot: AuthChallengeSnapshot | null | undefined,
  formKind: "signup" | "login",
): boolean {
  if (!snapshot || formKind !== "login") return false;
  if (snapshot.hasCaptchaInput || snapshot.hasCaptchaImage || snapshot.hasCaptchaContainer) return false;
  if (getChallengeTokenLength(snapshot) > 0 || snapshot.challengeSuccessVisible) return false;
  if ((snapshot.visibleErrors?.length || 0) > 0 || (snapshot.visibleErrorCodes?.length || 0) > 0) return false;
  if (snapshot.hasChallengeCheckbox || snapshot.hasTurnstileApi) return false;
  return snapshot.hasChallengeFrame && !snapshot.challengeHint;
}

function isManagedChallengeStableForSubmit(snapshot: AuthChallengeSnapshot | null | undefined): boolean {
  if (!snapshot) return false;
  if (snapshot.challengeSuccessVisible) return true;
  const tokenLength = getChallengeTokenLength(snapshot);
  if (tokenLength <= 0) {
    return snapshot.hasChallengeCheckbox ? snapshot.challengeCheckboxChecked === true : false;
  }
  if (!snapshot.hasChallengeFrame && !snapshot.hasChallengeCheckbox) {
    return true;
  }
  if (snapshot.hasChallengeCheckbox) {
    return snapshot.challengeCheckboxChecked === true;
  }
  return false;
}

async function waitForManagedChallengeStableToken(
  page: any,
  formKind: "signup" | "login",
  timeoutMs: number,
): Promise<AuthChallengeSnapshot | null> {
  const deadline = Date.now() + Math.max(1_500, timeoutMs);
  let latest: AuthChallengeSnapshot | null = null;
  while (Date.now() < deadline) {
    latest = await collectAuthChallengeSnapshot(page).catch(() => null);
    if (!latest) return latest;
    if (isManagedChallengeStableForSubmit(latest)) {
      return latest;
    }
    await page.waitForTimeout(300);
  }
  if (latest && getChallengeTokenLength(latest) > 0) {
    log(
      `${formKind} managed challenge token remained unstable (frame=${latest.hasChallengeFrame ? 1 : 0}, checkbox=${
        latest.hasChallengeCheckbox ? 1 : 0
      }, checked=${latest.challengeCheckboxChecked ? 1 : 0}, success=${latest.challengeSuccessVisible ? 1 : 0}, token=${getChallengeTokenLength(latest)})`,
    );
  }
  return latest;
}

function toChallengeBoxRect(content: number[] | undefined): ChallengeBoxRect | undefined {
  if (!Array.isArray(content) || content.length < 8) return undefined;
  const isFiniteNumber = (value: number | undefined): value is number => typeof value === "number" && Number.isFinite(value);
  const xs = [content[0], content[2], content[4], content[6]].filter(isFiniteNumber);
  const ys = [content[1], content[3], content[5], content[7]].filter(isFiniteNumber);
  if (xs.length !== 4 || ys.length !== 4) return undefined;
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  if (!Number.isFinite(minX) || !Number.isFinite(maxX) || !Number.isFinite(minY) || !Number.isFinite(maxY)) {
    return undefined;
  }
  return {
    x: minX,
    y: minY,
    width: Math.max(0, maxX - minX),
    height: Math.max(0, maxY - minY),
  };
}

async function createCdpSession(target: any): Promise<any | null> {
  try {
    const targetPage = typeof target?.page === "function" ? target.page() : target;
    const context = typeof targetPage?.context === "function" ? targetPage.context() : null;
    if (!context || typeof context.newCDPSession !== "function") return null;
    return await context.newCDPSession(target);
  } catch {
    return null;
  }
}

async function dispatchMouseClickViaCdp(page: any, x: number, y: number): Promise<void> {
  const pageCdp = await createCdpSession(page);
  if (!pageCdp) {
    throw new Error("cdp_session_unavailable");
  }
  const steps = 10;
  const startX = Math.max(0, x - randomInt(18, 42));
  const startY = Math.max(0, y - randomInt(6, 22));
  await pageCdp
    .send("Input.dispatchMouseEvent", {
      type: "mouseMoved",
      x: startX,
      y: startY,
      button: "none",
      buttons: 0,
    })
    .catch(() => {});
  for (let idx = 1; idx <= steps; idx += 1) {
    const progress = idx / steps;
    await pageCdp
      .send("Input.dispatchMouseEvent", {
        type: "mouseMoved",
        x: startX + (x - startX) * progress,
        y: startY + (y - startY) * progress,
        button: "none",
        buttons: 0,
      })
      .catch(() => {});
    await page.waitForTimeout(randomInt(12, 28));
  }
  await pageCdp
    .send("Input.dispatchMouseEvent", {
      type: "mousePressed",
      x,
      y,
      button: "left",
      buttons: 1,
      clickCount: 1,
    })
    .catch(() => {});
  await page.waitForTimeout(randomInt(70, 150));
  await pageCdp
    .send("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      x,
      y,
      button: "left",
      buttons: 0,
      clickCount: 1,
    })
    .catch(() => {});
}

async function dispatchEnterViaCdp(page: any): Promise<void> {
  const pageCdp = await createCdpSession(page);
  if (!pageCdp) {
    throw new Error("cdp_session_unavailable");
  }
  await pageCdp
    .send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key: "Enter",
      code: "Enter",
      windowsVirtualKeyCode: 13,
      nativeVirtualKeyCode: 13,
      text: "\r",
      unmodifiedText: "\r",
    })
    .catch(() => {});
  await page.waitForTimeout(randomInt(35, 90));
  await pageCdp
    .send("Input.dispatchKeyEvent", {
      type: "keyUp",
      key: "Enter",
      code: "Enter",
      windowsVirtualKeyCode: 13,
      nativeVirtualKeyCode: 13,
    })
    .catch(() => {});
}

async function dispatchEscapeViaCdp(page: any): Promise<void> {
  const pageCdp = await createCdpSession(page);
  if (!pageCdp) {
    throw new Error("cdp_session_unavailable");
  }
  await pageCdp
    .send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key: "Escape",
      code: "Escape",
      windowsVirtualKeyCode: 27,
      nativeVirtualKeyCode: 27,
    })
    .catch(() => {});
  await page.waitForTimeout(randomInt(35, 90));
  await pageCdp
    .send("Input.dispatchKeyEvent", {
      type: "keyUp",
      key: "Escape",
      code: "Escape",
      windowsVirtualKeyCode: 27,
      nativeVirtualKeyCode: 27,
    })
    .catch(() => {});
}

async function findClickablePointViaAxName(
  page: any,
  patterns: RegExp[],
  roles: string[] = ["button", "link"],
): Promise<{ x: number; y: number } | null> {
  const pageCdp = await createCdpSession(page);
  if (!pageCdp) return null;
  const axTree = await pageCdp.send("Accessibility.getFullAXTree").catch(() => null);
  const matchers = patterns;
  const roleSet = new Set(roles.map((role) => role.toLowerCase()));
  const matchNode =
    axTree?.nodes?.find((node: any) => {
      const role = String(node?.role?.value || "").toLowerCase();
      const name = String(node?.name?.value || "");
      if (!roleSet.has(role)) return false;
      return matchers.some((pattern) => pattern.test(name));
    }) || null;
  if (!matchNode?.backendDOMNodeId) return null;
  const box = await pageCdp
    .send("DOM.getBoxModel", { backendNodeId: matchNode.backendDOMNodeId })
    .catch(() => null);
  const rect = toChallengeBoxRect(box?.model?.content);
  if (!rect) return null;
  return {
    x: rect.x + rect.width / 2,
    y: rect.y + rect.height / 2,
  };
}

async function findClickablePointBySelector(page: any, selector: string): Promise<{ x: number; y: number } | null> {
  try {
    const point = await page.evaluate((rawSelector: string) => {
      const collectDeepMatches = (root: ParentNode, targetSelector: string): Element[] => {
        const matches = Array.from(root.querySelectorAll(targetSelector));
        const descendants = Array.from(root.querySelectorAll("*"));
        for (const el of descendants) {
          const shadowRoot = (el as HTMLElement & { shadowRoot?: ShadowRoot | null }).shadowRoot;
          if (shadowRoot) {
            matches.push(...collectDeepMatches(shadowRoot, targetSelector));
          }
        }
        return matches;
      };
      const isVisible = (el: Element): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        if (style.visibility === "hidden" || style.display === "none") return false;
        return true;
      };
      const target = collectDeepMatches(document, rawSelector).find(isVisible);
      if (!target) return null;
      const rect = target.getBoundingClientRect();
      return {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
      };
    }, selector);
    if (
      point &&
      typeof point.x === "number" &&
      Number.isFinite(point.x) &&
      typeof point.y === "number" &&
      Number.isFinite(point.y)
    ) {
      return point;
    }
  } catch {
    // ignore selector probe errors
  }
  return null;
}

async function findClickablePointByLinkText(page: any, pattern: RegExp): Promise<{ x: number; y: number } | null> {
  try {
    const point = await page.evaluate((source: string, flags: string) => {
      const matcher = new RegExp(source, flags);
      const collectDeepElements = (root: ParentNode, selector: string): Element[] => {
        const matches = Array.from(root.querySelectorAll(selector));
        const descendants = Array.from(root.querySelectorAll("*"));
        for (const el of descendants) {
          const shadowRoot = (el as HTMLElement & { shadowRoot?: ShadowRoot | null }).shadowRoot;
          if (shadowRoot) {
            matches.push(...collectDeepElements(shadowRoot, selector));
          }
        }
        return matches;
      };
      const isVisible = (el: Element): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        if (style.visibility === "hidden" || style.display === "none") return false;
        return true;
      };
      const target = collectDeepElements(document, "a").find(
        (el) => isVisible(el) && matcher.test(el.textContent || ""),
      ) as HTMLElement | undefined;
      if (!target) return null;
      const rect = target.getBoundingClientRect();
      return {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
      };
    }, pattern.source, pattern.flags);
    if (
      point &&
      typeof point.x === "number" &&
      Number.isFinite(point.x) &&
      typeof point.y === "number" &&
      Number.isFinite(point.y)
    ) {
      return point;
    }
  } catch {
    // ignore link probe errors
  }
  return null;
}

async function findClickablePointByActionText(
  page: any,
  patterns: RegExp[],
): Promise<{ x: number; y: number } | null> {
  try {
    const patternPayload = patterns.map((pattern) => ({ source: pattern.source, flags: pattern.flags }));
    const point = await page.evaluate((compiledPatterns: Array<{ source: string; flags: string }>) => {
      const matchers = compiledPatterns.map((item) => new RegExp(item.source, item.flags));
      const wantsSignupAction = compiledPatterns.some((item) => /sign\s*up|signup|create\s*account|register|get\s*started/i.test(item.source));
      const collectDeepElements = (root: ParentNode, selector: string): Element[] => {
        const matches = Array.from(root.querySelectorAll(selector));
        const descendants = Array.from(root.querySelectorAll("*"));
        for (const el of descendants) {
          const shadowRoot = (el as HTMLElement & { shadowRoot?: ShadowRoot | null }).shadowRoot;
          if (shadowRoot) {
            matches.push(...collectDeepElements(shadowRoot, selector));
          }
        }
        return matches;
      };
      const isVisible = (el: Element): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        if (style.visibility === "hidden" || style.display === "none") return false;
        return true;
      };
      const normalize = (value: string): string => value.replace(/\s+/g, " ").trim();
      const candidates = collectDeepElements(document, 'a, button, [role="button"], input[type="button"], input[type="submit"]')
        .filter(isVisible)
        .map((el) => {
          const text = normalize(
            [
              el.textContent || "",
              el.getAttribute("aria-label") || "",
              el.getAttribute("title") || "",
              el.getAttribute("value") || "",
              el.getAttribute("data-testid") || "",
              el.getAttribute("data-test") || "",
            ].join(" "),
          );
          const href = normalize(el.getAttribute("href") || "");
          return { el, text, href };
        });

      const scoreCandidate = (candidate: { text: string; href: string }) => {
        let score = -1;
        for (const matcher of matchers) {
          if (matcher.test(candidate.href)) score = Math.max(score, 100);
          if (matcher.test(candidate.text)) score = Math.max(score, 80);
        }
        if (wantsSignupAction && /signup|register/i.test(candidate.href)) score = Math.max(score, 95);
        if (wantsSignupAction && /sign up|create account|register|start for free|get started/i.test(candidate.text)) {
          score = Math.max(score, 70);
        }
        return score;
      };

      const winner = candidates
        .map((candidate) => ({ ...candidate, score: scoreCandidate(candidate) }))
        .filter((candidate) => candidate.score >= 0)
        .sort((left, right) => right.score - left.score)[0];
      if (!winner) return null;
      const rect = winner.el.getBoundingClientRect();
      return {
        x: rect.left + rect.width / 2,
        y: rect.top + rect.height / 2,
      };
    }, patternPayload);
    if (
      point &&
      typeof point.x === "number" &&
      Number.isFinite(point.x) &&
      typeof point.y === "number" &&
      Number.isFinite(point.y)
    ) {
      return point;
    }
  } catch {
    // ignore action probe errors
  }
  return null;
}

async function collectActionEntryHints(page: any): Promise<string[]> {
  try {
    const entries = await page.evaluate(() => {
      const collectDeepElements = (root: ParentNode, selector: string): Element[] => {
        const matches = Array.from(root.querySelectorAll(selector));
        const descendants = Array.from(root.querySelectorAll("*"));
        for (const el of descendants) {
          const shadowRoot = (el as HTMLElement & { shadowRoot?: ShadowRoot | null }).shadowRoot;
          if (shadowRoot) {
            matches.push(...collectDeepElements(shadowRoot, selector));
          }
        }
        return matches;
      };
      const isVisible = (el: Element): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        if (style.visibility === "hidden" || style.display === "none") return false;
        return true;
      };
      const normalize = (value: string): string => value.replace(/\s+/g, " ").trim();
      return collectDeepElements(document, 'a, button, [role="button"], input[type="button"], input[type="submit"]')
        .filter(isVisible)
        .map((el) => {
          const tag = el.tagName.toLowerCase();
          const text = normalize(
            [
              el.textContent || "",
              el.getAttribute("aria-label") || "",
              el.getAttribute("title") || "",
              el.getAttribute("value") || "",
            ].join(" "),
          ).slice(0, 120);
          const href = normalize(el.getAttribute("href") || "").slice(0, 160);
          return `${tag}|text=${text || "(empty)"}|href=${href || "(none)"}`;
        })
        .slice(0, 20);
    });
    return Array.isArray(entries) ? entries.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

async function collectManagedChallengeCdpSnapshot(page: any): Promise<ManagedChallengeCdpSnapshot | null> {
  const challengeFrame =
    typeof page.frames === "function"
      ? page.frames().find((frame: any) => /challenges\.cloudflare\.com/i.test(String(frame?.url?.() || "")))
      : null;
  if (!challengeFrame) {
    return {
      hasCheckbox: false,
    };
  }

  const pageCdp = await createCdpSession(page);
  const frameCdp = await createCdpSession(challengeFrame);
  if (!pageCdp || !frameCdp) {
    return {
      frameUrl: typeof challengeFrame.url === "function" ? challengeFrame.url() : undefined,
      hasCheckbox: false,
    };
  }

  const pageAx = await pageCdp.send("Accessibility.getFullAXTree").catch(() => null);
  const iframeNode =
    pageAx?.nodes?.find((node: any) => /Cloudflare security challenge/i.test(String(node?.name?.value || ""))) || null;
  const iframeBox = iframeNode?.backendDOMNodeId
    ? toChallengeBoxRect((await pageCdp.send("DOM.getBoxModel", { backendNodeId: iframeNode.backendDOMNodeId }).catch(() => null))?.model?.content)
    : undefined;

  const frameAx = await frameCdp.send("Accessibility.getFullAXTree").catch(() => null);
  const checkboxNode =
    frameAx?.nodes?.find(
      (node: any) => node?.role?.value === "checkbox" && /verify you are human/i.test(String(node?.name?.value || "")),
    ) || null;
  const refreshNode =
    frameAx?.nodes?.find((node: any) => node?.role?.value === "link" && /refresh/i.test(String(node?.name?.value || ""))) || null;
  const statusNode =
    frameAx?.nodes?.find((node: any) =>
      /verification expired|verify you are human|checking your browser/i.test(String(node?.name?.value || "")),
    ) || null;
  const successNode =
    frameAx?.nodes?.find((node: any) => /\bsuccess!?\b/i.test(String(node?.name?.value || ""))) || null;
  const checkboxBox = checkboxNode?.backendDOMNodeId
    ? toChallengeBoxRect((await frameCdp.send("DOM.getBoxModel", { backendNodeId: checkboxNode.backendDOMNodeId }).catch(() => null))?.model?.content)
    : undefined;
  const refreshBox = refreshNode?.backendDOMNodeId
    ? toChallengeBoxRect((await frameCdp.send("DOM.getBoxModel", { backendNodeId: refreshNode.backendDOMNodeId }).catch(() => null))?.model?.content)
    : undefined;
  const checkedValue = checkboxNode?.properties?.find?.((item: any) => item?.name === "checked")?.value?.value;

  return {
    frameUrl: typeof challengeFrame.url === "function" ? challengeFrame.url() : undefined,
    iframeBox,
    checkboxBox,
    refreshBox,
    checkboxChecked: checkedValue === "true" ? true : checkedValue === "false" ? false : undefined,
    hasCheckbox: Boolean(checkboxNode),
    statusText: typeof statusNode?.name?.value === "string" ? statusNode.name.value : undefined,
    successVisible: Boolean(successNode),
  };
}

async function waitForManagedChallengeReady(
  page: any,
  formKind: "signup" | "login",
  timeoutMs: number,
): Promise<AuthChallengeSnapshot | null> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  let latest: AuthChallengeSnapshot | null = null;
  while (Date.now() < deadline) {
    latest = await collectAuthChallengeSnapshot(page).catch(() => null);
    if (!latest || !hasManagedAuthChallenge(latest)) {
      return latest;
    }
    if (canSubmitManagedChallengeWithoutVisibleToken(latest)) {
      return latest;
    }
    await page.waitForTimeout(250);
  }
  if (latest && hasManagedAuthChallenge(latest)) {
    log(
      `${formKind} managed challenge still not ready (provider=${latest.captchaProvider || "unknown"}, input=${
        latest.hasCaptchaInput ? 1 : 0
      }, frame=${latest.hasChallengeFrame ? 1 : 0}, checkbox=${latest.hasChallengeCheckbox ? 1 : 0})`,
    );
  }
  return latest;
}

async function waitForManagedChallengeOutcome(
  page: any,
  formKind: "signup" | "login",
  successUrlPattern: RegExp,
  timeoutMs: number,
): Promise<{ status: "success" | "token_ready" | "timeout" | "rejected"; snapshot: AuthChallengeSnapshot | null; rejection?: string }> {
  const deadline = Date.now() + Math.max(1_500, timeoutMs);
  let latest: AuthChallengeSnapshot | null = null;
  while (Date.now() < deadline) {
    if (successUrlPattern.test(page.url())) {
      return { status: "success", snapshot: latest };
    }
    latest = await collectAuthChallengeSnapshot(page).catch(() => null);
    const rejection = latest ? detectExplicitFormRejection(latest.visibleErrors, latest.visibleErrorCodes) : null;
    if (rejection) {
      return { status: "rejected", snapshot: latest, rejection };
    }
    const tokenLength = getChallengeTokenLength(latest);
    if (tokenLength > 0) {
      log(
        `${formKind} managed challenge token ready (captcha=${latest?.captchaValueLength || 0}, turnstile=${
          latest?.turnstileValueLength || 0
        }, recaptcha=${latest?.recaptchaValueLength || 0}, hcaptcha=${latest?.hcaptchaValueLength || 0})`,
      );
      return { status: "token_ready", snapshot: latest };
    }
    await page.waitForTimeout(400);
  }
  return { status: "timeout", snapshot: latest };
}

async function waitForManagedChallengeToken(
  page: any,
  formKind: "signup" | "login",
  timeoutMs: number,
): Promise<{ status: "token_ready" | "timeout" | "rejected"; snapshot: AuthChallengeSnapshot | null; rejection?: string }> {
  const deadline = Date.now() + Math.max(1_500, timeoutMs);
  let latest: AuthChallengeSnapshot | null = null;
  while (Date.now() < deadline) {
    latest = await collectAuthChallengeSnapshot(page).catch(() => null);
    const rejection = latest ? detectExplicitFormRejection(latest.visibleErrors, latest.visibleErrorCodes) : null;
    if (rejection) {
      return { status: "rejected", snapshot: latest, rejection };
    }
    const tokenLength = getChallengeTokenLength(latest);
    if (tokenLength > 0) {
      log(
        `${formKind} managed challenge token ready before submit (captcha=${latest?.captchaValueLength || 0}, turnstile=${
          latest?.turnstileValueLength || 0
        }, recaptcha=${latest?.recaptchaValueLength || 0}, hcaptcha=${latest?.hcaptchaValueLength || 0})`,
      );
      return { status: "token_ready", snapshot: latest };
    }
    await page.waitForTimeout(400);
  }
  return { status: "timeout", snapshot: latest };
}

async function waitForAuthCaptchaValue(
  page: any,
  timeoutMs: number,
): Promise<{ value: string; length: number } | null> {
  const deadline = Date.now() + Math.max(1_000, timeoutMs);
  while (Date.now() < deadline) {
    const value = await page
      .evaluate(() => {
        const pickValue = (selector: string): string => {
          const field = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null;
          return typeof field?.value === "string" ? field.value.trim() : "";
        };
        const readRuntimeToken =
          typeof (globalThis as any).__kohaReadAuthChallengeToken === "function"
            ? String((globalThis as any).__kohaReadAuthChallengeToken() || "").trim()
            : "";
        const captchaField = document.querySelector('input[name="captcha"]') as HTMLInputElement | null;
        const directCaptcha = pickValue('input[name="captcha"]');
        if (directCaptcha) return directCaptcha;
        const fallbackToken =
          pickValue('input[name="cf-turnstile-response"]') ||
          pickValue('input[name="g-recaptcha-response"]') ||
          pickValue('textarea[name="h-captcha-response"]') ||
          pickValue('input[name="h-captcha-response"]') ||
          readRuntimeToken ||
          String((globalThis as any).__kohaLastChallengeToken || "").trim();
        if (captchaField && fallbackToken) {
          captchaField.value = fallbackToken;
          captchaField.dispatchEvent(new Event("input", { bubbles: true }));
          captchaField.dispatchEvent(new Event("change", { bubbles: true }));
          (globalThis as any).__kohaLastAuthCaptcha = fallbackToken;
          return fallbackToken;
        }
        return fallbackToken;
      })
      .catch(() => "");
    const trimmed = typeof value === "string" ? value.trim() : "";
    if (trimmed) {
      return { value: trimmed, length: trimmed.length };
    }
    await page.waitForTimeout(250);
  }
  return null;
}

async function waitForManagedChallengeDismissal(
  page: any,
  formKind: "signup" | "login",
  timeoutMs: number,
): Promise<AuthChallengeSnapshot | null> {
  const deadline = Date.now() + Math.max(1_500, timeoutMs);
  let latest: AuthChallengeSnapshot | null = null;
  while (Date.now() < deadline) {
    latest = await collectAuthChallengeSnapshot(page).catch(() => null);
    if (!latest) return latest;
    if (!latest.hasChallengeFrame && !latest.hasChallengeCheckbox) {
      return latest;
    }
    await page.waitForTimeout(300);
  }
  if (latest) {
    log(
      `${formKind} managed challenge still visible after token (frame=${latest.hasChallengeFrame ? 1 : 0}, checkbox=${
        latest.hasChallengeCheckbox ? 1 : 0
      }, token=${getChallengeTokenLength(latest)})`,
    );
  }
  return latest;
}

async function tryActivateManagedChallenge(page: any, formKind: "signup" | "login"): Promise<boolean> {
  const challengeFrame =
    typeof page.frames === "function"
      ? page.frames().find((frame: any) => /challenges\.cloudflare\.com/i.test(String(frame?.url?.() || "")))
      : null;
  if (challengeFrame) {
    const frameSelectors = [
      '[role="checkbox"]',
      'input[type="checkbox"]',
      'label.ctp-checkbox-label',
      'label',
      'body',
    ];
    for (const selector of frameSelectors) {
      try {
        const locator = challengeFrame.locator(selector).first();
        if ((await locator.count()) === 0) continue;
        await locator.click({ timeout: 2_000, force: true });
        await page.waitForTimeout(randomInt(400, 900));
        const afterFrameClick = await collectManagedChallengeCdpSnapshot(page).catch(() => null);
        if (afterFrameClick?.checkboxChecked === true) {
          log(`${formKind} managed challenge checkbox checked via frame locator (${selector})`);
          return true;
        }
      } catch {
        // fall through to the next interaction strategy
      }
    }
  }

  let cdpSnapshot = await collectManagedChallengeCdpSnapshot(page).catch(() => null);
  if (cdpSnapshot?.iframeBox && cdpSnapshot?.checkboxBox) {
    const clickAt = async (x: number, y: number): Promise<void> => {
      await dispatchMouseClickViaCdp(page, x, y);
    };

    if (cdpSnapshot.refreshBox && cdpSnapshot.statusText && /verification expired/i.test(cdpSnapshot.statusText)) {
      const refreshX = cdpSnapshot.iframeBox.x + cdpSnapshot.refreshBox.x + cdpSnapshot.refreshBox.width / 2;
      const refreshY = cdpSnapshot.iframeBox.y + cdpSnapshot.refreshBox.y + cdpSnapshot.refreshBox.height / 2;
      if (Number.isFinite(refreshX) && Number.isFinite(refreshY)) {
        await clickAt(refreshX, refreshY);
        log(`${formKind} managed challenge refreshed via cdp`);
        await page.waitForTimeout(randomInt(1_000, 1_800));
        cdpSnapshot = await collectManagedChallengeCdpSnapshot(page).catch(() => cdpSnapshot);
      }
    }

    if (!cdpSnapshot?.iframeBox || !cdpSnapshot?.checkboxBox) {
      return false;
    }
    const offsetCenterX = cdpSnapshot.iframeBox.x + cdpSnapshot.checkboxBox.x + cdpSnapshot.checkboxBox.width / 2;
    const offsetCenterY = cdpSnapshot.iframeBox.y + cdpSnapshot.checkboxBox.y + cdpSnapshot.checkboxBox.height / 2;
    if (Number.isFinite(offsetCenterX) && Number.isFinite(offsetCenterY)) {
      await clickAt(offsetCenterX, offsetCenterY);
      await page.waitForTimeout(randomInt(400, 900));
      const afterClickSnapshot = await collectManagedChallengeCdpSnapshot(page).catch(() => null);
      if (afterClickSnapshot?.checkboxChecked === true) {
        log(`${formKind} managed challenge checkbox checked via cdp`);
        return true;
      }
      if (afterClickSnapshot?.hasCheckbox) {
        const directCenterX = cdpSnapshot.checkboxBox.x + cdpSnapshot.checkboxBox.width / 2;
        const directCenterY = cdpSnapshot.checkboxBox.y + cdpSnapshot.checkboxBox.height / 2;
        if (Number.isFinite(directCenterX) && Number.isFinite(directCenterY)) {
          await clickAt(directCenterX, directCenterY);
          await page.waitForTimeout(randomInt(400, 900));
          const afterDirectClickSnapshot = await collectManagedChallengeCdpSnapshot(page).catch(() => null);
          if (afterDirectClickSnapshot?.checkboxChecked === true) {
            log(`${formKind} managed challenge checkbox checked via cdp direct-box click`);
            return true;
          }
        }
      }
      log(
        `${formKind} managed challenge checkbox activated via cdp (checkbox=${
          afterClickSnapshot?.hasCheckbox ? 1 : 0
        }, checked=${Boolean(afterClickSnapshot?.checkboxChecked) ? 1 : 0})`,
      );
      return true;
    }
  }
  return false;
}

async function ensureManagedChallengeTokenBeforeSubmit(
  page: any,
  formKind: "signup" | "login",
): Promise<{ status: "token_ready" | "timeout" | "rejected"; snapshot: AuthChallengeSnapshot | null; rejection?: string }> {
  let latest = await waitForManagedChallengeReady(page, formKind, 12_000);
  let lastOutcome = await waitForManagedChallengeToken(page, formKind, 8_000);
  if (lastOutcome.status === "rejected") {
    return lastOutcome;
  }
  if (lastOutcome.status === "token_ready") {
    const stableSnapshot = await waitForManagedChallengeStableToken(page, formKind, 8_000);
    if (isManagedChallengeStableForSubmit(stableSnapshot)) {
      return { status: "token_ready", snapshot: stableSnapshot };
    }
    lastOutcome = { status: "timeout", snapshot: stableSnapshot };
  }

  if (lastOutcome.status === "token_ready") {
    return lastOutcome;
  }

  for (let activationRound = 1; activationRound <= 3; activationRound += 1) {
    const snapshot = lastOutcome.snapshot || latest;
    const canInteract = Boolean(
      snapshot?.hasChallengeCheckbox ||
        snapshot?.hasChallengeFrame ||
        snapshot?.hasTurnstileApi ||
        snapshot?.hasCaptchaContainer,
    );
    if (!canInteract) {
      return lastOutcome;
    }
    const interacted = await tryActivateManagedChallenge(page, formKind);
    if (!interacted) {
      await page.waitForTimeout(800);
    }
    lastOutcome = await waitForManagedChallengeToken(page, formKind, activationRound === 1 ? 20_000 : 12_000);
    if (lastOutcome.status === "rejected") {
      return lastOutcome;
    }
    if (lastOutcome.status === "token_ready") {
      const stableSnapshot = await waitForManagedChallengeStableToken(page, formKind, 8_000);
      if (isManagedChallengeStableForSubmit(stableSnapshot)) {
        return { status: "token_ready", snapshot: stableSnapshot };
      }
      latest = stableSnapshot || latest;
      lastOutcome = { status: "timeout", snapshot: stableSnapshot };
    }
    latest = lastOutcome.snapshot || latest;
    log(
      `${formKind} managed challenge token still unavailable after activation round ${activationRound} (frame=${
        snapshot?.hasChallengeFrame ? 1 : 0
      }, checkbox=${snapshot?.hasChallengeCheckbox ? 1 : 0}, captcha=${lastOutcome.snapshot?.captchaValueLength || 0}, turnstile=${
        lastOutcome.snapshot?.turnstileValueLength || 0
      })`,
    );
  }

  return lastOutcome;
}

async function collectBrowserFingerprintSnapshot(page: any): Promise<BrowserFingerprintSnapshot> {
  const payload = await page.evaluate(async () => {
    const nav = navigator as Navigator & { webdriver?: boolean; deviceMemory?: number };
    let permissionNotificationViaQuery: string | undefined;
    try {
      if (nav.permissions && typeof nav.permissions.query === "function") {
        const status = await nav.permissions.query({ name: "notifications" as PermissionName });
        permissionNotificationViaQuery = status.state;
      }
    } catch {
      permissionNotificationViaQuery = undefined;
    }
    return {
      url: window.location.href,
      navigatorUserAgent: nav.userAgent,
      navigatorPlatform: nav.platform,
      navigatorLanguage: nav.language,
      navigatorLanguages: Array.isArray(nav.languages) ? nav.languages : [],
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      webdriver: typeof nav.webdriver === "boolean" ? nav.webdriver : undefined,
      hardwareConcurrency: Number.isFinite(nav.hardwareConcurrency) ? nav.hardwareConcurrency : undefined,
      deviceMemory: typeof nav.deviceMemory === "number" ? nav.deviceMemory : undefined,
      pluginsLength: typeof nav.plugins?.length === "number" ? nav.plugins.length : undefined,
      permissionNotification:
        typeof window !== "undefined" && "Notification" in window ? Notification.permission : undefined,
      permissionNotificationViaQuery,
    };
  });

  return {
    collectedAt: new Date().toISOString(),
    url: typeof payload.url === "string" ? payload.url : page.url(),
    navigatorUserAgent: typeof payload.navigatorUserAgent === "string" ? payload.navigatorUserAgent : undefined,
    navigatorPlatform: typeof payload.navigatorPlatform === "string" ? payload.navigatorPlatform : undefined,
    navigatorLanguage: typeof payload.navigatorLanguage === "string" ? payload.navigatorLanguage : undefined,
    navigatorLanguages: Array.isArray(payload.navigatorLanguages)
      ? (payload.navigatorLanguages as unknown[]).filter((item): item is string => typeof item === "string").slice(0, 10)
      : undefined,
    timezone: typeof payload.timezone === "string" ? payload.timezone : undefined,
    webdriver: typeof payload.webdriver === "boolean" ? payload.webdriver : undefined,
    hardwareConcurrency:
      typeof payload.hardwareConcurrency === "number" && Number.isFinite(payload.hardwareConcurrency)
        ? payload.hardwareConcurrency
        : undefined,
    deviceMemory:
      typeof payload.deviceMemory === "number" && Number.isFinite(payload.deviceMemory) ? payload.deviceMemory : undefined,
    pluginsLength:
      typeof payload.pluginsLength === "number" && Number.isFinite(payload.pluginsLength) ? payload.pluginsLength : undefined,
    permissionNotification:
      typeof payload.permissionNotification === "string" ? payload.permissionNotification : undefined,
    permissionNotificationViaQuery:
      typeof payload.permissionNotificationViaQuery === "string" ? payload.permissionNotificationViaQuery : undefined,
  };
}

async function waitForAuthFormPostResponse(page: any, pattern: RegExp, timeoutMs: number): Promise<boolean> {
  try {
    await page.waitForResponse(
      (resp: any) => {
        try {
          const url = String(resp.url?.() || "");
          const req = typeof resp.request === "function" ? resp.request() : null;
          const method = String(req?.method?.() || "GET").toUpperCase();
          return method === "POST" && pattern.test(url);
        } catch {
          return false;
        }
      },
      { timeout: timeoutMs },
    );
    return true;
  } catch {
    return false;
  }
}

async function waitForAuthSubmitSignal(
  page: any,
  pattern: RegExp,
  timeoutMs: number,
  previousUrl?: string,
): Promise<"post" | "navigation" | "none"> {
  const baselineUrl = previousUrl || page.url();
  try {
    return await Promise.race([
      (async () => {
        const posted = await waitForAuthFormPostResponse(page, pattern, timeoutMs);
        return posted ? "post" : "none";
      })(),
      (async () => {
        try {
          await page.waitForURL((url: URL) => url.toString() !== baselineUrl, { timeout: timeoutMs });
          return "navigation" as const;
        } catch {
          return "none" as const;
        }
      })(),
    ]);
  } catch {
    return "none";
  }
}

async function requestSubmitVisibleAuthForm(page: any): Promise<string | null> {
  try {
    return await page.evaluate(() => {
      const isVisible = (el: Element | null): el is HTMLElement => {
        if (!(el instanceof HTMLElement)) return false;
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) return false;
        const style = window.getComputedStyle(el);
        return style.display !== "none" && style.visibility !== "hidden";
      };
      const submitter =
        Array.from(
          document.querySelectorAll(
            'button[data-action-button-primary="true"], button[type="submit"], input[type="submit"], button[name="action"]',
          ),
        ).find(isVisible) || null;
      const form =
        (submitter instanceof HTMLElement ? submitter.closest("form") : null) ||
        Array.from(document.querySelectorAll("form")).find(isVisible) ||
        null;
      if (!(form instanceof HTMLFormElement)) return null;
      if (typeof form.requestSubmit === "function") {
        if (submitter instanceof HTMLElement) {
          form.requestSubmit(submitter as HTMLButtonElement);
          return "form.requestSubmit(submitter)";
        }
        form.requestSubmit();
        return "form.requestSubmit()";
      }
      if (submitter instanceof HTMLElement && typeof submitter.click === "function") {
        submitter.click();
        return "submitter.click()";
      }
      form.submit();
      return "form.submit()";
    });
  } catch {
    return null;
  }
}

async function forceNativeSubmitAuthForm(page: any): Promise<boolean> {
  try {
    return await page.evaluate(() => {
      const form =
        (document.querySelector('form[data-form-primary="true"]') as HTMLFormElement | null) ||
        (document.querySelector("form") as HTMLFormElement | null);
      if (!(form instanceof HTMLFormElement)) return false;
      form.submit();
      return true;
    });
  } catch {
    return false;
  }
}

async function syncAuthFormHiddenFields(page: any): Promise<string[]> {
  try {
    return await page.evaluate(() => {
      const touched: string[] = [];
      const globalState = window as Window & {
        __kohaLastAuthCaptcha?: string;
        __kohaLastChallengeToken?: string;
        __kohaLastAuthEmail?: string;
        __kohaLastAuthPassword?: string;
        __kohaLastEmailCode?: string;
        __kohaAuthFormPatched?: boolean;
        __kohaReadAuthChallengeToken?: () => string;
      };
      const captchaField = document.querySelector('input[name="captcha"]') as HTMLInputElement | null;
      const turnstileField = document.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null;
      const recaptchaField = document.querySelector('input[name="g-recaptcha-response"]') as HTMLInputElement | null;
      const hcaptchaField = document.querySelector(
        'textarea[name="h-captcha-response"], input[name="h-captcha-response"]',
      ) as HTMLInputElement | HTMLTextAreaElement | null;
      const emailField = document.querySelector('input[name="email"], input[type="email"]') as HTMLInputElement | null;
      const passwordField = document.querySelector('input[name="password"], input[type="password"]') as HTMLInputElement | null;
      const codeField = document.querySelector('input[name="code"]') as HTMLInputElement | null;
      const form =
        (document.querySelector('form[data-form-primary="true"]') as HTMLFormElement | null) ||
        (document.querySelector("form") as HTMLFormElement | null);

      const captchaValue = typeof captchaField?.value === "string" ? captchaField.value.trim() : "";
      const challengeToken =
        (typeof turnstileField?.value === "string" ? turnstileField.value.trim() : "") ||
        (typeof recaptchaField?.value === "string" ? recaptchaField.value.trim() : "") ||
        (typeof hcaptchaField?.value === "string" ? hcaptchaField.value.trim() : "") ||
        (typeof globalState.__kohaReadAuthChallengeToken === "function"
          ? String(globalState.__kohaReadAuthChallengeToken() || "").trim()
          : "");
      if (captchaValue) {
        globalState.__kohaLastAuthCaptcha = captchaValue;
      }
      if (challengeToken) {
        globalState.__kohaLastChallengeToken = challengeToken;
      }
      const restoredCaptcha = globalState.__kohaLastAuthCaptcha || globalState.__kohaLastChallengeToken;
      if (!captchaValue && captchaField && restoredCaptcha) {
        captchaField.value = restoredCaptcha;
        touched.push("captcha:restore");
        globalState.__kohaLastAuthCaptcha = restoredCaptcha;
      }

      const emailValue = typeof emailField?.value === "string" ? emailField.value.trim() : "";
      if (emailValue) {
        globalState.__kohaLastAuthEmail = emailValue;
      } else if (emailField && globalState.__kohaLastAuthEmail) {
        emailField.value = globalState.__kohaLastAuthEmail;
        touched.push("email:restore");
      }

      const passwordValue = typeof passwordField?.value === "string" ? passwordField.value : "";
      if (passwordValue) {
        globalState.__kohaLastAuthPassword = passwordValue;
      } else if (passwordField && globalState.__kohaLastAuthPassword) {
        passwordField.value = globalState.__kohaLastAuthPassword;
        touched.push("password:restore");
      }

      const codeValue = typeof codeField?.value === "string" ? codeField.value.trim() : "";
      if (codeValue) {
        globalState.__kohaLastEmailCode = codeValue;
      } else if (codeField && globalState.__kohaLastEmailCode) {
        codeField.value = globalState.__kohaLastEmailCode;
        touched.push("code:restore");
      }

      for (const field of [captchaField, emailField, passwordField, codeField]) {
        if (!field) continue;
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      }

      if (form && !globalState.__kohaAuthFormPatched) {
        const nativeSubmit = HTMLFormElement.prototype.submit;
        const nativeRequestSubmit = HTMLFormElement.prototype.requestSubmit;
        const syncBeforeSubmit = (targetForm: HTMLFormElement) => {
          const targetCaptcha = targetForm.querySelector('input[name="captcha"]') as HTMLInputElement | null;
          const targetTurnstile = targetForm.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null;
          const targetRecaptcha = targetForm.querySelector('input[name="g-recaptcha-response"]') as HTMLInputElement | null;
          const targetHcaptcha = targetForm.querySelector(
            'textarea[name="h-captcha-response"], input[name="h-captcha-response"]',
          ) as HTMLInputElement | HTMLTextAreaElement | null;
          const targetEmail = targetForm.querySelector('input[name="email"], input[type="email"]') as HTMLInputElement | null;
          const targetPassword = targetForm.querySelector('input[name="password"], input[type="password"]') as HTMLInputElement | null;
          const targetCode = targetForm.querySelector('input[name="code"]') as HTMLInputElement | null;
          const currentChallengeToken =
            (typeof targetTurnstile?.value === "string" ? targetTurnstile.value.trim() : "") ||
            (typeof targetRecaptcha?.value === "string" ? targetRecaptcha.value.trim() : "") ||
            (typeof targetHcaptcha?.value === "string" ? targetHcaptcha.value.trim() : "") ||
            globalState.__kohaLastChallengeToken ||
            globalState.__kohaLastAuthCaptcha ||
            "";
          if (currentChallengeToken) {
            globalState.__kohaLastChallengeToken = currentChallengeToken;
          }
          if (targetCaptcha && !targetCaptcha.value && currentChallengeToken) {
            targetCaptcha.value = currentChallengeToken;
            targetCaptcha.dispatchEvent(new Event("input", { bubbles: true }));
            targetCaptcha.dispatchEvent(new Event("change", { bubbles: true }));
            globalState.__kohaLastAuthCaptcha = currentChallengeToken;
          }
          if (targetEmail && !targetEmail.value && globalState.__kohaLastAuthEmail) {
            targetEmail.value = globalState.__kohaLastAuthEmail;
            targetEmail.dispatchEvent(new Event("input", { bubbles: true }));
            targetEmail.dispatchEvent(new Event("change", { bubbles: true }));
          }
          if (targetPassword && !targetPassword.value && globalState.__kohaLastAuthPassword) {
            targetPassword.value = globalState.__kohaLastAuthPassword;
            targetPassword.dispatchEvent(new Event("input", { bubbles: true }));
            targetPassword.dispatchEvent(new Event("change", { bubbles: true }));
          }
          if (targetCode && !targetCode.value && globalState.__kohaLastEmailCode) {
            targetCode.value = globalState.__kohaLastEmailCode;
            targetCode.dispatchEvent(new Event("input", { bubbles: true }));
            targetCode.dispatchEvent(new Event("change", { bubbles: true }));
          }
        };
        HTMLFormElement.prototype.submit = function patchedSubmit(this: HTMLFormElement) {
          syncBeforeSubmit(this);
          return nativeSubmit.call(this);
        };
        HTMLFormElement.prototype.requestSubmit = function patchedRequestSubmit(
          this: HTMLFormElement,
          submitter?: HTMLElement,
        ) {
          syncBeforeSubmit(this);
          return nativeRequestSubmit.call(this, submitter as HTMLElement | undefined);
        };
        globalState.__kohaAuthFormPatched = true;
        touched.push("form:patched");
      }

      return touched;
    });
  } catch {
    return [];
  }
}

async function collectAuthSubmitFields(
  page: any,
): Promise<{ captcha?: string; challengeToken?: string; email?: string; password?: string; code?: string; state?: string }> {
  try {
    const pickLocatorValue = async (selector: string): Promise<string | undefined> => {
      const locator = page.locator(selector).first();
      if ((await locator.count().catch(() => 0)) === 0) return undefined;
      const value = (await locator.inputValue().catch(() => "")).trim();
      return value || undefined;
    };
    const email =
      (await pickLocatorValue('input[name="email"]')) ||
      (await pickLocatorValue('input[type="email"]')) ||
      (await page.evaluate(() => (globalThis as any).__kohaLastAuthEmail || undefined).catch(() => undefined));
    const challengeToken =
      (await pickLocatorValue('input[name="cf-turnstile-response"]')) ||
      (await pickLocatorValue('input[name="g-recaptcha-response"]')) ||
      (await pickLocatorValue('textarea[name="h-captcha-response"]')) ||
      (await pickLocatorValue('input[name="h-captcha-response"]')) ||
      (await page
        .evaluate(() => {
          const reader = (globalThis as any).__kohaReadAuthChallengeToken;
          return typeof reader === "function" ? reader() || undefined : undefined;
        })
        .catch(() => undefined)) ||
      (await page.evaluate(() => (globalThis as any).__kohaLastChallengeToken || undefined).catch(() => undefined));
    const captcha =
      (await pickLocatorValue('input[name="captcha"]')) ||
      challengeToken ||
      (await page.evaluate(() => (globalThis as any).__kohaLastAuthCaptcha || undefined).catch(() => undefined));
    const password =
      (await pickLocatorValue('input[name="password"]')) ||
      (await pickLocatorValue('input[type="password"]')) ||
      (await page.evaluate(() => (globalThis as any).__kohaLastAuthPassword || undefined).catch(() => undefined));
    const code =
      (await pickLocatorValue('input[name="code"]')) ||
      (await page.evaluate(() => (globalThis as any).__kohaLastEmailCode || undefined).catch(() => undefined));
    const state = await pickLocatorValue('input[name="state"]');
    return { captcha, challengeToken, email, password, code, state };
  } catch {
    return {};
  }
}

async function dispatchChallengeResponseEvents(page: any): Promise<string[]> {
  try {
    return await page.evaluate(() => {
      const touched: string[] = [];
      const candidates = [
        'input[name="captcha"]',
        'input[name="cf-turnstile-response"]',
        'input[name="g-recaptcha-response"]',
        'textarea[name="h-captcha-response"]',
        'input[name="h-captcha-response"]',
      ];
      for (const selector of candidates) {
        const field = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null;
        const value = typeof field?.value === "string" ? field.value.trim() : "";
        if (!field || value.length === 0) continue;
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
        touched.push(selector);
      }
      return touched;
    });
  } catch {
    return [];
  }
}

async function submitAuthForm(page: any, postPattern: RegExp, logLabel: string): Promise<boolean> {
  const baselineUrl = page.url();
  const syncedHiddenFields = await syncAuthFormHiddenFields(page);
  if (syncedHiddenFields.length > 0) {
    log(`${logLabel} synced auth fields: ${syncedHiddenFields.join(", ")}`);
  }
  const touchedChallengeFields = await dispatchChallengeResponseEvents(page);
  if (touchedChallengeFields.length > 0) {
    log(`${logLabel} refreshed challenge fields via events: ${touchedChallengeFields.join(", ")}`);
    await page.waitForTimeout(randomInt(120, 260));
  }
  try {
    const visibleSubmitter = page
      .locator(
        'button[data-action-button-primary="true"], button[type="submit"]:not(.ulp-hidden-form-submit-button), input[type="submit"]',
      )
      .first();
    if ((await visibleSubmitter.count()) > 0) {
      await visibleSubmitter.click({ timeout: 2_000, force: true });
      const submitSignal = await waitForAuthSubmitSignal(page, postPattern, 3_500, baselineUrl);
      if (submitSignal !== "none") {
        if (submitSignal === "navigation") {
          log(`${logLabel} navigation detected after locator click`);
        }
        log(`${logLabel} submit via locator click`);
        return true;
      }
    }
  } catch {
    // Fall through to broader submit strategies.
  }
  await clickSubmit(page);
  {
    const submitSignal = await waitForAuthSubmitSignal(page, postPattern, 3_500, baselineUrl);
    if (submitSignal !== "none") {
      if (submitSignal === "navigation") {
        log(`${logLabel} navigation detected after cdp click`);
      }
      log(`${logLabel} submit via cdp click`);
      return true;
    }
  }
  const currentUrlAfterClick = page.url();
  if (currentUrlAfterClick !== baselineUrl) {
    log(`${logLabel} submit via cdp click`);
    return true;
  }
  const fallback = await requestSubmitVisibleAuthForm(page);
  if (fallback) {
    log(`${logLabel} submit fallback via ${fallback}`);
    const submitSignal = await waitForAuthSubmitSignal(page, postPattern, 4_500, baselineUrl);
    if (submitSignal !== "none") {
      if (submitSignal === "navigation") {
        log(`${logLabel} navigation detected after ${fallback}`);
      }
      return true;
    }
  }
  if (await forceNativeSubmitAuthForm(page)) {
    log(`${logLabel} submit fallback via form.submit()`);
    const submitSignal = await waitForAuthSubmitSignal(page, postPattern, 4_500, baselineUrl);
    if (submitSignal !== "none") {
      if (submitSignal === "navigation") {
        log(`${logLabel} navigation detected after form.submit()`);
      }
      return true;
    }
  }
  await dispatchEnterViaCdp(page).catch(() => {});
  log(`${logLabel} submit fallback via cdp Enter`);
  return (await waitForAuthSubmitSignal(page, postPattern, 4_500, baselineUrl)) !== "none";
}

async function clickSubmit(page: any): Promise<void> {
  await page.waitForTimeout(randomInt(220, 780));
  let point =
    (await findClickablePointBySelector(
      page,
      'button[type="submit"], input[type="submit"], button[name="action"], button[data-action-button-primary="true"]',
    )) ||
    (await findClickablePointViaAxName(page, [/^continue$/i, /^sign up$/i, /^create account$/i, /^get started$/i])) ||
    (await findClickablePointByActionText(page, [/^continue$/i, /^sign up$/i, /^create account$/i, /^get started$/i]));
  if (!point) {
    const deadline = Date.now() + 12_000;
    while (Date.now() < deadline && !point) {
      await page.waitForTimeout(600);
      point =
        (await findClickablePointBySelector(
          page,
          'button[type="submit"], input[type="submit"], button[name="action"], button[data-action-button-primary="true"]',
        )) ||
        (await findClickablePointViaAxName(page, [/^continue$/i, /^sign up$/i, /^create account$/i, /^get started$/i])) ||
        (await findClickablePointByActionText(page, [/^continue$/i, /^sign up$/i, /^create account$/i, /^get started$/i]));
    }
  }
  if (!point) {
    const inputPoint =
      (await findClickablePointBySelector(page, 'input[type="email"], input[name="email"], input[type="text"]')) || null;
    if (inputPoint) {
      await dispatchMouseClickViaCdp(page, inputPoint.x, inputPoint.y);
      await page.waitForTimeout(randomInt(120, 240));
      await dispatchEnterViaCdp(page);
      log("submit entry fallback via cdp Enter");
      return;
    }
    await dispatchEnterViaCdp(page);
    log("submit entry fallback via blind cdp Enter");
    return;
  }
  await dispatchMouseClickViaCdp(page, point.x, point.y);
}

async function clickSignUp(page: any): Promise<void> {
  const directPoint =
    (await findClickablePointBySelector(page, 'a[href*="/u/signup/identifier"], a[href*="signup"], a[href*="register"]')) ||
    (await findClickablePointViaAxName(page, [/^sign up$/i, /^create account$/i, /^get started$/i], ["link", "button"])) ||
    (await findClickablePointByActionText(page, [
      /\/u\/signup\/identifier/i,
      /signup/i,
      /register/i,
      /sign up/i,
      /create account/i,
      /start for free/i,
      /get started/i,
    ]));
  if (directPoint) {
    await dispatchMouseClickViaCdp(page, directPoint.x, directPoint.y);
    return;
  }

  const fallbackPoint =
    (await findClickablePointByLinkText(page, /sign up|create account|get started|start for free/i)) ||
    (await findClickablePointByActionText(page, [/sign up|create account|get started|start for free/i]));
  if (!fallbackPoint) {
    const hints = await collectActionEntryHints(page);
    if (hints.length > 0) {
      log(`signup entry candidates: ${hints.join(" || ")}`);
    } else {
      log("signup entry candidates: (none)");
    }
    log(`signup entry surface: ${await collectPageSurfaceSummary(page)}`);
    throw new Error("Sign up entry not found");
  }
  await dispatchMouseClickViaCdp(page, fallbackPoint.x, fallbackPoint.y);
}

async function solveCaptchaForm(
  page: any,
  solver: CaptchaSolver,
  formKind: "signup" | "login",
  email: string,
  maxRounds: number,
): Promise<void> {
  await page.waitForTimeout(randomInt(900, 2600));
  const emailSelector = formKind === "signup" ? 'input[name="email"]' : 'input[name="username"]';
  const successUrlPattern =
    formKind === "signup"
      ? /\/u\/signup\/password|app\.tavily\.com\/home/i
      : /\/u\/login\/password|app\.tavily\.com\/home/i;
  const submitPostPattern = formKind === "signup" ? /\/u\/signup\/identifier/i : /\/u\/login\/identifier/i;
  await ensureAuthIdentifierFieldReady(page, emailSelector, 12_000);

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

    if (hasCaptcha) {
      throw new Error(`${formKind}_image_captcha_not_supported`);
    }

    await fillInput(page, emailSelector, email);

    const preSubmitChallenge = hasCaptcha ? null : await collectAuthChallengeSnapshot(page).catch(() => null);
    if (!hasCaptcha && hasManagedAuthChallenge(preSubmitChallenge)) {
      const stabilizedChallenge = await waitForManagedChallengeStableToken(page, formKind, 2_500);
      if (stabilizedChallenge && getChallengeTokenLength(stabilizedChallenge) > 0) {
        const touchedChallengeFields = await dispatchChallengeResponseEvents(page);
        if (touchedChallengeFields.length > 0) {
          log(`${formKind} identifier pre-submit challenge fields refreshed: ${touchedChallengeFields.join(", ")}`);
        }
      }
    }

    const previousUrl = page.url();
    await fillInput(page, emailSelector, email);
    await page
      .waitForSelector('div[data-captcha-provider="auth0_v2"], input[name="captcha"], iframe[src*="challenges.cloudflare.com"]', {
        timeout: 8_000,
      })
      .catch(() => {});
    const preSubmitManaged = await collectAuthChallengeSnapshot(page).catch(() => null);
    if (hasManagedAuthChallenge(preSubmitManaged)) {
      const tokenOutcome = await ensureManagedChallengeTokenBeforeSubmit(page, formKind);
      if (tokenOutcome.status === "rejected" && tokenOutcome.rejection && tokenOutcome.rejection !== "invalid_captcha") {
        throw new Error(tokenOutcome.rejection);
      }
      const hiddenCaptcha = await waitForAuthCaptchaValue(page, tokenOutcome.status === "token_ready" ? 8_000 : 3_000);
      if (hiddenCaptcha) {
        log(`${formKind} identifier hidden captcha ready before submit (len=${hiddenCaptcha.length})`);
      } else if (tokenOutcome.status === "token_ready") {
        log(`${formKind} identifier token reported ready but hidden captcha still empty before submit`);
      }
    }
    const initialSubmitFields = await collectAuthSubmitFields(page);
    authSubmitFieldCache.set(page, initialSubmitFields);
    log(
      `${formKind} identifier cached submit fields before submit (email=${initialSubmitFields.email ? 1 : 0}, captcha=${
        initialSubmitFields.captcha ? String(initialSubmitFields.captcha).length : 0
      }, state=${initialSubmitFields.state ? 1 : 0})`,
    );
    let submitTriggered = await submitAuthForm(page, submitPostPattern, `${formKind} identifier`);

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

    if (!hasCaptcha) {
      const managedOutcome = await waitForManagedChallengeOutcome(page, formKind, successUrlPattern, 22_000);
      if (managedOutcome.status === "success") {
        return;
      }
      if (managedOutcome.status === "rejected" && managedOutcome.rejection) {
        if (managedOutcome.rejection !== "invalid_captcha") {
          throw new Error(managedOutcome.rejection);
        }
      }
      if (managedOutcome.status === "token_ready") {
        await fillInput(page, emailSelector, email);
        const postTokenFields = await collectAuthSubmitFields(page);
        authSubmitFieldCache.set(page, postTokenFields);
        log(
          `${formKind} identifier cached submit fields after token (email=${postTokenFields.email ? 1 : 0}, captcha=${
            postTokenFields.captcha ? String(postTokenFields.captcha).length : 0
          }, state=${postTokenFields.state ? 1 : 0})`,
        );
        submitTriggered = (await submitAuthForm(page, submitPostPattern, `${formKind} identifier post-token`)) || submitTriggered;
        try {
          await page.waitForURL(successUrlPattern, { timeout: 15_000 });
          return;
        } catch {
          await page.waitForTimeout(1500);
          if (successUrlPattern.test(page.url())) {
            return;
          }
        }
      }
      if (
        managedOutcome.status === "timeout" &&
        managedOutcome.snapshot &&
        hasManagedAuthChallenge(managedOutcome.snapshot)
      ) {
        const rescueToken = await waitForManagedChallengeToken(page, formKind, 12_000);
        if (rescueToken.status === "rejected" && rescueToken.rejection && rescueToken.rejection !== "invalid_captcha") {
          throw new Error(rescueToken.rejection);
        }
        if (rescueToken.status === "token_ready") {
          await fillInput(page, emailSelector, email);
          const rescueFields = await collectAuthSubmitFields(page);
          authSubmitFieldCache.set(page, rescueFields);
          log(
            `${formKind} identifier cached submit fields after rescue token (email=${rescueFields.email ? 1 : 0}, captcha=${
              rescueFields.captcha ? String(rescueFields.captcha).length : 0
            }, state=${rescueFields.state ? 1 : 0})`,
          );
          submitTriggered =
            (await submitAuthForm(page, submitPostPattern, `${formKind} identifier rescue-token`)) || submitTriggered;
          try {
            await page.waitForURL(successUrlPattern, { timeout: 15_000 });
            return;
          } catch {
            await page.waitForTimeout(1_500);
            if (successUrlPattern.test(page.url())) {
              return;
            }
          }
        }
      }
      if (
        managedOutcome.status === "timeout" &&
        managedOutcome.snapshot &&
        managedOutcome.snapshot.hasChallengeFrame &&
        managedOutcome.snapshot.captchaValueLength === 0
      ) {
        const interacted = await tryActivateManagedChallenge(page, formKind);
        if (interacted) {
          const postClickOutcome = await waitForManagedChallengeOutcome(page, formKind, successUrlPattern, 18_000);
          if (postClickOutcome.status === "success") {
            return;
          }
          if (postClickOutcome.status === "rejected" && postClickOutcome.rejection && postClickOutcome.rejection !== "invalid_captcha") {
            throw new Error(postClickOutcome.rejection);
          }
          if (postClickOutcome.status === "token_ready") {
            await fillInput(page, emailSelector, email);
            const activateFields = await collectAuthSubmitFields(page);
            authSubmitFieldCache.set(page, activateFields);
            log(
              `${formKind} identifier cached submit fields after activate (email=${activateFields.email ? 1 : 0}, captcha=${
                activateFields.captcha ? String(activateFields.captcha).length : 0
              }, state=${activateFields.state ? 1 : 0})`,
            );
            submitTriggered = (await submitAuthForm(page, submitPostPattern, `${formKind} identifier post-activate`)) || submitTriggered;
            try {
              await page.waitForURL(successUrlPattern, { timeout: 15_000 });
              return;
            } catch {
              await page.waitForTimeout(1500);
              if (successUrlPattern.test(page.url())) {
                return;
              }
            }
          }
        }
      }
      if (!submitTriggered && page.url() === previousUrl) {
        log(`${formKind} identifier submit did not trigger POST (attempt=${attempt})`);
      }
    }

    const formErrors = await collectVisibleFormErrors(page).catch(() => []);
    const errorCodes = await collectVisibleErrorCodes(page).catch(() => []);
    if (errorCodes.length > 0) {
      log(`${formKind} error codes after submit (attempt=${attempt}): ${errorCodes.join(", ")}`);
    }
    const explicitRejection = detectExplicitFormRejection(formErrors, errorCodes);
    if (explicitRejection && explicitRejection !== "invalid_captcha") {
      throw new Error(explicitRejection);
    }

    if (hasCaptcha) {
      log(`${formKind} image captcha rejected on attempt ${attempt}`);
    } else {
      log(`${formKind} challenge not satisfied on attempt ${attempt}, retrying`);
    }
  }

  throw new Error(`${formKind} challenge failed after ${maxRounds} rounds`);
}

interface SignupDiagHooks {
  onPasswordSnapshot?: (snapshot: PasswordStepSnapshot) => void;
  onFingerprintSnapshot?: (snapshot: BrowserFingerprintSnapshot) => void;
}

interface SignupAttemptPolicy {
  signupChallengeRounds: number;
  passwordStepRounds: number;
}

interface SignupFlowResult {
  password: string;
  emailVerifiedInFlow: boolean;
}

async function completeEmailIdentifierChallenge(
  page: any,
  mailbox: MailboxSession,
  cfg: AppConfig,
  proxyUrl?: string,
): Promise<boolean> {
  if (!/\/u\/email-identifier\/challenge/i.test(page.url())) {
    return false;
  }

  await page.waitForSelector('input[name="code"]', { timeout: 30_000 });
  await clearAuthFieldValidationState(page, 'input[name="code"]');
  await page.waitForTimeout(400);
  const code = await waitForEmailCode(mailbox, cfg.emailWaitMs, cfg.mailPollMs, proxyUrl);
  if (!code) {
    throw new Error("verification email code not found within timeout");
  }

  log(`email identifier challenge code received (${code.length} digits)`);
  await ensureInputValue(page, 'input[name="code"]', code, "email_code");
  const stableCodeInput = await waitForStableInputValue(page, 'input[name="code"]', code, 500, 6_000);
  if (!stableCodeInput) {
    throw new Error("email_code_input_not_stable");
  }
  const preSubmitErrors = await collectVisibleFormErrors(page).catch(() => []);
  if (preSubmitErrors.some((text) => /please enter a code/i.test(text))) {
    log("email identifier challenge stale empty-code error visible before submit, refilling code");
    await clearAuthFieldValidationState(page, 'input[name="code"]');
    await ensureInputValue(page, 'input[name="code"]', code, "email_code");
    const refilledStable = await waitForStableInputValue(page, 'input[name="code"]', code, 500, 6_000);
    if (!refilledStable) {
      throw new Error("email_code_input_not_stable_after_refill");
    }
  }
  await page.waitForTimeout(randomInt(250, 550));
  const codeSubmitFields = await collectAuthSubmitFields(page);
  authSubmitFieldCache.set(page, codeSubmitFields);
  log(
    `email identifier cached submit fields before submit (code=${codeSubmitFields.code ? String(codeSubmitFields.code).length : 0}, state=${codeSubmitFields.state ? 1 : 0})`,
  );

  const submitTriggered = await submitAuthForm(page, /\/u\/email-identifier\/challenge/i, "email identifier challenge");
  if (!submitTriggered) {
    log("email identifier challenge submit did not observe POST; waiting for URL transition");
  }

  await Promise.race([
    page.waitForURL((url: URL) => !/\/u\/email-identifier\/challenge/i.test(url.toString()), { timeout: 45_000 }),
    page.waitForTimeout(45_000),
  ]);

  if (/\/u\/email-identifier\/challenge/i.test(page.url())) {
    const formErrors = await collectVisibleFormErrors(page).catch(() => []);
    const errorCodes = await collectVisibleErrorCodes(page).catch(() => []);
    throw new Error(
      `email identifier challenge did not advance: current=${page.url()} errors=${formErrors.join(" | ") || "none"} codes=${
        errorCodes.join(",") || "none"
      }`,
    );
  }

  log(`email identifier challenge advanced to ${page.url()}`);
  return true;
}

async function completeSignup(
  page: any,
  solver: CaptchaSolver,
  email: string,
  password: string,
  mailbox: MailboxSession | null,
  cfg: AppConfig,
  outputDir: URL | null,
  policy: SignupAttemptPolicy,
  proxyUrl?: string,
  hooks?: SignupDiagHooks,
): Promise<SignupFlowResult> {
  let emailVerifiedInFlow = false;
  const currentSurface = page.url();
  const existingSignupSurface = /\/u\/signup\/identifier|\/u\/signup\/password|\/u\/email-identifier\/challenge/i.test(currentSurface);
  if (!existingSignupSurface) {
    await openAuthFlowEntry(page, "signup");

    if (!/\/u\/signup\/identifier|\/u\/signup\/password/i.test(page.url())) {
      if (/\/u\/login\/identifier/i.test(page.url())) {
        await clickSignUp(page);
      } else {
        await safeGoto(page, "https://auth.tavily.com/u/signup/identifier");
      }
    }
  } else {
    log(`signup flow: continuing existing auth surface ${currentSurface}`);
  }

  await page.waitForURL(/\/u\/signup\/identifier|\/u\/signup\/password|\/u\/email-identifier\/challenge|app\.tavily\.com\/home/i, {
    timeout: 90000,
  });
  if (/\/u\/signup\/identifier/i.test(page.url())) {
    await solveCaptchaForm(page, solver, "signup", email, Math.max(1, policy.signupChallengeRounds));
    await page.waitForTimeout(1200);
  }

  if (/app\.tavily\.com\/home/i.test(page.url())) {
    return { password, emailVerifiedInFlow };
  }
  if (/\/u\/email-identifier\/challenge/i.test(page.url())) {
    if (!mailbox) {
      throw new Error(`social_signup_email_challenge_unexpected:${page.url()}`);
    }
    emailVerifiedInFlow = await completeEmailIdentifierChallenge(page, mailbox, cfg, proxyUrl);
    await page.waitForTimeout(1200);
  }
  if (/app\.tavily\.com\/home/i.test(page.url())) {
    return { password, emailVerifiedInFlow };
  }
  if (!/\/u\/signup\/password/i.test(page.url())) {
    throw new Error(`signup did not reach password step, current=${page.url()}`);
  }

  if (/\/u\/signup\/password/i.test(page.url())) {
    // Slow down on password step to reduce bot-like burst behavior.
    await page.waitForTimeout(randomInt(3000, 8500));
    const passwordAttemptMax = Math.max(1, Math.min(policy.passwordStepRounds, cfg.maxCaptchaRounds, 8));
    let workingPassword = password;
    let invalidCaptchaSeenCount = 0;
    let captchaMissingStreak = 0;
    for (let attempt = 1; attempt <= passwordAttemptMax; attempt += 1) {
      if (attempt === 1) {
        const fingerprintSnapshot = await collectBrowserFingerprintSnapshot(page).catch(() => null);
        if (fingerprintSnapshot) {
          hooks?.onFingerprintSnapshot?.(fingerprintSnapshot);
        }
        if (outputDir) {
          await writePageArtifactsBestEffort(page, outputDir, "signup_password_before");
        }
      }

      const passwordInputs = page.locator('input[type="password"]');
      const pwdCount = await passwordInputs.count();
      if (pwdCount === 0) {
        await ensureInputValue(page, 'input[name="password"]', workingPassword, "signup_password");
      } else {
        for (let i = 0; i < pwdCount; i += 1) {
          await ensureInputValue(page, `input[type="password"] >> nth=${i}`, workingPassword, `signup_password_${i + 1}`);
        }
      }

      const preSubmitSnapshot = await collectPasswordStepSnapshot(page).catch(() => null);
      if (preSubmitSnapshot) {
        hooks?.onPasswordSnapshot?.(preSubmitSnapshot);
      }
      const preSubmitChallengeSnapshot = await collectAuthChallengeSnapshot(page).catch(() => null);
      const hasCaptchaImage = Boolean(
        preSubmitSnapshot?.hasCaptchaImage ?? (await page.locator('img[alt="captcha"]').count()).catch(() => 0),
      );
      let challengeReadyForSubmit = false;
      let allowSubmitWithoutCaptcha = false;
      if (hasCaptchaImage) {
        throw new Error("signup_password_image_captcha_not_supported");
      }

      if (hasManagedAuthChallenge(preSubmitChallengeSnapshot)) {
        const tokenOutcome = await ensureManagedChallengeTokenBeforeSubmit(page, "signup");
        if (tokenOutcome.status === "rejected" && tokenOutcome.rejection && tokenOutcome.rejection !== "invalid_captcha") {
          throw new Error(tokenOutcome.rejection);
        }
        const dismissalSnapshot =
          getChallengeTokenLength(tokenOutcome.snapshot) > 0 || tokenOutcome.snapshot?.challengeSuccessVisible
            ? await waitForManagedChallengeDismissal(page, "signup", 8_000)
            : tokenOutcome.snapshot;
        const effectiveChallengeSnapshot = dismissalSnapshot || tokenOutcome.snapshot;
        const hiddenCaptcha = await waitForAuthCaptchaValue(page, tokenOutcome.status === "token_ready" ? 8_000 : 3_000);
        if (hiddenCaptcha) {
          challengeReadyForSubmit = true;
          captchaMissingStreak = 0;
          log(`signup password hidden captcha ready before submit (len=${hiddenCaptcha.length})`);
        } else {
          challengeReadyForSubmit = canSubmitManagedChallengeWithoutVisibleToken(effectiveChallengeSnapshot);
        }
        if (!challengeReadyForSubmit) {
          captchaMissingStreak += 1;
          if (attempt >= passwordAttemptMax) {
            throw new Error("signup_password_captcha_missing");
          }
          log(`signup password managed challenge not ready for submit (attempt=${attempt}, streak=${captchaMissingStreak}), waiting`);
          await page.waitForTimeout(randomInt(1000, 1800));
          continue;
        }
      } else {
        const challengeHint = preSubmitSnapshot?.challengeHint || false;
        const hasCaptchaSignal =
          challengeHint ||
          Boolean(preSubmitSnapshot?.hasCaptchaContainer) ||
          Boolean(preSubmitSnapshot?.hasTurnstileResponseInput) ||
          Boolean(preSubmitSnapshot?.hasRecaptchaResponseInput) ||
          Boolean(preSubmitSnapshot?.hasHcaptchaResponseInput);
        if (!hasCaptchaSignal) {
          captchaMissingStreak += 1;
          const directSubmitDwellMs = attempt === 1 ? randomInt(1200, 2600) : randomInt(900, 1800);
          const shouldForceSubmitWithoutCaptcha = cfg.allowPasswordSubmitWithoutCaptcha;
          if (shouldForceSubmitWithoutCaptcha) {
            log(
              `signup password captcha input missing with no challenge signal (attempt=${attempt}, streak=${captchaMissingStreak}), force submit without captcha after dwell=${directSubmitDwellMs}ms`,
            );
            await page.waitForTimeout(directSubmitDwellMs);
            allowSubmitWithoutCaptcha = true;
          } else {
            // If no challenge signal is present, wait for late hydration once before deciding.
            log(
              `signup password captcha input missing with no challenge signal (attempt=${attempt}, streak=${captchaMissingStreak}), wait network idle after dwell=${directSubmitDwellMs}ms`,
            );
            await page.waitForTimeout(directSubmitDwellMs);
            await page.waitForLoadState("networkidle", { timeout: 2600 }).catch(() => {});
            await page.waitForSelector('input[name="captcha"]', { timeout: 1200 }).catch(() => {});
            const lateCaptchaInput = (await page.locator('input[name="captcha"]').count()) > 0;
            if (lateCaptchaInput) {
              log(`signup password captcha input appeared after network idle (attempt=${attempt}), image captcha unsupported`);
              continue;
            }
            log(
              `signup password still no captcha/challenge signal after network idle (attempt=${attempt}), submit without captcha`,
            );
            allowSubmitWithoutCaptcha = true;
          }
        } else {
          captchaMissingStreak += 1;
          const dwellMs = randomInt(2400, 4200);
          log(
            `signup password captcha input missing (attempt=${attempt}, streak=${captchaMissingStreak}, signal=${hasCaptchaSignal ? 1 : 0}, image=${hasCaptchaImage ? 1 : 0}, hint=${challengeHint ? 1 : 0}), dwell=${dwellMs}ms`,
          );
          await page.waitForTimeout(dwellMs);
          await page.waitForSelector('input[name="captcha"]', { timeout: 2600 }).catch(() => {});
          const lateCaptchaInput = (await page.locator('input[name="captcha"]').count()) > 0;
          if (lateCaptchaInput) {
            challengeReadyForSubmit = true;
            captchaMissingStreak = 0;
          } else {
            if (attempt >= passwordAttemptMax) {
              throw new Error("signup_password_captcha_missing");
            }
            log(`signup password captcha input still missing, reloading for challenge hydration (attempt=${attempt})`);
            await safeGoto(page, page.url());
            await page.waitForTimeout(randomInt(1200, 2600));
            continue;
          }
        }
      }

      if (!challengeReadyForSubmit && !allowSubmitWithoutCaptcha) {
        if (attempt >= passwordAttemptMax) {
          throw new Error("signup_password_captcha_missing");
        }
        log(`signup password challenge not ready for submit (attempt=${attempt}), retrying`);
        await page.waitForTimeout(randomInt(1000, 1800));
        continue;
      }

      const passwordDiag = await collectPasswordStrengthSnapshot(page).catch(() => ({
        len: workingPassword.length,
        lower: /[a-z]/.test(workingPassword),
        upper: /[A-Z]/.test(workingPassword),
        digit: /\d/.test(workingPassword),
        special: /[^A-Za-z0-9]/.test(workingPassword),
        tooWeak: false,
        visiblePolicyErrors: [],
      }));
      log(`signup password diag attempt=${attempt} ${JSON.stringify(passwordDiag)}`);
      const passwordLooksWeak =
        passwordDiag.len < 8 ||
        [passwordDiag.lower, passwordDiag.upper, passwordDiag.digit, passwordDiag.special].filter(Boolean).length < 3 ||
        passwordDiag.tooWeak;
      if (passwordLooksWeak) {
        if (!isCompliantGeneratedPassword(workingPassword)) {
          workingPassword = randomPassword();
          log(`signup password regenerated due to weak generator output (attempt=${attempt})`);
        } else {
          log(`signup password refill requested due to weak policy signal (attempt=${attempt})`);
        }
        await page.waitForTimeout(randomInt(500, 1100));
        continue;
      }

      await page.waitForTimeout(randomInt(900, 2600));
      const passwordSubmitFields = await collectAuthSubmitFields(page);
      authSubmitFieldCache.set(page, passwordSubmitFields);
      log(
        `signup password cached submit fields before submit (password=${passwordSubmitFields.password ? String(passwordSubmitFields.password).length : 0}, captcha=${
          passwordSubmitFields.captcha ? String(passwordSubmitFields.captcha).length : 0
        }, state=${passwordSubmitFields.state ? 1 : 0})`,
      );
      if (allowSubmitWithoutCaptcha) {
        log(`signup password submit without captcha challenge (attempt=${attempt})`);
      }
      const submitTriggered = await submitAuthForm(page, /\/u\/signup\/password/i, "signup password");
      if (!submitTriggered) {
        log(`signup password submit did not observe POST (attempt=${attempt}), waiting for page transition`);
      }
      await page.waitForTimeout(2200);

      if (attempt === 1) {
        if (outputDir) {
          await writePageArtifactsBestEffort(page, outputDir, "signup_password_after1");
        }
      }

        if (!/\/u\/signup\/password/i.test(page.url())) {
          return { password: workingPassword, emailVerifiedInFlow };
        }

      const formErrors = await collectVisibleFormErrors(page).catch(() => []);
      const compactErrors = formErrors
        .map((text) => text.replace(/\s+/g, " ").trim())
        .filter((text) => text.length > 0)
        .map((text) => (text.length > 180 ? `${text.slice(0, 180)}...` : text));
      log(`signup password step still present after submit (attempt=${attempt}) errors=${compactErrors.join(" | ") || "n/a"}`);
      const hasIpRateLimitMarker = formErrors.some((text) => /Too many signups from the same IP/i.test(text));
      const postSubmitErrorCodes = await collectVisibleErrorCodes(page).catch(() => []);
      if (postSubmitErrorCodes.length > 0) {
        log(`signup password error codes (attempt=${attempt}): ${postSubmitErrorCodes.join(", ")}`);
      }
      const explicitRejection = detectExplicitFormRejection(formErrors, postSubmitErrorCodes);
      const hasSuspiciousMarker = formErrors.some((text) => /Suspicious activity detected/i.test(text));
      if (explicitRejection === "risk_control_ip_rate_limit" || hasIpRateLimitMarker) {
        throw new Error("risk_control_ip_rate_limit");
      }
      if (explicitRejection === "auth0_extensibility_error") {
        throw new Error("auth0_extensibility_error");
      }
      if (hasSuspiciousMarker) {
        throw new Error("risk_control_suspicious_activity");
      }
      const postSubmitSnapshot = await collectPasswordStepSnapshot(page).catch(() => null);
      if (postSubmitSnapshot) {
        hooks?.onPasswordSnapshot?.(postSubmitSnapshot);
      }
      const postSubmitChallengeSnapshot = await collectAuthChallengeSnapshot(page).catch(() => null);
      if (postSubmitChallengeSnapshot && hasManagedAuthChallenge(postSubmitChallengeSnapshot)) {
        log(
          `signup password managed challenge detected after submit (attempt=${attempt}, frame=${
            postSubmitChallengeSnapshot.hasChallengeFrame ? 1 : 0
          }, checkbox=${postSubmitChallengeSnapshot.hasChallengeCheckbox ? 1 : 0}, token=${
            postSubmitChallengeSnapshot.captchaValueLength
          })`,
        );
        const readySnapshot = await waitForManagedChallengeReady(page, "signup", 12_000);
        let tokenOutcome = await waitForManagedChallengeToken(page, "signup", 8_000);
        if (
          tokenOutcome.status === "timeout" &&
          (readySnapshot?.hasChallengeCheckbox || tokenOutcome.snapshot?.hasChallengeCheckbox || readySnapshot?.hasChallengeFrame)
        ) {
          const interacted = await tryActivateManagedChallenge(page, "signup");
          if (interacted) {
            tokenOutcome = await waitForManagedChallengeToken(page, "signup", 20_000);
          }
        }
        if (tokenOutcome.status === "token_ready") {
          log(`signup password managed challenge token ready after submit (attempt=${attempt})`);
          await waitForManagedChallengeDismissal(page, "signup", 6_000);
          let submitTriggered = false;
          await clickSubmit(page);
          submitTriggered = await waitForAuthFormPostResponse(page, /\/u\/signup\/password/i, 8_000);
          if (!submitTriggered && /\/u\/signup\/password/i.test(page.url())) {
            await dispatchEnterViaCdp(page);
            log("signup password post-challenge submit fallback via cdp Enter");
            submitTriggered = await waitForAuthFormPostResponse(page, /\/u\/signup\/password/i, 6_000);
          }
          try {
            await page.waitForURL(/app\.tavily\.com\/home|\/u\/signup\/password/i, { timeout: 15_000 });
          } catch {
            await page.waitForTimeout(1800);
          }
          if (!/\/u\/signup\/password/i.test(page.url())) {
            return { password: workingPassword, emailVerifiedInFlow };
          }
          if (!submitTriggered) {
            log(`signup password post-challenge submit did not trigger POST (attempt=${attempt}), treat as suspicious`);
            throw new Error("risk_control_suspicious_activity");
          }
        }
      }
      const hasTooWeakMarker = formErrors.some((text) => /password is too weak/i.test(text));
      const hasChallengeLoadMarker = formErrors.some((text) => /we couldn.?t load the security challenge/i.test(text));
      const hasUsersValidationCode = postSubmitErrorCodes.some((code) => /auth0-users-validation/i.test(code));
      if ((hasTooWeakMarker || hasUsersValidationCode) && !hasChallengeLoadMarker) {
        if (attempt >= passwordAttemptMax) {
          throw new Error("signup_password_step_failed");
        }
        const previousPassword = workingPassword;
        workingPassword = randomPassword();
        log(
          `signup password rejected by validation (attempt=${attempt}), rotating password len=${previousPassword.length}->${workingPassword.length}`,
        );
        await page.waitForTimeout(randomInt(700, 1500));
        continue;
      }
      if (hasChallengeLoadMarker) {
        if (attempt >= passwordAttemptMax) {
          throw new Error("signup_password_captcha_missing");
        }
        log(`signup password challenge failed to hydrate after submit (attempt=${attempt}), reloading`);
        await safeGoto(page, page.url());
        await page.waitForTimeout(randomInt(1200, 2400));
        continue;
      }
      const hasInvalidCaptchaCode = postSubmitErrorCodes.some((code) =>
        /invalid-captcha/i.test(code),
      );
      if (hasInvalidCaptchaCode) {
        invalidCaptchaSeenCount += 1;
        if (invalidCaptchaSeenCount >= 2 || attempt >= passwordAttemptMax - 1) {
          log(`signup password invalid captcha repeated ${invalidCaptchaSeenCount} times, rotate mode attempt early`);
          throw new Error("invalid_captcha");
        }
        log(`signup password invalid captcha on attempt ${attempt}, refreshing and retrying`);
        await page.waitForTimeout(1300);
        continue;
      }
      invalidCaptchaSeenCount = 0;
      if (attempt < passwordAttemptMax) {
        log(`signup password submission not accepted on attempt ${attempt}, retrying`);
        continue;
      }
    }
    const terminalSnapshot = await collectPasswordStepSnapshot(page).catch(() => null);
    if (terminalSnapshot) {
      hooks?.onPasswordSnapshot?.(terminalSnapshot);
    }
    if (
      terminalSnapshot &&
      !terminalSnapshot.hasCaptchaInput &&
      (terminalSnapshot.hasCaptchaImage ||
        terminalSnapshot.hasCaptchaContainer ||
        terminalSnapshot.hasTurnstileResponseInput ||
        terminalSnapshot.hasRecaptchaResponseInput ||
        terminalSnapshot.hasHcaptchaResponseInput ||
        terminalSnapshot.challengeHint)
    ) {
      throw new Error("signup_password_captcha_missing");
    }
    throw new Error(`signup password step failed after ${passwordAttemptMax} attempts`);
  }

  return { password, emailVerifiedInFlow };
}

async function loginAndReachHome(
  page: any,
  solver: CaptchaSolver,
  email: string,
  password: string,
  cfg: AppConfig,
  mailbox?: MailboxSession | null,
  proxyUrl?: string,
  maxCycles = 5,
  outputDir?: URL | null,
): Promise<any> {
  const loginProvider = getConfiguredLoginProvider(cfg);
  const urlTrace: string[] = [];
  const pushUrlTrace = (label: string): void => {
    const currentUrl = page.url();
    const entry = `${label}:${currentUrl}`;
    if (urlTrace[urlTrace.length - 1] !== entry) {
      urlTrace.push(entry);
      if (urlTrace.length > 18) urlTrace.shift();
    }
  };
  for (let cycle = 1; cycle <= Math.max(1, maxCycles); cycle += 1) {
    await safeGoto(page, "https://app.tavily.com/home");
    await page.waitForTimeout(1200);
    pushUrlTrace(`cycle${cycle}:home`);

    if (/app\.tavily\.com\/home/i.test(page.url()) && !/auth\.tavily\.com/i.test(page.url())) {
      await acceptPostSignupConsent(page).catch(() => false);
      if (await waitHomeStable(page, 6500)) {
        return page;
      }
    }

    await openAuthFlowEntry(page, "login");
    await page.waitForTimeout(900);
    pushUrlTrace(`cycle${cycle}:auth-entry`);

    if (loginProvider === "microsoft") {
      page = await completeMicrosoftLogin(page, cfg, proxyUrl);
      pushUrlTrace(`cycle${cycle}:microsoft-return`);
      if (/auth\.tavily\.com\/u\/(?:signup\/identifier|signup\/password|email-identifier\/challenge)/i.test(page.url())) {
        log(`login flow: continuing Tavily social signup after Microsoft return ${page.url()}`);
        const socialSignupResult = await completeSignup(
          page,
          solver,
          email,
          password,
          mailbox || null,
          cfg,
          outputDir || null,
          {
            signupChallengeRounds: Math.max(1, Math.min(cfg.maxCaptchaRounds, 2)),
            passwordStepRounds: Math.max(1, Math.min(cfg.maxCaptchaRounds, 3)),
          },
          proxyUrl,
        );
        password = socialSignupResult.password;
        pushUrlTrace(`cycle${cycle}:social-signup`);
      }
    } else {
      if (/\/u\/login\/identifier/i.test(page.url())) {
        await solveCaptchaForm(page, solver, "login", email, cfg.maxCaptchaRounds);
        pushUrlTrace(`cycle${cycle}:identifier`);
      }
      if (/\/u\/email-identifier\/challenge/i.test(page.url()) && mailbox) {
        await completeEmailIdentifierChallenge(page, mailbox, cfg, proxyUrl);
        await page.waitForTimeout(1200);
        pushUrlTrace(`cycle${cycle}:email-challenge`);
      }

      if ((await page.locator('input[name="password"]').count()) > 0) {
        await fillInput(page, 'input[name="password"]', password);
        await clickSubmit(page);
        await page.waitForTimeout(1400);
        pushUrlTrace(`cycle${cycle}:password-submit`);
      }
    }

    const current = page.url();
    pushUrlTrace(`cycle${cycle}:post-login`);
    if (/app\.tavily\.com\/home/i.test(current) && !/auth\.tavily\.com/i.test(current)) {
      await acceptPostSignupConsent(page).catch(() => false);
      if (await waitHomeStable(page, 5000)) {
        return page;
      }
    }

    log(`login cycle ${cycle} not yet on home, current=${current}`);
  }

  throw new Error(`login flow did not reach home, last_url=${page.url()}, trace=${urlTrace.join(" -> ")}`);
}

async function getDefaultApiKey(page: any, cfg: AppConfig, maxRounds = 6): Promise<string | null> {
  await page.waitForLoadState("domcontentloaded", { timeout: 30000 });

  for (let round = 1; round <= Math.max(1, maxRounds); round += 1) {
    await page.waitForTimeout(1200);

    const fromDom = await page.evaluate(`(() => {
      const pick = (value) => {
        if (typeof value !== "string") return null;
        const match = value.match(/tvly-[A-Za-z0-9_-]{8,}/i);
        return match ? match[0] : null;
      };

      const selectOption = Array.from(document.querySelectorAll("option"))
        .map((el) => el.value || "")
        .map((v) => pick(v))
        .find((v) => !!v);
      if (selectOption) return { key: selectOption, source: "dom-option" };

      const inputVal = Array.from(document.querySelectorAll("input,textarea"))
        .map((el) => [el.value, el.getAttribute("value"), el.getAttribute("placeholder")])
        .flat()
        .map((v) => pick(v))
        .find((v) => !!v);
      if (inputVal) return { key: inputVal, source: "dom-input" };

      const textMatch = pick(document.body?.innerText || "");
      if (textMatch) return { key: textMatch, source: "dom-text" };
      return { key: null, source: "none" };
    })()`);

    if (fromDom?.key && isLikelyTavilyKey(fromDom.key)) {
      log(`default api key found from ${fromDom.source}`);
      return fromDom.key;
    }

    const pageResult = await page.evaluate(
      `async ({ keyName, keyLimit }) => {
        const isLikelyKey = (value) => /^tvly-[A-Za-z0-9_-]{8,}$/i.test((value || "").trim());
        const extractKey = (node) => {
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

        const parse = async (res) => {
          const text = await res.text();
          let body;
          try {
            body = JSON.parse(text);
          } catch {
            body = text;
          }
          return { ok: res.ok, status: res.status, body };
        };

        const safeFetch = async (url, init) => {
          try {
            const resp = await fetch(url, { credentials: "include", ...(init || {}) });
            return await parse(resp);
          } catch (error) {
            return { ok: false, status: 0, body: { error: String(error) } };
          }
        };

        const oidCandidates = new Set();
        const collectOidFromNode = (node) => {
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

        const endpoints = [];
        for (const oid of oidCandidates) endpoints.push("/api/keys?oid=" + encodeURIComponent(oid));
        endpoints.push("/api/keys?oid=");
        endpoints.push("/api/keys");

        const debug = [];
        for (const endpoint of endpoints) {
          const listed = await safeFetch(endpoint);
          debug.push({ step: "list:" + endpoint, status: listed.status });
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
          debug.push({ step: "create:" + endpoint, status: created.status });
          const createdKey = extractKey(created.body);
          if (createdKey) return { key: createdKey, debug };

          const listedAgain = await safeFetch(endpoint);
          debug.push({ step: "list2:" + endpoint, status: listedAgain.status });
          const listedAgainKey = extractKey(listedAgain.body);
          if (listedAgainKey) return { key: listedAgainKey, debug };
        }

        return { key: null, debug };
      }`,
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

function resolveGitCommonRepoRoot(cwd: string): string | null {
  try {
    const commonDir = execFileSync("git", ["rev-parse", "--git-common-dir"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (!commonDir) return null;
    const resolvedCommonDir = path.resolve(cwd, commonDir);
    if (path.basename(resolvedCommonDir) !== ".git") return null;
    return path.dirname(resolvedCommonDir);
  } catch {
    return null;
  }
}

function collectFingerprintChromiumCandidates(cwd: string): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();
  const pushCandidate = (candidate: string) => {
    if (seen.has(candidate)) return;
    seen.add(candidate);
    candidates.push(candidate);
  };

  pushCandidate(path.resolve(cwd, ".tools/Chromium.app/Contents/MacOS/Chromium"));
  const commonRepoRoot = resolveGitCommonRepoRoot(cwd);
  if (commonRepoRoot) {
    pushCandidate(path.resolve(commonRepoRoot, ".tools/Chromium.app/Contents/MacOS/Chromium"));
  }
  return candidates;
}

function resolveChromeExecutablePath(raw: string | undefined, cwd = process.cwd()): string | undefined {
  const trimmed = (raw || "").trim();
  if (trimmed) return trimmed;
  if (process.platform === "darwin") {
    for (const candidate of collectFingerprintChromiumCandidates(cwd)) {
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

function isFingerprintChromiumExecutable(executablePath: string | undefined): boolean {
  const normalized = (executablePath || "").trim().toLowerCase();
  return normalized.endsWith('/chromium') || normalized.includes('/chromium.app/');
}

function requireFingerprintChromiumExecutablePath(executablePath: string | undefined): string {
  if (!executablePath) {
    throw new Error("fingerprint Chromium executable path is not configured");
  }
  if (!isFingerprintChromiumExecutable(executablePath)) {
    throw new Error(`Unsupported CHROME_EXECUTABLE_PATH: ${executablePath}. Only fingerprint Chromium is allowed.`);
  }
  return executablePath;
}

function resolveChromeAppName(executablePath: string | undefined): string {
  return isFingerprintChromiumExecutable(executablePath) ? 'Chromium' : 'Google Chrome';
}

function buildFingerprintSeed(profileDir: string, proxyServer: string, locale: string): string {
  const digest = createHash('sha256').update(`${profileDir}|${proxyServer}|${locale}`).digest('hex');
  return String(parseInt(digest.slice(0, 8), 16) || 1000);
}

function resolveFingerprintChromiumPlatform(): "linux" | "macos" | null {
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "macos";
  return null;
}

function getFingerprintChromiumArgs(
  executablePath: string | undefined,
  profileDir: string,
  proxyServer: string,
  locale: string,
  acceptLanguage: string,
  timezoneId?: string,
): string[] {
  if (!isFingerprintChromiumExecutable(executablePath)) return [];
  const seed = buildFingerprintSeed(profileDir, proxyServer, locale);
  const args = [
    `--fingerprint=${seed}`,
    '--fingerprint-brand=Chrome',
    `--lang=${locale}`,
    `--accept-lang=${acceptLanguage}`,
    '--disable-non-proxied-udp',
  ];
  const platform = resolveFingerprintChromiumPlatform();
  if (platform) {
    args.splice(1, 0, `--fingerprint-platform=${platform}`);
  }
  if (timezoneId?.trim()) {
    args.push(`--timezone=${timezoneId.trim()}`);
  }
  return args;
}

export function loadConfig(): AppConfig {
  const rawRunMode = (process.env.RUN_MODE || "").trim();
  const envRunMode = parseRunMode(rawRunMode);
  if (rawRunMode && !envRunMode) {
    throw new Error(`Invalid env RUN_MODE: ${rawRunMode}. Supported values: headed|headless`);
  }
  const rawBrowserEngine = (process.env.BROWSER_ENGINE || "").trim();
  const parsedBrowserEngine = parseBrowserEngine(rawBrowserEngine || undefined);
  if (rawBrowserEngine && !parsedBrowserEngine) {
    throw new Error(`Invalid env BROWSER_ENGINE: ${rawBrowserEngine}. Supported values: chrome`);
  }
  const envBrowserEngine = parsedBrowserEngine || "chrome";
  const rawInspectBrowserEngine = (process.env.INSPECT_BROWSER_ENGINE || "").trim();
  const parsedInspectBrowserEngine = parseBrowserEngine(rawInspectBrowserEngine || undefined);
  if (rawInspectBrowserEngine && !parsedInspectBrowserEngine) {
    throw new Error(`Invalid env INSPECT_BROWSER_ENGINE: ${rawInspectBrowserEngine}. Supported values: chrome`);
  }
  const envInspectBrowserEngine = parsedInspectBrowserEngine || "chrome";
  const rawMailProvider = (process.env.MAIL_PROVIDER || "").trim();
  const envMailProvider = parseMailProvider(rawMailProvider || undefined) || "gptmail";
  if (rawMailProvider && !parseMailProvider(rawMailProvider)) {
    throw new Error(`Invalid env MAIL_PROVIDER: ${rawMailProvider}. Supported values: gptmail|duckmail|vmail`);
  }
  const gptmailBaseUrl = normalizeGptmailBaseUrl(process.env.GPTMAIL_BASE_URL || "https://mail.chatgpt.org.uk");
  const vmailBaseUrl = (process.env.VMAIL_BASE_URL || "").trim();
  const moemailBaseUrl = normalizeMoeMailBaseUrl(process.env.MOEMAIL_BASE_URL || "https://moemail.707079.xyz");
  const duckmailBaseUrl = (process.env.DUCKMAIL_BASE_URL || "").trim();
  if (envMailProvider === "vmail" && !vmailBaseUrl) {
    throw new Error("Missing env: VMAIL_BASE_URL (required when MAIL_PROVIDER=vmail)");
  }
  if (envMailProvider === "duckmail" && !duckmailBaseUrl) {
    throw new Error("Missing env: DUCKMAIL_BASE_URL (required when MAIL_PROVIDER=duckmail)");
  }
  const fallbackRunMode: RunMode = toBool(process.env.HEADLESS, false) ? "headless" : "headed";
  const verifyHostAllowlist = parseCsvList(process.env.VERIFY_HOST_ALLOWLIST).map((host) => host.toLowerCase());
  const blockedMailboxDomains = Array.from(new Set(parseCsvList(process.env.BLOCKED_MAILBOX_DOMAINS).map((item) => item.trim().toLowerCase()))).filter(
    (item) => item.length > 0,
  );
  const defaultApiPort = 39090 + randomInt(0, 2000);
  const defaultMixedPort = 49090 + randomInt(0, 2000);
  const existingEmail = (process.env.EXISTING_EMAIL || "").trim() || undefined;
  const existingPassword = (process.env.EXISTING_PASSWORD || "").trim() || undefined;
  const microsoftAccountEmail = (process.env.MICROSOFT_ACCOUNT_EMAIL || "").trim() || undefined;
  const microsoftAccountPassword = (process.env.MICROSOFT_ACCOUNT_PASSWORD || "").trim() || undefined;
  const rawMicrosoftProofMailboxProvider = (process.env.MICROSOFT_PROOF_MAILBOX_PROVIDER || "").trim().toLowerCase();
  const microsoftProofMailboxProvider = rawMicrosoftProofMailboxProvider
    ? rawMicrosoftProofMailboxProvider === "moemail"
      ? "moemail"
      : null
    : undefined;
  const microsoftProofMailboxAddress = (process.env.MICROSOFT_PROOF_MAILBOX_ADDRESS || "").trim() || undefined;
  const microsoftProofMailboxId = (process.env.MICROSOFT_PROOF_MAILBOX_ID || "").trim() || undefined;
  const resolvedChromeExecutablePath = resolveChromeExecutablePath(process.env.CHROME_EXECUTABLE_PATH);
  if (resolvedChromeExecutablePath && !isFingerprintChromiumExecutable(resolvedChromeExecutablePath)) {
    throw new Error(`Unsupported CHROME_EXECUTABLE_PATH: ${resolvedChromeExecutablePath}. Only fingerprint Chromium is allowed.`);
  }
  if (rawMicrosoftProofMailboxProvider && !microsoftProofMailboxProvider) {
    throw new Error(`Unsupported env MICROSOFT_PROOF_MAILBOX_PROVIDER: ${rawMicrosoftProofMailboxProvider}`);
  }
  if (microsoftProofMailboxProvider && !microsoftProofMailboxAddress) {
    throw new Error("MICROSOFT_PROOF_MAILBOX_PROVIDER requires MICROSOFT_PROOF_MAILBOX_ADDRESS");
  }
  if (microsoftProofMailboxId && !microsoftProofMailboxAddress) {
    throw new Error("MICROSOFT_PROOF_MAILBOX_ID requires MICROSOFT_PROOF_MAILBOX_ADDRESS");
  }
  if ((existingEmail && !existingPassword) || (!existingEmail && existingPassword)) {
    throw new Error("EXISTING_EMAIL and EXISTING_PASSWORD must be configured together");
  }
  if ((microsoftAccountEmail && !microsoftAccountPassword) || (!microsoftAccountEmail && microsoftAccountPassword)) {
    throw new Error("MICROSOFT_ACCOUNT_EMAIL and MICROSOFT_ACCOUNT_PASSWORD must be configured together");
  }
  if ((existingEmail || existingPassword) && (microsoftAccountEmail || microsoftAccountPassword)) {
    throw new Error("Configure either EXISTING_EMAIL/EXISTING_PASSWORD or MICROSOFT_ACCOUNT_EMAIL/MICROSOFT_ACCOUNT_PASSWORD, not both");
  }

  return {
    runMode: envRunMode || fallbackRunMode,
    browserEngine: envBrowserEngine,
    inspectBrowserEngine: envInspectBrowserEngine,
    chromeExecutablePath: resolvedChromeExecutablePath,
    chromeNativeAutomation: toBool(process.env.CHROME_NATIVE_AUTOMATION, true),
    chromeActivateOnLaunch: toBool(process.env.CHROME_ACTIVATE_ON_LAUNCH, true),
    chromeIdentityOverride: toBool(process.env.CHROME_IDENTITY_OVERRIDE, true),
    chromeStealthJsEnabled: toBool(process.env.CHROME_STEALTH_JS_ENABLED, true),
    chromeWebrtcHardened: toBool(process.env.CHROME_WEBRTC_HARDENED, true),
    chromeProfileDir: path.resolve(process.env.CHROME_PROFILE_DIR || path.join(OUTPUT_PATH, "chrome-profile")),
    chromeRemoteDebuggingPort: Math.max(0, toInt(process.env.CHROME_REMOTE_DEBUGGING_PORT, 0)),
    slowMoMs: toInt(process.env.SLOWMO_MS, 50),
    maxCaptchaRounds: toInt(process.env.MAX_CAPTCHA_ROUNDS, 30),
    allowPasswordSubmitWithoutCaptcha: toBool(process.env.ALLOW_PASSWORD_SUBMIT_WITHOUT_CAPTCHA, false),
    humanConfirmBeforeSignup: toBool(process.env.HUMAN_CONFIRM_BEFORE_SIGNUP, false),
    humanConfirmText: (process.env.HUMAN_CONFIRM_TEXT || "CONFIRM").trim() || "CONFIRM",
    mailProvider: envMailProvider,
    blockedMailboxDomains,
    mailPollMs: toInt(process.env.MAIL_POLL_MS || process.env.DUCKMAIL_POLL_MS, 2500),
    gptmailBaseUrl,
    vmailBaseUrl,
    vmailApiKey: (process.env.VMAIL_API_KEY || "").trim() || undefined,
    vmailDomain: (process.env.VMAIL_DOMAIN || "").trim() || undefined,
    moemailBaseUrl,
    moemailApiKey: (process.env.MOEMAIL_API_KEY || "").trim() || undefined,
    duckmailBaseUrl,
    duckmailApiKey: (process.env.DUCKMAIL_API_KEY || "").trim() || undefined,
    duckmailDomain: (process.env.DUCKMAIL_DOMAIN || "").trim() || undefined,
    emailWaitMs: toInt(process.env.EMAIL_WAIT_MS, 180_000),
    keyName: (process.env.KEY_NAME || "").trim() || `reg-key-${String(Date.now()).slice(-6)}`,
    keyLimit: toInt(process.env.KEY_LIMIT, 1000),
    existingEmail,
    existingPassword,
    microsoftAccountEmail,
    microsoftAccountPassword,
    microsoftProofMailboxProvider: microsoftProofMailboxAddress ? (microsoftProofMailboxProvider || "moemail") : undefined,
    microsoftProofMailboxAddress,
    microsoftProofMailboxId,
    microsoftKeepSignedIn: toBool(process.env.MICROSOFT_KEEP_SIGNED_IN, true),
    mihomoSubscriptionUrl: mustEnv("MIHOMO_SUBSCRIPTION_URL"),
    mihomoGroupName: (process.env.MIHOMO_GROUP_NAME || "CODEX_AUTO").trim() || "CODEX_AUTO",
    mihomoRouteGroupName: (process.env.MIHOMO_ROUTE_GROUP_NAME || "CODEX_ROUTE").trim() || "CODEX_ROUTE",
    mihomoApiPort: toInt(process.env.MIHOMO_API_PORT, defaultApiPort),
    mihomoMixedPort: toInt(process.env.MIHOMO_MIXED_PORT, defaultMixedPort),
    proxyCheckUrl: (process.env.PROXY_CHECK_URL || "https://www.cloudflare.com/cdn-cgi/trace").trim(),
    proxyCheckTimeoutMs: toInt(process.env.PROXY_CHECK_TIMEOUT_MS, 8000),
    proxyLatencyMaxMs: toInt(process.env.PROXY_LATENCY_MAX_MS, 3000),
    ipinfoToken: (process.env.IPINFO_TOKEN || "").trim() || undefined,
    browserPrecheckEnabled: toBool(process.env.BROWSER_PRECHECK_ENABLED, true),
    browserPrecheckStrict: toBool(process.env.BROWSER_PRECHECK_STRICT, true),
    browserPrecheckCheckHostingProvider: toBool(process.env.BROWSER_PRECHECK_CHECK_HOSTING_PROVIDER, false),
    requireWebrtcVisible: toBool(process.env.REQUIRE_WEBRTC_VISIBLE, false),
    verifyHostAllowlist:
      verifyHostAllowlist.length > 0
        ? verifyHostAllowlist
        : ["tavily.com", "auth.tavily.com", "app.tavily.com"],
    modeRetryMax: Math.max(1, toInt(process.env.MODE_RETRY_MAX, 3)),
    browserLaunchRetryMax: Math.max(1, toInt(process.env.BROWSER_LAUNCH_RETRY_MAX, 3)),
    taskAttemptTimeoutMs: Math.max(60_000, toInt(process.env.TASK_ATTEMPT_TIMEOUT_MS, 8 * 60_000)),
    nodeReuseCooldownMs: Math.max(12 * 60 * 60_000, toInt(process.env.NODE_REUSE_COOLDOWN_MS, 12 * 60 * 60_000)),
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
      dbPath: resolveTaskLedgerDbPath(OUTPUT_PATH, process.env.TASK_LEDGER_DB_PATH),
      busyTimeoutMs: Math.max(500, toInt(process.env.TASK_LEDGER_BUSY_TIMEOUT_MS, 5000)),
      ipRateLimitCooldownMs: Math.max(
        60_000,
        toInt(process.env.TASK_LEDGER_IP_RATE_LIMIT_COOLDOWN_MS, 12 * 60 * 60 * 1000),
      ),
      ipRateLimitMax: Math.max(1, toInt(process.env.TASK_LEDGER_IP_RATE_LIMIT_MAX, 64)),
      captchaMissingCooldownMs: Math.max(
        60_000,
        toInt(process.env.TASK_LEDGER_CAPTCHA_MISSING_COOLDOWN_MS, 12 * 60 * 60 * 1000),
      ),
      captchaMissingMax: Math.max(1, toInt(process.env.TASK_LEDGER_CAPTCHA_MISSING_MAX, 64)),
      captchaMissingThreshold: Math.max(1, toInt(process.env.TASK_LEDGER_CAPTCHA_MISSING_THRESHOLD, 2)),
      invalidCaptchaCooldownMs: Math.max(
        60_000,
        toInt(process.env.TASK_LEDGER_INVALID_CAPTCHA_COOLDOWN_MS, 8 * 60 * 60 * 1000),
      ),
      invalidCaptchaMax: Math.max(1, toInt(process.env.TASK_LEDGER_INVALID_CAPTCHA_MAX, 64)),
      invalidCaptchaThreshold: Math.max(1, toInt(process.env.TASK_LEDGER_INVALID_CAPTCHA_THRESHOLD, 3)),
      allowRateLimitedIpFallback: toBool(process.env.ALLOW_RATE_LIMITED_IP_FALLBACK, false),
    },
  };
}

function isRecoverableBrowserError(reason: string): boolean {
  return /Execution context was destroyed|Target closed|Navigation|Cannot find context|page has been closed|context has been closed|browser has been closed|Target page, context or browser has been closed/i.test(
    reason,
  );
}

function shouldRetryModeFailure(message: string): boolean {
  return /proxy_node_unavailable|proxy_no_distinct_egress_ip|browser precheck failed|ip\.skk did not expose an IP address|expected proxy IP not observed|cross-site IP mismatch|golden ip mismatch|webrtc probe candidates do not include expected proxy IP|captcha failed|captcha_ocr_unstable|signup_password_captcha_missing|signup password step failed|risk_control_suspicious_activity|risk_control_ip_rate_limit|too_many_signups_same_ip|invalid_captcha|native_cdp_unavailable|timeout|network|fetch failed|ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET|ERR_TIMED_OUT|Target closed|context has been closed|Failed to launch the browser process|browser has been closed/i.test(
    message,
  );
}

function shouldRetryTaskFailure(message: string): boolean {
  return !/browser_proxy_ip_missing|browser_proxy_same_as_local_ip|browser_proxy_ip_mismatch|risk_control_suspicious_activity|risk_control_ip_rate_limit|too_many_signups_same_ip|auth0_extensibility_error|mailbox_rate_limited|mailbox_domain_blocked|proxy_ip_quota_exceeded|proxy_node_inventory_empty|proxy_all_nodes_busy|proxy_distinct_ip_capacity_exhausted|mihomo_subscription_failed|mihomo_subscription_empty|microsoft_password_rate_limited|microsoft_password_incorrect|microsoft_password_submit_stalled|microsoft_provider_submit_stalled|microsoft_consent_accept_missing|microsoft_passkey_cancel_missing|microsoft_proof_add_email_input_missing|microsoft_proof_add_submit_missing|microsoft_proof_mailbox_missing|moemail_api_key_missing|moemail_mailbox_not_found|microsoft_proof_code_timeout|microsoft_proof_submit_failed|microsoft_unknown_recovery_email|microsoft_account_locked|microsoft_account_credentials_missing|unsupported_microsoft_proof_mailbox_provider|microsoft_auth_try_again_later|stage_login_home|login flow did not reach home|microsoft login flow did not reach home|referenceerror:\s*__name is not defined|__name is not defined/i.test(
    message,
  );
}

function shouldAbortBatchFailure(message: string): boolean {
  return /browser_proxy_same_as_local_ip|browser_proxy_ip_mismatch|proxy_node_inventory_empty|proxy_all_nodes_busy|proxy_distinct_ip_capacity_exhausted|mihomo_subscription_failed|mihomo_subscription_empty|Target page, context or browser has been closed|page has been closed|context has been closed|browser has been closed/i.test(
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

function getChromePasskeyDisableArgs(): string[] {
  const disabledFeatures = [
    "WebAuthentication",
    "WebAuthenticationBle",
    "WebAuthenticationCable",
    "WebAuthenticationConditionalUI",
    "WebAuthenticationPasskeysUI",
    "WebAuthenticationPasskeysUIExperiment",
    "WebAuthenticationPhoneSupport",
    "WebAuthenticationUI",
    "SecurePaymentConfirmationBrowser",
    "SecurePaymentConfirmationDebug",
  ];
  const disabledBlinkFeatures = [
    "AutomationControlled",
    "WebAuthenticationConditionalUI",
  ];
  return [
    `--disable-features=${disabledFeatures.join(",")}`,
    `--disable-blink-features=${disabledBlinkFeatures.join(",")}`,
  ];
}

function getChromeCredentialStoreArgs(): string[] {
  if (process.platform !== "darwin") return [];
  return ["--use-mock-keychain", "--password-store=basic"];
}

function getChromeNativePlatformArgs(): string[] {
  if (process.platform !== "linux") return [];
  return [
    "--no-sandbox",
    "--disable-dev-shm-usage",
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

function normalizePlatformVersion(raw: string, fallback = "0.0.0"): string {
  const parts = String(raw || "")
    .split(/[^0-9]+/)
    .filter((item) => item.length > 0)
    .slice(0, 3);
  while (parts.length < 3) parts.push("0");
  const normalized = parts.join(".");
  return /^\d+\.\d+\.\d+$/.test(normalized) ? normalized : fallback;
}

function buildBrowserIdentityProfile(locale: string, browserVersion: string): BrowserIdentityProfile {
  const normalizedLocale = locale || "en-US";
  const langPrefix = (normalizedLocale.split("-")[0] || "en").toLowerCase();
  const fallbackRegion = normalizedLocale.split("-")[1] || "US";
  const variantLanguages = shuffleChars([`${langPrefix}-${fallbackRegion}`, langPrefix, "en-US"]);
  const languages = [normalizedLocale, ...variantLanguages]
    .map((item) => item.trim())
    .filter((item, index, all) => item.length > 0 && all.indexOf(item) === index)
    .slice(0, 3);
  const acceptLanguage = `${languages[0]},${langPrefix};q=0.9,en;q=0.8`;
  const chromeVersion = normalizeChromeVersion(browserVersion);
  const isLinux = process.platform === "linux";
  const userAgent = isLinux
    ? `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} Safari/537.36`
    : `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} Safari/537.36`;
  return {
    userAgent,
    navigatorPlatform: isLinux ? "Linux x86_64" : "MacIntel",
    cdpPlatform: isLinux ? "Linux" : "macOS",
    cdpPlatformVersion: isLinux ? normalizePlatformVersion(osRelease(), "6.0.0") : "10.15.7",
    cdpArchitecture: "x86",
    cdpBitness: "64",
    acceptLanguage,
    languages,
    vendor: "Google Inc.",
    hardwareConcurrency: [4, 8, 10, 12][randomInt(0, 4)] || 8,
    deviceMemory: [4, 8, 16][randomInt(0, 3)] || 8,
    maxTouchPoints: 0,
    webglVendor: isLinux ? undefined : "Intel Inc.",
    webglRenderer: isLinux ? undefined : "Intel Iris OpenGL Engine",
  };
}

const IDENTITY_BOUND_CONTEXTS = new WeakSet<object>();
const PASSKEY_SUPPRESSION_BOUND_CONTEXTS = new WeakSet<object>();
const AUTH_REQUEST_ROUTE_BOUND_CONTEXTS = new WeakSet<object>();
const WORKER_PASSKEY_SUPPRESSION_SCRIPT = `(() => {
  if ((globalThis).__kohaWorkerPasskeySuppressed) {
    return true;
  }
  (globalThis).__kohaWorkerPasskeySuppressed = true;
  const notSupportedError = () => {
    try {
      return new DOMException("Passkeys disabled by automation", "NotSupportedError");
    } catch {
      const error = new Error("Passkeys disabled by automation");
      error.name = "NotSupportedError";
      return error;
    }
  };
  const rejectPublicKey = () => Promise.reject(notSupportedError());
  const patchCredentialMethod = (target, key) => {
    if (!target) return;
    const original = typeof target[key] === "function" ? target[key].bind(target) : null;
    const wrapped = function(options) {
      if (options && typeof options === "object" && "publicKey" in options) {
        return rejectPublicKey();
      }
      if (original) {
        return original(options);
      }
      return rejectPublicKey();
    };
    try {
      Object.defineProperty(target, key, {
        configurable: true,
        writable: true,
        value: wrapped,
      });
      return;
    } catch {}
    try {
      target[key] = wrapped;
    } catch {}
  };
  const credentials = globalThis.navigator?.credentials || null;
  patchCredentialMethod(credentials, "create");
  patchCredentialMethod(credentials, "get");
  const publicKeyCredential = globalThis.PublicKeyCredential;
  if (publicKeyCredential) {
    const defineStatic = (key, value) => {
      try {
        Object.defineProperty(publicKeyCredential, key, {
          configurable: true,
          writable: true,
          value,
        });
      } catch {}
    };
    defineStatic("isUserVerifyingPlatformAuthenticatorAvailable", async () => false);
    defineStatic("isConditionalMediationAvailable", async () => false);
    defineStatic("getClientCapabilities", async () => ({
      conditionalCreate: false,
      conditionalGet: false,
      hybridTransport: false,
      userVerifyingPlatformAuthenticator: false,
    }));
  } else {
    try {
      Object.defineProperty(globalThis, "PublicKeyCredential", {
        configurable: true,
        writable: true,
        value: undefined,
      });
    } catch {}
  }
  return true;
})()`;

async function installMicrosoftPasskeySuppression(context: any): Promise<void> {
  const contextObj = context as object;
  if (!PASSKEY_SUPPRESSION_BOUND_CONTEXTS.has(contextObj) && typeof context?.addInitScript === "function") {
    await context.addInitScript({ content: WORKER_PASSKEY_SUPPRESSION_SCRIPT }).catch(() => {});
    PASSKEY_SUPPRESSION_BOUND_CONTEXTS.add(contextObj);
  }
  const pages = typeof context?.pages === "function" ? context.pages() : [];
  for (const page of pages) {
    await page.evaluate(WORKER_PASSKEY_SUPPRESSION_SCRIPT).catch(() => {});
  }
}

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
  const normalizedChromeVersion = normalizeChromeVersion(identity.userAgent);
  const chromeMajorVersion = normalizedChromeVersion.split(".")[0] || "145";

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
      userAgentMetadata: {
        brands: [
          { brand: "Not:A-Brand", version: "99" },
          { brand: "Google Chrome", version: chromeMajorVersion },
          { brand: "Chromium", version: chromeMajorVersion },
        ],
        fullVersionList: [
          { brand: "Not:A-Brand", version: "99.0.0.0" },
          { brand: "Google Chrome", version: normalizedChromeVersion },
          { brand: "Chromium", version: normalizedChromeVersion },
        ],
        platform: identity.cdpPlatform,
        platformVersion: identity.cdpPlatformVersion,
        architecture: identity.cdpArchitecture,
        model: "",
        mobile: false,
        bitness: identity.cdpBitness,
        wow64: false,
      },
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
  injectNavigatorOverrides = true,
): Promise<void> {
  await installMicrosoftPasskeySuppression(context).catch(() => {});
  await context
    .setExtraHTTPHeaders({
      "Accept-Language": identity.acceptLanguage,
      "User-Agent": identity.userAgent,
    })
    .catch(() => {});
  if (injectNavigatorOverrides) {
    await context
      .addInitScript((profile: BrowserIdentityProfile) => {
        const defineReadonly = (key: string, value: unknown): void => {
          const targets = [navigator, (window as any).Navigator?.prototype].filter(Boolean);
          for (const target of targets) {
            try {
              Object.defineProperty(target, key, {
                configurable: true,
                get: () => value,
              });
            } catch {
              // ignore sealed properties
            }
          }
        };
        const firstLanguage = profile.languages[0] || "en-US";
        defineReadonly("userAgent", profile.userAgent);
        defineReadonly("appVersion", profile.userAgent.replace(/^Mozilla\//, ""));
        defineReadonly("platform", profile.navigatorPlatform);
        defineReadonly("vendor", profile.vendor);
        defineReadonly("language", firstLanguage);
        defineReadonly("languages", profile.languages);
        defineReadonly("hardwareConcurrency", profile.hardwareConcurrency);
        defineReadonly("deviceMemory", profile.deviceMemory);
        defineReadonly("maxTouchPoints", profile.maxTouchPoints);
        defineReadonly("pdfViewerEnabled", true);

        const pdfMimeType = {
          type: "application/pdf",
          suffixes: "pdf",
          description: "Portable Document Format",
          enabledPlugin: null as any,
        };
        const pdfPlugin = {
          name: "Chrome PDF Viewer",
          filename: "internal-pdf-viewer",
          description: "Portable Document Format",
          0: pdfMimeType,
          length: 1,
          item: (index: number) => (index === 0 ? pdfMimeType : null),
          namedItem: (name: string) => (name === pdfMimeType.type ? pdfMimeType : null),
        };
        pdfMimeType.enabledPlugin = pdfPlugin;
        const plugins = {
          0: pdfPlugin,
          length: 1,
          item: (index: number) => (index === 0 ? pdfPlugin : null),
          namedItem: (name: string) => (name === pdfPlugin.name ? pdfPlugin : null),
          refresh: () => undefined,
          [Symbol.iterator]: function* () {
            yield pdfPlugin;
          },
        };
        const mimeTypes = {
          0: pdfMimeType,
          length: 1,
          item: (index: number) => (index === 0 ? pdfMimeType : null),
          namedItem: (name: string) => (name === pdfMimeType.type ? pdfMimeType : null),
          [Symbol.iterator]: function* () {
            yield pdfMimeType;
          },
        };
        defineReadonly("plugins", plugins);
        defineReadonly("mimeTypes", mimeTypes);

        const patchWebgl = (Ctor: any): void => {
          if (!Ctor?.prototype?.getParameter) return;
          const originalGetParameter = Ctor.prototype.getParameter;
          Ctor.prototype.getParameter = function (param: number) {
            if (param === 37445 && profile.webglVendor) return profile.webglVendor;
            if (param === 37446 && profile.webglRenderer) return profile.webglRenderer;
            return originalGetParameter.call(this, param);
          };
        };
        patchWebgl((window as any).WebGLRenderingContext);
        patchWebgl((window as any).WebGL2RenderingContext);
      }, identity)
      .catch(() => {});
  }

  const applyToPage = async (page: any): Promise<void> => {
    await page.evaluate(WORKER_PASSKEY_SUPPRESSION_SCRIPT).catch(() => {});
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

export async function launchBrowserWithEngine(
  engine: BrowserEngine,
  cfg: AppConfig,
  mode: "headed" | "headless",
  proxyServer: string | undefined,
  locale: string,
  _geoIp: string,
): Promise<Browser> {
  const options: LaunchOptions = {
    headless: mode === "headless",
    slowMo: Math.max(0, cfg.slowMoMs),
    ignoreDefaultArgs: ["--enable-automation"],
    args: [
      `--lang=${locale}`,
      ...getChromePasskeyDisableArgs(),
      ...getChromeVisualArgs(),
      ...getChromeWebRtcPolicyArgs(cfg),
    ],
    timeout: 180_000,
  };
  if (proxyServer?.trim()) {
    options.proxy = { server: proxyServer.trim() };
  }
  const executablePath = requireFingerprintChromiumExecutablePath(cfg.chromeExecutablePath);
  options.executablePath = executablePath;
  const browser = await chromium.launch(options);
  if (process.platform === "darwin" && mode === "headed" && cfg.chromeActivateOnLaunch) {
    await activateMacApp(resolveChromeAppName(executablePath));
  }
  return browser;
}

function trySignalChildProcess(child: ReturnType<typeof spawn>, signal: NodeJS.Signals): void {
  const pid = child.pid;
  if (!pid) return;
  try {
    process.kill(-pid, signal);
    return;
  } catch {
    // fall back to the direct child pid when no dedicated process group exists
  }
  try {
    child.kill(signal);
  } catch {
    // ignore races while shutting down
  }
}

function createChildProcessStopper(child: ReturnType<typeof spawn>, profileDir?: string): () => Promise<void> {
  let stopping = false;
  return async () => {
    if (stopping) return;
    stopping = true;
    if (child.exitCode == null) {
      trySignalChildProcess(child, "SIGTERM");
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        if (child.exitCode != null) break;
        await delay(150);
      }
      if (child.exitCode == null) {
        trySignalChildProcess(child, "SIGKILL");
      }
    }
    if (profileDir) {
      await cleanupManagedChromeProcesses(profileDir).catch(() => {});
    }
  };
}

async function awaitCleanupBestEffort(task: Promise<unknown>, timeoutMs = 5_000): Promise<void> {
  await Promise.race([
    task.catch(() => {}),
    delay(timeoutMs),
  ]);
}

async function activateMacApp(appName: string): Promise<void> {
  if (process.platform !== "darwin") return;
  await new Promise<void>((resolve) => {
    const child = spawn("osascript", ["-e", `tell application "${appName}" to activate`], {
      stdio: "ignore",
    });
    child.once("error", () => resolve());
    child.once("exit", () => resolve());
  });
}

async function readPsTable(): Promise<Array<{ pid: number; pgid: number; command: string }>> {
  return await new Promise((resolve) => {
    const child = spawn("ps", ["-axo", "pid=,pgid=,command="], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    let stdout = "";
    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    const finish = () => {
      const rows = stdout
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const match = line.match(/^(\d+)\s+(\d+)\s+(.*)$/);
          if (!match) return null;
          return {
            pid: Number(match[1]),
            pgid: Number(match[2]),
            command: match[3] || "",
          };
        })
        .filter((row): row is { pid: number; pgid: number; command: string } => Boolean(row));
      resolve(rows);
    };
    child.once("error", () => resolve([]));
    child.once("close", finish);
  });
}

function normalizeProfileDir(profileDir: string): string {
  return path.resolve(profileDir).replace(/[\/]+$/, "");
}

function commandMatchesProfileDir(command: string, profileDir: string): boolean {
  if (!command || !profileDir) return false;
  return command.includes(`--user-data-dir=${profileDir}`);
}

async function cleanupChromeProfileArtifacts(profileDir: string): Promise<void> {
  const artifactNames = [
    'SingletonLock',
    'SingletonCookie',
    'SingletonSocket',
    'DevToolsActivePort',
    'CrashpadMetrics-active.pma',
  ];
  for (const name of artifactNames) {
    try {
      await rm(path.join(profileDir, name), { force: true, recursive: true });
    } catch {
      // ignore stale artifact cleanup failures
    }
  }
}

async function cleanupManagedChromeProcesses(profileDir: string): Promise<void> {
  const normalizedProfileDir = normalizeProfileDir(profileDir);
  const collectMatched = async () =>
    (await readPsTable()).filter((entry) => commandMatchesProfileDir(entry.command, normalizedProfileDir));

  let matched = await collectMatched();
  if (matched.length === 0) {
    await cleanupChromeProfileArtifacts(normalizedProfileDir).catch(() => {});
    return;
  }

  const signalMatched = (signal: NodeJS.Signals, rows: Array<{ pid: number; pgid: number; command: string }>) => {
    const pgids = Array.from(new Set(rows.map((entry) => entry.pgid).filter((pgid) => pgid > 1)));
    for (const pgid of pgids) {
      try {
        process.kill(-pgid, signal);
      } catch {
        // ignore vanished groups
      }
    }
    for (const entry of rows) {
      try {
        process.kill(entry.pid, signal);
      } catch {
        // ignore vanished children
      }
    }
  };

  signalMatched("SIGTERM", matched);
  const gracefulDeadline = Date.now() + 4_000;
  while (Date.now() < gracefulDeadline) {
    await delay(150);
    matched = await collectMatched();
    if (matched.length === 0) return;
  }

  signalMatched("SIGKILL", matched);
  const forceDeadline = Date.now() + 2_000;
  while (Date.now() < forceDeadline) {
    await delay(120);
    matched = await collectMatched();
    if (matched.length === 0) {
      await cleanupChromeProfileArtifacts(normalizedProfileDir).catch(() => {});
      return;
    }
  }
  await cleanupChromeProfileArtifacts(normalizedProfileDir).catch(() => {});
}

export async function cleanupManagedChromeProcessesUnder(baseDir: string): Promise<void> {
  const normalizedBaseDir = `${normalizeProfileDir(baseDir)}${pathSep}`;
  const processes = await readPsTable();
  const profileDirs = new Set<string>();
  for (const entry of processes) {
    const match = entry.command.match(/--user-data-dir=([^\s]+)/);
    const profileDir = match?.[1]?.trim();
    if (!profileDir) continue;
    const normalizedProfileDir = normalizeProfileDir(profileDir);
    if (normalizedProfileDir.startsWith(normalizedBaseDir)) {
      profileDirs.add(normalizedProfileDir);
    }
  }
  for (const profileDir of profileDirs) {
    await cleanupManagedChromeProcesses(profileDir);
  }
}

function buildChromeProfileCandidates(baseDir: string): string[] {
  const runProfile = path.join(baseDir, `run-${Date.now()}-${randomInt(1000, 9999)}`);
  // Each registration attempt must get its own isolated Chrome profile.
  return [runProfile];
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

const RESERVED_LOCAL_PORTS = new Set<number>();

async function reserveLocalPort(): Promise<number> {
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
          reject(new Error("failed to reserve local port"));
          return;
        }
        resolve(port);
      });
    });
  });
}

async function reserveUniqueLocalPort(): Promise<number> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const port = await reserveLocalPort();
    if (RESERVED_LOCAL_PORTS.has(port)) {
      continue;
    }
    RESERVED_LOCAL_PORTS.add(port);
    return port;
  }
  throw new Error("failed to reserve a unique local port");
}

async function reserveMihomoPorts(): Promise<{ apiPort: number; mixedPort: number }> {
  const apiPort = await reserveUniqueLocalPort();
  let mixedPort = await reserveUniqueLocalPort();
  while (mixedPort === apiPort) {
    mixedPort = await reserveUniqueLocalPort();
  }
  return { apiPort, mixedPort };
}

async function readChromeDevToolsActivePort(profileDir: string): Promise<{ port: number; wsPath?: string } | null> {
  try {
    const raw = await readFile(path.join(profileDir, "DevToolsActivePort"), "utf8");
    const [portLine, wsPathLine] = raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const filePort = Number.parseInt(portLine || "", 10);
    if (!Number.isFinite(filePort) || filePort <= 0) {
      return null;
    }
    return {
      port: filePort,
      wsPath: wsPathLine || undefined,
    };
  } catch {
    return null;
  }
}

async function waitForChromeWsEndpoint(
  port: number,
  profileDir: string,
  timeoutMs = 40_000,
  signal?: AbortSignal,
  childPid?: number,
): Promise<string> {
  const endpoint = `http://127.0.0.1:${port}/json/version`;
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    throwIfAborted(signal, `native chrome debugger wait aborted on port ${port}`);
    if (childPid && !isPidAlive(childPid)) {
      throw new Error(`native chrome exited before debugger became ready on port ${port} (profile=${profileDir})`);
    }
    try {
      const resp = await raceWithAbort(
        fetchWithTimeout(endpoint, 2500),
        signal,
        `native chrome debugger wait aborted on port ${port}`,
      );
      if (resp.ok) {
        const payload = (await resp.json()) as JsonRecord;
        const ws = typeof payload.webSocketDebuggerUrl === "string" ? payload.webSocketDebuggerUrl.trim() : "";
        if (ws) return ws;
      }
    } catch {
      // retry until timeout
    }
    const activePort = await readChromeDevToolsActivePort(profileDir);
    if (activePort?.port) {
      const candidateWs = activePort.wsPath?.startsWith("/")
        ? `ws://127.0.0.1:${activePort.port}${activePort.wsPath}`
        : "";
      if (candidateWs) {
        return candidateWs;
      }
      if (activePort.port !== port) {
        try {
          const fallbackResp = await raceWithAbort(
            fetchWithTimeout(`http://127.0.0.1:${activePort.port}/json/version`, 2500),
            signal,
            `native chrome debugger wait aborted on port ${port}`,
          );
          if (fallbackResp.ok) {
            const payload = (await fallbackResp.json()) as JsonRecord;
            const ws = typeof payload.webSocketDebuggerUrl === "string" ? payload.webSocketDebuggerUrl.trim() : "";
            if (ws) return ws;
          }
        } catch {
          // keep polling
        }
      }
    }
    await raceWithAbort(delay(250), signal, `native chrome debugger wait aborted on port ${port}`);
  }
  throw new Error(`native chrome debugger endpoint timeout on port ${port} (profile=${profileDir})`);
}

function isPidAlive(pid: number | undefined): boolean {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function launchNativeChromeCdp(
  cfg: AppConfig,
  mode: "headed" | "headless",
  proxyServer: string,
  locale: string,
  acceptLanguage: string,
  timezoneId?: string,
  signal?: AbortSignal,
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
    throwIfAborted(signal, "native chrome launch aborted");
    const profileDir = profileCandidates[i]!;
    const usingBaseProfile = i > 0;
    await mkdir(profileDir, { recursive: true });
    await cleanupChromeProfileArtifacts(profileDir).catch(() => {});
    const debugPort = await resolveDebuggingPort(cfg.chromeRemoteDebuggingPort);
    const startupTargets = ["https://app.tavily.com/"];
    const args = [
      `--remote-debugging-port=${debugPort}`,
      "--remote-debugging-address=127.0.0.1",
      "--remote-allow-origins=*",
      `--user-data-dir=${profileDir}`,
      `--proxy-server=${proxyServer}`,
      `--lang=${locale}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-mode",
      "--disable-background-networking",
      ...getChromePasskeyDisableArgs(),
      ...getChromeVisualArgs(),
      ...getChromeWebRtcPolicyArgs(cfg),
      ...getChromeCredentialStoreArgs(),
      ...getChromeNativePlatformArgs(),
      ...getFingerprintChromiumArgs(cfg.chromeExecutablePath, profileDir, proxyServer, locale, acceptLanguage, timezoneId),
    ];
    if (mode === "headless") {
      args.push("--headless=new", "--hide-scrollbars", "--mute-audio", ...startupTargets);
    } else {
      args.push("--new-window", ...startupTargets);
    }
    const chromeLogPath = path.join(profileDir, "native-chrome.log");
    const chromeLogFd = openSync(chromeLogPath, "a");
    const child = spawn(cfg.chromeExecutablePath, args, { stdio: ["ignore", chromeLogFd, chromeLogFd], detached: true });
    child.unref();
    const stop = createChildProcessStopper(child, profileDir);
    const abortNativeChrome = () => {
      void stop().catch(() => {});
    };
    signal?.addEventListener("abort", abortNativeChrome, { once: true });
    try {
      await raceWithAbort(delay(1800), signal, "native chrome launch aborted during startup");
      if (child.exitCode != null) {
        lastError = new Error(
          `native chrome exited early: ${child.exitCode}${usingBaseProfile ? " (base profile fallback)" : ""}`,
        );
        continue;
      }
      if (!isPidAlive(child.pid)) {
        const chromeLog = existsSync(chromeLogPath) ? (await readFile(chromeLogPath, "utf8").catch(() => "")) : "";
        const compactLog = chromeLog.split(/\r?\n/).filter(Boolean).slice(-20).join(" | ");
        lastError = new Error(
          `native chrome exited before debugger became ready${usingBaseProfile ? " (base profile fallback)" : ""}${
            compactLog ? `: ${compactLog}` : ""
          }`,
        );
        await stop().catch(() => {});
        continue;
      }

      if (mode === "headed" && cfg.chromeActivateOnLaunch) {
        await raceWithAbort(
          activateMacApp(resolveChromeAppName(cfg.chromeExecutablePath)),
          signal,
          "native chrome launch aborted before activation",
        );
      }
      const wsEndpoint = await waitForChromeWsEndpoint(debugPort, profileDir, 40_000, signal, child.pid);
      // Prefer HTTP endpoint first; it is less sensitive to websocket handshake quirks on some hosts.
      const cdpEndpoints = [`http://127.0.0.1:${debugPort}`, wsEndpoint];
      let browser: Browser | null = null;
      const connectErrors: string[] = [];
      for (const endpoint of cdpEndpoints) {
        throwIfAborted(signal, "native chrome launch aborted before CDP connect");
        try {
          browser = await raceWithAbort(
            connectOverCdpWithTimeout(endpoint, 60_000),
            signal,
            `native chrome launch aborted while connecting to ${endpoint.startsWith("ws://") ? "ws" : "http"} endpoint`,
          );
          break;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          connectErrors.push(`${endpoint.startsWith("ws://") ? "ws" : "http"}: ${message.split("\n")[0]}`);
          await raceWithAbort(delay(500), signal, "native chrome launch aborted between CDP retries");
        }
      }
      if (!browser) {
        throw new Error(`overCDP: ${connectErrors.join(" | ") || "unknown connect error"}`);
      }
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
      const chromeLog = existsSync(chromeLogPath) ? (await readFile(chromeLogPath, "utf8").catch(() => "")) : "";
      const compactLog = chromeLog.split(/\r?\n/).filter(Boolean).slice(-20).join(" | ");
      const baseError = error instanceof Error ? error : new Error(String(error));
      lastError = compactLog ? new Error(`${baseError.message}; chrome_log=${compactLog}`) : baseError;
      await stop().catch(() => {});
    } finally {
      signal?.removeEventListener("abort", abortNativeChrome);
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
          "--no-first-run",
          "--no-default-browser-check",
          `--lang=${locale}`,
          ...getChromePasskeyDisableArgs(),
          ...getChromeVisualArgs(),
          ...getChromeWebRtcPolicyArgs(cfg),
          ...getChromeCredentialStoreArgs(),
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

function shouldUseNativeChromeAutomation(
  browserEngine: BrowserEngine,
  mode: "headed" | "headless",
  enabled: boolean,
): boolean {
  if (browserEngine !== "chrome" || !enabled) return false;
  void mode;
  return true;
}

async function launchNativeChromeInspect(
  cfg: AppConfig,
  proxyServer: string,
  locale: string,
  acceptLanguage: string,
  timezoneId?: string,
): Promise<{
  stop: () => Promise<void>;
  details: { executablePath: string; profileDir: string; targets: string[] };
}> {
  if (!cfg.chromeExecutablePath) {
    throw new Error("chrome executable path is not configured");
  }
  const targets = ["https://app.tavily.com/"];
  await mkdir(cfg.inspectChromeProfileDir, { recursive: true });
  await cleanupChromeProfileArtifacts(cfg.inspectChromeProfileDir).catch(() => {});

  const args = [
    `--user-data-dir=${cfg.inspectChromeProfileDir}`,
    `--proxy-server=${proxyServer}`,
    `--lang=${locale}`,
    ...getChromePasskeyDisableArgs(),
    ...getChromeVisualArgs(),
    ...getChromeWebRtcPolicyArgs(cfg),
    ...getChromeCredentialStoreArgs(),
    ...getChromeNativePlatformArgs(),
    ...getFingerprintChromiumArgs(cfg.chromeExecutablePath, cfg.inspectChromeProfileDir, proxyServer, locale, acceptLanguage, timezoneId),
    "--disable-background-mode",
    "--disable-background-networking",
    "--new-window",
    ...targets,
  ];
  const child = spawn(cfg.chromeExecutablePath, args, {
    stdio: "ignore",
    detached: true,
  });
  child.unref();
  const stop = createChildProcessStopper(child, cfg.inspectChromeProfileDir);
  await delay(1800);
  if (child.exitCode != null) {
    throw new Error(`native chrome exited early: ${child.exitCode}`);
  }
  if (cfg.chromeActivateOnLaunch) {
    await activateMacApp(resolveChromeAppName(cfg.chromeExecutablePath));
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

    const globalState = window as Window & {
      __kohaLastAuthCaptcha?: string;
      __kohaLastChallengeToken?: string;
      __kohaLastAuthEmail?: string;
      __kohaLastAuthPassword?: string;
      __kohaLastEmailCode?: string;
      __kohaAuthFieldWatcherInstalled?: boolean;
      __kohaTurnstileWidgetIds?: Array<string | number>;
      __kohaReadAuthChallengeToken?: () => string;
    };
    if (!globalState.__kohaAuthFieldWatcherInstalled) {
      globalState.__kohaAuthFieldWatcherInstalled = true;
      const ensureTokenField = (name: string, value: string): void => {
        if (!value) return;
        const primaryForm =
          (document.querySelector('form[data-form-primary="true"]') as HTMLFormElement | null) ||
          (document.querySelector("form") as HTMLFormElement | null);
        let field = document.querySelector(`[name="${name}"]`) as HTMLInputElement | HTMLTextAreaElement | null;
        if (!field && primaryForm) {
          const created = document.createElement("input");
          created.type = "hidden";
          created.name = name;
          primaryForm.appendChild(created);
          field = created;
        }
        if (!field) return;
        if ((field.value || "") !== value) {
          field.value = value;
        }
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      };
      const rememberChallengeToken = (rawValue: unknown): string => {
        const token = typeof rawValue === "string" ? rawValue.trim() : "";
        if (!token) return "";
        globalState.__kohaLastChallengeToken = token;
        globalState.__kohaLastAuthCaptcha = token;
        ensureTokenField("cf-turnstile-response", token);
        ensureTokenField("captcha", token);
        return token;
      };
      const readTurnstileRuntimeToken = (): string => {
        const directToken =
          (document.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null)?.value?.trim() ||
          (document.querySelector('input[name="g-recaptcha-response"]') as HTMLInputElement | null)?.value?.trim() ||
          (
            document.querySelector('textarea[name="h-captcha-response"], input[name="h-captcha-response"]') as
              | HTMLInputElement
              | HTMLTextAreaElement
              | null
          )?.value?.trim() ||
          (document.querySelector('input[name="captcha"]') as HTMLInputElement | null)?.value?.trim() ||
          "";
        if (directToken) return rememberChallengeToken(directToken);
        const turnstileApi = (window as Window & { turnstile?: { getResponse?: (...args: unknown[]) => unknown } }).turnstile;
        if (turnstileApi && typeof turnstileApi.getResponse === "function") {
          const widgetIds = Array.isArray(globalState.__kohaTurnstileWidgetIds) ? globalState.__kohaTurnstileWidgetIds : [];
          for (const candidate of [undefined, ...widgetIds]) {
            try {
              const response =
                candidate === undefined ? turnstileApi.getResponse() : turnstileApi.getResponse(candidate);
              if (typeof response === "string" && response.trim()) {
                return rememberChallengeToken(response);
              }
            } catch {
              // ignore widget lookup failures
            }
          }
        }
        return String(globalState.__kohaLastChallengeToken || globalState.__kohaLastAuthCaptcha || "").trim();
      };
      const registerTurnstileApi = (api: unknown): void => {
        if (!api || typeof api !== "object") return;
        const turnstileApi = api as {
          render?: (...args: unknown[]) => unknown;
          getResponse?: (...args: unknown[]) => unknown;
        };
        if (typeof turnstileApi.render === "function" && !(turnstileApi.render as any).__kohaWrapped) {
          const originalRender = turnstileApi.render.bind(turnstileApi);
          const wrappedRender = (...args: unknown[]) => {
            const maybeOptions = args[1];
            if (maybeOptions && typeof maybeOptions === "object") {
              const options = maybeOptions as Record<string, unknown>;
              const callback = options.callback;
              if (typeof callback === "function") {
                options.callback = (token: unknown, ...cbArgs: unknown[]) => {
                  rememberChallengeToken(token);
                  return (callback as (...innerArgs: unknown[]) => unknown)(token, ...cbArgs);
                };
              }
            }
            const widgetId = originalRender(...args);
            if (
              (typeof widgetId === "string" || typeof widgetId === "number") &&
              (!Array.isArray(globalState.__kohaTurnstileWidgetIds) ||
                !globalState.__kohaTurnstileWidgetIds.includes(widgetId))
            ) {
              globalState.__kohaTurnstileWidgetIds = [...(globalState.__kohaTurnstileWidgetIds || []), widgetId];
            }
            readTurnstileRuntimeToken();
            return widgetId;
          };
          (wrappedRender as any).__kohaWrapped = true;
          turnstileApi.render = wrappedRender;
        }
        if (typeof turnstileApi.getResponse === "function" && !(turnstileApi.getResponse as any).__kohaWrapped) {
          const originalGetResponse = turnstileApi.getResponse.bind(turnstileApi);
          const wrappedGetResponse = (...args: unknown[]) => {
            const response = originalGetResponse(...args);
            if (typeof response === "string" && response.trim()) {
              rememberChallengeToken(response);
            }
            return response;
          };
          (wrappedGetResponse as any).__kohaWrapped = true;
          turnstileApi.getResponse = wrappedGetResponse;
        }
      };
      globalState.__kohaReadAuthChallengeToken = () => readTurnstileRuntimeToken();
      let currentTurnstile = (window as Window & { turnstile?: unknown }).turnstile;
      if (currentTurnstile) registerTurnstileApi(currentTurnstile);
      const turnstileDescriptor = Object.getOwnPropertyDescriptor(window, "turnstile");
      if (!turnstileDescriptor || turnstileDescriptor.configurable) {
        Object.defineProperty(window, "turnstile", {
          configurable: true,
          enumerable: turnstileDescriptor?.enumerable ?? true,
          get: () => currentTurnstile,
          set: (value) => {
            currentTurnstile = value;
            registerTurnstileApi(value);
            readTurnstileRuntimeToken();
          },
        });
      }
      const syncFields = (): void => {
        const captchaField = document.querySelector('input[name="captcha"]') as HTMLInputElement | null;
        const turnstileField = document.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null;
        const recaptchaField = document.querySelector('input[name="g-recaptcha-response"]') as HTMLInputElement | null;
        const hcaptchaField = document.querySelector(
          'textarea[name="h-captcha-response"], input[name="h-captcha-response"]',
        ) as HTMLInputElement | HTMLTextAreaElement | null;
        const emailField = document.querySelector('input[name="email"], input[type="email"]') as HTMLInputElement | null;
        const passwordField = document.querySelector('input[name="password"], input[type="password"]') as HTMLInputElement | null;
        const codeField = document.querySelector('input[name="code"]') as HTMLInputElement | null;
        const captchaValue = typeof captchaField?.value === "string" ? captchaField.value.trim() : "";
        const runtimeChallengeToken = readTurnstileRuntimeToken();
        const challengeToken =
          (typeof turnstileField?.value === "string" ? turnstileField.value.trim() : "") ||
          (typeof recaptchaField?.value === "string" ? recaptchaField.value.trim() : "") ||
          (typeof hcaptchaField?.value === "string" ? hcaptchaField.value.trim() : "") ||
          runtimeChallengeToken;
        const emailValue = typeof emailField?.value === "string" ? emailField.value.trim() : "";
        const passwordValue = typeof passwordField?.value === "string" ? passwordField.value : "";
        const codeValue = typeof codeField?.value === "string" ? codeField.value.trim() : "";
        if (captchaValue) globalState.__kohaLastAuthCaptcha = captchaValue;
        if (challengeToken) globalState.__kohaLastChallengeToken = challengeToken;
        if (!captchaValue && captchaField && challengeToken) {
          captchaField.value = challengeToken;
          captchaField.dispatchEvent(new Event("input", { bubbles: true }));
          captchaField.dispatchEvent(new Event("change", { bubbles: true }));
          globalState.__kohaLastAuthCaptcha = challengeToken;
        }
        if (emailValue) globalState.__kohaLastAuthEmail = emailValue;
        if (passwordValue) globalState.__kohaLastAuthPassword = passwordValue;
        if (codeValue) globalState.__kohaLastEmailCode = codeValue;
      };
      const startWatcher = (): void => {
        syncFields();
        const observer = new MutationObserver(() => syncFields());
        observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ["value"] });
        window.setInterval(syncFields, 250);
        document.addEventListener("input", syncFields, true);
        document.addEventListener("change", syncFields, true);
      };
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", startWatcher, { once: true });
      } else {
        startWatcher();
      }
    }
  }, lang);
}

function collectBlockedIpsFromLedger(taskLedger: TaskLedger | null): Set<string> {
  const blockedIps = new Set<string>();
  if (!taskLedger) return blockedIps;
  try {
    // Only keep IP-scoped failures here. Mailbox/account-side validation must not poison proxy rotation.
    for (const ip of taskLedger.listRecentRateLimitedIps()) blockedIps.add(ip);
    for (const ip of taskLedger.listRecentCaptchaMissingIps()) blockedIps.add(ip);
    for (const ip of taskLedger.listRecentInvalidCaptchaIps()) blockedIps.add(ip);
  } catch (error) {
    log(`task ledger read skipped (recent blocked ips): ${error instanceof Error ? error.message : String(error)}`);
  }
  return blockedIps;
}

function collectBlockedIpsFromUsage(ipEmailUsage: Map<string, Set<string>>): Set<string> {
  const blockedIps = new Set<string>();
  for (const [ip, emails] of ipEmailUsage.entries()) {
    if (emails.size >= 3) {
      blockedIps.add(ip);
    }
  }
  return blockedIps;
}

async function preselectTaskProxy(
  cfg: AppConfig,
  args: CliArgs,
  batchId: string,
  taskId: string,
  taskLedger: TaskLedger | null,
  ipQuotaBlocked: Set<string>,
  runtimeRecentProxyIps: string[],
  busyProxyNames: Set<string>,
  busyProxyIps: Set<string>,
  existingController?: Awaited<ReturnType<typeof startMihomo>>,
): Promise<NodeCheckResult> {
  const blockedIps = collectBlockedIpsFromLedger(taskLedger);
  for (const ip of ipQuotaBlocked) blockedIps.add(ip);

  if (existingController) {
    return await selectProxyNode(
      existingController,
      cfg,
      args.proxyNode,
      blockedIps,
      runtimeRecentProxyIps,
      undefined,
      busyProxyNames,
      busyProxyIps,
    );
  }

  const batchEnabled = args.need > 1 || args.parallel > 1;
  let mihomoOverrides: { apiPort?: number; mixedPort?: number; workDir?: string } | undefined;
  if (batchEnabled) {
    const ports = await reserveMihomoPorts();
    mihomoOverrides = {
      apiPort: ports.apiPort,
      mixedPort: ports.mixedPort,
      workDir: path.join(OUTPUT_PATH, "mihomo", batchId, `${taskId}-preselect`),
    };
  }

  const controller = await startMihomo(buildMihomoConfig(cfg, mihomoOverrides));
  try {
    return await selectProxyNode(controller, cfg, args.proxyNode, blockedIps, runtimeRecentProxyIps, undefined, busyProxyNames, busyProxyIps);
  } finally {
    await controller.stop();
  }
}

async function createTaskMailboxSession(
  cfg: AppConfig,
  blockedDomains: ReadonlySet<string>,
  batchId: string,
  taskId: string,
  proxyName: string,
  proxyIpHint?: string,
): Promise<MailboxSession> {
  let mihomoOverrides: { apiPort?: number; mixedPort?: number; workDir?: string } | undefined;
  const ports = await reserveMihomoPorts();
  mihomoOverrides = {
    apiPort: ports.apiPort,
    mixedPort: ports.mixedPort,
    workDir: path.join(OUTPUT_PATH, "mihomo", batchId, `${taskId}-mailbox`),
  };

  const controller = await startMihomo(buildMihomoConfig(cfg, mihomoOverrides));
  try {
    await switchProxyGroup(controller, proxyName);
    const mailbox = await createMailboxSession(cfg, blockedDomains, controller.proxyServer);
    log(
      `mailbox created via task proxy: provider=${mailbox.provider} node=${proxyName} proxy_ip_hint=${proxyIpHint || "unknown"} address=${mailbox.address}`,
    );
    return mailbox;
  } finally {
    await controller.stop();
  }
}

async function prepareSignupTask(
  cfg: AppConfig,
  args: CliArgs,
  batchId: string,
  taskLedger: TaskLedger | null,
  existingController: Awaited<ReturnType<typeof startMihomo>> | undefined,
  ipEmailUsage: Map<string, Set<string>>,
  runtimeRecentProxyIps: string[],
  activeProxyNames: Set<string>,
  activeProxyIps: Set<string>,
  blockedMailboxDomains: ReadonlySet<string>,
  taskOrdinal: number,
  preloadMailbox: boolean,
): Promise<PreparedSignupTask> {
  const password = getConfiguredLoginPassword(cfg) || randomPassword();
  const ipQuotaBlocked = collectBlockedIpsFromUsage(ipEmailUsage);

  const taskId = `task-${taskOrdinal}-${randomBytes(2).toString("hex")}`;
  const proxyBootstrapAttempts = 6;
  let lastError: Error | null = null;
  const distinctIpCapacityError = (detail: string): Error =>
    new Error(`proxy_distinct_ip_capacity_exhausted:${detail}`);

  for (let attempt = 1; attempt <= proxyBootstrapAttempts; attempt += 1) {
    let selectedProxy: NodeCheckResult;
    let proxyIp: string | undefined;
    try {
      ({ selectedProxy, proxyIp } = await withProxyBootstrapLock(async () => {
        const proxy = await preselectTaskProxy(
          cfg,
          args,
          batchId,
          taskId,
          taskLedger,
          ipQuotaBlocked,
          runtimeRecentProxyIps,
          activeProxyNames,
          activeProxyIps,
          existingController,
        );
        const ip = normalizeIp(proxy.geo?.ip);
        if (activeProxyNames.has(proxy.name)) {
          throw distinctIpCapacityError(`busy_node:${proxy.name}`);
        }
        if (ip && activeProxyIps.has(ip)) {
          throw distinctIpCapacityError(`busy_ip:${proxy.name}->${ip}`);
        }
        activeProxyNames.add(proxy.name);
        if (ip) activeProxyIps.add(ip);
        return { selectedProxy: proxy, proxyIp: ip };
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      lastError = error instanceof Error ? error : new Error(message);
      if (/proxy_no_available_node|proxy_all_nodes_busy/i.test(message)) {
        throw distinctIpCapacityError(message.split("\n")[0] || message);
      }
      throw lastError;
    }

    try {
      const mailboxPromise =
        preloadMailbox && !hasConfiguredLoginAccount(cfg)
          ? createTaskMailboxSession(cfg, blockedMailboxDomains, batchId, taskId, selectedProxy.name, proxyIp || undefined)
              .then((mailbox) => ({ ok: true as const, mailbox }))
              .catch((error) => ({ ok: false as const, error }))
          : null;
      return {
        taskId,
        email: getConfiguredLoginEmail(cfg) || "",
        password,
        mailbox: null,
        mailboxPromise,
        proxyName: selectedProxy.name,
        proxyIp: proxyIp || undefined,
        proxyGeo: compactGeo(selectedProxy.geo),
        ipEmailOrdinal: 0,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      lastError = error instanceof Error ? error : new Error(message);
      activeProxyNames.delete(selectedProxy.name);
      if (proxyIp) activeProxyIps.delete(proxyIp);
      await recordProxyNodeTaskOutcome(selectedProxy.name, selectedProxy.geo, "fail");
      log(
        `task proxy bootstrap failed ${attempt}/${proxyBootstrapAttempts}: node=${selectedProxy.name} ip=${proxyIp || "unknown"} error=${message.split("\n")[0]}`,
      );
      if (attempt >= proxyBootstrapAttempts) {
        break;
      }
    }
  }

  throw lastError || new Error("task proxy bootstrap failed");
}

function shouldRotatePreparedTaskProxy(reason: string): boolean {
  return /challenge_unresponsive|browser_proxy_ip_missing|browser_proxy_same_as_local_ip|browser_proxy_ip_mismatch|stage_browser_ip_probe|browser precheck failed|expected proxy IP not observed|cross-site IP mismatch|golden ip mismatch|webrtc probe candidates do not include expected proxy IP|ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET/i.test(
    reason,
  );
}

async function rotatePreparedTaskProxy(
  cfg: AppConfig,
  args: CliArgs,
  taskLedger: TaskLedger | null,
  taskMihomoController: Awaited<ReturnType<typeof startMihomo>>,
  preparedTask: PreparedSignupTask,
  runtimeRecentProxyIps: string[],
  ipEmailUsage: Map<string, Set<string>>,
  activeProxyNames: Set<string>,
  activeProxyIps: Set<string>,
): Promise<void> {
  const previousName = preparedTask.proxyName;
  const previousIp = normalizeIp(preparedTask.proxyIp);
  const blockedIps = collectBlockedIpsFromUsage(ipEmailUsage);

  const nextSelection = await withProxyBootstrapLock(async () => {
    const proxy = await preselectTaskProxy(
      cfg,
      args,
      "",
      preparedTask.taskId,
      taskLedger,
      blockedIps,
      runtimeRecentProxyIps,
      activeProxyNames,
      activeProxyIps,
      taskMihomoController,
    );
    const proxyIp = normalizeIp(proxy.geo?.ip);
    if (activeProxyNames.has(proxy.name)) {
      throw new Error(`proxy_distinct_ip_capacity_exhausted:busy_node:${proxy.name}`);
    }
    if (proxyIp && activeProxyIps.has(proxyIp)) {
      throw new Error(`proxy_distinct_ip_capacity_exhausted:busy_ip:${proxy.name}->${proxyIp}`);
    }
    activeProxyNames.add(proxy.name);
    if (proxyIp) activeProxyIps.add(proxyIp);
    return { proxy, proxyIp };
  });

  activeProxyNames.delete(previousName);
  if (previousIp) activeProxyIps.delete(previousIp);
  await recordProxyNodeTaskOutcome(previousName, preparedTask.proxyGeo, "fail").catch(() => {});

  preparedTask.proxyName = nextSelection.proxy.name;
  preparedTask.proxyIp = nextSelection.proxyIp || undefined;
  preparedTask.proxyGeo = compactGeo(nextSelection.proxy.geo);
  preparedTask.ipEmailOrdinal = 0;

  log(
    `task proxy rotated: ${previousName} (${previousIp || "unknown"}) -> ${preparedTask.proxyName} (${preparedTask.proxyIp || "unknown"})`,
  );
}

async function runSingleMode(
  cfg: AppConfig,
  args: CliArgs,
  solver: CaptchaSolver,
  resolvedModel: string,
  mode: "headed" | "headless",
  ctx: ModeRunContext,
  preparedTask?: PreparedSignupTask,
  existingMihomoController?: Awaited<ReturnType<typeof startMihomo>>,
): Promise<ResultPayload> {
  const notes: string[] = [];
  let failureStage = "init";
  const runId = preparedTask
    ? `${preparedTask.taskId}-attempt-${ctx.modeAttempt}-${randomBytes(3).toString("hex")}`
    : `signup-${Date.now()}-${randomBytes(4).toString("hex")}`;
  const startedAt = new Date().toISOString();
  const ledger = ctx.taskLedger;

  let mailbox: MailboxSession | null = preparedTask?.mailbox || null;
  let email = preparedTask?.email || getConfiguredLoginEmail(cfg) || "";
  let password = preparedTask?.password || getConfiguredLoginPassword(cfg) || "";
  let verificationLink: string | null = null;
  let apiKey: string | null = null;
  let verifyPassed = false;
  let precheckPassed = !cfg.browserPrecheckEnabled || args.skipPrecheck;

  const configuredLoginProvider = getConfiguredLoginProvider(cfg);
  const envJobId = Number.parseInt((process.env.TASK_LEDGER_JOB_ID || "").trim(), 10);
  const envAccountId = Number.parseInt((process.env.TASK_LEDGER_ACCOUNT_ID || "").trim(), 10);
  const linkedJobId = Number.isFinite(envJobId) ? envJobId : undefined;
  const linkedAccountId = Number.isFinite(envAccountId) ? envAccountId : undefined;
  if (!preparedTask && email && password && configuredLoginProvider) {
    log(`[${mode}] configured ${configuredLoginProvider} account mode: ${email}`);
    notes.push(`configured ${configuredLoginProvider} account mode enabled`);
  }
  if (preparedTask) {
    notes.push(`task id: ${preparedTask.taskId}`);
    notes.push(`task retry: ${ctx.modeAttempt}/3`);
    notes.push(`task fixed proxy: ${preparedTask.proxyName} (${preparedTask.proxyIp || "ip-pending"})`);
    if (preparedTask.ipEmailOrdinal > 0) {
      notes.push(`task ip-email ordinal: ${preparedTask.ipEmailOrdinal}/3`);
    }
  }

  const batchEnabled = args.need > 1 || args.parallel > 1;
  const diagOutputDir = batchEnabled ? new URL(`runs/${ctx.batchId}/${runId}/`, OUTPUT_DIR) : OUTPUT_DIR;
  await mkdir(diagOutputDir, { recursive: true });

  let mihomoOverrides: { apiPort?: number; mixedPort?: number; workDir?: string } | undefined;
  if (!existingMihomoController && batchEnabled) {
    const ports = await reserveMihomoPorts();
    mihomoOverrides = {
      apiPort: ports.apiPort,
      mixedPort: ports.mixedPort,
      workDir: path.join(OUTPUT_PATH, "mihomo", ctx.batchId, runId),
    };
  }

  const mihomoController = existingMihomoController || (await startMihomo(buildMihomoConfig(cfg, mihomoOverrides)));
  const browserEngine = args.browserEngine || cfg.browserEngine;
  const useNativeChrome = shouldUseNativeChromeAutomation(browserEngine, mode, cfg.chromeNativeAutomation);
  let browser: Browser | null = null;
  let context: any = null;
  let page: any = null;
  let ipProbePage: any = null;
  let ipProbePreloadPromise: Promise<void> | null = null;
  let nativeChromeStop: (() => Promise<void>) | null = null;
  let nativeChromeContext: any = null;
  let nativeChromeMode: "cdp" | "persistent" | null = null;
  const observedApiKeys = new Set<string>();
  const networkLog: NetworkDiagRecord[] = [];
  const requestLog: RequestDiagRecord[] = [];
  const resourceLog: ResourceDiagRecord[] = [];
  const passwordStepSnapshots: PasswordStepSnapshot[] = [];
  const browserFingerprintSnapshots: BrowserFingerprintSnapshot[] = [];
  let identity: BrowserIdentityProfile | null = null;
  let selectedProxy: NodeCheckResult | null = null;
  let selectedGeo: GeoInfo | undefined;
  let localErrorCode = "";
  let localErrorMessage = "";
  const taskScopedAttempt = Boolean(preparedTask);
  const browserLaunchAbortController = new AbortController();
  const signupAttemptPolicy: SignupAttemptPolicy = {
    signupChallengeRounds: taskScopedAttempt ? 1 : cfg.maxCaptchaRounds,
    passwordStepRounds: taskScopedAttempt ? 1 : Math.min(cfg.maxCaptchaRounds, 8),
  };
  const loginCycleMax = taskScopedAttempt ? (configuredLoginProvider === "microsoft" ? 2 : 1) : 5;
  const apiKeyFetchRoundMax = taskScopedAttempt ? 1 : 6;

  const { domain: initialEmailDomain, localLen: initialEmailLocalLen } = splitEmail(email);
  const ledgerRecord: SignupTaskRecord = {
    runId,
    jobId: linkedJobId,
    accountId: linkedAccountId,
    batchId: ctx.batchId,
    mode,
    attemptIndex: ctx.modeAttempt,
    modeRetryMax: preparedTask ? 3 : cfg.modeRetryMax,
    status: "running",
    startedAt,
    modelName: resolvedModel,
    browserEngine,
    browserMode: useNativeChrome ? "chrome-native" : browserEngine,
    emailAddress: email || undefined,
    emailDomain: initialEmailDomain,
    emailLocalLen: initialEmailLocalLen,
    password: password || undefined,
    notesJson: safeJsonStringify(notes),
  };
  const persistLedgerRecord = (reason: string): void => {
    if (!ledger) return;
    try {
      if (ledgerRecord.status === "running") {
        ledgerRecord.failureStage = failureStage;
      }
      ledger.upsertTask(ledgerRecord);
    } catch (error) {
      log(`task ledger write skipped (${reason}): ${error instanceof Error ? error.message : String(error)}`);
    }
  };
  persistLedgerRecord("start");
  let taskHeartbeat: ReturnType<typeof setInterval> | null = null;
  let taskTimeout: ReturnType<typeof setTimeout> | null = null;
  let taskTimedOut = false;
  const stopTaskWatchers = (): void => {
    if (taskHeartbeat) {
      clearInterval(taskHeartbeat);
      taskHeartbeat = null;
    }
    if (taskTimeout) {
      clearTimeout(taskTimeout);
      taskTimeout = null;
    }
  };
  const waitForBrowserInspection = async (): Promise<void> => {
    if (mode !== "headed") return;

    const keepOnExit = toBool(process.env.KEEP_BROWSER_OPEN_ON_EXIT, false);
    const keepOnFailure = Boolean(localErrorMessage) && ctx.keepBrowserOpenOnFailure;
    if (!keepOnExit && !keepOnFailure) return;

    const holdUrl = page ? page.url() : "unknown";
    const reason = keepOnFailure && !keepOnExit ? "failure" : "exit";

    if (process.stdin.isTTY && process.stdout.isTTY) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      try {
        await rl.question(`Browser paused on ${reason} at stage=${failureStage} url=${holdUrl}. Press Enter to close: `);
      } finally {
        rl.close();
      }
      return;
    }

    const configuredHoldMs = toInt(process.env.KEEP_BROWSER_OPEN_MS, keepOnFailure ? 0 : 15 * 60_000);
    const holdMs = keepOnFailure && !keepOnExit ? Math.max(0, configuredHoldMs) : Math.max(30_000, configuredHoldMs);
    if (holdMs > 0) {
      log(`keep browser open on ${reason} for ${holdMs}ms at stage=${failureStage} url=${holdUrl}`);
      await delay(holdMs);
      return;
    }

    log(`keep browser open on ${reason} until manually closed at stage=${failureStage} url=${holdUrl}`);
    while (true) {
      const pageClosed = !page || (typeof page.isClosed === "function" ? page.isClosed() : false);
      const browserClosed = !browser || (typeof browser.isConnected === "function" ? !browser.isConnected() : false);
      if (pageClosed || browserClosed) break;
      await delay(1000);
    }
  };

  const bindPageEvents = (targetPage: any): void => {
    const pushResourceLog = (entry: ResourceDiagRecord): void => {
      resourceLog.push(entry);
      if (resourceLog.length > 320) resourceLog.shift();
    };

    targetPage.on("request", (req: any) => {
      try {
        const url = String(req.url?.() || "");
        const method = String(req.method?.() || "GET").toUpperCase();
        const resourceType = String(req.resourceType?.() || "");
        if (isChallengeResourceUrl(url)) {
          pushResourceLog({
            phase: "request",
            url,
            method,
            resourceType: resourceType || undefined,
            startedAt: new Date().toISOString(),
          });
        }
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

    targetPage.on("requestfailed", (req: any) => {
      try {
        const url = String(req.url?.() || "");
        if (!isChallengeResourceUrl(url) && !/https?:\/\/(app|auth)\.tavily\.com/i.test(url)) return;
        const method = String(req.method?.() || "GET").toUpperCase();
        const resourceType = String(req.resourceType?.() || "");
        const failure = req.failure?.();
        pushResourceLog({
          phase: "requestfailed",
          url,
          method,
          resourceType: resourceType || undefined,
          failureText:
            failure && typeof failure.errorText === "string" && failure.errorText
              ? failure.errorText
              : JSON.stringify(failure || {}).slice(0, 160),
          startedAt: new Date().toISOString(),
        });
      } catch {
        // ignore request-failed diagnostics errors
      }
    });

    targetPage.on("response", async (resp: any) => {
      try {
        const url = String(resp.url?.() || "");
        const status = Number(resp.status?.() || 0);
        const req = typeof resp.request === "function" ? resp.request() : null;
        const method = String(req?.method?.() || "GET").toUpperCase();
        const resourceType = String(req?.resourceType?.() || "");
        const headers = resp.headers?.() || {};
        const contentType = String(headers["content-type"] || "");
        const isChallengeResource = isChallengeResourceUrl(url);

        if (isChallengeResource) {
          let challengeBodyPreview: string | undefined;
          if (status >= 400 && /(json|text\/|javascript|html)/i.test(contentType)) {
            challengeBodyPreview = (await resp.text().catch(() => "")).slice(0, 320) || undefined;
          }
          pushResourceLog({
            phase: "response",
            url,
            method,
            resourceType: resourceType || undefined,
            status,
            contentType: contentType || undefined,
            bodyPreview: challengeBodyPreview,
            startedAt: new Date().toISOString(),
          });
        }

        if (!/https?:\/\/(app|auth)\.tavily\.com/i.test(url)) return;
        if (/\.(?:css|js|png|jpg|jpeg|webp|gif|svg|woff2?|ttf|ico)(?:\?|$)/i.test(url)) return;

        const shouldSampleBody = /\/api\/|json|text\//i.test(`${url} ${contentType}`);
        let bodyText = "";
        if (shouldSampleBody) {
          bodyText = await resp.text();
        }

        let responseErrorCodes: string[] | undefined;
        let suspiciousSnippet: string | undefined;
        if (bodyText && status >= 400) {
          const matchedCodes = Array.from(bodyText.matchAll(/data-error-code=\"([^\"]+)\"/g))
            .map((entry) => entry[1])
            .filter(
              (entry): entry is string =>
                typeof entry === "string" &&
                /^[a-z0-9_-]{3,80}$/i.test(entry) &&
                !isIgnorableErrorCode(entry),
            );
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

  const installAuthRequestRoute = async (targetContext: any): Promise<void> => {
    if (!targetContext || typeof targetContext.route !== "function") return;
    if (AUTH_REQUEST_ROUTE_BOUND_CONTEXTS.has(targetContext)) return;
    await targetContext.route(
      /https?:\/\/auth\.tavily\.com\/u\/((signup|login)\/(identifier|password)|email-identifier\/challenge)/i,
      async (route: any) => {
      try {
        const req = route.request();
        const method = String(req.method?.() || "GET").toUpperCase();
        if (method !== "POST") {
          await route.continue();
          return;
        }
        const headers = (req.headers?.() || {}) as Record<string, string>;
        const contentType = String(headers["content-type"] || "");
        const payload = parseRequestPayload(String(req.postData?.() || ""), contentType);
        let touched = false;
        const requestUrl = String(req.url?.() || "");
        const isProviderConnectionSubmit =
          /\/u\/(?:signup|login)\/identifier/i.test(requestUrl) &&
          typeof payload["connection"] === "string" &&
          String(payload["connection"]).trim().length > 0;
        if (isProviderConnectionSubmit) {
          await route.continue();
          return;
        }
        const cachedFields = (page && typeof page === "object" ? authSubmitFieldCache.get(page) : undefined) || {};
        const fallbackEmail = cachedFields.email || email;
        const challengeToken =
          cachedFields.challengeToken ||
          cachedFields.captcha ||
          (await page
            .evaluate(() => {
              const pickValue = (selector: string): string => {
                const field = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null;
                return typeof field?.value === "string" ? field.value.trim() : "";
              };
              const runtimeToken =
                typeof (globalThis as any).__kohaReadAuthChallengeToken === "function"
                  ? String((globalThis as any).__kohaReadAuthChallengeToken() || "").trim()
                  : "";
              return (
                pickValue('input[name="captcha"]') ||
                pickValue('input[name="cf-turnstile-response"]') ||
                pickValue('input[name="g-recaptcha-response"]') ||
                pickValue('textarea[name="h-captcha-response"]') ||
                pickValue('input[name="h-captcha-response"]') ||
                runtimeToken ||
                String((globalThis as any).__kohaLastAuthCaptcha || "").trim() ||
                String((globalThis as any).__kohaLastChallengeToken || "").trim()
              );
            })
            .catch(() => ""));
        const livePassword =
          cachedFields.password ||
          (await page
            .evaluate(() => {
              const candidates = Array.from(
                document.querySelectorAll('input[type="password"], input[name="password"]'),
              ) as HTMLInputElement[];
              for (const field of candidates) {
                const value = typeof field?.value === "string" ? field.value : "";
                if (value) return value;
              }
              return "";
            })
            .catch(() => "")) || "";
        const liveCode =
          cachedFields.code ||
          (await page
            .evaluate(() => {
              const field = document.querySelector('input[name="code"]') as HTMLInputElement | null;
              return typeof field?.value === "string" ? field.value.trim() : "";
            })
            .catch(() => "")) || "";
        if (!isProviderConnectionSubmit && (!payload["email"] || !String(payload["email"]).trim()) && fallbackEmail) {
          payload["email"] = fallbackEmail;
          touched = true;
        }
        if (!isProviderConnectionSubmit && (!payload["captcha"] || !String(payload["captcha"]).trim()) && challengeToken) {
          payload["captcha"] = challengeToken;
          touched = true;
        }
        if (
          !isProviderConnectionSubmit &&
          (!payload["cf-turnstile-response"] || !String(payload["cf-turnstile-response"]).trim()) &&
          challengeToken
        ) {
          payload["cf-turnstile-response"] = challengeToken;
          touched = true;
        }
        if ((!payload["state"] || !String(payload["state"]).trim()) && cachedFields.state) {
          payload["state"] = cachedFields.state;
          touched = true;
        }
        if (/\/u\/(?:signup|login)\/password/i.test(requestUrl) && (!payload["password"] || !String(payload["password"]).trim()) && livePassword) {
          payload["password"] = livePassword;
          touched = true;
        }
        if (/\/u\/email-identifier\/challenge/i.test(requestUrl) && (!payload["code"] || !String(payload["code"]).trim()) && liveCode) {
          payload["code"] = liveCode;
          touched = true;
        }
        if (!touched) {
          await route.continue();
          return;
        }
        const nextHeaders = { ...headers };
        delete nextHeaders["content-length"];
        delete nextHeaders["Content-Length"];
        const nextBody = new URLSearchParams(
          Object.entries(payload).map(([key, value]) => [key, typeof value === "string" ? value : String(value)]),
        ).toString();
        log(
          `patched auth submit payload via route (email=${payload["email"] ? 1 : 0}, captcha=${payload["captcha"] ? 1 : 0}, password=${payload["password"] ? 1 : 0}, code=${payload["code"] ? 1 : 0}, state=${payload["state"] ? 1 : 0})`,
        );
        await route.continue({
          headers: nextHeaders,
          postData: nextBody,
        });
      } catch {
        await route.continue().catch(() => {});
      }
    },
    );
    AUTH_REQUEST_ROUTE_BOUND_CONTEXTS.add(targetContext);
  };

  try {
    failureStage = "proxy_select";
    if (preparedTask) {
      const expectedTaskIp = normalizeIp(preparedTask.proxyIp);
      selectedProxy = await selectProxyNode(
        mihomoController,
        cfg,
        preparedTask.proxyName,
        new Set(),
        ctx.runtimeRecentProxyIps,
        expectedTaskIp,
      );
      const actualProxyIp = normalizeIp(selectedProxy.geo?.ip);
      if (expectedTaskIp && (!actualProxyIp || !sameIp(actualProxyIp, expectedTaskIp))) {
        throw new Error(
          `task_proxy_ip_mismatch: expected=${expectedTaskIp} actual=${actualProxyIp || "unknown"} node=${preparedTask.proxyName}`,
        );
      }
    } else {
      selectedProxy = await selectProxyNode(
        mihomoController,
        cfg,
        args.proxyNode,
        collectBlockedIpsFromLedger(ledger),
        ctx.runtimeRecentProxyIps,
      );
    }
    selectedProxy.geo = (await enrichGeoInfo((selectedProxy.geo || {}) as GeoInfo, cfg.ipinfoToken)) || selectedProxy.geo;
    const geo = (selectedProxy.geo || {}) as GeoInfo;
    selectedGeo = geo;

    let locale = resolveBrowserLocale(geo.country);
    let acceptLanguage = buildAcceptLanguage(locale);
    notes.push(`proxy node: ${selectedProxy.name}`);
    if (geo.ip) {
      notes.push(`proxy ip: ${geo.ip}`);
    } else {
      notes.push("proxy ip: pending browser confirmation");
    }
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

    const syncGeoDerivedBrowserProfile = async (reason: string): Promise<void> => {
      if (!selectedProxy) return;
      const nextGeo = (selectedProxy.geo || {}) as GeoInfo;
      selectedGeo = nextGeo;
      const nextLocale = resolveBrowserLocale(nextGeo.country);
      const nextAcceptLanguage = buildAcceptLanguage(nextLocale);
      const nextTimezone = nextGeo.timezone;
      const changed =
        nextLocale !== locale ||
        nextAcceptLanguage !== acceptLanguage ||
        (nextTimezone || "") !== (contextOptions.timezoneId || "");
      if (!changed) return;

      locale = nextLocale;
      acceptLanguage = nextAcceptLanguage;
      contextOptions.locale = locale;
      contextOptions.extraHTTPHeaders = {
        ...(contextOptions.extraHTTPHeaders || {}),
        "Accept-Language": acceptLanguage,
      };
      if (nextTimezone) {
        contextOptions.timezoneId = nextTimezone;
      } else {
        delete contextOptions.timezoneId;
      }
      ledgerRecord.proxyCountry = nextGeo.country;
      ledgerRecord.proxyCity = nextGeo.city;
      ledgerRecord.proxyTimezone = nextGeo.timezone;
      ledgerRecord.browserLocale = locale;
      ledgerRecord.browserTimezone = nextGeo.timezone;
      notes.push(
        `browser geo synced after ${reason}: locale=${locale}, timezone=${nextGeo.timezone || "unknown"}, country=${nextGeo.country || "unknown"}`,
      );

      if (context) {
        if (browserEngine === "chrome" && cfg.chromeIdentityOverride && !isFingerprintChromiumExecutable(cfg.chromeExecutablePath)) {
          identity = buildBrowserIdentityProfile(locale, browser?.version?.() || "");
          await applyBrowserIdentityToContext(context, identity, nextGeo.timezone, !useNativeChrome);
          if (useNativeChrome && page && nativeChromeMode === "cdp") {
            await configureNativeChromePage(context, page, identity, nextGeo.timezone);
          }
        } else if (nextGeo.timezone && page && identity) {
          await applyPageIdentityOverrides(context, page, identity, nextGeo.timezone);
        }
      }
    };

    failureStage = "browser_launch";
    const launchBrowser = async (): Promise<Browser> => {
      if (useNativeChrome) {
        try {
          const launched = await launchNativeChromeCdp(
            cfg,
            mode,
            mihomoController.proxyServer,
            locale,
            acceptLanguage,
            selectedGeo?.timezone,
            browserLaunchAbortController.signal,
          );
          nativeChromeMode = "cdp";
          nativeChromeStop = launched.stop;
          nativeChromeContext = launched.context;
          notes.push(`native chrome executable: ${launched.details.executablePath}`);
          notes.push(`native chrome profile: ${launched.details.profileDir}`);
          notes.push(`native chrome debug port: ${launched.details.debugPort}`);
          return launched.browser;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          const compact = message.split("\n")[0] || "unknown";
          if (/^task_attempt_timeout:/i.test(compact) || browserLaunchAbortController.signal.aborted) {
            throw (error instanceof Error ? error : new Error(compact));
          }
          notes.push(`native chrome cdp unavailable: ${compact}`);
          throw new Error(`native_cdp_unavailable: ${compact}`);
        }
      }
      return await launchBrowserWithEngine(browserEngine, cfg, mode, mihomoController.proxyServer, locale, geo.ip || "");
    };

    const closeBrowserSession = async (): Promise<void> => {
      ipProbePreloadPromise = null;
      if (ipProbePage) {
        await ipProbePage.close().catch(() => {});
        ipProbePage = null;
      }
      if (context) {
        if (!useNativeChrome) {
          await context.close().catch(() => {});
        }
        context = null;
      }
      page = null;
      const launchedBrowser = browser;
      browser = null;
      const stopNativeChrome = nativeChromeStop;
      nativeChromeStop = null;
      if (useNativeChrome) {
        if (stopNativeChrome != null) {
          await awaitCleanupBestEffort((stopNativeChrome as () => Promise<void>)(), 5_000);
        } else if (launchedBrowser) {
          await awaitCleanupBestEffort(launchedBrowser.close(), 5_000);
        }
      } else if (launchedBrowser) {
        await awaitCleanupBestEffort(launchedBrowser.close(), 5_000);
      }
      if (!useNativeChrome && stopNativeChrome != null) {
        await awaitCleanupBestEffort((stopNativeChrome as () => Promise<void>)(), 5_000);
        nativeChromeStop = null;
      }
      nativeChromeContext = null;
      nativeChromeMode = null;
    };
    const startTaskWatchers = (): void => {
      stopTaskWatchers();
      taskHeartbeat = setInterval(() => {
        ledgerRecord.notesJson = safeJsonStringify(notes);
        persistLedgerRecord("heartbeat");
      }, 15_000);
      taskTimeout = setTimeout(() => {
        taskTimedOut = true;
        log(`[${mode}] task attempt timeout after ${cfg.taskAttemptTimeoutMs}ms at stage=${failureStage}`);
        browserLaunchAbortController.abort(new Error(`task_attempt_timeout:${failureStage}:${cfg.taskAttemptTimeoutMs}`));
        void closeBrowserSession();
        if (!existingMihomoController) {
          void mihomoController.stop().catch(() => {});
        }
      }, cfg.taskAttemptTimeoutMs);
    };
    startTaskWatchers();

    const syncBrowserIdentityProfile = (recordNote: boolean): void => {
      if (browserEngine === "chrome" && cfg.chromeIdentityOverride && !isFingerprintChromiumExecutable(cfg.chromeExecutablePath)) {
        identity = buildBrowserIdentityProfile(locale, browser?.version?.() || "");
        if (recordNote) notes.push(`browser ua profile: ${identity.userAgent}`);
        return;
      }
      if (browserEngine === "chrome") {
        identity = null;
        if (recordNote) notes.push("browser ua profile: native");
        return;
      }
      identity = null;
    };

    const rebuildPage = async (): Promise<void> => {
      ipProbePage = null;
      if (context && !useNativeChrome) {
        await context.close().catch(() => {});
      }
      if (useNativeChrome) {
        context = nativeChromeContext;
        if (!context) {
          throw new Error("native chrome context missing");
        }
        await installAuthRequestRoute(context);
        if (identity) {
          await applyBrowserIdentityToContext(context, identity, selectedGeo?.timezone, false);
        }
        if (!isFingerprintChromiumExecutable(cfg.chromeExecutablePath)) {
          await applyEngineStealth(context, "chrome", locale, cfg.chromeStealthJsEnabled && !useNativeChrome);
        }
        const probeHost = new URL(SINGLE_BROWSER_IP_PROBE_TARGET.url).hostname.toLowerCase();
        const existingPages = typeof context.pages === "function" ? context.pages() : [];
        const disposablePages: any[] = [];
        for (const existing of existingPages) {
          const currentUrl = typeof existing?.url === "function" ? String(existing.url() || "") : "";
          let currentHost = "";
          try {
            currentHost = currentUrl ? new URL(currentUrl).hostname.toLowerCase() : "";
          } catch {
            currentHost = "";
          }
          if (!ipProbePage && currentHost && (currentHost === probeHost || currentHost.endsWith(`.${probeHost}`))) {
            ipProbePage = existing;
            continue;
          }
          if (!page) {
            page = existing;
            continue;
          }
          disposablePages.push(existing);
        }
        for (const extraPage of disposablePages) {
          await extraPage.close().catch(() => {});
        }
        if (!page) {
          page = await context.newPage();
        }
        if (nativeChromeMode === "cdp" && identity) {
          await configureNativeChromePage(
            context,
            page,
            identity,
            selectedGeo?.timezone,
          );
        }
      } else {
        context = await browser!.newContext(contextOptions);
        await installAuthRequestRoute(context);
        if (identity) {
          await applyBrowserIdentityToContext(context, identity, selectedGeo?.timezone);
        }
        if (!isFingerprintChromiumExecutable(cfg.chromeExecutablePath)) {
          if (!isFingerprintChromiumExecutable(cfg.chromeExecutablePath)) {
        await applyEngineStealth(context, browserEngine, locale, cfg.chromeStealthJsEnabled);
      }
        }
        page = await context.newPage();
      }
      bindPageEvents(page);
      const preloadTasks: Promise<unknown>[] = [
        /app\.tavily\.com/i.test(String(page.url?.() || ""))
          ? page.waitForLoadState("domcontentloaded", { timeout: 30_000 }).catch(() => {})
          : safeGoto(page, "https://app.tavily.com/", 30_000).catch(() => {}),
      ];
      if (context && !ipProbePage) {
        ipProbePage = await context.newPage().catch(() => null);
      }
      if (ipProbePage) {
        const ipProbeUrl = String(ipProbePage.url?.() || "");
        ipProbePreloadPromise = (/ifconfig\.me/i.test(ipProbeUrl)
          ? ipProbePage.waitForLoadState("domcontentloaded", { timeout: 15_000 })
          : safeGoto(ipProbePage, SINGLE_BROWSER_IP_PROBE_TARGET.url, 15_000).then(async () => {
              await ipProbePage.waitForLoadState("domcontentloaded", { timeout: 15_000 }).catch(() => {});
            })
        ).catch(() => {});
      }
      await Promise.allSettled(preloadTasks);
      await page.bringToFront().catch(() => {});
    };

    const launchAndPreparePage = async (recordIdentityNote: boolean): Promise<void> => {
      await closeBrowserSession();
      browser = await launchBrowser();
      syncBrowserIdentityProfile(recordIdentityNote);
      await rebuildPage();
    };

    const rebuildPageWithRecovery = async (reason: string): Promise<void> => {
      try {
        await rebuildPage();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!isRecoverableBrowserError(message)) {
          throw error;
        }
        log(`[${mode}] ${reason}: page rebuild failed, relaunching browser session (${message})`);
        await launchAndPreparePage(false);
        notes.push(`browser session relaunched after ${reason}`);
      }
    };

    let browserReady = false;
    let launchErr: Error | null = null;
    for (let launchAttempt = 1; launchAttempt <= cfg.browserLaunchRetryMax; launchAttempt += 1) {
      try {
        await launchAndPreparePage(true);
        browserReady = true;
        if (launchAttempt > 1) {
          notes.push(`browser launch recovered on attempt ${launchAttempt}`);
        }
        break;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        launchErr = error instanceof Error ? error : new Error(message);
        log(`[${mode}] browser launch/context attempt ${launchAttempt} failed: ${message}`);
        await closeBrowserSession();
        if (taskTimedOut || browserLaunchAbortController.signal.aborted) {
          break;
        }
        if (launchAttempt >= cfg.browserLaunchRetryMax) {
          break;
        }
        await delay(Math.min(3000, 700 * launchAttempt));
      }
    }
    if (!browserReady) {
      throw launchErr || new Error("browser launch failed without details");
    }
    ledgerRecord.browserMode = useNativeChrome ? nativeChromeMode || "cdp" : browserEngine;
    ledgerRecord.browserUserAgent = (identity as BrowserIdentityProfile | null)?.userAgent;
    ledgerRecord.browserLocale = locale;
    ledgerRecord.browserTimezone = selectedGeo?.timezone;
    ledgerRecord.notesJson = safeJsonStringify(notes);
    persistLedgerRecord("after-browser-launch");

    failureStage = "browser_ip_probe";
    const pendingIpProbePreload: Promise<void> | null = ipProbePreloadPromise;
    if (pendingIpProbePreload) {
      await pendingIpProbePreload;
      ipProbePreloadPromise = null;
    }
    let browserIpProbe =
      ipProbePage != null
        ? await collectSingleBrowserIpProbe(ipProbePage)
        : context != null
          ? await collectIpProbeSnapshotInContext(context, SINGLE_BROWSER_IP_PROBE_TARGET, 4500)
        : await collectSingleBrowserIpProbe(page);
    let browserObservedIp = normalizeIp(browserIpProbe.ip || browserIpProbe.ipCandidates?.[0]);
    if (!browserObservedIp && browser && browserEngine === "chrome" && process.platform === "darwin") {
      log(`browser ip probe fallback via minimal context: ${browserIpProbe.error || browserIpProbe.url}`);
      const fallbackProbe = await collectSingleBrowserIpProbeWithMinimalContext(browser);
      const fallbackObservedIp = normalizeIp(fallbackProbe.ip || fallbackProbe.ipCandidates?.[0]);
      if (fallbackObservedIp) {
        browserIpProbe = fallbackProbe;
        browserObservedIp = fallbackObservedIp;
        notes.push(`browser ip probe fallback used: ${fallbackProbe.name}`);
      }
    }
    if (!browserObservedIp) {
      const probeReason = browserIpProbe.error || browserIpProbe.url || selectedProxy.name;
      notes.push(`browser ip probe unresolved: ${probeReason}`);
      log(`browser ip probe unresolved: ${probeReason}`);
      throw new Error(`browser_proxy_ip_missing:${probeReason}`);
    }
    const browserProxyIdentity = browserObservedIp;
    if (browserObservedIp) {
      const localDirectIp = await resolveLocalEgressIp(8_000);
      if (localDirectIp && sameIp(localDirectIp, browserObservedIp)) {
        throw new Error(`browser_proxy_same_as_local_ip:${browserObservedIp}:${selectedProxy.name}`);
      }
      const expectedProxyIp = normalizeIp(selectedProxy.geo?.ip);
      if (expectedProxyIp && !sameIp(expectedProxyIp, browserObservedIp)) {
        notes.push(`browser ip superseded cached ip: expected=${expectedProxyIp} actual=${browserObservedIp}`);
      }
      selectedProxy.geo = mergeGeoInfo(
        { ...(selectedProxy.geo || {}), ip: browserObservedIp } as GeoInfo,
        await enrichGeoInfo({ ip: browserObservedIp } as GeoInfo, cfg.ipinfoToken),
      ) as GeoInfo;
      await syncGeoDerivedBrowserProfile("browser ip probe");
      ledgerRecord.proxyIp = browserObservedIp;
    } else {
      ledgerRecord.proxyIp = undefined;
    }
    selectedGeo = selectedProxy.geo;
    if (preparedTask) {
      const previousTaskIp = normalizeIp(preparedTask.proxyIp);
      if (previousTaskIp && browserObservedIp && previousTaskIp !== browserObservedIp) {
        ctx.activeProxyIps.delete(previousTaskIp);
      }
      preparedTask.proxyIp = browserObservedIp || preparedTask.proxyIp;
      ctx.activeProxyIps.add(browserProxyIdentity);
      const existingEmailSet = ctx.ipEmailUsage.get(browserProxyIdentity);
      if ((!email || !email.trim()) && existingEmailSet && existingEmailSet.size >= 3) {
        throw new Error(`proxy_ip_quota_exceeded:${browserProxyIdentity}`);
      }
      if (email) {
        let emailSet = existingEmailSet;
        if (!emailSet) {
          emailSet = new Set<string>();
          ctx.ipEmailUsage.set(browserProxyIdentity, emailSet);
        }
        if (!emailSet.has(email) && emailSet.size >= 3) {
          throw new Error(`proxy_ip_quota_exceeded:${browserProxyIdentity}`);
        }
        emailSet.add(email);
        preparedTask.ipEmailOrdinal = emailSet.size;
        notes.push(`task ip-email ordinal confirmed: ${preparedTask.ipEmailOrdinal}/3`);
      }
    }
    precheckPassed = true;
    notes.push(`browser observed ip: ${browserObservedIp || "unavailable"}`);
    ledgerRecord.precheckPassed = true;
    ledgerRecord.notesJson = safeJsonStringify(notes);
    ledgerRecord.detailsJson = safeJsonStringify({
      browserIpProbe,
      browserProxyIdentity,
    });
    persistLedgerRecord("after-browser-ip-probe");

    if (configuredLoginProvider) {
      notes.push(`skip signup (${configuredLoginProvider} account)`);
    } else {
      if (!mailbox && preparedTask?.mailboxPromise) {
        try {
          const mailboxResult = await preparedTask.mailboxPromise;
          preparedTask.mailboxPromise = null;
          if (!mailboxResult.ok) {
            throw mailboxResult.error;
          }
          mailbox = mailboxResult.mailbox;
          preparedTask.mailbox = mailbox;
          email = mailbox.address;
          password = password || randomPassword();
          notes.push(`${mailbox.provider} mailbox preloaded via proxy (${mailbox.accountId})`);
          log(`[${mode}] ${mailbox.provider} mailbox preloaded via proxy ${browserObservedIp || browserProxyIdentity}: ${email}`);
          let emailSet = ctx.ipEmailUsage.get(browserProxyIdentity);
          if (!emailSet) {
            emailSet = new Set<string>();
            ctx.ipEmailUsage.set(browserProxyIdentity, emailSet);
          }
          if (!emailSet.has(email) && emailSet.size >= 3) {
            throw new Error(`proxy_ip_quota_exceeded:${browserProxyIdentity}`);
          }
          emailSet.add(email);
          preparedTask.ipEmailOrdinal = emailSet.size;
          notes.push(`task ip-email ordinal confirmed: ${preparedTask.ipEmailOrdinal}/3`);
          ledgerRecord.emailAddress = email;
          const mailboxSplit = splitEmail(email);
          ledgerRecord.emailDomain = mailboxSplit.domain;
          ledgerRecord.emailLocalLen = mailboxSplit.localLen;
          ledgerRecord.password = password;
          ledgerRecord.notesJson = safeJsonStringify(notes);
          persistLedgerRecord("after-mailbox-preload");
        } catch (error) {
          preparedTask.mailboxPromise = null;
          const message = error instanceof Error ? error.message : String(error);
          notes.push(`mailbox preload failed: ${message.split("\n")[0]}`);
        }
      }

      if (!mailbox) {
        if (!email) {
          let emailSet = ctx.ipEmailUsage.get(browserProxyIdentity);
          if (!emailSet) {
            emailSet = new Set<string>();
            ctx.ipEmailUsage.set(browserProxyIdentity, emailSet);
          }
          if (emailSet.size >= 3) {
            throw new Error(`proxy_ip_quota_exceeded:${browserProxyIdentity}`);
          }
        }
        mailbox = await createMailboxSession(cfg, ctx.blockedMailboxDomains, mihomoController.proxyServer);
        email = mailbox.address;
        password = password || randomPassword();
        log(`[${mode}] ${mailbox.provider} mailbox via proxy ${browserObservedIp || browserProxyIdentity}: ${email}`);
        notes.push(`${mailbox.provider} mailbox created via proxy (${mailbox.accountId})`);
        if (preparedTask) {
          preparedTask.mailbox = mailbox;
          preparedTask.email = email;
          let emailSet = ctx.ipEmailUsage.get(browserProxyIdentity);
          if (!emailSet) {
            emailSet = new Set<string>();
            ctx.ipEmailUsage.set(browserProxyIdentity, emailSet);
          }
          if (!emailSet.has(email) && emailSet.size >= 3) {
            throw new Error(`proxy_ip_quota_exceeded:${browserProxyIdentity}`);
          }
          emailSet.add(email);
          preparedTask.ipEmailOrdinal = emailSet.size;
          notes.push(`task ip-email ordinal confirmed: ${preparedTask.ipEmailOrdinal}/3`);
        }
        ledgerRecord.emailAddress = email;
        const mailboxSplit = splitEmail(email);
        ledgerRecord.emailDomain = mailboxSplit.domain;
        ledgerRecord.emailLocalLen = mailboxSplit.localLen;
        ledgerRecord.password = password;
        ledgerRecord.notesJson = safeJsonStringify(notes);
        persistLedgerRecord("after-mailbox-create");
      }

      failureStage = "signup";
      if (cfg.humanConfirmBeforeSignup) {
        await confirmHumanControl(cfg, email, "before signup");
        notes.push("human confirmation accepted before signup");
      }

      for (let attempt = 1; attempt <= (taskScopedAttempt ? 1 : 2); attempt += 1) {
        try {
          const signupResult = await completeSignup(
            page,
            solver,
            email,
            password,
            mailbox!,
            cfg,
            diagOutputDir,
            signupAttemptPolicy,
            mihomoController.proxyServer,
            {
            onPasswordSnapshot: (snapshot) => {
              passwordStepSnapshots.push(snapshot);
              if (passwordStepSnapshots.length > 120) passwordStepSnapshots.shift();
            },
            onFingerprintSnapshot: (snapshot) => {
              browserFingerprintSnapshots.push(snapshot);
              if (browserFingerprintSnapshots.length > 20) browserFingerprintSnapshots.shift();
            },
          });
          password = signupResult.password;
          notes.push("signup flow submitted");
          if (signupResult.emailVerifiedInFlow) {
            verifyPassed = true;
            verificationLink = "email-code";
            notes.push("email verification confirmed via code challenge");
          }
          ledgerRecord.signupSubmitted = true;
          ledgerRecord.password = password;
          ledgerRecord.notesJson = safeJsonStringify(notes);
          persistLedgerRecord("after-signup-submit");
          break;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (!isRecoverableBrowserError(message) || attempt === 2) {
            throw error;
          }
          log(`[${mode}] signup retry after browser reset (attempt=${attempt}): ${message.split("\n")[0]}`);
          await rebuildPageWithRecovery("signup retry");
        }
      }

      if (!verifyPassed) {
        failureStage = "email_verify_wait";
        verificationLink = await waitForVerificationLink(
          mailbox!,
          cfg.emailWaitMs,
          cfg.mailPollMs,
          cfg.verifyHostAllowlist,
          mihomoController.proxyServer,
        );
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
    }

    failureStage = "login_home";
    for (let attempt = 1; attempt <= (taskScopedAttempt ? 1 : 2); attempt += 1) {
      try {
        page = await loginAndReachHome(page, solver, email, password, cfg, mailbox, mihomoController.proxyServer, loginCycleMax, diagOutputDir);
        await dismissCookieBannerBestEffort(page).catch(() => {});
        notes.push("reached app home");
        break;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!isRecoverableBrowserError(message) || attempt === 2) {
          throw error;
        }
        log(`[${mode}] login retry after browser reset (attempt=${attempt}): ${message.split("\n")[0]}`);
        await rebuildPageWithRecovery("login retry");
      }
    }

    failureStage = "api_key";
    let lastKeyError: Error | null = null;
    for (let attempt = 1; attempt <= (taskScopedAttempt ? 1 : 5); attempt += 1) {
      try {
        const sampled = Array.from(observedApiKeys).find((key) => isLikelyTavilyKey(key));
        if (sampled) {
          apiKey = sampled;
          break;
        }

        page = await loginAndReachHome(page, solver, email, password, cfg, mailbox, mihomoController.proxyServer, loginCycleMax, diagOutputDir);
        await acceptPostSignupConsent(page).catch(() => false);
        await dismissCookieBannerBestEffort(page).catch(() => {});
        await page.waitForTimeout(1500);
        if (attempt === 1) {
          await writeFile(new URL(`home_${mode}.html`, diagOutputDir), await page.content(), "utf8");
          await writeJson(new URL(`network_${mode}.json`, diagOutputDir), networkLog.slice(-120));
        }

        apiKey = await getDefaultApiKey(page, cfg, apiKeyFetchRoundMax);
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
          await rebuildPageWithRecovery("api-key retry");
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
    ledgerRecord.verifyPassed = verifyPassed || hasConfiguredLoginAccount(cfg);
    ledgerRecord.precheckPassed = precheckPassed;
    ledgerRecord.hasIpRateLimit = successRisk.hasIpRateLimit;
    ledgerRecord.hasSuspiciousActivity = successRisk.hasSuspiciousActivity;
    ledgerRecord.hasExtensibilityError = successRisk.hasExtensibilityError;
    ledgerRecord.hasInvalidCaptcha = successRisk.hasInvalidCaptcha;
    ledgerRecord.requestCount = successRisk.requestCount;
    ledgerRecord.suspiciousHitCount = successRisk.suspiciousHitCount;
    ledgerRecord.captchaSubmitCount = successRisk.captchaSubmitCount;
    ledgerRecord.maxCaptchaLength = successRisk.maxCaptchaLength;
    ledgerRecord.password = password;
    ledgerRecord.apiKey = apiKey;
    ledgerRecord.apiKeyPrefix = apiKey.slice(0, Math.min(apiKey.length, 12));
    ledgerRecord.notesJson = safeJsonStringify(notes);
    if (selectedProxy?.name) {
      await recordProxyNodeTaskOutcome(selectedProxy.name, selectedProxy.geo, "ok");
    }
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
      resourceLog: resourceLog.slice(-120),
      passwordStepSnapshots: passwordStepSnapshots.slice(-80),
      browserFingerprintSnapshots: browserFingerprintSnapshots.slice(-12),
      notes,
    });
    persistLedgerRecord("success");
    await syncLinkedMicrosoftAccountOutcome(cfg, {
      status: "succeeded",
      apiKey,
    }).catch((error) => {
      log(`linked account success sync skipped: ${error instanceof Error ? error.message : String(error)}`);
    });

    return {
      mode,
      email,
      password,
      verificationLink,
      apiKey,
      model: resolvedModel,
      precheckPassed,
      verifyPassed: verifyPassed || hasConfiguredLoginAccount(cfg),
      notes,
    };
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : String(error);
    const message = taskTimedOut ? `task_attempt_timeout:${failureStage}:${cfg.taskAttemptTimeoutMs}` : rawMessage;
    const risk = summarizeRiskSignals(requestLog, networkLog);
    localErrorCode = deriveErrorCode(message, failureStage, risk);
    localErrorMessage = message;
    try {
      await writeJson(new URL(`network_fail_${mode}.json`, diagOutputDir), networkLog.slice(-180));
      await writeJson(new URL(`request_fail_${mode}.json`, diagOutputDir), requestLog.slice(-180));
      await writeJson(new URL(`resource_fail_${mode}.json`, diagOutputDir), resourceLog.slice(-220));
      await writeJson(new URL(`failure_context_${mode}.json`, diagOutputDir), {
        failedAt: new Date().toISOString(),
        stage: failureStage,
        url: page ? page.url() : null,
        email,
        browserEngine,
        notes,
      });
      if (page) {
        await writeFile(new URL(`failure_page_${mode}.html`, diagOutputDir), await page.content(), "utf8");
      }
    } catch {
      // best effort diagnostics only
    }
    if (selectedProxy?.name) {
      await recordProxyNodeTaskOutcome(selectedProxy.name, selectedProxy.geo, "fail");
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
      resourceLog: resourceLog.slice(-200),
      passwordStepSnapshots: passwordStepSnapshots.slice(-120),
      browserFingerprintSnapshots: browserFingerprintSnapshots.slice(-20),
      notes,
    });
    persistLedgerRecord("failure");
    await syncLinkedMicrosoftAccountOutcome(cfg, {
      status: "failed",
      errorCode: localErrorCode || null,
    }).catch((error) => {
      log(`linked account failure sync skipped: ${error instanceof Error ? error.message : String(error)}`);
    });
    throw new Error(`mode=${mode} stage=${failureStage} code=${localErrorCode || "unknown"}: ${message}`);
  } finally {
    stopTaskWatchers();
    const preserveBrowserOnFailure = mode === "headed" && Boolean(localErrorMessage) && ctx.keepBrowserOpenOnFailure;
    await waitForBrowserInspection();
    if (!preserveBrowserOnFailure && context && !useNativeChrome) {
      await awaitCleanupBestEffort(context.close(), 5_000);
    }
    if (!preserveBrowserOnFailure && useNativeChrome && nativeChromeStop != null) {
      await awaitCleanupBestEffort((nativeChromeStop as () => Promise<void>)(), 5_000);
    } else if (!preserveBrowserOnFailure && browser) {
      await awaitCleanupBestEffort(browser.close(), 5_000);
    }
    if (!preserveBrowserOnFailure && !useNativeChrome && nativeChromeStop != null) {
      await awaitCleanupBestEffort((nativeChromeStop as () => Promise<void>)(), 5_000);
    }
    if (!existingMihomoController) {
      await mihomoController.stop();
    }
  }
}

async function runInspectSites(cfg: AppConfig, args: CliArgs): Promise<void> {
  const mode: "headed" = "headed";
  const notes: string[] = [];
  const mihomoController = await startMihomo(buildMihomoConfig(cfg));
  const browserEngine = args.browserEngine || cfg.inspectBrowserEngine;
  const useNativeChrome = shouldUseNativeChromeAutomation(browserEngine, mode, cfg.inspectChromeNative);
  let browser: Browser | null = null;
  let context: any = null;
  let nativeChromeStop: (() => Promise<void>) | null = null;

  try {
    const selectedProxy = await selectProxyNode(mihomoController, cfg, args.proxyNode);
    const geo = (selectedProxy.geo || {}) as GeoInfo;

    const locale = resolveBrowserLocale(geo.country);
    const acceptLanguage = buildAcceptLanguage(locale);
    notes.push(`proxy node: ${selectedProxy.name}`);
    notes.push(`proxy ip: ${geo.ip || "pending browser confirmation"}`);
    notes.push(`browser engine: ${browserEngine}`);

    if (useNativeChrome) {
      const nativeChrome = await launchNativeChromeInspect(
        cfg,
        mihomoController.proxyServer,
        locale,
        acceptLanguage,
        geo.timezone,
      );
      nativeChromeStop = nativeChrome.stop;
      notes.push(`native chrome executable: ${nativeChrome.details.executablePath}`);
      notes.push(`native chrome profile: ${nativeChrome.details.profileDir}`);
      notes.push("opened app.tavily.com");
      notes.push(`fingerprint browser active: ${isFingerprintChromiumExecutable(cfg.chromeExecutablePath) ? "yes" : "no"}`);

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
      browser = await launchBrowserWithEngine(browserEngine, cfg, mode, mihomoController.proxyServer, locale, geo.ip || "");

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

      const tavilyPage = await context.newPage();
      await safeGoto(tavilyPage, "https://app.tavily.com/", 120000);
      await tavilyPage.waitForLoadState("domcontentloaded", { timeout: 60000 });
      if (/\/u\/login\/identifier/i.test(tavilyPage.url())) {
        await clickSignUp(tavilyPage).catch(() => {});
        await tavilyPage.waitForTimeout(1200);
      }
      await writeFile(new URL("inspect_tavily.png", OUTPUT_DIR), await tavilyPage.screenshot({ fullPage: true }));
      notes.push("opened app.tavily.com");

      const ipInfoPage = await context.newPage();
      await safeGoto(ipInfoPage, SINGLE_BROWSER_IP_PROBE_TARGET.url, 120000);
      await ipInfoPage.waitForLoadState("domcontentloaded", { timeout: 60000 });
      await writeFile(new URL("inspect_ipinfo.png", OUTPUT_DIR), await ipInfoPage.screenshot({ fullPage: true }));
      await tavilyPage.bringToFront();
      notes.push(`opened ${SINGLE_BROWSER_IP_PROBE_TARGET.url}`);

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
          { url: await tavilyPage.url(), title: await tavilyPage.title().catch(() => "") },
          { url: await ipInfoPage.url(), title: await ipInfoPage.title().catch(() => "") },
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
      await awaitCleanupBestEffort(context.close(), 5_000);
    }
    if (useNativeChrome && nativeChromeStop) {
      await awaitCleanupBestEffort(nativeChromeStop(), 5_000);
    } else if (browser) {
      await awaitCleanupBestEffort(browser.close(), 5_000);
    }
    if (!useNativeChrome && nativeChromeStop) {
      await awaitCleanupBestEffort(nativeChromeStop(), 5_000);
    }
    await mihomoController.stop();
  }
}

async function run(): Promise<void> {
  const cfg = loadConfig();
  await cleanupManagedChromeProcessesUnder(cfg.chromeProfileDir).catch(() => {});
  await cleanupManagedChromeProcessesUnder(cfg.inspectChromeProfileDir).catch(() => {});
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
  const historicalBlockedMailboxDomains = new Set<string>(cfg.blockedMailboxDomains);
  if (taskLedger) {
    log(`task ledger enabled: ${taskLedger.dbPath()}`);
    const recovered = taskLedger.markStaleRunningAsFailed();
    if (recovered > 0) {
      log(`task ledger recovered interrupted running rows: ${recovered}`);
    }
    if (historicalBlockedMailboxDomains.size > 0) {
      log(`mailbox denylist loaded: ${Array.from(historicalBlockedMailboxDomains).join(", ")}`);
    }
  } else {
    log("task ledger disabled");
  }

  try {
    const requestedMode = args.mode || cfg.runMode;
    const batchEnabled = args.need > 1 || args.parallel > 1;
    log(
      `start mode=${requestedMode} precheck=${cfg.browserPrecheckEnabled && !args.skipPrecheck ? "on" : "off"} need=${args.need} parallel=${args.parallel}`,
    );

    const resolvedModel = "disabled";
    const solver = new CaptchaSolver();

    const results: ResultPayload[] = [];
    const failures: Array<{ runIndex: number; taskId?: string; error: string }> = [];
    const taskRetryMax = 3;
    const mailboxPreloadTarget = computeMailboxPreloadTarget(args.need);
    const ipEmailUsage = new Map<string, Set<string>>();
    const runtimeRecentProxyIps: string[] = [];
    const activeProxyNames = new Set<string>();
    const activeProxyIps = new Set<string>();
    const blockedMailboxDomains = new Set<string>(historicalBlockedMailboxDomains);

    const runOne = async (runIndex: number): Promise<ResultPayload> => {
      let mihomoOverrides: { apiPort?: number; mixedPort?: number; workDir?: string } | undefined;
      const ports = batchEnabled
        ? await reserveMihomoPorts()
        : {
            apiPort: cfg.mihomoApiPort,
            mixedPort: cfg.mihomoMixedPort,
          };
      mihomoOverrides = {
        apiPort: ports.apiPort,
        mixedPort: ports.mixedPort,
        workDir: path.join(OUTPUT_PATH, "mihomo", batchId, `task-${runIndex}`),
      };
      const taskMihomoController = await startMihomo(buildMihomoConfig(cfg, mihomoOverrides));
      let preparedTask: PreparedSignupTask | null = null;
      let lastError: Error | null = null;

      try {
        preparedTask = await prepareSignupTask(
          cfg,
          args,
          batchId,
          taskLedger,
          taskMihomoController,
          ipEmailUsage,
          runtimeRecentProxyIps,
          activeProxyNames,
          activeProxyIps,
          blockedMailboxDomains,
          runIndex,
          runIndex <= mailboxPreloadTarget,
        );

        for (let attempt = 1; attempt <= taskRetryMax; attempt += 1) {
          try {
            const result = await runSingleMode(
              cfg,
              args,
              solver,
              resolvedModel,
              requestedMode,
              {
                batchId,
                modeAttempt: attempt,
                keepBrowserOpenOnFailure:
                  toBool(process.env.KEEP_BROWSER_OPEN_ON_FAILURE, false) ||
                  (attempt === taskRetryMax && process.stdin.isTTY && process.stdout.isTTY),
                taskLedger,
                runtimeRecentProxyIps,
                ipEmailUsage,
                activeProxyIps,
                blockedMailboxDomains,
              },
              preparedTask,
              taskMihomoController,
            );
            if (attempt > 1) {
              result.notes.push(`task retry succeeded on attempt ${attempt}`);
            }
            return result;
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            lastError = error instanceof Error ? error : new Error(message);
            if (attempt < taskRetryMax && preparedTask && shouldRotatePreparedTaskProxy(message)) {
              try {
                await rotatePreparedTaskProxy(
                  cfg,
                  args,
                  taskLedger,
                  taskMihomoController,
                  preparedTask,
                  runtimeRecentProxyIps,
                  ipEmailUsage,
                  activeProxyNames,
                  activeProxyIps,
                );
                log(
                  `[${requestedMode}] task ${preparedTask.taskId} attempt ${attempt}/${taskRetryMax} failed on proxy/browser stage, retrying with fresh proxy ${preparedTask.proxyName} (${preparedTask.proxyIp || "ip-pending"}): ${message}`,
                );
                continue;
              } catch (rotateError) {
                const rotateMessage = rotateError instanceof Error ? rotateError.message : String(rotateError);
                log(
                  `[${requestedMode}] task ${preparedTask.taskId} proxy rotation failed after attempt ${attempt}/${taskRetryMax}: ${rotateMessage}`,
                );
                lastError = rotateError instanceof Error ? rotateError : new Error(rotateMessage);
                break;
              }
            }
            if (attempt < taskRetryMax && shouldRetryTaskFailure(message)) {
              log(
                `[${requestedMode}] task ${preparedTask.taskId} attempt ${attempt}/${taskRetryMax} failed (run=${runIndex}, email=${preparedTask.email}, ip=${preparedTask.proxyIp}), retrying with fresh browser: ${message}`,
              );
              continue;
            }
            if (attempt < taskRetryMax) {
              log(
                `[${requestedMode}] task ${preparedTask.taskId} fail-fast after attempt ${attempt}/${taskRetryMax} (run=${runIndex}, email=${preparedTask.email}, ip=${preparedTask.proxyIp}): ${message}`,
              );
            }
            break;
          }
        }
      } finally {
        if (preparedTask) {
          activeProxyNames.delete(preparedTask.proxyName);
          if (preparedTask.proxyIp) activeProxyIps.delete(preparedTask.proxyIp);
        }
        await taskMihomoController.stop().catch(() => {});
      }

      throw lastError || new Error(`[${requestedMode}] task failed without result`);
    };

    if (!batchEnabled) {
      const result = await runOne(1);
      results.push(result);
      log(`[${requestedMode}] finished account=${result.email}`);
    } else {
      const need = args.need;
      const parallel = args.parallel;
      const configuredMaxBatchAttempts = toInt(process.env.BATCH_MAX_ATTEMPTS, need * 5);
      const maxBatchAttempts = Math.max(need, configuredMaxBatchAttempts);
      const running = new Set<Promise<void>>();
      let batchAbortError: Error | null = null;
      let launched = 0;

      const launch = (): void => {
        launched += 1;
        const runIndex = launched;
        const p = (async () => {
          log(`[batch] start run=${runIndex} active=${running.size + 1}/${parallel} success=${results.length}/${need}`);
          try {
            const result = await runOne(runIndex);
            results.push(result);
            log(`[batch] success run=${runIndex} account=${result.email} success=${results.length}/${need}`);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            failures.push({ runIndex, error: message });
            log(`[batch] fail run=${runIndex} success=${results.length}/${need}: ${message}`);
            if (!batchAbortError && shouldAbortBatchFailure(message)) {
              batchAbortError = error instanceof Error ? error : new Error(message);
              log(`[batch] abort requested after run=${runIndex}: ${message}`);
            }
          }
        })().finally(() => {
          running.delete(p);
        });
        running.add(p);
      };

      while (results.length < need) {
        if (batchAbortError && running.size === 0) {
          throw batchAbortError;
        }
        while (running.size < parallel && results.length + running.size < need) {
          if (batchAbortError) break;
          if (launched >= maxBatchAttempts) break;
          launch();
        }
        if (running.size === 0) {
          if (launched >= maxBatchAttempts) {
            throw new Error(
              `batch attempt limit reached: success=${results.length}/${need} launched=${launched}/${maxBatchAttempts}`,
            );
          }
          throw new Error(`batch scheduler stalled: need=${need} success=${results.length}`);
        }
        await Promise.race(Array.from(running));
      }

      await Promise.all(Array.from(running));
      if (batchAbortError) {
        throw batchAbortError;
      }
      if (results.length < need && launched >= maxBatchAttempts) {
        throw new Error(`batch attempt limit reached: success=${results.length}/${need} launched=${launched}/${maxBatchAttempts}`);
      }
      log(`[batch] completed success=${results.length}/${need} failures=${failures.length}`);
    }

    const summaryPayload = {
      batchId,
      requestedMode,
      completedAt: new Date().toISOString(),
      model: resolvedModel,
      need: args.need,
      parallel: args.parallel,
      successCount: results.length,
      failureCount: failures.length,
      failures: failures.slice(-50),
      results,
    };
    await writeJson(new URL("run_summary.json", OUTPUT_DIR), summaryPayload);

    const resultOutput = results[results.length - 1]!;
    await writeJson(new URL("result.json", OUTPUT_DIR), resultOutput);
    log("saved output/result.json");

    if (!batchEnabled) {
      console.log(renderAccountSummaryLine(1, resultOutput, args.printSecrets));
      if (args.printSecrets) {
        return;
      }
      console.log("SECRETS=hidden (pass --print-secrets to show)");
      return;
    }

    console.log(`BATCH_ID=${batchId}`);
    console.log(`NEED=${args.need}`);
    console.log(`SUCCESS=${results.length}`);
    console.log(`FAILURE=${failures.length}`);
    for (let i = 0; i < results.length; i += 1) {
      const item = results[i]!;
      console.log(renderAccountSummaryLine(i + 1, item, args.printSecrets));
    }
    if (!args.printSecrets) {
      console.log("SECRETS=hidden (pass --print-secrets to show)");
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

const MAIN_MODULE_PATH = fileURLToPath(import.meta.url);
const INVOKED_MODULE_PATH = process.argv[1] ? path.resolve(process.argv[1]) : "";

if (MAIN_MODULE_PATH === INVOKED_MODULE_PATH) {
  await main();
}
