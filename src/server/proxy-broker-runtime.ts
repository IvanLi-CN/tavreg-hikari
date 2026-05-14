import { Impit } from "impit";
import type { AccountBrowserSessionRecord, AppSettings } from "../storage/app-db.js";
import {
  ProxyBrokerClient,
  ProxyBrokerError,
  proxyBrokerMetadataHealthy,
  proxyBrokerMetadataIp,
  proxyBrokerProbeUpdatedAtMs,
  type ProxyBrokerCatalog,
  type ProxyBrokerConfig,
  type ProxyBrokerSession,
} from "../proxy/broker.js";
import type { ProxyController, ProxyNode } from "../proxy/adapter.js";
import type { GeoInfo } from "../proxy/geo.js";

export type ProxyBrokerBusinessSite = "tavily" | "microsoft" | "chatgpt" | "grok";

export interface ProxyBrokerRuntimeSession {
  session: ProxyBrokerSession;
  proxyUrl: string;
}

const PROXY_BROKER_PROBE_MAX_AGE_MS = 30 * 60 * 1000;

type ProxyBrokerRuntimeSettings = Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs" | "maxLatencyMs">;

export interface ProxyBrokerDomainProbeResult {
  site: ProxyBrokerBusinessSite;
  url: string;
  status: number;
  ok: boolean;
}

export class ProxyBrokerDomainProbeError extends Error {
  code = "proxy_domain_unreachable";
  site: ProxyBrokerBusinessSite;
  url: string;
  sessionId: string;
  nodeName: string;
  selectedIp: string | null;
  attempts: number;

  constructor(input: {
    site: ProxyBrokerBusinessSite;
    url: string;
    sessionId: string;
    nodeName: string;
    selectedIp?: string | null;
    attempts: number;
    causeMessage: string;
  }) {
    super(
      `proxy_domain_unreachable: site=${input.site} url=${input.url} node=${input.nodeName || "unknown"} session=${input.sessionId || "unknown"} ip=${input.selectedIp || "unknown"} cause=${input.causeMessage}`,
    );
    this.name = "proxy_domain_unreachable";
    this.site = input.site;
    this.url = input.url;
    this.sessionId = input.sessionId;
    this.nodeName = input.nodeName;
    this.selectedIp = input.selectedIp || null;
    this.attempts = input.attempts;
  }
}

export const PROXY_BROKER_BUSINESS_PROBE_URLS: Record<ProxyBrokerBusinessSite, string[]> = {
  microsoft: ["https://login.microsoftonline.com/"],
  tavily: ["https://app.tavily.com/home", "https://auth.tavily.com/"],
  chatgpt: ["https://chatgpt.com/", "https://auth.openai.com/"],
  grok: ["https://grok.com/", "https://accounts.x.ai/", "https://console.x.ai/home"],
};

export function buildProxyBrokerConfig(settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">): ProxyBrokerConfig {
  return {
    baseUrl: String(process.env.PROXY_BROKER_BASE_URL || settings.proxyBrokerBaseUrl || "https://proxy-broker.ivanli.cc").trim(),
    profileId: String(process.env.PROXY_BROKER_PROFILE_ID || settings.proxyBrokerProfileId || "Tavily").trim() || "Tavily",
    apiKey: String(process.env.PROXY_BROKER_API_KEY || "").trim(),
    timeoutMs: Number(process.env.PROXY_BROKER_TIMEOUT_MS || 30000),
  };
}

export function createProxyBrokerClient(settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">): ProxyBrokerClient {
  return new ProxyBrokerClient(buildProxyBrokerConfig(settings));
}

export function reusableBrowserSessionProxyIp(
  session: Pick<AccountBrowserSessionRecord, "status" | "proxyIp"> | null | undefined,
): string | null {
  if (session?.status !== "ready") return null;
  return session.proxyIp?.trim() || null;
}

function normalizeMaxLatencyMs(settings: Pick<AppSettings, "maxLatencyMs">): number {
  const value = Number(settings.maxLatencyMs);
  return Number.isFinite(value) ? Math.max(100, Math.trunc(value)) : 3000;
}

function catalogNeedsProbeRefresh(
  catalog: ProxyBrokerCatalog,
  excludedNodeNamePattern?: RegExp,
  nowMs = Date.now(),
): boolean {
  let sawRefreshableNode = false;
  for (const group of catalog.groups || []) {
    for (const node of group.nodes || []) {
      if (!node.can_open_session) continue;
      if (excludedNodeNamePattern?.test(node.proxy_name)) continue;
      sawRefreshableNode = true;
      const metadataRows = node.ip_metadata || [];
      if (metadataRows.length === 0) return true;
      for (const metadata of metadataRows) {
        const updatedAtMs = proxyBrokerProbeUpdatedAtMs(metadata);
        if (updatedAtMs == null || nowMs - updatedAtMs > PROXY_BROKER_PROBE_MAX_AGE_MS) return true;
      }
    }
  }
  return !sawRefreshableNode;
}

function collectHealthyCandidateIps(input: {
  catalog: ProxyBrokerCatalog;
  maxLatencyMs: number;
  excludedIps: Set<string>;
  excludedNodeNamePattern?: RegExp;
  nowMs?: number;
}): string[] {
  const nowMs = input.nowMs ?? Date.now();
  const candidateIps: string[] = [];
  const seen = new Set<string>();
  for (const group of input.catalog.groups || []) {
    for (const node of group.nodes || []) {
      if (!node.can_open_session) continue;
      if (input.excludedNodeNamePattern?.test(node.proxy_name)) continue;
      const metadataRows = node.ip_metadata || [];
      for (const metadata of metadataRows) {
        const ip = proxyBrokerMetadataIp(node, metadata);
        if (!ip || input.excludedIps.has(ip) || seen.has(ip)) continue;
        if (!proxyBrokerMetadataHealthy(metadata, input.maxLatencyMs, nowMs, PROXY_BROKER_PROBE_MAX_AGE_MS)) continue;
        seen.add(ip);
        candidateIps.push(ip);
      }
    }
  }
  return candidateIps;
}

async function listFreshCatalog(client: ProxyBrokerClient, maxLatencyMs: number, excludedIps: Set<string>, excludedNodeNamePattern?: RegExp): Promise<{
  catalog: ProxyBrokerCatalog;
  candidateIps: string[];
}> {
  let catalog = await client.listCatalog();
  let candidateIps = collectHealthyCandidateIps({ catalog, maxLatencyMs, excludedIps, excludedNodeNamePattern });
  if (candidateIps.length === 0 && catalogNeedsProbeRefresh(catalog, excludedNodeNamePattern)) {
    await client.refreshProject();
    for (let attempt = 0; attempt < 4; attempt += 1) {
      if (attempt > 0) {
        await new Promise((resolve) => setTimeout(resolve, 750));
      }
      catalog = await client.listCatalog();
      candidateIps = collectHealthyCandidateIps({ catalog, maxLatencyMs, excludedIps, excludedNodeNamePattern });
      if (candidateIps.length > 0) {
        break;
      }
    }
  }
  return { catalog, candidateIps };
}

function noHealthyBrokerNodeError(maxLatencyMs: number): ProxyBrokerError {
  return new ProxyBrokerError(
    0,
    "proxy_broker_no_healthy_nodes",
    `no Proxy Broker node passed probe health and latency gate (last_probe_ok=true, latency <= ${maxLatencyMs}ms)`,
  );
}

function isNoHealthyBrokerNodeError(error: unknown): boolean {
  return error instanceof ProxyBrokerError
    && (error.code === "proxy_broker_no_healthy_nodes" || error.code === "proxy_broker_no_healthy_node");
}

function isRetryableBrokerOpenError(error: unknown): boolean {
  if (!(error instanceof ProxyBrokerError)) return false;
  return new Set([
    "not_found",
    "ip_not_found",
    "no_healthy_proxy_nodes",
    "proxy_runtime_apply_failed",
    "proxy_broker_request_failed",
    "proxy_broker_request_timeout",
  ]).has(error.code);
}

function brokerAttemptSummary(ip: string, error: unknown): Record<string, unknown> {
  return {
    ip,
    code: error instanceof ProxyBrokerError ? error.code : "unknown",
    message: error instanceof Error ? error.message : String(error),
  };
}

export async function openProxyBrokerRuntimeSession(input: {
  settings: ProxyBrokerRuntimeSettings;
  preferredNodeId?: string | null;
  preferredIp?: string | null;
  excludedIps?: string[];
  excludedNodeNamePattern?: RegExp;
  fallbackOnPreferredIpFailure?: boolean;
  maxOpenAttempts?: number;
}): Promise<ProxyBrokerRuntimeSession> {
  const client = createProxyBrokerClient(input.settings);
  const preferredNodeId = input.preferredNodeId?.trim();
  if (preferredNodeId) {
    const session = await client.openSessionByNode({
      node_id: preferredNodeId,
    });
    return {
      session,
      proxyUrl: client.proxyUrl(session),
    };
  }
  const maxLatencyMs = normalizeMaxLatencyMs(input.settings);
  const preferredIp = input.preferredIp?.trim();
  const excludedIps = new Set((input.excludedIps || []).map((item) => item.trim()).filter(Boolean));
  if (preferredIp && input.fallbackOnPreferredIpFailure === false && !input.excludedNodeNamePattern) {
    const session = await client.openSession({
      selection_mode: "ip",
      specified_ips: [preferredIp],
      excluded_ips: Array.from(excludedIps),
      sort_mode: "lru",
    });
    return {
      session,
      proxyUrl: client.proxyUrl(session),
    };
  }
  const { catalog, candidateIps } = await listFreshCatalog(client, maxLatencyMs, excludedIps, input.excludedNodeNamePattern);
  if (input.excludedNodeNamePattern) {
    for (const group of catalog.groups || []) {
      for (const node of group.nodes || []) {
        if (!input.excludedNodeNamePattern.test(node.proxy_name)) continue;
        if (node.primary_ip) excludedIps.add(node.primary_ip);
        for (const ip of node.resolved_ips || []) excludedIps.add(ip);
      }
    }
  }
  const healthyIps = candidateIps.filter((ip) => !excludedIps.has(ip));
  if (healthyIps.length === 0) throw noHealthyBrokerNodeError(maxLatencyMs);
  const preferredHealthy = preferredIp ? healthyIps.includes(preferredIp) : false;
  if (preferredIp && !preferredHealthy && input.fallbackOnPreferredIpFailure === false) {
    throw noHealthyBrokerNodeError(maxLatencyMs);
  }
  const maxOpenAttempts = input.maxOpenAttempts == null
    ? healthyIps.length
    : Math.max(1, Math.trunc(input.maxOpenAttempts));
  const queue = [
    ...(preferredIp && preferredHealthy ? [preferredIp] : []),
    ...healthyIps.filter((ip) => ip !== preferredIp),
  ].slice(0, maxOpenAttempts);
  const attempts: Array<Record<string, unknown>> = [];
  let lastError: unknown = null;
  for (const ip of queue) {
    if (excludedIps.has(ip)) continue;
    try {
      const session = await client.openSession({
        selection_mode: "ip",
        specified_ips: [ip],
        excluded_ips: Array.from(excludedIps),
        sort_mode: "lru",
      });
      return {
        session,
        proxyUrl: client.proxyUrl(session),
      };
    } catch (error) {
      attempts.push(brokerAttemptSummary(ip, error));
      lastError = error;
      excludedIps.add(ip);
      if (input.fallbackOnPreferredIpFailure === false || !isRetryableBrokerOpenError(error)) {
        throw error;
      }
    }
  }
  if (lastError instanceof ProxyBrokerError) {
    throw new ProxyBrokerError(lastError.status, lastError.code, `${lastError.message}; broker open attempts exhausted`, {
      attempts,
      cause: lastError.details,
    });
  }
  if (lastError) throw lastError;
  throw noHealthyBrokerNodeError(maxLatencyMs);
}

function isDomainProbeReachableStatus(status: number): boolean {
  return (status >= 200 && status < 400) || status === 401 || status === 403 || status === 404;
}

async function defaultProxyDomainProbeFetch(input: {
  proxyUrl: string;
  url: string;
  timeoutMs: number;
}): Promise<{ status: number }> {
  const impit = new Impit({ proxyUrl: input.proxyUrl, timeout: input.timeoutMs, followRedirects: false });
  const resp = await impit.fetch(input.url, {
    headers: {
      Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    },
  });
  return { status: resp.status };
}

async function probeProxyBrokerBusinessDomains(input: {
  site: ProxyBrokerBusinessSite;
  session: ProxyBrokerRuntimeSession;
  timeoutMs: number;
  probeUrls?: string[];
  probeFetch?: (input: { proxyUrl: string; url: string; timeoutMs: number }) => Promise<{ status: number }>;
}): Promise<ProxyBrokerDomainProbeResult[]> {
  const urls = (input.probeUrls?.length ? input.probeUrls : PROXY_BROKER_BUSINESS_PROBE_URLS[input.site])
    .map((item) => item.trim())
    .filter(Boolean);
  const probeFetch = input.probeFetch || defaultProxyDomainProbeFetch;
  const results: ProxyBrokerDomainProbeResult[] = [];
  for (const url of urls) {
    try {
      const resp = await probeFetch({ proxyUrl: input.session.proxyUrl, url, timeoutMs: input.timeoutMs });
      const ok = isDomainProbeReachableStatus(resp.status);
      results.push({ site: input.site, url, status: resp.status, ok });
      if (!ok) {
        throw new Error(`http_status_${resp.status}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new ProxyBrokerDomainProbeError({
        site: input.site,
        url,
        sessionId: input.session.session.session_id,
        nodeName: input.session.session.proxy_name,
        selectedIp: input.session.session.selected_ip,
        attempts: 1,
        causeMessage: message || "domain probe failed",
      });
    }
  }
  return results;
}

export async function openDomainProbedProxyBrokerRuntimeSession(input: {
  settings: ProxyBrokerRuntimeSettings;
  businessSite: ProxyBrokerBusinessSite;
  preferredNodeId?: string | null;
  preferredIp?: string | null;
  excludedIps?: string[];
  excludedNodeNamePattern?: RegExp;
  fallbackOnPreferredIpFailure?: boolean;
  maxProbeRotations?: number;
  probeUrls?: string[];
  probeFetch?: (input: { proxyUrl: string; url: string; timeoutMs: number }) => Promise<{ status: number }>;
}): Promise<ProxyBrokerRuntimeSession> {
  const maxProbeRotations = Math.max(0, Math.trunc(input.maxProbeRotations ?? 3));
  const maxAttempts = maxProbeRotations + 1;
  const excludedIps = new Set((input.excludedIps || []).map((item) => item.trim()).filter(Boolean));
  let lastError: ProxyBrokerDomainProbeError | null = null;
  const preferredNodeId = input.preferredNodeId?.trim() || null;
  const preferredIp = input.preferredIp?.trim() || null;
  const requiresPreferredNode = Boolean(preferredNodeId);
  const requiresPreferredIp = Boolean(preferredIp && input.fallbackOnPreferredIpFailure === false);
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    let session: ProxyBrokerRuntimeSession;
    try {
      session = await openProxyBrokerRuntimeSession({
        settings: input.settings,
        preferredNodeId,
        preferredIp: preferredIp && (requiresPreferredIp || !excludedIps.has(preferredIp)) ? preferredIp : null,
        excludedIps: Array.from(excludedIps),
        excludedNodeNamePattern: input.excludedNodeNamePattern,
        fallbackOnPreferredIpFailure: input.fallbackOnPreferredIpFailure,
      });
    } catch (error) {
      if (lastError && isNoHealthyBrokerNodeError(error)) {
        throw lastError;
      }
      throw error;
    }
    try {
      await probeProxyBrokerBusinessDomains({
        site: input.businessSite,
        session,
        timeoutMs: buildProxyBrokerConfig(input.settings).timeoutMs,
        probeUrls: input.probeUrls,
        probeFetch: input.probeFetch,
      });
      return session;
    } catch (error) {
      const probeError =
        error instanceof ProxyBrokerDomainProbeError
          ? error
          : new ProxyBrokerDomainProbeError({
              site: input.businessSite,
              url: input.probeUrls?.[0] || PROXY_BROKER_BUSINESS_PROBE_URLS[input.businessSite][0] || "unknown",
              sessionId: session.session.session_id,
              nodeName: session.session.proxy_name,
              selectedIp: session.session.selected_ip,
              attempts: attempt,
              causeMessage: error instanceof Error ? error.message : String(error),
            });
      probeError.attempts = attempt;
      lastError = probeError;
      if (session.session.selected_ip) excludedIps.add(session.session.selected_ip);
      await closeProxyBrokerRuntimeSession(input.settings, session.session.session_id).catch((closeError) => {
        logProxyBrokerSessionCloseError(session.session.session_id, closeError, `${input.businessSite}-domain-probe-rotation`);
      });
      if (requiresPreferredNode || requiresPreferredIp || attempt >= maxAttempts) {
        throw probeError;
      }
    }
  }
  throw lastError || new Error("proxy_domain_unreachable");
}

export async function closeProxyBrokerRuntimeSession(
  settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">,
  sessionId: string | null | undefined,
): Promise<void> {
  const normalized = String(sessionId || "").trim();
  if (!normalized) return;
  await createProxyBrokerClient(settings).closeSession(normalized);
}

export function logProxyBrokerSessionCloseError(sessionId: string | null | undefined, error: unknown, context: string): void {
  const normalized = String(sessionId || "").trim() || "unknown";
  const message = error instanceof Error ? error.message : String(error);
  console.warn(`[proxy-broker] failed to close session ${normalized} during ${context}: ${message}`);
}

export function buildProxyBrokerEnv(session: ProxyBrokerRuntimeSession): NodeJS.ProcessEnv {
  return {
    PROXY_BROKER_SESSION_ID: session.session.session_id,
    PROXY_BROKER_PROXY_URL: session.proxyUrl,
    PROXY_BROKER_PROXY_NODE: session.session.proxy_name,
    PROXY_BROKER_PROXY_NODE_ID: session.session.node_id,
    PROXY_BROKER_PROXY_IP: session.session.selected_ip,
    PROXY_BROKER_PROXY_DISPLAY_ADDRESS: session.session.display_address,
  };
}

export function getInjectedProxyFromEnv(env: NodeJS.ProcessEnv = process.env): {
  sessionId: string | null;
  proxyUrl: string;
  nodeName: string;
  nodeId: string | null;
  ip: string | null;
  displayAddress: string | null;
} | null {
  const proxyUrl = String(env.PROXY_BROKER_PROXY_URL || "").trim();
  if (!proxyUrl) return null;
  return {
    sessionId: String(env.PROXY_BROKER_SESSION_ID || "").trim() || null,
    proxyUrl,
    nodeName: String(env.PROXY_BROKER_PROXY_NODE || env.PROXY_BROKER_PROXY_NODE_ID || "proxy-broker-session").trim(),
    nodeId: String(env.PROXY_BROKER_PROXY_NODE_ID || "").trim() || null,
    ip: String(env.PROXY_BROKER_PROXY_IP || "").trim() || null,
    displayAddress: String(env.PROXY_BROKER_PROXY_DISPLAY_ADDRESS || "").trim() || null,
  };
}

export function buildInjectedProxyGeo(env: NodeJS.ProcessEnv = process.env): GeoInfo {
  const injected = getInjectedProxyFromEnv(env);
  return {
    ip: injected?.ip || "",
  };
}

export function createInjectedProxyController(env: NodeJS.ProcessEnv = process.env): ProxyController | null {
  const injected = getInjectedProxyFromEnv(env);
  if (!injected) return null;
  let selected = injected.nodeName;
  const node: ProxyNode = { name: injected.nodeName, type: "mixed" };
  return {
    apiBaseUrl: "proxy-broker://session",
    proxyServer: injected.proxyUrl,
    groupName: "Proxy Broker",
    async listGroupNodes() {
      return [node];
    },
    async getGroupSelection() {
      return selected;
    },
    async setGroupProxy(name: string) {
      selected = name.trim() || injected.nodeName;
    },
    async testDelay() {
      return 1;
    },
    async stop() {
      return;
    },
  };
}
