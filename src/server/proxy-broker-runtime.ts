import type { AppSettings } from "../storage/app-db.js";
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

export interface ProxyBrokerRuntimeSession {
  session: ProxyBrokerSession;
  proxyUrl: string;
}

const PROXY_BROKER_PROBE_MAX_AGE_MS = 30 * 60 * 1000;

type ProxyBrokerRuntimeSettings = Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs" | "maxLatencyMs">;

export function buildProxyBrokerConfig(settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">): ProxyBrokerConfig {
  return {
    baseUrl: String(process.env.PROXY_BROKER_BASE_URL || settings.proxyBrokerBaseUrl || "https://proxy-broker.ivanli.cc").trim(),
    profileId: String(process.env.PROXY_BROKER_PROFILE_ID || settings.proxyBrokerProfileId || "Tavily").trim() || "Tavily",
    apiKey: String(process.env.PROXY_BROKER_API_KEY || "").trim(),
    timeoutMs: Number(process.env.PROXY_BROKER_TIMEOUT_MS || settings.timeoutMs || 8000),
  };
}

export function createProxyBrokerClient(settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">): ProxyBrokerClient {
  return new ProxyBrokerClient(buildProxyBrokerConfig(settings));
}

function normalizeMaxLatencyMs(settings: Pick<AppSettings, "maxLatencyMs">): number {
  const value = Number(settings.maxLatencyMs);
  return Number.isFinite(value) ? Math.max(100, Math.trunc(value)) : 3000;
}

function catalogHasFreshProbeMetadata(catalog: ProxyBrokerCatalog, nowMs = Date.now()): boolean {
  for (const group of catalog.groups || []) {
    for (const node of group.nodes || []) {
      for (const metadata of node.ip_metadata || []) {
        const updatedAtMs = proxyBrokerProbeUpdatedAtMs(metadata);
        if (updatedAtMs != null && nowMs - updatedAtMs <= PROXY_BROKER_PROBE_MAX_AGE_MS) return true;
      }
    }
  }
  return false;
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
  if (candidateIps.length === 0 || !catalogHasFreshProbeMetadata(catalog)) {
    await client.refreshProject();
    catalog = await client.listCatalog();
    candidateIps = collectHealthyCandidateIps({ catalog, maxLatencyMs, excludedIps, excludedNodeNamePattern });
  }
  return { catalog, candidateIps };
}

function noHealthyBrokerNodeError(maxLatencyMs: number): ProxyBrokerError {
  return new ProxyBrokerError(
    0,
    "proxy_broker_no_healthy_node",
    `no Proxy Broker node passed probe health and latency gate (last_probe_ok=true, latency <= ${maxLatencyMs}ms)`,
  );
}

export async function openProxyBrokerRuntimeSession(input: {
  settings: ProxyBrokerRuntimeSettings;
  preferredIp?: string | null;
  excludedIps?: string[];
  excludedNodeNamePattern?: RegExp;
  fallbackOnPreferredIpFailure?: boolean;
}): Promise<ProxyBrokerRuntimeSession> {
  const client = createProxyBrokerClient(input.settings);
  const maxLatencyMs = normalizeMaxLatencyMs(input.settings);
  const preferredIp = input.preferredIp?.trim();
  const excludedIps = new Set((input.excludedIps || []).map((item) => item.trim()).filter(Boolean));
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
  const fallbackRequest = {
    selection_mode: "ip" as const,
    specified_ips: healthyIps,
    excluded_ips: Array.from(excludedIps),
    sort_mode: "lru" as const,
  };
  const preferredHealthy = preferredIp ? healthyIps.includes(preferredIp) : false;
  if (preferredIp && !preferredHealthy && input.fallbackOnPreferredIpFailure === false) {
    throw noHealthyBrokerNodeError(maxLatencyMs);
  }
  const session = preferredIp && preferredHealthy
    ? await client.openSession({
        selection_mode: "ip",
        specified_ips: [preferredIp],
        excluded_ips: Array.from(excludedIps),
        sort_mode: "lru",
      }).catch((error) => {
        if (input.fallbackOnPreferredIpFailure === false) throw error;
        return client.openSession(fallbackRequest);
      })
    : await client.openSession(fallbackRequest);
  return {
    session,
    proxyUrl: client.proxyUrl(session),
  };
}

export async function closeProxyBrokerRuntimeSession(
  settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">,
  sessionId: string | null | undefined,
): Promise<void> {
  const normalized = String(sessionId || "").trim();
  if (!normalized) return;
  await createProxyBrokerClient(settings).closeSession(normalized);
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
