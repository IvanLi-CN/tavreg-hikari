import type { AppSettings } from "../storage/app-db.js";
import { ProxyBrokerClient, type ProxyBrokerConfig, type ProxyBrokerSession } from "../proxy/broker.js";
import type { ProxyController, ProxyNode } from "../proxy/adapter.js";
import type { GeoInfo } from "../proxy/geo.js";

export interface ProxyBrokerRuntimeSession {
  session: ProxyBrokerSession;
  proxyUrl: string;
}

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

export async function openProxyBrokerRuntimeSession(input: {
  settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">;
  preferredIp?: string | null;
  excludedIps?: string[];
  excludedNodeNamePattern?: RegExp;
  fallbackOnPreferredIpFailure?: boolean;
}): Promise<ProxyBrokerRuntimeSession> {
  const client = createProxyBrokerClient(input.settings);
  const preferredIp = input.preferredIp?.trim();
  const excludedIps = new Set((input.excludedIps || []).map((item) => item.trim()).filter(Boolean));
  if (input.excludedNodeNamePattern) {
    try {
      const catalog = await client.listCatalog();
      for (const group of catalog.groups || []) {
        for (const node of group.nodes || []) {
          if (!input.excludedNodeNamePattern.test(node.proxy_name)) continue;
          if (node.primary_ip) excludedIps.add(node.primary_ip);
          for (const ip of node.resolved_ips || []) excludedIps.add(ip);
        }
      }
    } catch {
      // Machine keys can open/list sessions even when catalog is admin-only; do not block task launch.
    }
  }
  const fallbackRequest = {
    selection_mode: "any" as const,
    excluded_ips: Array.from(excludedIps),
    sort_mode: "lru" as const,
  };
  const session = preferredIp
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
