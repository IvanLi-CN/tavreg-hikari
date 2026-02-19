import { Impit } from "impit";
import type { ProxyController } from "./adapter.js";
import { parseIpInfoPayload, type GeoInfo } from "./geo.js";

export interface NodeCheckResult {
  name: string;
  latencyMs?: number | null;
  geo?: GeoInfo;
  ok: boolean;
  error?: string;
}

const LOCAL_IP_CACHE_TTL_MS = 10 * 60_000;
let cachedLocalIp: { value?: string; fetchedAtMs: number } = { value: undefined, fetchedAtMs: 0 };

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

async function fetchTextWithTimeout(url: string, timeoutMs: number): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, timeoutMs));
  try {
    const resp = await fetch(url, { signal: controller.signal, headers: { Accept: "text/plain, application/json" } });
    if (!resp.ok) {
      throw new Error(`status_${resp.status}`);
    }
    return (await resp.text()).trim();
  } finally {
    clearTimeout(timer);
  }
}

export async function resolveLocalEgressIp(timeoutMs: number): Promise<string | undefined> {
  const now = Date.now();
  if (cachedLocalIp.value && now - cachedLocalIp.fetchedAtMs <= LOCAL_IP_CACHE_TTL_MS) {
    return cachedLocalIp.value;
  }

  const candidates = ["https://ipinfo.io/ip", "https://api.ipify.org", "https://ifconfig.me/ip"];
  for (const url of candidates) {
    try {
      const text = await fetchTextWithTimeout(url, timeoutMs);
      const ip = normalizeIp(text);
      if (ip) {
        cachedLocalIp = { value: ip, fetchedAtMs: now };
        return ip;
      }
    } catch {
      // ignore and try next source
    }
  }

  cachedLocalIp = { value: undefined, fetchedAtMs: now };
  return undefined;
}

async function fetchViaProxy(url: string, proxyUrl: string, timeoutMs: number): Promise<string> {
  const impit = new Impit({ proxyUrl, timeout: timeoutMs });
  const resp = await impit.fetch(url);
  if (!resp.ok) {
    throw new Error(`proxy_fetch_failed:${resp.status}`);
  }
  return await resp.text();
}

async function fetchIpInfoViaProxy(proxyUrl: string, timeoutMs: number, token?: string): Promise<GeoInfo> {
  const url = new URL("https://ipinfo.io/json");
  if (token && token.trim()) {
    url.searchParams.set("token", token.trim());
  }
  const body = await fetchViaProxy(url.toString(), proxyUrl, timeoutMs);
  const payload = JSON.parse(body) as Record<string, unknown>;
  return parseIpInfoPayload(payload);
}

export async function checkNode(
  controller: ProxyController,
  name: string,
  options: { checkUrl: string; timeoutMs: number; ipinfoToken?: string; maxLatencyMs?: number },
): Promise<NodeCheckResult> {
  try {
    const latency = await controller.testDelay(name, options.checkUrl, options.timeoutMs);
    await controller.setGroupProxy(name);
    const proxyUrl = controller.proxyServer;
    const geo = await fetchIpInfoViaProxy(proxyUrl, options.timeoutMs, options.ipinfoToken);
    const localIp = await resolveLocalEgressIp(options.timeoutMs);
    const nodeIp = normalizeIp(geo.ip);
    if (localIp && nodeIp && localIp === nodeIp) {
      return {
        name,
        latencyMs: latency,
        geo,
        ok: false,
        error: `proxy_same_as_local_ip:${nodeIp}`,
      };
    }
    const threshold = options.maxLatencyMs ?? options.timeoutMs;
    const ok = typeof latency === "number" ? latency <= threshold : false;
    return { name, latencyMs: latency, geo, ok };
  } catch (error) {
    return { name, ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function checkAllNodes(
  controller: ProxyController,
  options: { checkUrl: string; timeoutMs: number; ipinfoToken?: string; maxLatencyMs?: number },
): Promise<NodeCheckResult[]> {
  const nodes = await controller.listGroupNodes();
  const names = nodes.map((n) => n.name);
  const results: NodeCheckResult[] = [];
  for (const name of names) {
    const result = await checkNode(controller, name, options);
    results.push(result);
  }
  return results;
}

export function pickRandomAvailableNode(results: NodeCheckResult[]): NodeCheckResult | null {
  const candidates = results.filter((r) => r.ok);
  if (candidates.length === 0) return null;
  const idx = Math.floor(Math.random() * candidates.length);
  return candidates[idx] || null;
}
