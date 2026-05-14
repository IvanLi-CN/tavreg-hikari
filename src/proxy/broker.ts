export interface ProxyBrokerConfig {
  baseUrl: string;
  profileId: string;
  apiKey: string;
  timeoutMs: number;
}

export interface ProxyBrokerOpenSessionRequest {
  selection_mode?: "any" | "geo" | "ip";
  country_codes?: string[];
  cities?: string[];
  specified_ips?: string[];
  excluded_ips?: string[];
  sort_mode?: "mru" | "lru";
  desired_port?: number | null;
}

export interface ProxyBrokerOpenSessionByNodeRequest {
  node_id: string;
  desired_port?: number | null;
}

export interface ProxyBrokerIpMetadata {
  ip?: string | null;
  last_probe_ok?: boolean | null;
  last_latency_ms?: number | null;
  median_latency_ms?: number | null;
  probe_updated_at?: string | number | null;
  last_probe_samples?: unknown;
  recent_probe_samples?: unknown;
  country_name?: string | null;
  region_name?: string | null;
  city?: string | null;
}

export interface ProxyBrokerSession {
  session_id: string;
  listen: string;
  bind_host: string;
  display_host: string;
  display_address: string;
  port: number;
  selected_ip: string;
  proxy_name: string;
  node_id: string;
  candidate_node_ids?: string[];
}

export interface ProxyBrokerCatalogNode {
  import_id: string;
  node_id: string;
  proxy_name: string;
  proxy_type: string;
  server: string;
  resolved_ips: string[];
  primary_ip?: string | null;
  ip_metadata?: ProxyBrokerIpMetadata[];
  can_open_session: boolean;
}

export interface ProxyBrokerCatalogGroup {
  import: {
    import_id: string;
    name?: string | null;
    proxy_count: number;
    distinct_ip_count: number;
  };
  nodes: ProxyBrokerCatalogNode[];
}

export interface ProxyBrokerCatalog {
  view: string;
  project_id?: string | null;
  groups: ProxyBrokerCatalogGroup[];
}

export interface ProxyBrokerRefreshResult {
  probed_ips?: number;
  geo_updated?: number;
  skipped_cached?: number;
  [key: string]: unknown;
}

export class ProxyBrokerError extends Error {
  code: string;
  status: number;
  details: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ProxyBrokerError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

export function proxyBrokerMetadataLatencyMs(metadata: ProxyBrokerIpMetadata | null | undefined): number | null {
  return numberValue(metadata?.median_latency_ms) ?? numberValue(metadata?.last_latency_ms);
}

export function proxyBrokerProbeUpdatedAtMs(metadata: ProxyBrokerIpMetadata | null | undefined): number | null {
  const value = metadata?.probe_updated_at;
  if (typeof value === "number" && Number.isFinite(value)) {
    return value < 10_000_000_000 ? value * 1000 : value;
  }
  if (typeof value === "string" && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

export function proxyBrokerMetadataIp(
  node: Pick<ProxyBrokerCatalogNode, "primary_ip" | "resolved_ips">,
  metadata: ProxyBrokerIpMetadata | null | undefined,
): string | null {
  const metadataIp = String(metadata?.ip || "").trim();
  return metadataIp || String(node.primary_ip || node.resolved_ips?.[0] || "").trim() || null;
}

export function proxyBrokerMetadataFresh(
  metadata: ProxyBrokerIpMetadata | null | undefined,
  nowMs = Date.now(),
  maxAgeMs = 30 * 60 * 1000,
): boolean {
  const updatedAtMs = proxyBrokerProbeUpdatedAtMs(metadata);
  return updatedAtMs != null && nowMs - updatedAtMs <= maxAgeMs;
}

export function proxyBrokerMetadataHealthy(
  metadata: ProxyBrokerIpMetadata | null | undefined,
  maxLatencyMs: number,
  nowMs = Date.now(),
  maxAgeMs = 30 * 60 * 1000,
): boolean {
  if (metadata?.last_probe_ok !== true) return false;
  if (!proxyBrokerMetadataFresh(metadata, nowMs, maxAgeMs)) return false;
  const latencyMs = proxyBrokerMetadataLatencyMs(metadata);
  return latencyMs != null && latencyMs <= maxLatencyMs;
}

function normalizeBaseUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/g, "");
  if (!trimmed) return "";
  return trimmed;
}

function buildUrl(cfg: ProxyBrokerConfig, path: string, query?: Record<string, string>): string {
  const url = new URL(`${normalizeBaseUrl(cfg.baseUrl)}${path}`);
  for (const [key, value] of Object.entries(query || {})) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

function mapBrokerStatusCode(status: number): string {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status >= 500) return "server_error";
  return `proxy_broker_http_${status}`;
}

async function parseBrokerResponse(resp: Response): Promise<unknown> {
  const text = await resp.text();
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export class ProxyBrokerClient {
  private cfg: ProxyBrokerConfig;

  constructor(cfg: ProxyBrokerConfig) {
    this.cfg = {
      ...cfg,
      baseUrl: normalizeBaseUrl(cfg.baseUrl),
      profileId: cfg.profileId.trim() || "Tavily",
      apiKey: cfg.apiKey.trim(),
      timeoutMs: Math.max(1000, Math.trunc(cfg.timeoutMs || 8000)),
    };
  }

  get configured(): boolean {
    return Boolean(this.cfg.baseUrl && this.cfg.profileId && this.cfg.apiKey);
  }

  proxyUrl(session: Pick<ProxyBrokerSession, "display_address">): string {
    const displayAddress = String(session.display_address || "").trim();
    const hostOverride = String(process.env.PROXY_BROKER_DISPLAY_HOST_OVERRIDE || "").trim();
    if (!hostOverride) return `http://${displayAddress}`;
    const url = new URL(`http://${displayAddress}`);
    url.hostname = hostOverride;
    return url.toString().replace(/\/$/, "");
  }

  async authMe(): Promise<unknown> {
    return await this.request("/api/v1/auth/me");
  }

  async listCatalog(): Promise<ProxyBrokerCatalog> {
    return (await this.request("/api/v1/proxy-catalog", "GET", undefined, {
      view: "project",
      project_id: this.cfg.profileId,
    })) as ProxyBrokerCatalog;
  }

  async refreshProject(): Promise<ProxyBrokerRefreshResult> {
    const payload = await this.request(`/api/v1/projects/${encodeURIComponent(this.cfg.profileId)}/refresh`, "POST", {});
    return payload && typeof payload === "object" ? payload as ProxyBrokerRefreshResult : {};
  }

  async listSessions(): Promise<{ sessions: ProxyBrokerSession[] }> {
    const payload = await this.request(`/api/v1/projects/${encodeURIComponent(this.cfg.profileId)}/sessions`);
    if (Array.isArray(payload)) return { sessions: payload as ProxyBrokerSession[] };
    if (payload && typeof payload === "object" && Array.isArray((payload as { sessions?: unknown }).sessions)) {
      return { sessions: (payload as { sessions: ProxyBrokerSession[] }).sessions };
    }
    return { sessions: [] };
  }

  async openSession(input: ProxyBrokerOpenSessionRequest = {}): Promise<ProxyBrokerSession> {
    return (await this.request(`/api/v1/projects/${encodeURIComponent(this.cfg.profileId)}/sessions/open`, "POST", {
      selection_mode: input.selection_mode || "any",
      country_codes: input.country_codes || [],
      cities: input.cities || [],
      specified_ips: input.specified_ips || [],
      excluded_ips: input.excluded_ips || [],
      sort_mode: input.sort_mode || "lru",
      desired_port: input.desired_port ?? null,
    })) as ProxyBrokerSession;
  }

  async openSessionByNode(input: ProxyBrokerOpenSessionByNodeRequest): Promise<ProxyBrokerSession> {
    return (await this.request(`/api/v1/projects/${encodeURIComponent(this.cfg.profileId)}/sessions/open-by-node`, "POST", {
      node_id: input.node_id,
      desired_port: input.desired_port ?? null,
    })) as ProxyBrokerSession;
  }

  async closeSession(sessionId: string): Promise<void> {
    await this.request(`/api/v1/projects/${encodeURIComponent(this.cfg.profileId)}/sessions/${encodeURIComponent(sessionId)}`, "DELETE");
  }

  private async request(
    path: string,
    method = "GET",
    body?: unknown,
    query?: Record<string, string>,
  ): Promise<unknown> {
    if (!this.cfg.baseUrl) throw new ProxyBrokerError(0, "proxy_broker_not_configured", "PROXY_BROKER_BASE_URL is not configured");
    if (!this.cfg.apiKey) throw new ProxyBrokerError(0, "proxy_broker_not_configured", "PROXY_BROKER_API_KEY is not configured");
    const controller = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.cfg.timeoutMs);
    try {
      const resp = await fetch(buildUrl(this.cfg, path, query), {
        method,
        signal: controller.signal,
        headers: {
          "accept": "application/json",
          "content-type": "application/json",
          "authorization": `Bearer ${this.cfg.apiKey}`,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const payload = await parseBrokerResponse(resp);
      if (!resp.ok) {
        const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
        const code = typeof record.code === "string" ? record.code : mapBrokerStatusCode(resp.status);
        const message = typeof record.message === "string" ? record.message : `${resp.status} ${resp.statusText}`;
        throw new ProxyBrokerError(resp.status, code, message, payload);
      }
      return payload;
    } catch (error) {
      if (error instanceof ProxyBrokerError) throw error;
      if (timedOut || controller.signal.aborted || (error instanceof Error && error.name === "AbortError")) {
        throw new ProxyBrokerError(0, "proxy_broker_request_timeout", `Proxy Broker request timed out after ${this.cfg.timeoutMs}ms`, {
          method,
          path,
          timeoutMs: this.cfg.timeoutMs,
        });
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new ProxyBrokerError(0, "proxy_broker_request_failed", message, {
        method,
        path,
      });
    } finally {
      clearTimeout(timeout);
    }
  }
}
