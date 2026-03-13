import { spawn } from "node:child_process";
import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { gunzipSync } from "node:zlib";
import path from "node:path";
import process from "node:process";
import { parse as yamlParse, stringify as yamlStringify } from "yaml";
import type { ProxyController, ProxyNode } from "./adapter.js";

interface ReleaseAsset {
  name?: string;
  browser_download_url?: string;
}

interface ReleaseInfo {
  tag_name?: string;
  assets?: ReleaseAsset[];
}

export interface MihomoConfig {
  subscriptionUrl: string;
  apiPort: number;
  mixedPort: number;
  groupName: string;
  routeGroupName?: string;
  checkUrl: string;
  workDir: string;
  downloadDir: string;
  version?: string;
}

interface MihomoProcess {
  stop: () => Promise<void>;
}

const RESERVED_PROXY_NAMES = new Set([
  "DIRECT",
  "REJECT",
  "GLOBAL",
  "AUTO",
  "PROXY",
  "COMPATIBLE",
  "PASS",
  "FINAL",
  "CODEX_ROUTE",
  "CODEX_AUTO",
]);

const RELEASE_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest";
const RELEASE_TAG_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags";

// Avoid duplicate downloads when multiple runs start in parallel.
const mihomoBinaryCache = new Map<string, Promise<string>>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function resolvePlatform(): { os: string; archAliases: string[] } {
  const platform = process.platform;
  const arch = process.arch;

  let os: string;
  if (platform === "darwin") os = "darwin";
  else if (platform === "linux") os = "linux";
  else if (platform === "win32") os = "windows";
  else throw new Error(`mihomo unsupported platform: ${platform}`);

  let archAliases: string[] = [];
  if (arch === "x64") archAliases = ["amd64"];
  else if (arch === "arm64") archAliases = ["arm64", "arm64-v8", "aarch64", "armv8"];
  else if (arch === "arm") archAliases = ["armv7", "armv6", "arm"];
  else if (arch === "ia32") archAliases = ["386", "x86"];
  else throw new Error(`mihomo unsupported arch: ${arch}`);

  return { os, archAliases };
}

async function fetchRelease(url: string): Promise<{ tag: string; assets: ReleaseAsset[] }> {
  const resp = await fetch(url, {
    headers: {
      "Accept": "application/vnd.github+json",
      "User-Agent": "tavreg-hikari",
    },
  });
  if (!resp.ok) {
    throw new Error(`mihomo_release_failed:${resp.status}`);
  }
  const payload = (await resp.json()) as ReleaseInfo;
  const tag = payload.tag_name?.trim();
  if (!tag) throw new Error("mihomo_release_missing_tag");
  return { tag, assets: payload.assets || [] };
}

function selectAsset(
  assets: ReleaseAsset[],
  os: string,
  archAliases: string[],
  tag: string,
): ReleaseAsset {
  const gzAssets = assets.filter((asset) => (asset.name || "").endsWith(".gz"));

  const matchByArch = gzAssets.filter((asset) => {
    const name = asset.name || "";
    if (!name.startsWith(`mihomo-${os}-`)) return false;
    return archAliases.some((arch) => name.startsWith(`mihomo-${os}-${arch}`));
  });

  if (matchByArch.length === 0) {
    throw new Error(
      `mihomo_asset_not_found: os=${os} arch=${archAliases.join(",")} assets=${gzAssets
        .map((a) => a.name)
        .join(", ")}`,
    );
  }

  const exact = matchByArch.find((asset) => asset.name === `mihomo-${os}-${archAliases[0]}-${tag}.gz`);
  if (exact) return exact;

  const preferredSuffixes = ["compatible", "v1", "v2", "v3"];
  for (const suffix of preferredSuffixes) {
    const candidate = matchByArch.find((asset) => (asset.name || "").includes(`-${suffix}-${tag}.gz`));
    if (candidate) return candidate;
  }

  const tagMatch = matchByArch.find((asset) => (asset.name || "").includes(`-${tag}.gz`));
  if (tagMatch) return tagMatch;

  return matchByArch[0]!;
}

async function downloadMihomoBinary(cfg: MihomoConfig): Promise<string> {
  const cacheKey = `${cfg.version || "latest"}:${process.platform}:${process.arch}`;
  const cached = mihomoBinaryCache.get(cacheKey);
  if (cached) {
    return await cached;
  }

  const downloadPromise = (async (): Promise<string> => {
    const { os, archAliases } = resolvePlatform();
    const tagOverride = cfg.version ? (cfg.version.startsWith("v") ? cfg.version : `v${cfg.version}`) : null;
    const release = await fetchRelease(tagOverride ? `${RELEASE_TAG_API}/${tagOverride}` : RELEASE_API);
    const tag = tagOverride || release.tag;
    const assets = release.assets;
    const asset = selectAsset(assets, os, archAliases, tag);

    if (!asset.browser_download_url || !asset.name) {
      throw new Error("mihomo_asset_invalid");
    }

    const versionLabel = tag.replace(/^v/, "");
    const dir = path.join(cfg.downloadDir, versionLabel);
    const binName = os === "windows" ? "mihomo.exe" : "mihomo";
    const binPath = path.join(dir, binName);

    if (await fileExists(binPath)) {
      return binPath;
    }

    await mkdir(dir, { recursive: true });
    const resp = await fetch(asset.browser_download_url);
    if (!resp.ok) {
      throw new Error(`mihomo_download_failed:${resp.status}`);
    }

    const gzBuffer = Buffer.from(await resp.arrayBuffer());
    const binBuffer = gunzipSync(gzBuffer);
    await writeFile(binPath, binBuffer);
    if (os !== "windows") {
      await chmod(binPath, 0o755);
    }

    return binPath;
  })();

  mihomoBinaryCache.set(cacheKey, downloadPromise);
  try {
    return await downloadPromise;
  } catch (error) {
    // Allow retry after transient download failures.
    mihomoBinaryCache.delete(cacheKey);
    throw error;
  }
}

function looksLikeBase64(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed || trimmed.length % 4 !== 0) return false;
  if (/[^A-Za-z0-9+/=\r\n]/.test(trimmed)) return false;
  return true;
}

function decodeBase64IfNeeded(text: string): string {
  if (!looksLikeBase64(text)) return text;
  try {
    const decoded = Buffer.from(text.trim(), "base64").toString("utf8");
    if (/proxies:|proxy-providers:|proxy-groups:|:\/\//i.test(decoded)) {
      return decoded;
    }
  } catch {
    // ignore
  }
  return text;
}

function decodeBase64Loose(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const normalized = trimmed.replace(/\s+/g, "");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  try {
    return Buffer.from(`${normalized}${padding}`, "base64").toString("utf8");
  } catch {
    return null;
  }
}

function decodeNodeName(hash: string): string {
  const raw = hash.replace(/^#/, "").trim();
  if (!raw) return "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function parseBooleanFlag(value: string | null, fallback: boolean): boolean {
  if (value == null || value.trim() === "") return fallback;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function parsePortValue(raw: string): number | null {
  const port = Number.parseInt(raw.trim(), 10);
  return Number.isInteger(port) && port > 0 ? port : null;
}

function pushUniqueProxy(
  deduped: Map<string, Record<string, unknown>>,
  proxy: Record<string, unknown> | null,
): void {
  if (!proxy) return;
  const name = typeof proxy.name === "string" ? proxy.name.trim() : "";
  if (!name || deduped.has(name)) return;
  deduped.set(name, proxy);
}

function parseVlessUri(line: string): Record<string, unknown> | null {
  let url: URL;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const name = decodeNodeName(url.hash);
  const port = parsePortValue(url.port);
  if (!name || !url.hostname || !port || !url.username) return null;

  const params = url.searchParams;
  const network = (params.get("type") || "tcp").trim().toLowerCase();
  const security = (params.get("security") || "").trim().toLowerCase();
  const proxy: Record<string, unknown> = {
    name,
    type: "vless",
    server: url.hostname,
    port,
    uuid: decodeURIComponent(url.username),
    udp: true,
    cipher: "auto",
  };
  if (security === "tls" || security === "reality") {
    proxy.tls = true;
  }
  const flow = params.get("flow")?.trim();
  if (flow) proxy.flow = flow;
  const fingerprint = params.get("fp")?.trim();
  if (fingerprint) proxy["client-fingerprint"] = fingerprint;
  const servername = params.get("sni")?.trim();
  if (servername) {
    proxy.servername = servername;
    proxy["skip-cert-verify"] = parseBooleanFlag(params.get("insecure"), false);
  }
  if (security === "reality") {
    const realityOpts: Record<string, unknown> = {};
    const publicKey = params.get("pbk")?.trim();
    if (publicKey) realityOpts["public-key"] = publicKey;
    if (params.has("sid")) realityOpts["short-id"] = params.get("sid") || "";
    if (Object.keys(realityOpts).length > 0) proxy["reality-opts"] = realityOpts;
  }
  if (network && network !== "tcp") {
    proxy.network = network;
  }
  if (network === "grpc") {
    const serviceName = params.get("serviceName")?.trim();
    if (serviceName) {
      proxy["grpc-opts"] = { "grpc-service-name": serviceName };
    }
  } else if (network === "ws") {
    const wsOpts: Record<string, unknown> = {};
    const host = params.get("host")?.trim();
    const pathValue = params.get("path")?.trim();
    if (pathValue) wsOpts.path = pathValue;
    if (host) wsOpts.headers = { Host: host };
    if (Object.keys(wsOpts).length > 0) proxy["ws-opts"] = wsOpts;
  }
  return proxy;
}

function parseHysteria2Uri(line: string): Record<string, unknown> | null {
  let url: URL;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const name = decodeNodeName(url.hash);
  const port = parsePortValue(url.port);
  if (!name || !url.hostname || !port || !url.username) return null;

  const proxy: Record<string, unknown> = {
    name,
    type: "hysteria2",
    server: url.hostname,
    port,
    password: decodeURIComponent(url.username),
    udp: true,
    "skip-cert-verify": parseBooleanFlag(url.searchParams.get("insecure"), false),
  };
  const sni = url.searchParams.get("sni")?.trim();
  if (sni) proxy.sni = sni;
  const obfs = url.searchParams.get("obfs")?.trim();
  if (obfs) proxy.obfs = obfs;
  const obfsPassword = url.searchParams.get("obfs-password")?.trim();
  if (obfsPassword) proxy["obfs-password"] = obfsPassword;
  return proxy;
}

function parseShadowsocksUri(line: string): Record<string, unknown> | null {
  let url: URL;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const name = decodeNodeName(url.hash);
  const port = parsePortValue(url.port);
  if (!name || !url.hostname || !port) return null;

  let cipher = "";
  let password = "";
  const rawUser = decodeURIComponent(url.username || "");
  if (rawUser) {
    const decodedUser = decodeBase64Loose(rawUser);
    const auth = decodedUser && decodedUser.includes(":") ? decodedUser : rawUser;
    const idx = auth.indexOf(":");
    if (idx > 0) {
      cipher = auth.slice(0, idx);
      password = auth.slice(idx + 1);
    }
  }
  if ((!cipher || !password) && url.password) {
    cipher = rawUser;
    password = decodeURIComponent(url.password);
  }
  if (!cipher || !password) return null;

  return {
    name,
    type: "ss",
    server: url.hostname,
    port,
    cipher,
    password,
    udp: true,
  };
}

function parseTuicUri(line: string): Record<string, unknown> | null {
  let url: URL;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const name = decodeNodeName(url.hash);
  const port = parsePortValue(url.port);
  if (!name || !url.hostname || !port || !url.username) return null;

  const proxy: Record<string, unknown> = {
    name,
    type: "tuic",
    server: url.hostname,
    port,
    version: 5,
    uuid: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password || ""),
    "skip-cert-verify": parseBooleanFlag(url.searchParams.get("insecure"), false),
  };
  if (!proxy.password) return null;
  const sni = url.searchParams.get("sni")?.trim();
  if (sni) proxy.sni = sni;
  const alpn = url.searchParams
    .get("alpn")
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (alpn && alpn.length > 0) proxy.alpn = alpn;
  const congestion = url.searchParams.get("congestion_control")?.trim();
  if (congestion) proxy["congestion-controller"] = congestion;
  const udpRelayMode = url.searchParams.get("udp_relay_mode")?.trim();
  if (udpRelayMode) proxy["udp-relay-mode"] = udpRelayMode;
  return proxy;
}

function parseProxyUri(line: string): Record<string, unknown> | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  if (trimmed.startsWith("vless://")) return parseVlessUri(trimmed);
  if (trimmed.startsWith("hysteria2://")) return parseHysteria2Uri(trimmed);
  if (trimmed.startsWith("ss://")) return parseShadowsocksUri(trimmed);
  if (trimmed.startsWith("tuic://")) return parseTuicUri(trimmed);
  return null;
}

function parseProviderPayloadToProxies(content: string): Record<string, unknown>[] {
  const text = decodeBase64IfNeeded(content).trim();
  if (!text) return [];

  const deduped = new Map<string, Record<string, unknown>>();
  try {
    const parsed = yamlParse(text) as unknown;
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item && typeof item === "object") {
          pushUniqueProxy(deduped, { ...(item as Record<string, unknown>) });
        }
      }
    } else if (parsed && typeof parsed === "object") {
      const record = parsed as Record<string, unknown>;
      const proxies = Array.isArray(record.proxies) ? record.proxies : [];
      for (const item of proxies) {
        if (item && typeof item === "object") {
          pushUniqueProxy(deduped, { ...(item as Record<string, unknown>) });
        }
      }
    }
  } catch {
    // fall through to URI parsing
  }
  if (deduped.size > 0) {
    return [...deduped.values()];
  }

  for (const line of text.split(/\r?\n/)) {
    pushUniqueProxy(deduped, parseProxyUri(line));
  }
  return [...deduped.values()];
}

function extractUriProxyName(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const hashIndex = trimmed.lastIndexOf("#");
  if (hashIndex < 0 || hashIndex >= trimmed.length - 1) return null;
  const raw = trimmed.slice(hashIndex + 1).trim();
  if (!raw) return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

async function parseProviderNodeNames(filePath: string): Promise<ProxyNode[]> {
  let raw = "";
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const text = raw.trim();
  if (!text) return [];

  const deduped = new Map<string, ProxyNode>();
  const pushNode = (name: unknown, type?: unknown): void => {
    if (typeof name !== "string") return;
    const trimmed = name.trim();
    if (!trimmed) return;
    if (!deduped.has(trimmed)) {
      deduped.set(trimmed, { name: trimmed, type: typeof type === "string" ? type : undefined });
    }
  };

  try {
    const parsed = yamlParse(text) as unknown;
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item && typeof item === "object") {
          const record = item as Record<string, unknown>;
          pushNode(record.name, record.type);
        }
      }
    } else if (parsed && typeof parsed === "object") {
      const record = parsed as Record<string, unknown>;
      const proxies = Array.isArray(record.proxies) ? record.proxies : [];
      for (const item of proxies) {
        if (item && typeof item === "object") {
          const proxy = item as Record<string, unknown>;
          pushNode(proxy.name, proxy.type);
        }
      }
    }
  } catch {
    // fall through to URI-line parsing
  }

  if (deduped.size > 0) {
    return [...deduped.values()];
  }

  for (const line of text.split(/\r?\n/)) {
    const name = extractUriProxyName(line);
    if (name) pushNode(name);
  }
  return [...deduped.values()];
}

function normalizeProviders(
  providers: Record<string, Record<string, unknown>>,
  checkUrl: string,
): Record<string, Record<string, unknown>> {
  const normalized: Record<string, Record<string, unknown>> = {};
  for (const [name, provider] of Object.entries(providers)) {
    if (!provider || typeof provider !== "object") continue;
    const entry: Record<string, unknown> = { ...provider };
    if (typeof entry.type !== "string") {
      entry.type = "http";
    }
    entry.path = `./proxy_providers/${name}.yaml`;
    if (!entry["health-check"]) {
      entry["health-check"] = { enable: true, url: checkUrl, interval: 600, timeout: 5000 };
    }
    normalized[name] = entry;
  }
  return normalized;
}

function normalizeRuleProviders(
  providers: Record<string, Record<string, unknown>>,
): Record<string, Record<string, unknown>> {
  const normalized: Record<string, Record<string, unknown>> = {};
  for (const [name, provider] of Object.entries(providers)) {
    if (!provider || typeof provider !== "object") continue;
    const entry: Record<string, unknown> = { ...provider };
    if (typeof entry.path !== "string" || !entry.path.trim()) {
      entry.path = `./rule_providers/${name}.yaml`;
    }
    normalized[name] = entry;
  }
  return normalized;
}

async function fetchSubscription(url: string): Promise<Record<string, unknown>> {
  const resp = await fetch(url, { headers: { Accept: "text/plain, application/yaml, text/yaml" } });
  if (!resp.ok) {
    throw new Error(`mihomo_subscription_failed:${resp.status}`);
  }
  const raw = await resp.text();
  const content = decodeBase64IfNeeded(raw);
  const parsed = yamlParse(content) as Record<string, unknown>;
  const subscription = typeof parsed === "object" && parsed ? parsed : {};
  const providers = (subscription["proxy-providers"] || {}) as Record<string, Record<string, unknown>>;
  const materializedProviders: Record<string, Record<string, unknown>[]> = {};

  for (const [name, provider] of Object.entries(providers)) {
    const providerUrl = typeof provider?.url === "string" ? provider.url.trim() : "";
    if (!providerUrl) continue;
    try {
      const providerResp = await fetch(providerUrl, { headers: { Accept: "text/plain, application/yaml, text/yaml" } });
      if (!providerResp.ok) continue;
      const providerText = await providerResp.text();
      const proxies = parseProviderPayloadToProxies(providerText);
      if (proxies.length > 0) {
        materializedProviders[name] = proxies;
      }
    } catch {
      // ignore individual provider fetch failures and keep the rest of the subscription usable
    }
  }

  if (Object.keys(materializedProviders).length > 0) {
    subscription.__materializedProxyProviders = materializedProviders;
  }

  return subscription;
}

function buildConfigObject(
  cfg: MihomoConfig,
  subscription: Record<string, unknown> | null,
): { config: Record<string, unknown>; providerNames: string[] } {
  const autoGroupName = cfg.groupName;
  const routeGroupName = cfg.routeGroupName || "CODEX_ROUTE";
  const subscriptionDns =
    subscription?.dns && typeof subscription.dns === "object" ? { ...(subscription.dns as Record<string, unknown>) } : {};
  const dnsConfig: Record<string, unknown> = {
    ...subscriptionDns,
    enable: true,
    ipv6: typeof subscriptionDns.ipv6 === "boolean" ? subscriptionDns.ipv6 : false,
    "use-hosts": typeof subscriptionDns["use-hosts"] === "boolean" ? subscriptionDns["use-hosts"] : true,
    "default-nameserver": Array.isArray(subscriptionDns["default-nameserver"])
      ? subscriptionDns["default-nameserver"]
      : ["223.5.5.5", "1.1.1.1", "8.8.8.8"],
    nameserver: Array.isArray(subscriptionDns.nameserver)
      ? subscriptionDns.nameserver
      : ["https://dns.alidns.com/dns-query", "https://cloudflare-dns.com/dns-query"],
    "proxy-server-nameserver": Array.isArray(subscriptionDns["proxy-server-nameserver"])
      ? subscriptionDns["proxy-server-nameserver"]
      : [
          "https://dns.alidns.com/dns-query#DIRECT",
          "https://doh.pub/dns-query#DIRECT",
          "1.1.1.1#DIRECT",
          "223.5.5.5#DIRECT",
        ],
  };
  const config: Record<string, unknown> = {
    "mixed-port": cfg.mixedPort,
    "external-controller": `127.0.0.1:${cfg.apiPort}`,
    mode: "rule",
    "log-level": "warning",
    ipv6: true,
    dns: dnsConfig,
  };

  const providersRaw = (subscription?.["proxy-providers"] || {}) as Record<string, Record<string, unknown>>;
  const ruleProvidersRaw = (subscription?.["rule-providers"] || {}) as Record<string, Record<string, unknown>>;
  const proxiesRaw = Array.isArray(subscription?.proxies) ? subscription?.proxies : [];
  const materializedProviderMap = (
    subscription?.__materializedProxyProviders && typeof subscription.__materializedProxyProviders === "object"
      ? subscription.__materializedProxyProviders
      : {}
  ) as Record<string, Record<string, unknown>[]>;
  const materializedProviderNames = new Set(
    Object.entries(materializedProviderMap)
      .filter(([, proxies]) => Array.isArray(proxies) && proxies.length > 0)
      .map(([name]) => name),
  );
  const materializedProviderProxies = Object.values(materializedProviderMap).flatMap((proxies) =>
    Array.isArray(proxies) ? proxies : [],
  );
  const subscriptionGroupsRaw = Array.isArray(subscription?.["proxy-groups"])
    ? (subscription?.["proxy-groups"] as unknown[]).filter((item) => item && typeof item === "object")
    : [];
  const subscriptionGroupNames = new Set(
    subscriptionGroupsRaw
      .map((item) => ((item as Record<string, unknown>).name as string | undefined) || "")
      .filter((name) => typeof name === "string" && name.trim().length > 0),
  );
  const normalizeDialerProxyName = (name: string): string | null => {
    if (subscriptionGroupNames.has(name)) return name;
    const variants = [name.replace("Korean", "Korea"), name.replace("Korea", "Korean")];
    for (const variant of variants) {
      if (subscriptionGroupNames.has(variant)) return variant;
    }
    return null;
  };
  const normalizeProxy = (item: unknown): unknown => {
    if (!item || typeof item !== "object") return item;
    const clone = { ...(item as Record<string, unknown>) };
    const dialer = clone["dialer-proxy"];
    if (typeof dialer === "string" && dialer.trim()) {
      const normalized = normalizeDialerProxyName(dialer.trim());
      if (normalized) {
        clone["dialer-proxy"] = normalized;
      } else {
        delete clone["dialer-proxy"];
      }
    }
    return clone;
  };
  const normalizedProxyMap = new Map<string, Record<string, unknown>>();
  for (const item of [...proxiesRaw, ...materializedProviderProxies]) {
    const normalized = normalizeProxy(item);
    if (!normalized || typeof normalized !== "object") continue;
    const proxy = normalized as Record<string, unknown>;
    const name = typeof proxy.name === "string" ? proxy.name.trim() : "";
    if (!name || normalizedProxyMap.has(name)) continue;
    normalizedProxyMap.set(name, proxy);
  }
  const normalizedProxies = [...normalizedProxyMap.values()];

  const expandedSubscriptionGroups = subscriptionGroupsRaw.map((item) => {
    const clone = { ...(item as Record<string, unknown>) };
    const rawUse = Array.isArray(clone.use) ? clone.use.filter((value) => typeof value === "string") : [];
    const rawProxies = Array.isArray(clone.proxies) ? clone.proxies.filter((value) => typeof value === "string") : [];
    const expandedNames = rawUse.flatMap((providerName) =>
      materializedProviderNames.has(providerName as string)
        ? (materializedProviderMap[providerName as string] || [])
            .map((proxy) => (typeof proxy.name === "string" ? proxy.name : ""))
            .filter(Boolean)
        : [],
    );
    const mergedNames = [...new Set([...rawProxies, ...expandedNames])];
    const remainingUse = rawUse.filter((providerName) => !materializedProviderNames.has(providerName as string));
    if (mergedNames.length > 0) {
      clone.proxies = mergedNames;
    }
    if (remainingUse.length > 0) {
      clone.use = remainingUse;
    } else {
      delete clone.use;
    }
    return clone;
  });

  const activeProvidersRaw = Object.fromEntries(
    Object.entries(providersRaw).filter(([name]) => !materializedProviderNames.has(name)),
  ) as Record<string, Record<string, unknown>>;
  const providerNames = Object.keys(activeProvidersRaw);
  if (providerNames.length > 0) {
    config["proxy-providers"] = normalizeProviders(activeProvidersRaw, cfg.checkUrl);
  }
  if (Object.keys(ruleProvidersRaw).length > 0) {
    config["rule-providers"] = normalizeRuleProviders(ruleProvidersRaw);
  }

  if (Array.isArray(normalizedProxies) && normalizedProxies.length > 0) {
    config.proxies = normalizedProxies;
  }

  const inlineNames = Array.isArray(normalizedProxies)
    ? normalizedProxies
        .map((item: any) => (item && typeof item.name === "string" ? item.name : undefined))
        .filter(Boolean)
    : [];

  const autoGroup: Record<string, unknown> = {
    name: autoGroupName,
    type: "select",
  };
  if (providerNames.length > 0) {
    autoGroup.use = providerNames;
  }
  if (inlineNames.length > 0) {
    autoGroup.proxies = inlineNames;
  }
  const routeGroup: Record<string, unknown> = {
    name: routeGroupName,
    type: "select",
    proxies: [autoGroupName, "DIRECT"],
  };
  if (providerNames.length > 0) {
    routeGroup.use = providerNames;
  }
  if (inlineNames.length > 0) {
    routeGroup.proxies = [...inlineNames, autoGroupName, "DIRECT"];
  }

  config["proxy-groups"] = [
    ...expandedSubscriptionGroups,
    autoGroup,
    routeGroup,
  ];
  config.rules = [`MATCH,${routeGroupName}`];

  if (providerNames.length === 0 && inlineNames.length === 0) {
    config["proxy-providers"] = {
      subscription: {
        type: "http",
        url: cfg.subscriptionUrl,
        interval: 86400,
        path: "./proxy_providers/subscription.yaml",
        "health-check": {
          enable: true,
          url: cfg.checkUrl,
          interval: 600,
        },
      },
    };
    (config["proxy-groups"] as Array<Record<string, unknown>>)[0] = {
      name: autoGroupName,
      type: "select",
      use: ["subscription"],
    };
    (config["proxy-groups"] as Array<Record<string, unknown>>)[1] = {
      name: routeGroupName,
      type: "select",
      use: ["subscription"],
      proxies: [autoGroupName, "DIRECT"],
    };
    return { config, providerNames: ["subscription"] };
  }

  return { config, providerNames };
}

async function writeConfig(cfg: MihomoConfig): Promise<{ configPath: string; providerNames: string[] }> {
  await mkdir(cfg.workDir, { recursive: true });
  const configPath = path.join(cfg.workDir, "mihomo.yaml");
  const subscription = await fetchSubscription(cfg.subscriptionUrl);
  const { config, providerNames } = buildConfigObject(cfg, subscription);
  const yaml = yamlStringify(config);
  await writeFile(configPath, yaml, "utf8");
  return { configPath, providerNames };
}

async function waitForApi(
  apiBaseUrl: string,
  options?: { timeoutMs?: number; child?: ReturnType<typeof spawn>; getLogTail?: () => string },
): Promise<void> {
  const timeoutMs = options?.timeoutMs ?? 15000;
  const child = options?.child;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (child && child.exitCode != null) {
      const tail = options?.getLogTail?.();
      const suffix = tail ? ` logs=${tail.slice(-1000)}` : "";
      throw new Error(`mihomo_process_exited:${child.exitCode}${suffix}`);
    }
    try {
      const resp = await fetch(`${apiBaseUrl}/version`);
      if (resp.ok) return;
    } catch {
      // ignore
    }
    await sleep(500);
  }
  const tail = options?.getLogTail?.();
  if (tail) {
    throw new Error(`mihomo_api_timeout logs=${tail.slice(-1000)}`);
  }
  throw new Error("mihomo_api_timeout");
}

async function httpJson<T = unknown>(method: string, url: string, body?: unknown, timeoutMs = 12_000): Promise<T> {
  const headers: Record<string, string> = {};
  let payload: string | undefined;
  if (body !== undefined) {
    payload = JSON.stringify(body);
    headers["Content-Type"] = "application/json";
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, timeoutMs));
  try {
    const resp = await fetch(url, { method, headers, body: payload, signal: controller.signal });
    const text = await resp.text();
    if (!resp.ok) {
      throw new Error(`mihomo_http_failed:${resp.status}:${text.slice(0, 200)}`);
    }
    return (text ? (JSON.parse(text) as T) : ({} as T));
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`mihomo_http_timeout:${Math.max(1000, timeoutMs)}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function createProcessStopper(child: ReturnType<typeof spawn>): MihomoProcess {
  let stopping = false;
  return {
    stop: async () => {
      if (stopping) return;
      stopping = true;
      if (child.exitCode != null) return;
      child.kill("SIGTERM");
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        if (child.exitCode != null) return;
        await sleep(200);
      }
      child.kill("SIGKILL");
    },
  };
}

async function updateProxyProvider(apiBaseUrl: string, name: string): Promise<void> {
  try {
    await httpJson("PUT", `${apiBaseUrl}/providers/proxies/${encodeURIComponent(name)}`, undefined, 10_000);
  } catch {
    // ignore if not supported
  }
}

function isReservedProxyName(name: string): boolean {
  return RESERVED_PROXY_NAMES.has(name.trim().toUpperCase());
}

function isNonSelectableProxyName(name: string): boolean {
  const normalized = name.trim();
  if (!normalized) return true;
  if (isReservedProxyName(normalized)) return true;
  return /剩余流量|套餐到期|到期时间|官网|流量重置|重置时间|会员群|售后|备用网址|公告|通知/i.test(normalized);
}

async function listProviderNodes(workDir: string, providerNames: string[]): Promise<ProxyNode[]> {
  const deduped = new Map<string, ProxyNode>();
  for (const providerName of providerNames) {
    const candidates = [
      path.join(workDir, "proxy_providers", `${providerName}.yaml`),
      path.join(workDir, "proxy_providers", `${providerName}.yml`),
    ];
    for (const filePath of candidates) {
      const nodes = await parseProviderNodeNames(filePath);
      if (nodes.length === 0) continue;
      for (const node of nodes) {
        if (isNonSelectableProxyName(node.name)) continue;
        if (!deduped.has(node.name)) {
          deduped.set(node.name, node);
        }
      }
      break;
    }
  }
  return [...deduped.values()];
}

async function ensureRouteGroupSelection(apiBaseUrl: string, routeGroup: string, targetGroup: string): Promise<void> {
  await httpJson("PUT", `${apiBaseUrl}/proxies/${encodeURIComponent(routeGroup)}`, { name: targetGroup }, 10_000);
  const payload = await httpJson<{ proxies?: Record<string, { now?: string }> }>(
    "GET",
    `${apiBaseUrl}/proxies`,
    undefined,
    10_000,
  );
  const now = payload.proxies?.[routeGroup]?.now;
  if (now !== targetGroup) {
    throw new Error(`mihomo_route_group_mismatch:${routeGroup}:${now || "unknown"}!=${targetGroup}`);
  }
}

export async function startMihomo(cfg: MihomoConfig): Promise<ProxyController> {
  const binary = await downloadMihomoBinary(cfg);
  const { configPath, providerNames } = await writeConfig(cfg);

  const startupLogs: string[] = [];
  const appendLog = (source: "stdout" | "stderr", chunk: Buffer): void => {
    const text = chunk.toString("utf8");
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      startupLogs.push(`[${source}] ${line}`);
      if (startupLogs.length > 240) {
        startupLogs.splice(0, startupLogs.length - 240);
      }
    }
  };

  const child = spawn(binary, ["-d", cfg.workDir, "-f", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", (chunk: Buffer) => appendLog("stdout", chunk));
  child.stderr?.on("data", (chunk: Buffer) => appendLog("stderr", chunk));
  const stopper = createProcessStopper(child);
  const getStartupLogTail = (): string => startupLogs.slice(-20).join(" | ");

  const apiBaseUrl = `http://127.0.0.1:${cfg.apiPort}`;
  try {
    await waitForApi(apiBaseUrl, { child, getLogTail: getStartupLogTail });
  } catch (error) {
    await stopper.stop();
    throw error;
  }

  for (const name of providerNames) {
    await updateProxyProvider(apiBaseUrl, name);
  }
  const routeGroupName = cfg.routeGroupName || "CODEX_ROUTE";
  if (cfg.groupName !== routeGroupName) {
    await ensureRouteGroupSelection(apiBaseUrl, routeGroupName, cfg.groupName);
  }

  const proxyServer = `http://127.0.0.1:${cfg.mixedPort}`;

  const listGroupNodes = async (): Promise<ProxyNode[]> => {
    const payload = await httpJson<{ proxies?: Record<string, { all?: string[]; type?: string }> }>(
      "GET",
      `${apiBaseUrl}/proxies`,
      undefined,
      10_000,
    );
    const group = payload.proxies?.[cfg.groupName];
    const groupNodes = Array.isArray(group?.all) ? group.all : [];
    const providerNodes = await listProviderNodes(cfg.workDir, providerNames);
    const providerByName = new Map<string, ProxyNode>();
    for (const node of providerNodes) {
      providerByName.set(node.name, node);
    }

    const deduped = new Map<string, ProxyNode>();
    for (const rawName of groupNodes) {
      if (typeof rawName !== "string") continue;
      const name = rawName.trim();
      if (isNonSelectableProxyName(name)) continue;
      deduped.set(name, providerByName.get(name) || { name });
    }

    if (deduped.size > 0) return [...deduped.values()];

    for (const node of providerNodes) {
      if (isNonSelectableProxyName(node.name)) continue;
      deduped.set(node.name, node);
    }
    return [...deduped.values()];
  };

  const getGroupSelection = async (): Promise<string | null> => {
    const payload = await httpJson<{ proxies?: Record<string, { now?: string }> }>(
      "GET",
      `${apiBaseUrl}/proxies`,
      undefined,
      10_000,
    );
    const group = payload.proxies?.[cfg.groupName];
    return typeof group?.now === "string" ? group.now : null;
  };

  const setGroupProxy = async (name: string): Promise<void> => {
    await httpJson("PUT", `${apiBaseUrl}/proxies/${encodeURIComponent(cfg.groupName)}`, { name }, 10_000);
  };

  const testDelay = async (name: string, url: string, timeoutMs: number): Promise<number | null> => {
    try {
      const endpoint = `${apiBaseUrl}/proxies/${encodeURIComponent(name)}/delay?url=${encodeURIComponent(url)}&timeout=${timeoutMs}`;
      const payload = await httpJson<{ delay?: number }>("GET", endpoint, undefined, Math.max(timeoutMs + 3_000, 8_000));
      if (typeof payload.delay === "number") return payload.delay;
      return null;
    } catch {
      return null;
    }
  };

  return {
    apiBaseUrl,
    proxyServer,
    groupName: cfg.groupName,
    listGroupNodes,
    getGroupSelection,
    setGroupProxy,
    testDelay,
    stop: stopper.stop,
  };
}
