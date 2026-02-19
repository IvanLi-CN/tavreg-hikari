import { spawn } from "node:child_process";
import { access, chmod, mkdir, writeFile } from "node:fs/promises";
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

const RELEASE_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest";
const RELEASE_TAG_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags";

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
    if (/proxies:|proxy-providers:|proxy-groups:/i.test(decoded)) {
      return decoded;
    }
  } catch {
    // ignore
  }
  return text;
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
  return typeof parsed === "object" && parsed ? parsed : {};
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
  const normalizedProxies = proxiesRaw.map((item) => {
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
  });

  const providerNames = Object.keys(providersRaw);
  if (providerNames.length > 0) {
    config["proxy-providers"] = normalizeProviders(providersRaw, cfg.checkUrl);
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
    ...subscriptionGroupsRaw,
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
    const nodes = group?.all || [];
    return nodes
      .filter((name) => typeof name === "string")
      .filter((name) => {
        const normalized = String(name).trim().toUpperCase();
        return !["DIRECT", "REJECT", "GLOBAL", "AUTO", "PROXY", "CODEX_ROUTE", "CODEX_AUTO"].includes(normalized);
      })
      .map((name) => ({ name }));
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
