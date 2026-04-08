import { normalizeAccountExtractorAccountType, type AppSettings } from "../storage/app-db.js";

export const PROXY_SETTINGS_KEYS = [
  "subscriptionUrl",
  "groupName",
  "routeGroupName",
  "checkUrl",
  "timeoutMs",
  "maxLatencyMs",
  "apiPort",
  "mixedPort",
] as const;

export type ProxySettingsKey = typeof PROXY_SETTINGS_KEYS[number];
export type ProxySettingsUpdate = Pick<AppSettings, ProxySettingsKey>;

export function normalizeSettings(input: Partial<AppSettings>): Partial<AppSettings> {
  const next: Partial<AppSettings> = {};
  const isExtractorProvider = (value: unknown): value is AppSettings["defaultAutoExtractSources"][number] =>
    value === "zhanghaoya" || value === "shanyouxiang" || value === "shankeyun" || value === "hotmail666";
  const normalizeSources = (value: unknown): AppSettings["defaultAutoExtractSources"] => {
    if (!Array.isArray(value)) return [];
    return Array.from(
      new Set(
        value.filter(isExtractorProvider),
      ),
    );
  };
  if (typeof input.subscriptionUrl === "string") next.subscriptionUrl = input.subscriptionUrl.trim();
  if (typeof input.groupName === "string") next.groupName = input.groupName.trim();
  if (typeof input.routeGroupName === "string") next.routeGroupName = input.routeGroupName.trim();
  if (typeof input.checkUrl === "string") next.checkUrl = input.checkUrl.trim();
  if (typeof input.timeoutMs === "number" && Number.isFinite(input.timeoutMs)) next.timeoutMs = Math.max(1000, input.timeoutMs);
  if (typeof input.maxLatencyMs === "number" && Number.isFinite(input.maxLatencyMs)) next.maxLatencyMs = Math.max(100, input.maxLatencyMs);
  if (typeof input.apiPort === "number" && Number.isFinite(input.apiPort)) next.apiPort = Math.max(1, input.apiPort);
  if (typeof input.mixedPort === "number" && Number.isFinite(input.mixedPort)) next.mixedPort = Math.max(1, input.mixedPort);
  if (typeof input.serverHost === "string") next.serverHost = input.serverHost.trim();
  if (typeof input.serverPort === "number" && Number.isFinite(input.serverPort)) next.serverPort = Math.max(1, input.serverPort);
  if (input.defaultRunMode === "headed" || input.defaultRunMode === "headless") next.defaultRunMode = input.defaultRunMode;
  if (typeof input.defaultNeed === "number" && Number.isFinite(input.defaultNeed)) next.defaultNeed = Math.max(1, input.defaultNeed);
  if (typeof input.defaultParallel === "number" && Number.isFinite(input.defaultParallel)) next.defaultParallel = Math.max(1, input.defaultParallel);
  if (typeof input.defaultMaxAttempts === "number" && Number.isFinite(input.defaultMaxAttempts)) next.defaultMaxAttempts = Math.max(1, input.defaultMaxAttempts);
  if (typeof input.extractorZhanghaoyaKey === "string") next.extractorZhanghaoyaKey = input.extractorZhanghaoyaKey.trim();
  if (typeof input.extractorShanyouxiangKey === "string") next.extractorShanyouxiangKey = input.extractorShanyouxiangKey.trim();
  if (typeof input.extractorShankeyunKey === "string") next.extractorShankeyunKey = input.extractorShankeyunKey.trim();
  if (typeof input.extractorHotmail666Key === "string") next.extractorHotmail666Key = input.extractorHotmail666Key.trim();
  if (Array.isArray(input.defaultAutoExtractSources)) next.defaultAutoExtractSources = normalizeSources(input.defaultAutoExtractSources);
  if (typeof input.defaultAutoExtractQuantity === "number" && Number.isFinite(input.defaultAutoExtractQuantity)) {
    next.defaultAutoExtractQuantity = Math.max(1, input.defaultAutoExtractQuantity);
  }
  if (typeof input.defaultAutoExtractMaxWaitSec === "number" && Number.isFinite(input.defaultAutoExtractMaxWaitSec)) {
    next.defaultAutoExtractMaxWaitSec = Math.max(1, input.defaultAutoExtractMaxWaitSec);
  }
  if (input.defaultAutoExtractAccountType !== undefined) {
    next.defaultAutoExtractAccountType = normalizeAccountExtractorAccountType(input.defaultAutoExtractAccountType);
  }
  if (typeof input.microsoftGraphClientId === "string") next.microsoftGraphClientId = input.microsoftGraphClientId.trim();
  if (typeof input.microsoftGraphClientSecret === "string") next.microsoftGraphClientSecret = input.microsoftGraphClientSecret.trim();
  if (typeof input.microsoftGraphRedirectUri === "string") next.microsoftGraphRedirectUri = input.microsoftGraphRedirectUri.trim();
  if (typeof input.microsoftGraphAuthority === "string") {
    const normalizedAuthority = input.microsoftGraphAuthority.trim().replace(/^\/+|\/+$/g, "");
    next.microsoftGraphAuthority = normalizedAuthority || "common";
  }
  return next;
}

export function listUnexpectedProxySettingsKeys(input: Record<string, unknown> | null | undefined): string[] {
  if (!input || typeof input !== "object" || Array.isArray(input)) return [];
  const allowed = new Set<string>(PROXY_SETTINGS_KEYS);
  return Object.keys(input).filter((key) => !allowed.has(key));
}

export function normalizeProxySettings(input: Partial<ProxySettingsUpdate>): Partial<ProxySettingsUpdate> {
  const normalized = normalizeSettings(input);
  return {
    ...(Object.prototype.hasOwnProperty.call(normalized, "subscriptionUrl") ? { subscriptionUrl: normalized.subscriptionUrl as string } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "groupName") ? { groupName: normalized.groupName as string } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "routeGroupName") ? { routeGroupName: normalized.routeGroupName as string } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "checkUrl") ? { checkUrl: normalized.checkUrl as string } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "timeoutMs") ? { timeoutMs: normalized.timeoutMs as number } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "maxLatencyMs") ? { maxLatencyMs: normalized.maxLatencyMs as number } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "apiPort") ? { apiPort: normalized.apiPort as number } : {}),
    ...(Object.prototype.hasOwnProperty.call(normalized, "mixedPort") ? { mixedPort: normalized.mixedPort as number } : {}),
  };
}

export function buildNextSettings(current: AppSettings, input: Partial<AppSettings> | null | undefined): AppSettings {
  return {
    ...current,
    ...normalizeSettings(input || {}),
  };
}

export function buildNextProxySettings(current: AppSettings, input: Partial<ProxySettingsUpdate> | null | undefined): AppSettings {
  return {
    ...current,
    ...normalizeProxySettings(input || {}),
  };
}

export async function validateBeforePersist<T>(options: {
  current: AppSettings;
  input: Partial<AppSettings> | null | undefined;
  sync: (settings: AppSettings) => Promise<T>;
  persist: (settings: AppSettings) => void;
}): Promise<{ settings: AppSettings; result: T }> {
  const settings = buildNextSettings(options.current, options.input);
  const result = await options.sync(settings);
  options.persist(settings);
  return { settings, result };
}

export async function validateProxySettingsBeforePersist<T>(options: {
  current: AppSettings;
  input: Partial<ProxySettingsUpdate> | null | undefined;
  sync: (settings: AppSettings) => Promise<T>;
  persist: (settings: AppSettings) => void;
}): Promise<{ settings: AppSettings; result: T }> {
  const settings = buildNextProxySettings(options.current, options.input);
  const result = await options.sync(settings);
  options.persist(settings);
  return { settings, result };
}
