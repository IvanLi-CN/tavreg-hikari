import type { AppSettings } from "../storage/app-db.js";

export function normalizeSettings(input: Partial<AppSettings>): Partial<AppSettings> {
  const next: Partial<AppSettings> = {};
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
  return next;
}

export function buildNextSettings(current: AppSettings, input: Partial<AppSettings> | null | undefined): AppSettings {
  return {
    ...current,
    ...normalizeSettings(input || {}),
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
