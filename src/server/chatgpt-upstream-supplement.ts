import type { AppDatabase, ChatGptCredentialRecord, JobRecord } from "../storage/app-db.js";
import { buildCodexVibeMonitorCredentialObject } from "./chatgpt-credential-format.js";

export const CHATGPT_UPSTREAM_BASE_URL_SETTING_KEY = "chatgptUpstreamBaseUrl";
export const CHATGPT_UPSTREAM_API_KEY_SETTING_KEY = "chatgptUpstreamApiKey";
export const CHATGPT_UPSTREAM_GROUP_HISTORY_SETTING_KEY = "chatgptUpstreamGroupHistory";

export const CHATGPT_UPSTREAM_BASE_URL_ENV_KEY = "CHATGPT_UPSTREAM_BASE_URL";
export const CHATGPT_UPSTREAM_API_KEY_ENV_KEY = "CHATGPT_UPSTREAM_API_KEY";

const MAX_GROUP_HISTORY = 24;
const MAX_DISPLAY_NAME_LENGTH = 120;
const DEFAULT_SUPPLEMENT_REQUEST_TIMEOUT_MS = 15_000;

export type ChatGptUpstreamSettingsSource = "db" | "env" | "unset";

export type ChatGptUpstreamSettingsState = {
  baseUrl: string;
  apiKey: string;
  groupHistory: string[];
  baseUrlSource: ChatGptUpstreamSettingsSource;
  apiKeySource: ChatGptUpstreamSettingsSource;
};

export type ChatGptUpstreamSettingsView = {
  baseUrl: string;
  apiKeyMasked: string;
  hasApiKey: boolean;
  configured: boolean;
  groupHistory: string[];
  baseUrlSource: ChatGptUpstreamSettingsSource;
  apiKeySource: ChatGptUpstreamSettingsSource;
};

export type ChatGptUpstreamSettingsUpdate = {
  baseUrl?: string;
  apiKey?: string;
  clearBaseUrl?: boolean;
  clearApiKey?: boolean;
  groupHistory?: string[];
};

export type ChatGptCredentialSupplementResult = {
  credentialId: number;
  email: string | null;
  accountId: string | null;
  groupName: string;
  success: boolean;
  message: string;
};

export type ChatGptCredentialSupplementBatchResult = {
  groupName: string;
  requested: number;
  succeeded: number;
  failed: number;
  results: ChatGptCredentialSupplementResult[];
};

function normalizeTrimmedString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

export function normalizeChatGptUpstreamGroupName(value: unknown): string {
  return normalizeTrimmedString(value);
}

export function readChatGptJobUpstreamGroupName(job: Pick<JobRecord, "payloadJson"> | null | undefined): string | null {
  const groupName = normalizeChatGptUpstreamGroupName(job?.payloadJson?.upstreamGroupName);
  return groupName || null;
}

function normalizeGroupHistory(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const item of value) {
    const groupName = normalizeTrimmedString(item);
    if (!groupName) continue;
    const dedupeKey = groupName.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    normalized.push(groupName);
    if (normalized.length >= MAX_GROUP_HISTORY) break;
  }
  return normalized;
}

function rememberGroupName(groupHistory: string[], groupName: string): string[] {
  const normalizedGroupName = normalizeTrimmedString(groupName);
  if (!normalizedGroupName) return normalizeGroupHistory(groupHistory);
  return normalizeGroupHistory([normalizedGroupName, ...groupHistory]);
}

function normalizeBaseUrl(input: unknown): string {
  const raw = normalizeTrimmedString(input);
  if (!raw) return "";
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("invalid upstream baseUrl");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("upstream baseUrl must start with http or https");
  }
  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/+$/, "");
}

function normalizeOptionalBaseUrl(input: unknown): string {
  const raw = normalizeTrimmedString(input);
  if (!raw) return "";
  try {
    return normalizeBaseUrl(raw);
  } catch {
    return "";
  }
}

function resolveSettingsSource(dbValue: string, envValue: string): ChatGptUpstreamSettingsSource {
  if (dbValue) return "db";
  if (envValue) return "env";
  return "unset";
}

function maskSecret(secret: string, visible = 4): string {
  if (!secret) return "";
  if (secret.length <= visible) return "*".repeat(secret.length);
  return `${"*".repeat(Math.max(4, secret.length - visible))}${secret.slice(-visible)}`;
}

function buildStableDisplayName(projectLabel: string, email: string, accountId: string): string {
  const raw = `${projectLabel} / ${email} / ${accountId}`;
  return raw.length > MAX_DISPLAY_NAME_LENGTH ? raw.slice(0, MAX_DISPLAY_NAME_LENGTH) : raw;
}

function extractRemoteErrorMessage(status: number, bodyText: string): string {
  if (!bodyText.trim()) return `upstream api responded with ${status}`;
  try {
    const parsed = JSON.parse(bodyText) as Record<string, unknown>;
    const candidate =
      normalizeTrimmedString(parsed.message)
      || normalizeTrimmedString(parsed.error)
      || normalizeTrimmedString(parsed.detail)
      || normalizeTrimmedString(parsed.msg);
    return candidate || `upstream api responded with ${status}`;
  } catch {
    return bodyText.trim() || `upstream api responded with ${status}`;
  }
}

function buildUpstreamTimeoutMessage(timeoutMs: number): string {
  return `upstream request timed out after ${timeoutMs}ms`;
}

function pickStoredString(db: AppDatabase, key: string): string {
  const raw = db.getJsonSetting<unknown>(key, null);
  return normalizeTrimmedString(raw);
}

export function readChatGptUpstreamSettingsState(
  db: AppDatabase,
  env: NodeJS.ProcessEnv = process.env,
): ChatGptUpstreamSettingsState {
  const dbBaseUrl = normalizeOptionalBaseUrl(pickStoredString(db, CHATGPT_UPSTREAM_BASE_URL_SETTING_KEY));
  const dbApiKey = pickStoredString(db, CHATGPT_UPSTREAM_API_KEY_SETTING_KEY);
  const envBaseUrl = normalizeOptionalBaseUrl(env[CHATGPT_UPSTREAM_BASE_URL_ENV_KEY]);
  const envApiKey = normalizeTrimmedString(env[CHATGPT_UPSTREAM_API_KEY_ENV_KEY]);
  const groupHistory = normalizeGroupHistory(db.getJsonSetting(CHATGPT_UPSTREAM_GROUP_HISTORY_SETTING_KEY, []));
  return {
    baseUrl: dbBaseUrl || envBaseUrl,
    apiKey: dbApiKey || envApiKey,
    groupHistory,
    baseUrlSource: resolveSettingsSource(dbBaseUrl, envBaseUrl),
    apiKeySource: resolveSettingsSource(dbApiKey, envApiKey),
  };
}

export function serializeChatGptUpstreamSettings(state: ChatGptUpstreamSettingsState): ChatGptUpstreamSettingsView {
  return {
    baseUrl: state.baseUrl,
    apiKeyMasked: maskSecret(state.apiKey),
    hasApiKey: Boolean(state.apiKey),
    configured: Boolean(state.baseUrl && state.apiKey),
    groupHistory: state.groupHistory,
    baseUrlSource: state.baseUrlSource,
    apiKeySource: state.apiKeySource,
  };
}

export class ChatGptUpstreamSupplementService {
  constructor(
    private readonly db: AppDatabase,
    private readonly options?: {
      env?: NodeJS.ProcessEnv;
      projectLabel?: string;
      fetchImpl?: typeof fetch;
      requestTimeoutMs?: number;
    },
  ) {}

  readSettings(): ChatGptUpstreamSettingsState {
    return readChatGptUpstreamSettingsState(this.db, this.options?.env || process.env);
  }

  serializeSettings(): ChatGptUpstreamSettingsView {
    return serializeChatGptUpstreamSettings(this.readSettings());
  }

  updateSettings(input: ChatGptUpstreamSettingsUpdate): ChatGptUpstreamSettingsView {
    if (input.clearBaseUrl) {
      this.db.deleteSetting(CHATGPT_UPSTREAM_BASE_URL_SETTING_KEY);
    } else if (typeof input.baseUrl === "string" && input.baseUrl.trim()) {
      this.db.setJsonSetting(CHATGPT_UPSTREAM_BASE_URL_SETTING_KEY, normalizeBaseUrl(input.baseUrl));
    }

    if (input.clearApiKey) {
      this.db.deleteSetting(CHATGPT_UPSTREAM_API_KEY_SETTING_KEY);
    } else if (typeof input.apiKey === "string" && input.apiKey.trim()) {
      this.db.setJsonSetting(CHATGPT_UPSTREAM_API_KEY_SETTING_KEY, input.apiKey.trim());
    }

    if (Array.isArray(input.groupHistory)) {
      this.db.setJsonSetting(CHATGPT_UPSTREAM_GROUP_HISTORY_SETTING_KEY, normalizeGroupHistory(input.groupHistory));
    }

    return this.serializeSettings();
  }

  async supplementCredentials(ids: number[], groupName: string): Promise<ChatGptCredentialSupplementBatchResult> {
    const normalizedIds = Array.from(new Set(ids.filter((id) => Number.isInteger(id) && id > 0)));
    const normalizedGroupName = normalizeTrimmedString(groupName);
    if (!normalizedGroupName) {
      throw new Error("groupName is required");
    }
    const results: ChatGptCredentialSupplementResult[] = [];
    for (const credentialId of normalizedIds) {
      const credential = this.db.getChatGptCredential(credentialId);
      if (!credential) {
        results.push({
          credentialId,
          email: null,
          accountId: null,
          groupName: normalizedGroupName,
          success: false,
          message: `credential #${credentialId} not found`,
        });
        continue;
      }
      results.push(await this.supplementCredential(credential, normalizedGroupName));
    }
    return {
      groupName: normalizedGroupName,
      requested: normalizedIds.length,
      succeeded: results.filter((item) => item.success).length,
      failed: results.filter((item) => !item.success).length,
      results,
    };
  }

  async supplementCredential(
    credential: ChatGptCredentialRecord,
    groupName: string,
  ): Promise<ChatGptCredentialSupplementResult> {
    const normalizedGroupName = normalizeTrimmedString(groupName);
    const accountId = normalizeTrimmedString(credential.accountId) || null;
    const baseResult = {
      credentialId: credential.id,
      email: normalizeTrimmedString(credential.email) || null,
      accountId,
      groupName: normalizedGroupName,
    };
    if (!normalizedGroupName) {
      return { ...baseResult, success: false, message: "groupName is required" };
    }
    if (!accountId) {
      return { ...baseResult, success: false, message: "missing accountId" };
    }

    const settings = this.readSettings();
    if (!settings.baseUrl || !settings.apiKey) {
      return { ...baseResult, success: false, message: "chatgpt upstream settings are not configured" };
    }

    const credentialObject = buildCodexVibeMonitorCredentialObject({
      email: credential.email,
      accountId,
      accessToken: credential.accessToken,
      refreshToken: credential.refreshToken,
      idToken: credential.idToken,
      expiresAt: credential.expiresAt,
      createdAt: credential.createdAt,
      credentialJson: credential.credentialJson,
    });

    const email = normalizeTrimmedString(credentialObject.email);
    const accessToken = normalizeTrimmedString(credentialObject.access_token);
    const refreshToken = normalizeTrimmedString(credentialObject.refresh_token);
    const idToken = normalizeTrimmedString(credentialObject.id_token);
    const tokenType = normalizeTrimmedString(credentialObject.token_type) || "Bearer";
    const expired = normalizeTrimmedString(credentialObject.expired) || null;

    if (!email) return { ...baseResult, success: false, message: "missing oauth.email" };
    if (!accessToken) return { ...baseResult, success: false, message: "missing oauth.accessToken" };
    if (!refreshToken) return { ...baseResult, success: false, message: "missing oauth.refreshToken" };
    if (!idToken) return { ...baseResult, success: false, message: "missing oauth.idToken" };

    const projectLabel = normalizeTrimmedString(this.options?.projectLabel) || "tavreg-hikari";
    const requestUrl = new URL(`api/external/v1/upstream-accounts/oauth/${encodeURIComponent(accountId)}`, `${settings.baseUrl}/`);
    const fetchImpl = this.options?.fetchImpl || fetch;
    const requestTimeoutMs = Math.max(1, Math.trunc(this.options?.requestTimeoutMs || DEFAULT_SUPPLEMENT_REQUEST_TIMEOUT_MS));
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort(new Error(buildUpstreamTimeoutMessage(requestTimeoutMs)));
    }, requestTimeoutMs);
    let response: Response;
    try {
      response = await fetchImpl(requestUrl, {
        method: "PUT",
        signal: controller.signal,
        headers: {
          authorization: `Bearer ${settings.apiKey}`,
          "content-type": "application/json; charset=utf-8",
        },
        body: JSON.stringify({
          displayName: buildStableDisplayName(projectLabel, email, accountId),
          groupName: normalizedGroupName,
          oauth: {
            email,
            accessToken,
            refreshToken,
            idToken,
            tokenType,
            expired,
          },
        }),
      });
    } catch (error) {
      clearTimeout(timeoutId);
      const message = error instanceof Error ? error.message : String(error);
      return {
        ...baseResult,
        success: false,
        message: controller.signal.aborted ? message || buildUpstreamTimeoutMessage(requestTimeoutMs) : message,
      };
    }
    clearTimeout(timeoutId);

    const responseText = await response.text();
    if (!response.ok) {
      return {
        ...baseResult,
        success: false,
        message: extractRemoteErrorMessage(response.status, responseText),
      };
    }

    this.db.setJsonSetting(
      CHATGPT_UPSTREAM_GROUP_HISTORY_SETTING_KEY,
      rememberGroupName(this.readSettings().groupHistory, normalizedGroupName),
    );
    return {
      ...baseResult,
      success: true,
      message: "ok",
    };
  }
}
