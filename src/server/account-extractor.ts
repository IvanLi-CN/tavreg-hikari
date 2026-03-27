import type { AccountExtractorAccountType, AccountExtractorProvider } from "../storage/app-db.js";

export type AccountExtractorFailureCode = "invalid_key" | "insufficient_stock" | "parse_failed" | "upstream_error";

export interface AccountExtractorCandidate {
  provider: AccountExtractorProvider;
  rawPayload: string;
  email: string | null;
  password: string | null;
  parseStatus: "parsed" | "invalid";
}

export interface AccountExtractorFetchResult {
  provider: AccountExtractorProvider;
  accountType: AccountExtractorAccountType;
  rawResponse: string;
  candidates: AccountExtractorCandidate[];
  ok: boolean;
  failureCode: AccountExtractorFailureCode | null;
  message: string | null;
  maskedKey: string | null;
}

export interface AccountExtractorRuntimeConfig {
  zhanghaoyaKey: string;
  shanyouxiangKey: string;
  shankeyunKey: string;
  hotmail666Key: string;
  timeoutMs?: number;
}

const PROVIDER_LABELS: Record<AccountExtractorProvider, string> = {
  zhanghaoya: "账号鸭",
  shanyouxiang: "闪邮箱",
  shankeyun: "闪客云",
  hotmail666: "Hotmail666",
};

interface ExtractorRequestSpec {
  url: string;
  init?: RequestInit;
}

interface ExtractorSuccessPayload {
  ok: boolean;
  candidates: AccountExtractorCandidate[];
  failureCode: AccountExtractorFailureCode | null;
  message: string | null;
}

interface ExtractorDescriptor {
  label: string;
  getKey: (config: AccountExtractorRuntimeConfig) => string;
  buildRequest: (key: string, accountType: AccountExtractorAccountType) => ExtractorRequestSpec;
  parseResponse: (rawResponse: string, accountType: AccountExtractorAccountType) => ExtractorSuccessPayload;
}

function normalizeLines(raw: string): string[] {
  return raw
    .replace(/\\r<br>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/\r/g, "\n")
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function maskKey(raw: string | null | undefined): string | null {
  const value = String(raw || "").trim();
  if (!value) return null;
  if (value.length <= 8) return `${"*".repeat(Math.max(0, value.length - 2))}${value.slice(-2)}`;
  return `${value.slice(0, 4)}${"*".repeat(Math.max(4, value.length - 8))}${value.slice(-4)}`;
}

function splitDashedFields(line: string): string[] {
  return line.split("----").map((segment) => segment.trim());
}

function parseAccountCandidate(provider: AccountExtractorProvider, line: string): AccountExtractorCandidate {
  const parts = line.includes("----")
    ? splitDashedFields(line)
    : line.split(":").map((segment) => segment.trim());
  const email = parts[0] || null;
  const password = parts[1] || null;
  if (email && password && isValidEmail(email)) {
    return {
      provider,
      rawPayload: line,
      email: email.toLowerCase(),
      password,
      parseStatus: "parsed",
    };
  }
  return {
    provider,
    rawPayload: line,
    email: null,
    password: null,
    parseStatus: "invalid",
  };
}

function parseCandidates(provider: AccountExtractorProvider, raw: string): AccountExtractorCandidate[] {
  return normalizeLines(raw).map((line) => parseAccountCandidate(provider, line));
}

function buildSuccessfulParse(
  provider: AccountExtractorProvider,
  raw: string,
  emptyMessage: string,
): ExtractorSuccessPayload {
  const candidates = parseCandidates(provider, raw);
  const valid = candidates.some((candidate) => candidate.parseStatus === "parsed");
  return {
    ok: valid,
    candidates,
    failureCode: valid ? null : "parse_failed",
    message: valid ? null : emptyMessage,
  };
}

function extractJsonMessage(rawResponse: string): string | null {
  try {
    const payload = JSON.parse(rawResponse) as Record<string, unknown>;
    for (const key of ["Message", "message", "msg", "detail", "error"]) {
      const value = payload[key];
      if (typeof value === "string" && value.trim()) return value.trim();
    }
  } catch {
    // ignore invalid JSON bodies and fall back to plain text heuristics.
  }
  const normalized = rawResponse.trim();
  return normalized || null;
}

function mapFailure(provider: AccountExtractorProvider, message: string): AccountExtractorFailureCode {
  const normalized = message.trim().toLowerCase();
  if (
    /库存不足|余额不足|无此类型卡号|insufficient|out of stock|notfound|剩余次数不足/.test(normalized)
    || (provider === "zhanghaoya" && normalized.includes("notfound"))
  ) {
    return "insufficient_stock";
  }
  if (/卡密不存在|卡密无效|已过期|invalid key|minimum length|maxim|expired/.test(normalized)) {
    return "invalid_key";
  }
  return "upstream_error";
}

async function fetchText(request: ExtractorRequestSpec, timeoutMs: number): Promise<{ status: number; rawResponse: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(request.url, {
      method: request.init?.method || "GET",
      headers: {
        "user-agent": "Mozilla/5.0 Codex/1.0",
        accept: "application/json,text/plain,*/*",
        ...(request.init?.headers || {}),
      },
      body: request.init?.body,
      signal: controller.signal,
    });
    return {
      status: response.status,
      rawResponse: await response.text(),
    };
  } finally {
    clearTimeout(timer);
  }
}

function buildFailureResult(
  provider: AccountExtractorProvider,
  accountType: AccountExtractorAccountType,
  rawResponse: string,
  message: string,
  key: string,
): AccountExtractorFetchResult {
  return {
    provider,
    accountType,
    rawResponse,
    candidates: [],
    ok: false,
    failureCode: mapFailure(provider, message),
    message,
    maskedKey: maskKey(key),
  };
}

const EXTRACTOR_DESCRIPTORS: Record<AccountExtractorProvider, ExtractorDescriptor> = {
  zhanghaoya: {
    label: PROVIDER_LABELS.zhanghaoya,
    getKey: (config) => config.zhanghaoyaKey,
    buildRequest: (key, accountType) => {
      const url = new URL("https://www.zhanghaoya.com/store/ga/account");
      url.searchParams.set("type", accountType);
      url.searchParams.set("quantity", "1");
      url.searchParams.set("key", key);
      return { url: url.toString() };
    },
    parseResponse: (rawResponse) => {
      try {
        const payload = JSON.parse(rawResponse) as { Code?: number; Message?: string; Data?: string };
        if (payload.Code !== 200 || typeof payload.Data !== "string") {
          const message = String(payload.Message || "unexpected upstream response");
          return { ok: false, candidates: [], failureCode: mapFailure("zhanghaoya", message), message };
        }
        return buildSuccessfulParse("zhanghaoya", payload.Data, "zhanghaoya response did not contain a parsable account");
      } catch {
        return {
          ok: false,
          candidates: parseCandidates("zhanghaoya", rawResponse),
          failureCode: "parse_failed",
          message: "zhanghaoya response was not valid JSON",
        };
      }
    },
  },
  shanyouxiang: {
    label: PROVIDER_LABELS.shanyouxiang,
    getKey: (config) => config.shanyouxiangKey,
    buildRequest: (key, accountType) => {
      const url = new URL("https://zizhu.shanyouxiang.com/huoqu");
      url.searchParams.set("shuliang", "1");
      url.searchParams.set("leixing", accountType);
      url.searchParams.set("card", key);
      return { url: url.toString() };
    },
    parseResponse: (rawResponse) => {
      try {
        const payload = JSON.parse(rawResponse) as { status?: number; msg?: string };
        if (typeof payload.status === "number" && payload.status !== 0 && payload.status !== 1) {
          const message = String(payload.msg || "unexpected upstream response");
          return { ok: false, candidates: [], failureCode: mapFailure("shanyouxiang", message), message };
        }
      } catch {
        // shanyouxiang success bodies are often plain text; ignore JSON parse errors here.
      }
      return buildSuccessfulParse("shanyouxiang", rawResponse, "shanyouxiang response did not contain a parsable account");
    },
  },
  shankeyun: {
    label: PROVIDER_LABELS.shankeyun,
    getKey: (config) => config.shankeyunKey,
    buildRequest: (key, accountType) => {
      const url = new URL("https://fk.shankeyun.com/api/win/buy");
      url.searchParams.set("card", key);
      url.searchParams.set("type", accountType);
      url.searchParams.set("num", "1");
      return { url: url.toString() };
    },
    parseResponse: (rawResponse) => {
      try {
        const payload = JSON.parse(rawResponse) as { status?: number; msg?: string; data?: string };
        if (payload.status === 0) {
          const message = String(payload.msg || "unexpected upstream response");
          return { ok: false, candidates: [], failureCode: mapFailure("shankeyun", message), message };
        }
        if (payload.status === 1 && typeof payload.data === "string") {
          return buildSuccessfulParse("shankeyun", payload.data, "shankeyun response did not contain a parsable account");
        }
      } catch {
        // shankeyun success bodies are plain text according to docs; ignore JSON parse errors.
      }
      return buildSuccessfulParse("shankeyun", rawResponse, "shankeyun response did not contain a parsable account");
    },
  },
  hotmail666: {
    label: PROVIDER_LABELS.hotmail666,
    getKey: (config) => config.hotmail666Key,
    buildRequest: (key, accountType) => ({
      url: "https://api.hotmail666.com/api/extract-mail",
      init: {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          cardKey: key,
          mailType: accountType,
          quantity: 1,
        }),
      },
    }),
    parseResponse: (rawResponse) => {
      try {
        const payload = JSON.parse(rawResponse) as {
          success?: boolean;
          message?: string;
          data?: { mails?: unknown[] };
        };
        if (!payload.success) {
          const message = String(payload.message || "unexpected upstream response");
          return { ok: false, candidates: [], failureCode: mapFailure("hotmail666", message), message };
        }
        const mails = Array.isArray(payload.data?.mails)
          ? payload.data?.mails.filter((item): item is string => typeof item === "string")
          : [];
        return buildSuccessfulParse("hotmail666", mails.join("\n"), "hotmail666 response did not contain a parsable account");
      } catch {
        return {
          ok: false,
          candidates: parseCandidates("hotmail666", rawResponse),
          failureCode: "parse_failed",
          message: "hotmail666 response was not valid JSON",
        };
      }
    },
  },
};

export async function fetchSingleExtractedAccount(input: {
  provider: AccountExtractorProvider;
  accountType?: AccountExtractorAccountType;
  config: AccountExtractorRuntimeConfig;
}): Promise<AccountExtractorFetchResult> {
  const accountType = input.accountType || "outlook";
  const timeoutMs = Math.max(3000, input.config.timeoutMs || 20000);
  const descriptor = EXTRACTOR_DESCRIPTORS[input.provider];
  const key = descriptor.getKey(input.config).trim();
  const request = descriptor.buildRequest(key, accountType);
  const { status, rawResponse } = await fetchText(request, timeoutMs);
  if (status < 200 || status >= 300) {
    const message = extractJsonMessage(rawResponse) || `HTTP ${status}`;
    return buildFailureResult(input.provider, accountType, rawResponse, message, key);
  }
  const parsed = descriptor.parseResponse(rawResponse, accountType);
  return {
    provider: input.provider,
    accountType,
    rawResponse,
    candidates: parsed.candidates,
    ok: parsed.ok,
    failureCode: parsed.failureCode,
    message: parsed.message,
    maskedKey: maskKey(key),
  };
}

export function getAccountExtractorProviderLabel(provider: AccountExtractorProvider): string {
  return EXTRACTOR_DESCRIPTORS[provider].label;
}

export function getConfiguredExtractorKey(
  provider: AccountExtractorProvider,
  config: AccountExtractorRuntimeConfig,
): string {
  return EXTRACTOR_DESCRIPTORS[provider].getKey(config).trim();
}

export function keyConfiguredForProvider(
  provider: AccountExtractorProvider,
  config: AccountExtractorRuntimeConfig,
): boolean {
  return Boolean(getConfiguredExtractorKey(provider, config));
}
