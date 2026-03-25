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
  timeoutMs?: number;
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

function parseZhanghaoyaLine(line: string): AccountExtractorCandidate {
  const parts = line.split(":").map((segment) => segment.trim());
  const email = parts[0] || null;
  const password = parts[1] || null;
  if (email && password && isValidEmail(email)) {
    return {
      provider: "zhanghaoya",
      rawPayload: line,
      email: email.toLowerCase(),
      password,
      parseStatus: "parsed",
    };
  }
  return {
    provider: "zhanghaoya",
    rawPayload: line,
    email: null,
    password: null,
    parseStatus: "invalid",
  };
}

function parseShanyouxiangLine(line: string): AccountExtractorCandidate {
  const parts = line.split("----").map((segment) => segment.trim());
  const email = parts[0] || null;
  const password = parts[1] || null;
  if (email && password && isValidEmail(email)) {
    return {
      provider: "shanyouxiang",
      rawPayload: line,
      email: email.toLowerCase(),
      password,
      parseStatus: "parsed",
    };
  }
  return {
    provider: "shanyouxiang",
    rawPayload: line,
    email: null,
    password: null,
    parseStatus: "invalid",
  };
}

function mapFailure(provider: AccountExtractorProvider, message: string): AccountExtractorFailureCode {
  const normalized = message.trim().toLowerCase();
  if (
    /库存不足|insufficient|out of stock|notfound/.test(normalized)
    || (provider === "zhanghaoya" && normalized.includes("notfound"))
  ) {
    return "insufficient_stock";
  }
  if (/卡密不存在|invalid key|minimum length|maxim/.test(normalized)) {
    return "invalid_key";
  }
  return "upstream_error";
}

async function fetchText(url: string, timeoutMs: number): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0 Codex/1.0",
        accept: "application/json,text/plain,*/*",
      },
      signal: controller.signal,
    });
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchSingleExtractedAccount(input: {
  provider: AccountExtractorProvider;
  accountType?: AccountExtractorAccountType;
  config: AccountExtractorRuntimeConfig;
}): Promise<AccountExtractorFetchResult> {
  const accountType = input.accountType || "outlook";
  const timeoutMs = Math.max(3000, input.config.timeoutMs || 20000);
  if (input.provider === "zhanghaoya") {
    const key = input.config.zhanghaoyaKey.trim();
    const url = new URL("https://www.zhanghaoya.com/store/ga/account");
    url.searchParams.set("type", accountType);
    url.searchParams.set("quantity", "1");
    url.searchParams.set("key", key);
    const rawResponse = await fetchText(url.toString(), timeoutMs);
    try {
      const payload = JSON.parse(rawResponse) as { Code?: number; Message?: string; Data?: string };
      if (payload.Code !== 200 || typeof payload.Data !== "string") {
        const message = String(payload.Message || "unexpected upstream response");
        return {
          provider: "zhanghaoya",
          accountType,
          rawResponse,
          candidates: [],
          ok: false,
          failureCode: mapFailure("zhanghaoya", message),
          message,
          maskedKey: maskKey(key),
        };
      }
      const candidates = normalizeLines(payload.Data).map(parseZhanghaoyaLine);
      const valid = candidates.some((candidate) => candidate.parseStatus === "parsed");
      return {
        provider: "zhanghaoya",
        accountType,
        rawResponse,
        candidates,
        ok: valid,
        failureCode: valid ? null : "parse_failed",
        message: valid ? null : "zhanghaoya response did not contain a parsable account",
        maskedKey: maskKey(key),
      };
    } catch {
      return {
        provider: "zhanghaoya",
        accountType,
        rawResponse,
        candidates: normalizeLines(rawResponse).map(parseZhanghaoyaLine),
        ok: false,
        failureCode: "parse_failed",
        message: "zhanghaoya response was not valid JSON",
        maskedKey: maskKey(key),
      };
    }
  }

  const card = input.config.shanyouxiangKey.trim();
  const url = new URL("https://zizhu.shanyouxiang.com/huoqu");
  url.searchParams.set("shuliang", "1");
  url.searchParams.set("leixing", accountType);
  url.searchParams.set("card", card);
  const rawResponse = await fetchText(url.toString(), timeoutMs);
  try {
    const payload = JSON.parse(rawResponse) as { status?: number; msg?: string };
    if (typeof payload.status === "number" && payload.status !== 0 && payload.status !== 1) {
      const message = String(payload.msg || "unexpected upstream response");
      return {
        provider: "shanyouxiang",
        accountType,
        rawResponse,
        candidates: [],
        ok: false,
        failureCode: mapFailure("shanyouxiang", message),
        message,
        maskedKey: maskKey(card),
      };
    }
  } catch {
    // shanyouxiang success bodies are often plain text; ignore JSON parse errors here.
  }
  const candidates = normalizeLines(rawResponse).map(parseShanyouxiangLine);
  const valid = candidates.some((candidate) => candidate.parseStatus === "parsed");
  return {
    provider: "shanyouxiang",
    accountType,
    rawResponse,
    candidates,
    ok: valid,
    failureCode: valid ? null : "parse_failed",
    message: valid ? null : "shanyouxiang response did not contain a parsable account",
    maskedKey: maskKey(card),
  };
}

export function keyConfiguredForProvider(
  provider: AccountExtractorProvider,
  config: AccountExtractorRuntimeConfig,
): boolean {
  return provider === "zhanghaoya" ? Boolean(config.zhanghaoyaKey.trim()) : Boolean(config.shanyouxiangKey.trim());
}
