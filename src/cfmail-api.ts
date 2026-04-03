type JsonRecord = Record<string, unknown>;

export interface CfMailHttpJsonOptions {
  headers?: Record<string, string>;
  body?: unknown;
  proxyUrl?: string;
}

export type CfMailHttpJson = <T = unknown>(method: string, url: string, options?: CfMailHttpJsonOptions) => Promise<T>;

export interface CfMailMailboxRecord {
  id: string;
  address: string;
  localPart: string;
  subdomain: string;
  rootDomain: string | null;
}

export interface CfMailMeta {
  domains: string[];
  defaultMailboxTtlMinutes: number;
  minMailboxTtlMinutes: number;
  maxMailboxTtlMinutes: number;
  addressRules: {
    format: string;
    localPartPattern: string;
    subdomainPattern: string;
    examples: string[];
  } | null;
}

export interface CfMailMessageSummary {
  id: string;
  mailboxId: string;
  mailboxAddress: string;
  subject: string;
  previewText: string;
  fromName: string | null;
  fromAddress: string | null;
  receivedAt: string | null;
  sizeBytes: number;
  attachmentCount: number;
  hasHtml: boolean;
}

function parseHttpStatus(message: string): number | null {
  const matched = String(message).match(/http_failed:(\d{3}):/i);
  if (!matched?.[1]) return null;
  const status = Number.parseInt(matched[1], 10);
  return Number.isFinite(status) ? status : null;
}

export function normalizeCfMailBaseUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  return trimmed || "https://api.cfm.707979.xyz";
}

export function buildCfMailAuthHeaders(apiKey: string): Record<string, string> {
  return {
    Accept: "application/json",
    Authorization: `Bearer ${apiKey.trim()}`,
  };
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => (typeof item === "string" ? item.trim() : "")).filter(Boolean);
}

function collectStrings(value: unknown, bucket: string[], depth = 0): void {
  if (depth > 8 || value == null) return;
  if (typeof value === "string") {
    bucket.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, bucket, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value as JsonRecord)) collectStrings(item, bucket, depth + 1);
  }
}

export function isLikelyMicrosoftProofPayload(payload: unknown): boolean {
  const texts: string[] = [];
  collectStrings(payload, texts);
  if (texts.length === 0) return false;
  const joined = texts.join(" ").replace(/\s+/g, " ");
  return /(microsoft|accountprotection|account-security-noreply|security code|安全代码|个人 microsoft 帐户)/i.test(joined);
}

export function extractMicrosoftProofCodeFromPayload(payload: unknown): string | null {
  if (!isLikelyMicrosoftProofPayload(payload)) {
    return null;
  }
  const texts: string[] = [];
  collectStrings(payload, texts);
  const seen = new Set<string>();
  for (const text of texts) {
    const normalized = text
      .replaceAll("\\/", "/")
      .replaceAll("&amp;", "&")
      .replaceAll("\\u003d", "=")
      .replaceAll("\\u0026", "&")
      .replace(/\s+/g, " ");
    const sanitized = normalized
      .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, " ")
      .replace(/\bhttps?:\/\/\S+/gi, " ")
      .replace(/\b[a-z0-9-]+(?:\.[a-z0-9-]+){1,}\b/gi, (value) => (/\d{6}/.test(value) ? " " : value));
    const strongMatches = [
      ...sanitized.matchAll(/\b(?:your\s+)?single-use code(?:\s+is|:)?\D{0,16}(\d{6})\b/gi),
      ...sanitized.matchAll(/\b(?:your\s+)?security code(?:\s+is|:)?\D{0,16}(\d{6})\b/gi),
      ...sanitized.matchAll(/\b(?:验证码|安全代码)\s*(?:是|为|:)?\D{0,16}(\d{6})\b/g),
      ...sanitized.matchAll(/\b(\d{6})\b\D{0,24}\b(?:single-use code|security code|验证码|安全代码)\b/gi),
    ];
    for (const match of strongMatches) {
      const code = match[1];
      if (!code || seen.has(code)) continue;
      seen.add(code);
      return code;
    }
    const matches = Array.from(sanitized.matchAll(/\b(\d{6})\b/g));
    for (const match of matches) {
      const code = match[1];
      if (!code || seen.has(code)) continue;
      seen.add(code);
      const start = Math.max(0, (match.index || 0) - 96);
      const end = Math.min(sanitized.length, (match.index || 0) + code.length + 96);
      const context = sanitized.slice(start, end);
      if (/(microsoft|account|security code|安全代码|验证码|code)/i.test(context)) {
        return code;
      }
    }
  }
  if (seen.size === 1) {
    return Array.from(seen)[0] || null;
  }
  return null;
}

function extractMailboxRecord(payload: unknown): CfMailMailboxRecord | null {
  const record = payload && typeof payload === "object" ? (payload as JsonRecord) : null;
  if (!record) return null;
  const id = String(record.id || "").trim();
  const address = String(record.address || "").trim().toLowerCase();
  const localPart = String(record.localPart || "").trim();
  const subdomain = String(record.subdomain || "").trim();
  const rootDomain = String(record.rootDomain || "").trim() || null;
  if (!id || !address) return null;
  return { id, address, localPart, subdomain, rootDomain };
}

export async function fetchCfMailMeta(options: {
  baseUrl: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
}): Promise<CfMailMeta> {
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  const response = await options.httpJson<JsonRecord>("GET", `${baseUrl}/api/meta`, {
    proxyUrl: options.proxyUrl,
  });
  const addressRules =
    response.addressRules && typeof response.addressRules === "object"
      ? {
          format: String((response.addressRules as JsonRecord).format || "").trim(),
          localPartPattern: String((response.addressRules as JsonRecord).localPartPattern || "").trim(),
          subdomainPattern: String((response.addressRules as JsonRecord).subdomainPattern || "").trim(),
          examples: toStringArray((response.addressRules as JsonRecord).examples),
        }
      : null;
  return {
    domains: toStringArray(response.domains),
    defaultMailboxTtlMinutes: Number.parseInt(String(response.defaultMailboxTtlMinutes || "0"), 10) || 0,
    minMailboxTtlMinutes: Number.parseInt(String(response.minMailboxTtlMinutes || "0"), 10) || 0,
    maxMailboxTtlMinutes: Number.parseInt(String(response.maxMailboxTtlMinutes || "0"), 10) || 0,
    addressRules,
  };
}

export async function provisionCfMailMailbox(options: {
  baseUrl: string;
  apiKey: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
  localPart?: string;
  subdomain?: string;
  rootDomain?: string;
  expiresInMinutes?: number;
}): Promise<CfMailMailboxRecord> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  const response = await options.httpJson<JsonRecord>("POST", `${baseUrl}/api/mailboxes`, {
    headers: buildCfMailAuthHeaders(apiKey),
    proxyUrl: options.proxyUrl,
    body: {
      localPart: options.localPart?.trim() || undefined,
      subdomain: options.subdomain?.trim() || undefined,
      rootDomain: options.rootDomain?.trim() || undefined,
      expiresInMinutes: options.expiresInMinutes,
    },
  });
  const mailbox = extractMailboxRecord(response);
  if (!mailbox) {
    throw new Error("cfmail_mailbox_provision_failed:invalid_response");
  }
  return mailbox;
}

export async function ensureCfMailMailbox(options: {
  baseUrl: string;
  apiKey: string;
  address: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
  expiresInMinutes?: number;
}): Promise<CfMailMailboxRecord> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  const response = await options.httpJson<JsonRecord>("POST", `${baseUrl}/api/mailboxes/ensure`, {
    headers: buildCfMailAuthHeaders(apiKey),
    proxyUrl: options.proxyUrl,
    body: {
      address: options.address.trim().toLowerCase(),
      expiresInMinutes: options.expiresInMinutes,
    },
  });
  const mailbox = extractMailboxRecord(response);
  if (!mailbox) {
    throw new Error("cfmail_mailbox_provision_failed:invalid_response");
  }
  return mailbox;
}

export async function resolveCfMailMailbox(options: {
  baseUrl: string;
  apiKey: string;
  address: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
}): Promise<CfMailMailboxRecord | null> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  try {
    const response = await options.httpJson<JsonRecord>(
      "GET",
      `${baseUrl}/api/mailboxes/resolve?address=${encodeURIComponent(options.address.trim().toLowerCase())}`,
      {
        headers: buildCfMailAuthHeaders(apiKey),
        proxyUrl: options.proxyUrl,
      },
    );
    return extractMailboxRecord(response);
  } catch (error) {
    const status = parseHttpStatus(error instanceof Error ? error.message : String(error));
    if (status === 404) {
      return null;
    }
    throw error;
  }
}

export async function listCfMailMessages(options: {
  baseUrl: string;
  apiKey: string;
  address: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
  after?: string;
  since?: string;
}): Promise<CfMailMessageSummary[]> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  const query = new URLSearchParams();
  query.append("mailbox", options.address.trim().toLowerCase());
  if (options.after?.trim()) query.set("after", options.after.trim());
  if (options.since?.trim()) query.set("since", options.since.trim());
  const response = await options.httpJson<JsonRecord>("GET", `${baseUrl}/api/messages?${query.toString()}`, {
    headers: buildCfMailAuthHeaders(apiKey),
    proxyUrl: options.proxyUrl,
  });
  return Array.isArray(response.messages) ? (response.messages as CfMailMessageSummary[]) : [];
}

export async function getCfMailMessage(options: {
  baseUrl: string;
  apiKey: string;
  messageId: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
}): Promise<JsonRecord> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  const response = await options.httpJson<JsonRecord>("GET", `${baseUrl}/api/messages/${encodeURIComponent(options.messageId)}`, {
    headers: buildCfMailAuthHeaders(apiKey),
    proxyUrl: options.proxyUrl,
  });
  return response.message && typeof response.message === "object" ? (response.message as JsonRecord) : response;
}

export function buildCfMailRawMessageUrl(baseUrl: string, messageId: string): string {
  return `${normalizeCfMailBaseUrl(baseUrl)}/api/messages/${encodeURIComponent(messageId)}/raw`;
}
