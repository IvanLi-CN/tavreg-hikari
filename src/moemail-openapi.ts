type JsonRecord = Record<string, unknown>;

export interface MoeMailHttpJsonOptions {
  headers?: Record<string, string>;
  proxyUrl?: string;
}

export type MoeMailHttpJson = <T = unknown>(method: string, url: string, options?: MoeMailHttpJsonOptions) => Promise<T>;

export function normalizeMoeMailBaseUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  return trimmed || "https://moemail.707079.xyz";
}

export function buildMoeMailAuthHeaders(apiKey: string): Record<string, string> {
  return {
    Accept: "application/json",
    "X-API-Key": apiKey.trim(),
  };
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
    const matches = Array.from(normalized.matchAll(/\b(\d{6})\b/g));
    for (const match of matches) {
      const code = match[1];
      if (!code || seen.has(code)) continue;
      seen.add(code);
      const start = Math.max(0, (match.index || 0) - 96);
      const end = Math.min(normalized.length, (match.index || 0) + code.length + 96);
      const context = normalized.slice(start, end);
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

function parseMessageTimestamp(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 0 ? value : null;
  }
  if (typeof value === "string" && value.trim()) {
    if (/^\d+$/.test(value.trim())) {
      const parsedInt = Number.parseInt(value.trim(), 10);
      return Number.isFinite(parsedInt) && parsedInt > 0 ? parsedInt : null;
    }
    const parsedDate = Date.parse(value);
    return Number.isFinite(parsedDate) ? parsedDate : null;
  }
  return null;
}

export function extractFreshMicrosoftProofCodeFromMoeMailResponse(payload: unknown, notBeforeMs: number): string | null {
  const response = payload && typeof payload === "object" ? (payload as JsonRecord) : null;
  const messages = Array.isArray(response?.messages) ? (response?.messages as unknown[]) : null;
  if (!messages || messages.length === 0) {
    return extractMicrosoftProofCodeFromPayload(payload);
  }

  let sawTimestamp = false;
  for (const message of messages) {
    if (!message || typeof message !== "object") continue;
    const record = message as JsonRecord;
    const receivedAt = parseMessageTimestamp(record.received_at ?? record.receivedAt ?? record.sent_at ?? record.sentAt);
    if (receivedAt != null) {
      sawTimestamp = true;
      if (receivedAt < notBeforeMs) {
        continue;
      }
    }
    const code = extractMicrosoftProofCodeFromPayload(message);
    if (code) {
      return code;
    }
  }

  return sawTimestamp ? null : extractMicrosoftProofCodeFromPayload(payload);
}

function findMailboxIdByAddress(response: unknown, address: string): string | null {
  const normalizedAddress = address.trim().toLowerCase();
  if (!normalizedAddress) return null;
  const emails = Array.isArray((response as JsonRecord | null)?.emails) ? ((response as JsonRecord).emails as unknown[]) : [];
  for (const item of emails) {
    if (!item || typeof item !== "object") continue;
    const record = item as JsonRecord;
    if (String(record.address || "").trim().toLowerCase() !== normalizedAddress) continue;
    const mailboxId = String(record.id || "").trim();
    if (mailboxId) return mailboxId;
  }
  return null;
}

export async function resolveMoeMailMailboxId(options: {
  baseUrl: string;
  apiKey: string;
  address: string;
  httpJson: MoeMailHttpJson;
  proxyUrl?: string;
  maxPages?: number;
}): Promise<string | null> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("moemail_api_key_missing");
  }
  const baseUrl = normalizeMoeMailBaseUrl(options.baseUrl);
  const headers = buildMoeMailAuthHeaders(apiKey);
  let cursor = "";
  const maxPages = Math.max(1, options.maxPages || 20);
  for (let page = 1; page <= maxPages; page += 1) {
    const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
    const response = await options.httpJson<JsonRecord>("GET", `${baseUrl}/api/emails${query}`, {
      headers,
      proxyUrl: options.proxyUrl,
    });
    const mailboxId = findMailboxIdByAddress(response, options.address);
    if (mailboxId) {
      return mailboxId;
    }
    const nextCursor = typeof response.nextCursor === "string" ? response.nextCursor.trim() : "";
    if (!nextCursor) {
      break;
    }
    cursor = nextCursor;
  }
  return null;
}
