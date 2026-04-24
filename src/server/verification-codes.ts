import { extractMicrosoftProofCodeFromPayload } from "../cfmail-api.js";
import { extractEmailCodeFromPayload } from "../main.js";

type JsonRecord = Record<string, unknown>;

export type ParsedVerificationCodeKind = "numeric" | "alphanumeric" | "microsoftProof";
export type ParsedVerificationCodeSource =
  | "subject"
  | "bodyPreview"
  | "bodyContent"
  | "cfmailSummary"
  | "cfmailDetail";

export interface ParsedVerificationCode {
  code: string;
  kind: ParsedVerificationCodeKind;
  source: ParsedVerificationCodeSource;
  snippet: string;
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
    for (const item of Object.values(value as JsonRecord)) {
      collectStrings(item, bucket, depth + 1);
    }
  }
}

function normalizeCode(code: string, kind: ParsedVerificationCodeKind): string {
  if (kind === "alphanumeric") {
    return code.replace(/[^A-Z0-9]/gi, "").toUpperCase();
  }
  return code.trim();
}

function buildSnippet(text: string, start: number, length: number): string {
  const from = Math.max(0, start - 40);
  const to = Math.min(text.length, start + length + 40);
  return text.slice(from, to).replace(/\s+/g, " ").trim();
}

function appendCode(
  bucket: ParsedVerificationCode[],
  seen: Set<string>,
  input: ParsedVerificationCode,
): void {
  const dedupeKey = input.code;
  if (seen.has(dedupeKey)) return;
  seen.add(dedupeKey);
  bucket.push(input);
}

function parseTextCodes(
  text: string,
  source: ParsedVerificationCodeSource,
  bucket: ParsedVerificationCode[],
  seen: Set<string>,
): void {
  const normalized = text
    .replaceAll("\\/", "/")
    .replaceAll("&amp;", "&")
    .replaceAll("\\u003d", "=")
    .replaceAll("\\u0026", "&")
    .replace(/\s+/g, " ");
  const contextualMatches = [
    ...normalized.matchAll(/\b(\d{6})\b/gi),
    ...normalized.matchAll(/\b([A-Z0-9]{3})-([A-Z0-9]{3})\b/gi),
  ];
  for (const match of contextualMatches) {
    const rawCode = match.length >= 3 ? `${match[1] || ""}${match[2] || ""}` : (match[1] || "");
    const kind: ParsedVerificationCodeKind = match.length >= 3 ? "alphanumeric" : "numeric";
    const code = normalizeCode(rawCode, kind);
    if (!code) continue;
    const snippet = buildSnippet(normalized, match.index || 0, match[0]?.length || code.length);
    if (!/(code|otp|one-time|one time|verification|verify|login|sign in|identity|安全代码|验证码|security)/i.test(snippet)) {
      continue;
    }
    appendCode(bucket, seen, {
      code,
      kind,
      source,
      snippet,
    });
  }
}

function parsePayloadCodes(
  payload: unknown,
  source: ParsedVerificationCodeSource,
  bucket: ParsedVerificationCode[],
  seen: Set<string>,
): void {
  const texts: string[] = [];
  collectStrings(payload, texts);
  for (const text of texts) {
    parseTextCodes(text, source, bucket, seen);
  }
}

function addPrimaryDetectedCode(
  code: string | null,
  kind: ParsedVerificationCodeKind,
  source: ParsedVerificationCodeSource,
  bucket: ParsedVerificationCode[],
  seen: Set<string>,
): void {
  if (!code) return;
  const inferredKind = kind === "numeric" && /[^\d]/.test(code) ? "alphanumeric" : kind;
  appendCode(bucket, seen, {
    code: normalizeCode(code, inferredKind),
    kind: inferredKind,
    source,
    snippet: code,
  });
}

export function parseMailboxVerificationCodes(message: {
  subject?: string | null;
  bodyPreview?: string | null;
  bodyContent?: string | null;
}): ParsedVerificationCode[] {
  const codes: ParsedVerificationCode[] = [];
  const seen = new Set<string>();

  const subject = String(message.subject || "").trim();
  const bodyPreview = String(message.bodyPreview || "").trim();
  const bodyContent = String(message.bodyContent || "").trim();

  addPrimaryDetectedCode(extractEmailCodeFromPayload({ subject }), "numeric", "subject", codes, seen);
  addPrimaryDetectedCode(extractEmailCodeFromPayload({ bodyPreview }), "numeric", "bodyPreview", codes, seen);
  addPrimaryDetectedCode(extractEmailCodeFromPayload({ bodyContent }), "numeric", "bodyContent", codes, seen);

  if (subject) parseTextCodes(subject, "subject", codes, seen);
  if (bodyPreview) parseTextCodes(bodyPreview, "bodyPreview", codes, seen);
  if (bodyContent) parseTextCodes(bodyContent, "bodyContent", codes, seen);

  return codes;
}

export function parseProofMailboxVerificationCodes(input: {
  summary?: unknown;
  detail?: unknown;
}): ParsedVerificationCode[] {
  const codes: ParsedVerificationCode[] = [];
  const seen = new Set<string>();

  addPrimaryDetectedCode(
    extractMicrosoftProofCodeFromPayload(input.summary),
    "microsoftProof",
    "cfmailSummary",
    codes,
    seen,
  );
  addPrimaryDetectedCode(
    extractMicrosoftProofCodeFromPayload(input.detail),
    "microsoftProof",
    "cfmailDetail",
    codes,
    seen,
  );

  if (input.summary !== undefined) {
    parsePayloadCodes(input.summary, "cfmailSummary", codes, seen);
  }
  if (input.detail !== undefined) {
    parsePayloadCodes(input.detail, "cfmailDetail", codes, seen);
  }

  return codes;
}
