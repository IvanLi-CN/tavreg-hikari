export type MailboxVerificationCodeProvider = "microsoft" | "chatgpt" | "grok" | "generic";

export interface MailboxVerificationCodeInput {
  subject?: string | null;
  fromName?: string | null;
  fromAddress?: string | null;
  preview?: string | null;
  body?: string | null;
}

export interface MailboxVerificationCodeMatch {
  code: string;
  provider: MailboxVerificationCodeProvider;
  evidence: string;
}

function stripHtml(value: string): string {
  return value
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&#(\d+);/g, (_, digits: string) => {
      const codePoint = Number.parseInt(digits, 10);
      return Number.isFinite(codePoint) ? String.fromCharCode(codePoint) : " ";
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => {
      const codePoint = Number.parseInt(hex, 16);
      return Number.isFinite(codePoint) ? String.fromCharCode(codePoint) : " ";
    });
}

function normalizeText(value: string | null | undefined): string {
  return String(value || "")
    .replaceAll("\\/", "/")
    .replaceAll("\\u003d", "=")
    .replaceAll("\\u0026", "&")
    .replace(/\s+/g, " ")
    .trim();
}

function buildSegments(input: MailboxVerificationCodeInput): string[] {
  const segments = [
    normalizeText(input.subject),
    normalizeText(input.fromName),
    normalizeText(input.fromAddress),
    normalizeText(input.preview),
    normalizeText(input.body),
    stripHtml(normalizeText(input.body)),
  ].filter(Boolean);
  return Array.from(new Set(segments));
}

function buildJoinedText(input: MailboxVerificationCodeInput): string {
  return buildSegments(input).join(" | ");
}

function scanSixDigitCode(text: string, contextPattern: RegExp): string | null {
  for (const match of text.matchAll(/\b(\d{6})\b/g)) {
    const code = match[1];
    if (!code) continue;
    const start = Math.max(0, (match.index || 0) - 96);
    const end = Math.min(text.length, (match.index || 0) + code.length + 96);
    const context = text.slice(start, end);
    if (contextPattern.test(context)) {
      return code;
    }
  }
  return null;
}

function extractMicrosoftCode(texts: string[]): MailboxVerificationCodeMatch | null {
  for (const text of texts) {
    const hasMicrosoftHint = /(microsoft|account\.microsoft|accountprotection|account-security-noreply|microsoft account|outlook|hotmail)/i.test(text);
    if (!hasMicrosoftHint) continue;
    const explicitMatches = [
      ...text.matchAll(/\b(?:single-use|security|verification)\s+code(?:\s+is|:)?\D{0,24}(\d{6})\b/gi),
      ...text.matchAll(/\b(?:验证码|安全代码)(?:是|为|:)?\D{0,24}(\d{6})\b/g),
      ...text.matchAll(/\b(\d{6})\b\D{0,24}\b(?:single-use|security|verification)\s+code\b/gi),
    ];
    for (const match of explicitMatches) {
      const code = match[1];
      if (!code) continue;
      return {
        code,
        provider: "microsoft",
        evidence: "microsoft_explicit",
      };
    }
    const code = scanSixDigitCode(text, /(microsoft|account\.microsoft|accountprotection|account-security-noreply|security code|verification code|验证码|安全代码)/i);
    if (code) {
      return {
        code,
        provider: "microsoft",
        evidence: "microsoft_context",
      };
    }
  }
  return null;
}

function extractChatGptCode(texts: string[]): MailboxVerificationCodeMatch | null {
  for (const text of texts) {
    const explicitMatches = [
      ...text.matchAll(/\b(?:your\s+)?chatgpt code(?:\s+is|:)?\D{0,24}(\d{6})\b/gi),
      ...text.matchAll(/\b(?:openai|chatgpt).{0,48}\b(\d{6})\b/gi),
    ];
    for (const match of explicitMatches) {
      const code = match[1];
      if (!code) continue;
      return {
        code,
        provider: "chatgpt",
        evidence: "chatgpt_explicit",
      };
    }
    const code = scanSixDigitCode(text, /(openai|chatgpt|tm\.openai\.com|verification code|one-time|one time|login|sign in)/i);
    if (code) {
      return {
        code,
        provider: "chatgpt",
        evidence: "chatgpt_context",
      };
    }
  }
  return null;
}

function extractGrokCode(texts: string[]): MailboxVerificationCodeMatch | null {
  for (const text of texts) {
    for (const match of text.matchAll(/\b([A-Z0-9]{3})-([A-Z0-9]{3})\b/gi)) {
      const compact = `${match[1] || ""}${match[2] || ""}`.toUpperCase();
      if (!compact) continue;
      const start = Math.max(0, (match.index || 0) - 96);
      const end = Math.min(text.length, (match.index || 0) + match[0].length + 96);
      const context = text.slice(start, end);
      if (/(grok|x\.ai|accounts\.x\.ai|verification code|verify|login|sign in)/i.test(context)) {
        return {
          code: compact,
          provider: "grok",
          evidence: "grok_hyphenated",
        };
      }
    }
    const code = scanSixDigitCode(text, /(grok|x\.ai|accounts\.x\.ai|verification code|verify|login|sign in)/i);
    if (code) {
      return {
        code,
        provider: "grok",
        evidence: "grok_context",
      };
    }
  }
  return null;
}

function extractGenericCode(texts: string[]): MailboxVerificationCodeMatch | null {
  for (const text of texts) {
    const sixDigit = scanSixDigitCode(text, /(verification|verify|one-time|one time|security code|login|sign in|code)/i);
    if (sixDigit) {
      return {
        code: sixDigit,
        provider: "generic",
        evidence: "generic_six_digit",
      };
    }
    for (const match of text.matchAll(/\b([A-Z0-9]{3})-([A-Z0-9]{3})\b/gi)) {
      const compact = `${match[1] || ""}${match[2] || ""}`.toUpperCase();
      if (!compact) continue;
      const start = Math.max(0, (match.index || 0) - 96);
      const end = Math.min(text.length, (match.index || 0) + match[0].length + 96);
      const context = text.slice(start, end);
      if (/(verification|verify|one-time|one time|login|sign in|code)/i.test(context)) {
        return {
          code: compact,
          provider: "generic",
          evidence: "generic_hyphenated",
        };
      }
    }
  }
  return null;
}

export function matchMailboxVerificationCode(input: MailboxVerificationCodeInput): MailboxVerificationCodeMatch | null {
  const texts = buildSegments(input);
  if (texts.length === 0) return null;
  return (
    extractMicrosoftCode(texts)
    || extractChatGptCode(texts)
    || extractGrokCode(texts)
    || extractGenericCode(texts)
  );
}

export function extractMailboxVerificationCode(input: MailboxVerificationCodeInput): string | null {
  return matchMailboxVerificationCode(input)?.code || null;
}

export function mailboxVerificationCodeSignals(input: MailboxVerificationCodeInput): string {
  return buildJoinedText(input);
}
