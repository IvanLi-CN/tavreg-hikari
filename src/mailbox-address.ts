import { randomInt } from "node:crypto";

const MAILBOX_FIRST_NAMES = [
  "alex",
  "sam",
  "jordan",
  "taylor",
  "kai",
  "mika",
  "ren",
  "haru",
  "noa",
  "niko",
  "rei",
  "yuna",
  "mina",
  "leo",
  "luna",
] as const;

const MAILBOX_LAST_NAMES = [
  "lin",
  "park",
  "chen",
  "wong",
  "tan",
  "mori",
  "sato",
  "kato",
  "ito",
  "kim",
  "li",
  "ng",
  "choi",
  "song",
] as const;

const MAILBOX_ALIASES = ["nova", "echo", "rio", "mio", "sena", "riku", "aki", "nami"] as const;
const MAILBOX_SEPARATORS = ["", "", "", "-"] as const;
const MAILBOX_SUBDOMAINS = ["alpha", "bravo", "charlie", "delta", "echo", "atlas", "aurora", "lumen"] as const;

export const REALISTIC_MAILBOX_LOCAL_PART_PATTERN = /^[a-z0-9]+(?:-?[a-z0-9]+)*$/;
const SYNTHETIC_HEX_PATTERN = /\b(?:mail|box)-[a-f0-9]{6,}\b|[a-f0-9]{8,}/i;
const CFMAIL_ADDRESS_PART_HINT_PATTERN = /auto.?generat|auto.?assign|provider.?managed|local.?part|subdomain/i;
const CFMAIL_RECOVERABLE_REASON_PATTERN = /require(?:s|d)?|missing|invalid|format|unsupported|validation/i;

function pickRandom<T>(values: readonly T[]): T {
  return values[randomInt(0, values.length)]!;
}

function sanitizeMailboxLocalPart(value: string): string {
  return value
    .replace(/[^a-z0-9-]/gi, "")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-")
    .toLowerCase();
}

export function isRealisticMailboxLocalPart(value: string): boolean {
  const normalized = sanitizeMailboxLocalPart(value);
  if (!normalized || normalized.length < 6 || normalized.length > 32) {
    return false;
  }
  if (!REALISTIC_MAILBOX_LOCAL_PART_PATTERN.test(normalized)) {
    return false;
  }
  return !SYNTHETIC_HEX_PATTERN.test(normalized);
}

export function generateRealisticMailboxLocalPart(): string {
  for (let attempt = 1; attempt <= 24; attempt += 1) {
    const first = pickRandom(MAILBOX_FIRST_NAMES);
    const tail = randomInt(0, 4) === 0 ? pickRandom(MAILBOX_ALIASES) : pickRandom(MAILBOX_LAST_NAMES);
    const separator = pickRandom(MAILBOX_SEPARATORS);
    const digits = String(randomInt(10, 10_000));
    const candidate = sanitizeMailboxLocalPart(`${first}${separator}${tail}${digits}`);
    if (isRealisticMailboxLocalPart(candidate)) {
      return candidate;
    }
  }
  return `user${randomInt(100, 10_000)}`;
}

export function generateRealisticMailboxSubdomain(): string {
  return pickRandom(MAILBOX_SUBDOMAINS);
}

function parseHttpStatus(message: string): number | null {
  const matched = String(message || "").match(/http_failed:(\d{3}):/i);
  if (!matched?.[1]) return null;
  const status = Number.parseInt(matched[1], 10);
  return Number.isFinite(status) ? status : null;
}

export function shouldFallbackCfMailProviderManagedMailbox(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || "");
  if (!message) return false;
  if (/cfmail_mailbox_provision_failed:invalid_response/i.test(message)) {
    return true;
  }
  const status = parseHttpStatus(message);
  if (status == null) {
    return false;
  }
  if (![400, 409, 422].includes(status)) {
    return false;
  }
  return CFMAIL_ADDRESS_PART_HINT_PATTERN.test(message) && CFMAIL_RECOVERABLE_REASON_PATTERN.test(message);
}

export function shouldRetryCfMailFallbackWithSubdomain(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || "");
  if (!message) return false;
  const status = parseHttpStatus(message);
  if (status != null && ![400, 422].includes(status)) {
    return false;
  }
  return /subdomain/i.test(message) && /(required|missing|format|validation|invalid|unsupported)/i.test(message);
}

export function isMailboxAddressConflictError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || "");
  const status = parseHttpStatus(message);
  if (status === 409) return true;
  return /already exists|already used|duplicate|taken|conflict/i.test(message);
}
