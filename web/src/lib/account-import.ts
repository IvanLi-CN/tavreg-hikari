export interface ParsedImportEntry {
  lineNumber: number;
  rawLine: string;
  email: string;
  normalizedEmail: string;
  password: string;
}

export interface InvalidImportRow {
  lineNumber: number;
  rawLine: string;
  reason: string;
}

export interface ImportPreviewItemLike {
  email: string;
  normalizedEmail: string;
  password: string;
  decision: "create" | "update_password" | "keep_existing" | "input_duplicate" | "invalid";
}

export interface ImportPreviewPayloadLike {
  items: ImportPreviewItemLike[];
  effectiveEntries: Array<{ email: string; password: string }>;
}

const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
const LEADING_BOUNDARY_PATTERN = /^(?:\s*(?:[,|:：;；]+|[-—–]{2,})\s*|\s+)/;
const TRAILING_BOUNDARY_PATTERN = /(?:\s*(?:[,|:：;；]+|[-—–]{2,})\s*|\s+)$/;

function normalizeLine(rawLine: string): string {
  return rawLine
    .replace(/\u3000/g, " ")
    .replace(/[，]/g, ",")
    .replace(/[｜]/g, "|")
    .trim();
}

function readPasswordAfterEmail(value: string): string {
  return value.trimEnd().replace(LEADING_BOUNDARY_PATTERN, "").trim();
}

function readPasswordBeforeEmail(value: string): string {
  return value.trimStart().replace(TRAILING_BOUNDARY_PATTERN, "").trim();
}

export function parseImportLine(rawLine: string, lineNumber: number): ParsedImportEntry | InvalidImportRow {
  const normalizedLine = normalizeLine(rawLine);
  if (!normalizedLine) {
    return {
      lineNumber,
      rawLine,
      reason: "empty_line",
    };
  }

  const emailMatch = normalizedLine.match(EMAIL_PATTERN);
  if (!emailMatch || typeof emailMatch.index !== "number") {
    return {
      lineNumber,
      rawLine,
      reason: "email_not_found",
    };
  }

  const email = emailMatch[0].trim();
  const normalizedEmail = email.toLowerCase();
  const before = readPasswordBeforeEmail(normalizedLine.slice(0, emailMatch.index));
  const after = readPasswordAfterEmail(normalizedLine.slice(emailMatch.index + email.length));
  const password = after || before;

  if (!password) {
    return {
      lineNumber,
      rawLine,
      reason: "password_not_found",
    };
  }

  return {
    lineNumber,
    rawLine,
    email,
    normalizedEmail,
    password,
  };
}

export function parseImportContent(content: string): { entries: ParsedImportEntry[]; invalidRows: InvalidImportRow[] } {
  const entries: ParsedImportEntry[] = [];
  const invalidRows: InvalidImportRow[] = [];

  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    const result = parseImportLine(rawLine, index + 1);
    if ("reason" in result) {
      if (normalizeLine(rawLine)) {
        invalidRows.push(result);
      }
      continue;
    }
    entries.push(result);
  }

  return { entries, invalidRows };
}

export function buildImportCommitEntries(preview: ImportPreviewPayloadLike | null, groupName: string): Array<{ email: string; password: string }> {
  if (!preview) return [];
  if (!groupName.trim()) {
    return preview.effectiveEntries;
  }

  const entries: Array<{ email: string; password: string }> = [];
  const seen = new Set<string>();
  for (const item of preview.items) {
    if (!["create", "update_password", "keep_existing"].includes(item.decision)) continue;
    if (!item.email || !item.password) continue;
    const key = item.normalizedEmail || item.email.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push({ email: item.email, password: item.password });
  }
  return entries;
}
