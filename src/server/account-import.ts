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

export interface ExistingImportAccount {
  id: number;
  microsoftEmail: string;
  passwordPlaintext: string;
  hasApiKey: boolean;
  groupName: string | null;
}

export type ImportDecision = "create" | "update_password" | "keep_existing" | "input_duplicate" | "invalid";

export interface ImportPreviewItem {
  lineNumber: number;
  rawLine: string;
  email: string;
  normalizedEmail: string;
  password: string;
  decision: ImportDecision;
  note: string;
  duplicateOfLine?: number;
  existingAccountId?: number;
  existingHasApiKey?: boolean;
  groupName?: string | null;
}

export interface ImportPreviewSummary {
  parsed: number;
  invalid: number;
  create: number;
  updatePassword: number;
  keepExisting: number;
  inputDuplicate: number;
}

export interface ImportPreviewResult {
  items: ImportPreviewItem[];
  effectiveEntries: Array<{ email: string; password: string }>;
  summary: ImportPreviewSummary;
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

export function buildImportPreview(entries: ParsedImportEntry[], invalidRows: InvalidImportRow[], existingAccounts: ExistingImportAccount[]): ImportPreviewResult {
  const lastIndexByEmail = new Map<string, number>();
  const lineByIndex = new Map<number, number>();
  for (const [index, entry] of entries.entries()) {
    lastIndexByEmail.set(entry.normalizedEmail, index);
    lineByIndex.set(index, entry.lineNumber);
  }

  const existingByEmail = new Map(existingAccounts.map((account) => [account.microsoftEmail.toLowerCase(), account]));
  const items: ImportPreviewItem[] = [];
  const effectiveEntries: Array<{ email: string; password: string }> = [];
  const firstLineByEmail = new Map<string, number>();
  const summary: ImportPreviewSummary = {
    parsed: entries.length,
    invalid: invalidRows.length,
    create: 0,
    updatePassword: 0,
    keepExisting: 0,
    inputDuplicate: 0,
  };

  for (const [index, entry] of entries.entries()) {
    const firstLine = firstLineByEmail.get(entry.normalizedEmail);
    if (firstLine == null) {
      firstLineByEmail.set(entry.normalizedEmail, entry.lineNumber);
    }

    const isEffective = lastIndexByEmail.get(entry.normalizedEmail) === index;
    if (!isEffective) {
      const effectiveLine = lineByIndex.get(lastIndexByEmail.get(entry.normalizedEmail) ?? -1);
      items.push({
        lineNumber: entry.lineNumber,
        rawLine: entry.rawLine,
        email: entry.email,
        normalizedEmail: entry.normalizedEmail,
        password: entry.password,
        decision: "input_duplicate",
        note: "同一批导入中邮箱重复，已以后出现的记录为准",
        duplicateOfLine: effectiveLine ?? firstLine,
      });
      summary.inputDuplicate += 1;
      continue;
    }

    const existing = existingByEmail.get(entry.normalizedEmail);
    if (!existing) {
      items.push({
        lineNumber: entry.lineNumber,
        rawLine: entry.rawLine,
        email: entry.email,
        normalizedEmail: entry.normalizedEmail,
        password: entry.password,
        decision: "create",
        note: "新增账号",
      });
      effectiveEntries.push({ email: entry.email, password: entry.password });
      summary.create += 1;
      continue;
    }

    const shouldUpdatePassword = existing.passwordPlaintext !== entry.password;
    items.push({
      lineNumber: entry.lineNumber,
      rawLine: entry.rawLine,
      email: entry.email,
      normalizedEmail: entry.normalizedEmail,
      password: entry.password,
      decision: shouldUpdatePassword ? "update_password" : "keep_existing",
      note: shouldUpdatePassword
        ? existing.hasApiKey
          ? "已有账号，密码会更新；该账号已有 API key，后续调度仍会跳过"
          : "已有账号，密码会更新"
        : existing.hasApiKey
          ? "已有账号且密码未变；该账号已有 API key，后续调度会跳过"
          : "已有账号且密码未变",
      existingAccountId: existing.id,
      existingHasApiKey: existing.hasApiKey,
      groupName: existing.groupName,
    });
    if (shouldUpdatePassword) {
      effectiveEntries.push({ email: entry.email, password: entry.password });
      summary.updatePassword += 1;
    } else {
      summary.keepExisting += 1;
    }
  }

  for (const invalidRow of invalidRows) {
    items.push({
      lineNumber: invalidRow.lineNumber,
      rawLine: invalidRow.rawLine,
      email: "",
      normalizedEmail: "",
      password: "",
      decision: "invalid",
      note: invalidRow.reason === "password_not_found" ? "未识别到密码" : "未识别到邮箱",
    });
  }

  items.sort((left, right) => left.lineNumber - right.lineNumber);

  return {
    items,
    effectiveEntries,
    summary,
  };
}
