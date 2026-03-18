export interface ImportedAccountEntry {
  email: string;
  password: string;
}

const ACCOUNT_LINE_PATTERN = /^\s*(\S+@\S+?)\s*(?:[,|:：]|\s+)\s*(.+?)\s*$/;

export function parseAccountImportLine(line: string): ImportedAccountEntry | null {
  const normalized = line.trim();
  if (!normalized) return null;

  const match = normalized.match(ACCOUNT_LINE_PATTERN);
  if (!match) return null;

  const email = match[1];
  const password = match[2];
  if (typeof email !== "string" || typeof password !== "string") return null;

  const nextEmail = email.trim();
  const nextPassword = password.trim();
  if (!nextEmail || !nextPassword) return null;

  return {
    email: nextEmail,
    password: nextPassword,
  };
}

export function parseAccountImportContent(content: string): ImportedAccountEntry[] {
  return content
    .split(/\r?\n/)
    .map((line) => parseAccountImportLine(line))
    .filter((entry): entry is ImportedAccountEntry => entry != null);
}
