import { existsSync, mkdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

export const TASK_LEDGER_DB_DIRNAME = "registry";
export const TASK_LEDGER_DB_FILENAME = "tavreg-hikari.sqlite";
export const LEGACY_TASK_LEDGER_DB_FILENAME = "signup-tasks.sqlite";

interface SnapshotDatabase {
  exec: (sql: string) => void;
  close: () => void;
}

function openSnapshotDatabase(dbPath: string): SnapshotDatabase {
  if (typeof Bun !== "undefined") {
    const { Database } = require("bun:sqlite") as typeof import("bun:sqlite");
    const db = new Database(dbPath, { create: false, strict: true });
    return {
      exec: (sql: string) => db.exec(sql),
      close: () => db.close(false),
    };
  }

  const Database = require("better-sqlite3") as typeof import("better-sqlite3");
  const db = new Database(dbPath, { fileMustExist: true, readonly: true });
  return {
    exec: (sql: string) => db.exec(sql),
    close: () => db.close(),
  };
}

function escapeSqlitePath(filePath: string): string {
  return filePath.replaceAll("'", "''");
}

function snapshotLegacyDb(sourcePath: string, targetPath: string): void {
  mkdirSync(path.dirname(targetPath), { recursive: true });
  rmSync(targetPath, { force: true });

  const db = openSnapshotDatabase(sourcePath);
  try {
    db.exec("PRAGMA busy_timeout=5000;");
    db.exec(`VACUUM INTO '${escapeSqlitePath(targetPath)}';`);
  } finally {
    db.close();
  }
}

export function getDefaultTaskLedgerDbPath(outputRoot: string): string {
  return path.resolve(path.join(outputRoot, TASK_LEDGER_DB_DIRNAME, TASK_LEDGER_DB_FILENAME));
}

export function getLegacyTaskLedgerDbPath(outputRoot: string): string {
  return path.resolve(path.join(outputRoot, TASK_LEDGER_DB_DIRNAME, LEGACY_TASK_LEDGER_DB_FILENAME));
}

export function ensureTaskLedgerDbPath(dbPath: string): string {
  const resolvedPath = path.resolve(dbPath);
  if (path.basename(resolvedPath) !== TASK_LEDGER_DB_FILENAME || existsSync(resolvedPath)) {
    return resolvedPath;
  }

  const legacyPath = path.join(path.dirname(resolvedPath), LEGACY_TASK_LEDGER_DB_FILENAME);
  if (!existsSync(legacyPath)) {
    return resolvedPath;
  }

  try {
    snapshotLegacyDb(legacyPath, resolvedPath);
    return resolvedPath;
  } catch {
    return legacyPath;
  }
}

export function resolveTaskLedgerDbPath(outputRoot: string, configuredPath?: string | null): string {
  const explicitPath = String(configuredPath || "").trim();
  if (explicitPath) {
    return path.resolve(explicitPath);
  }
  return ensureTaskLedgerDbPath(getDefaultTaskLedgerDbPath(outputRoot));
}
