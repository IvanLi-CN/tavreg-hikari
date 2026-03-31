import { existsSync } from "node:fs";
import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  getDefaultTaskLedgerDbPath,
  getLegacyTaskLedgerDbPath,
  resolveTaskLedgerDbPath,
} from "../src/storage/db-paths.ts";

test("default task ledger path uses registry.sqlite", () => {
  const outputRoot = "/tmp/tavreg-output";
  expect(getDefaultTaskLedgerDbPath(outputRoot)).toBe(path.resolve(outputRoot, "registry", "registry.sqlite"));
});

test("default task ledger path snapshots the legacy signup database into registry.sqlite", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-db-paths-"));
  try {
    const outputRoot = path.join(tempRoot, "output");
    const legacyPath = getLegacyTaskLedgerDbPath(outputRoot);
    await mkdir(path.dirname(legacyPath), { recursive: true });

    const legacyDb = new Database(legacyPath);
    legacyDb.exec("PRAGMA journal_mode=WAL;");
    legacyDb.exec("CREATE TABLE smoke (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);");
    legacyDb.query("INSERT INTO smoke (value) VALUES (?)").run("legacy-row");
    legacyDb.close(false);

    const resolvedPath = resolveTaskLedgerDbPath(outputRoot);
    expect(resolvedPath).toBe(getDefaultTaskLedgerDbPath(outputRoot));

    const migratedDb = new Database(resolvedPath, { create: false, strict: true });
    const row = migratedDb.query("SELECT value FROM smoke ORDER BY id DESC LIMIT 1").get() as { value?: string } | null;
    migratedDb.close(false);

    expect(row?.value).toBe("legacy-row");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test("explicit registry.sqlite path does not trigger legacy-path migration", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-db-paths-explicit-"));
  try {
    const explicitDir = path.join(tempRoot, "custom");
    const explicitPath = path.join(explicitDir, "registry.sqlite");
    const legacyPath = path.join(explicitDir, "signup-tasks.sqlite");
    await mkdir(explicitDir, { recursive: true });

    const legacyDb = new Database(legacyPath);
    legacyDb.exec("CREATE TABLE smoke (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);");
    legacyDb.query("INSERT INTO smoke (value) VALUES (?)").run("legacy-row");
    legacyDb.close(false);

    const resolvedPath = resolveTaskLedgerDbPath(path.join(tempRoot, "output"), explicitPath);
    expect(resolvedPath).toBe(path.resolve(explicitPath));
    expect(existsSync(resolvedPath)).toBe(false);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});
