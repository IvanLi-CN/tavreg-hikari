import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const REPO_ROOT = path.resolve(import.meta.dir, "..");
const SQLITE_SNAPSHOT = path.join(REPO_ROOT, "scripts", "sqlite-snapshot.sh");

test("sqlite snapshot script preserves committed WAL rows", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-sqlite-snapshot-"));
  const sourcePath = path.join(tempRoot, "signup-tasks.sqlite");
  const snapshotPath = path.join(tempRoot, "registry.sqlite");

  try {
    const sourceDb = new Database(sourcePath);
    sourceDb.exec("PRAGMA journal_mode=WAL;");
    sourceDb.exec("CREATE TABLE smoke (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);");
    sourceDb.query("INSERT INTO smoke (value) VALUES (?)").run("live-row");

    const result = spawnSync("sh", [SQLITE_SNAPSHOT, sourcePath, snapshotPath], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });

    sourceDb.close(false);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(existsSync(snapshotPath)).toBe(true);

    const snapshotDb = new Database(snapshotPath, { create: false, strict: true });
    const row = snapshotDb.query("SELECT value FROM smoke ORDER BY id DESC LIMIT 1").get() as { value?: string } | null;
    snapshotDb.close(false);

    expect(row?.value).toBe("live-row");
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});
