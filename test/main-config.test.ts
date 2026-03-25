import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dir, "..");

test("CLI rejects MAIL_PROVIDER=moemail because MoeMail is proof-only", () => {
  const nodeBinary = process.env.NODE_BINARY?.trim() || "node";
  const result = spawnSync(nodeBinary, ["--import", "tsx", "src/main.ts"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      MAIL_PROVIDER: "moemail",
    },
    encoding: "utf8",
  });

  expect(result.status).toBe(1);
  expect(`${result.stdout}\n${result.stderr}`).toContain("Invalid env MAIL_PROVIDER: moemail");
});

test("CLI defers AppDatabase loading until proof sync needs it", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).not.toContain('from "./storage/app-db.js"');
  expect(source).toContain('await import("./storage/app-db.js")');
});
