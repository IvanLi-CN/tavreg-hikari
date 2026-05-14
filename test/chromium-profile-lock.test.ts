import { describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { cleanupStaleChromiumSingletonLocks } from "../src/main.ts";

async function withTempProfile(run: (profileDir: string) => Promise<void>): Promise<void> {
  const profileDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-profile-lock-"));
  try {
    await run(profileDir);
  } finally {
    await rm(profileDir, { recursive: true, force: true });
  }
}

describe("Chromium profile lock recovery", () => {
  test("cleans stale singleton artifacts when hinted PID is not alive", async () => {
    await withTempProfile(async (profileDir) => {
      await writeFile(path.join(profileDir, "SingletonLock"), "host-99999999");
      await writeFile(path.join(profileDir, "SingletonCookie"), "cookie");

      const cleaned = await cleanupStaleChromiumSingletonLocks(profileDir, []);

      expect(cleaned).toBe(true);
      expect(existsSync(path.join(profileDir, "SingletonLock"))).toBe(false);
      expect(existsSync(path.join(profileDir, "SingletonCookie"))).toBe(false);
    });
  });

  test("does not clean singleton artifacts while a Chromium process owns the profile", async () => {
    await withTempProfile(async (profileDir) => {
      const lockPath = path.join(profileDir, "SingletonLock");
      await writeFile(lockPath, `host-${process.pid}`);

      const cleaned = await cleanupStaleChromiumSingletonLocks(profileDir, [
        {
          pid: process.pid,
          pgid: process.pid,
          command: `/Applications/Chromium --user-data-dir=${profileDir}`,
        },
      ]);

      expect(cleaned).toBe(false);
      expect(existsSync(lockPath)).toBe(true);
    });
  });

  test("cleans singleton symlinks when hinted PID belongs to a non-Chromium process", async () => {
    await withTempProfile(async (profileDir) => {
      const lockPath = path.join(profileDir, "SingletonLock");
      await symlink(`host-${process.pid}`, lockPath);

      const cleaned = await cleanupStaleChromiumSingletonLocks(profileDir, [
        {
          pid: process.pid,
          pgid: process.pid,
          command: "zsh",
        },
      ]);

      expect(cleaned).toBe(true);
      expect(existsSync(lockPath)).toBe(false);
    });
  });
});
