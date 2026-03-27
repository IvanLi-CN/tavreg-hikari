import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { downloadMihomoBinary, type MihomoConfig } from "../src/proxy/mihomo.ts";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;

function createMihomoConfig(downloadDir: string, overrides: Partial<MihomoConfig> = {}): MihomoConfig {
  return {
    subscriptionUrl: "https://example.com/sub.yaml",
    apiPort: 39090,
    mixedPort: 49090,
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: "https://example.com/trace",
    workDir: path.join(downloadDir, "work"),
    downloadDir,
    ...overrides,
  };
}

async function createCachedBinary(downloadDir: string, version: string, contents: string): Promise<string> {
  const dir = path.join(downloadDir, version);
  const binaryPath = path.join(dir, process.platform === "win32" ? "mihomo.exe" : "mihomo");
  await mkdir(dir, { recursive: true });
  await writeFile(binaryPath, contents);
  if (process.platform !== "win32") {
    await chmod(binaryPath, 0o755);
  }
  return binaryPath;
}

afterEach(async () => {
  globalThis.fetch = originalFetch;
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

describe("downloadMihomoBinary", () => {
  test("reuses the latest cached binary before querying GitHub releases", async () => {
    globalThis.fetch = ((() => {
      throw new Error("fetch should not be called when a cached mihomo binary exists");
    }) as unknown) as typeof fetch;

    const downloadDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-mihomo-"));
    tempDirs.push(downloadDir);
    await createCachedBinary(downloadDir, "1.19.20", "old-binary");
    const latestBinary = await createCachedBinary(downloadDir, "1.19.21", "new-binary");

    await expect(downloadMihomoBinary(createMihomoConfig(downloadDir))).resolves.toBe(latestBinary);
  });

  test("scopes the in-memory cache by download directory", async () => {
    globalThis.fetch = ((() => {
      throw new Error("fetch should not be called when cached binaries already exist");
    }) as unknown) as typeof fetch;

    const firstDownloadDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-mihomo-a-"));
    const secondDownloadDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-mihomo-b-"));
    tempDirs.push(firstDownloadDir, secondDownloadDir);
    const firstBinary = await createCachedBinary(firstDownloadDir, "1.19.21", "first-binary");
    const secondBinary = await createCachedBinary(secondDownloadDir, "1.19.21", "second-binary");

    await expect(downloadMihomoBinary(createMihomoConfig(firstDownloadDir))).resolves.toBe(firstBinary);
    await expect(downloadMihomoBinary(createMihomoConfig(secondDownloadDir))).resolves.toBe(secondBinary);
  });
});
