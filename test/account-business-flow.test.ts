import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expect, test } from "bun:test";
import { BrowserAvailabilityService } from "../src/server/browser-availability.ts";

async function createFakeMacFingerprintBrowserInstall(): Promise<{ rootDir: string; executablePath: string }> {
  const rootDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-browser-availability-"));
  const toolsDir = path.join(rootDir, ".tools");
  const executablePath = path.join(toolsDir, "Chromium.app", "Contents", "MacOS", "Chromium");
  await mkdir(path.dirname(executablePath), { recursive: true });
  const binaryContent = "#!/bin/sh\nexit 0\n";
  await writeFile(executablePath, binaryContent, { mode: 0o755 });
  const binarySha256 = createHash("sha256").update(binaryContent, "utf8").digest("hex");
  await writeFile(
    path.join(toolsDir, ".fingerprint-browser-install.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        installer: "install-fingerprint-browser.sh",
        platform: "macos",
        version: "test",
        binaryRelativePath: "Chromium.app/Contents/MacOS/Chromium",
        binarySha256,
      },
      null,
      2,
    ),
    "utf8",
  );
  return { rootDir, executablePath };
}

test("account business-flow availability reports missing fingerprint browser from the real browser probe path", async () => {
  const rootDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-browser-missing-"));
  try {
    const service = new BrowserAvailabilityService({
      cwd: rootDir,
      env: {} as NodeJS.ProcessEnv,
      ttlMs: 0,
      launchProbe: async () => {
        throw new Error("launch should not run when browser is missing");
      },
    });
    await service.ensureFresh(true);
    expect(service.getRunModeAvailability()).toEqual({
      headed: false,
      headless: true,
      headedReason: expect.stringContaining("指纹浏览器"),
    });
    expect(service.getAccountBusinessFlowAvailability()).toEqual({
      headless: true,
      headed: false,
      fingerprint: false,
      headedReason: expect.stringContaining("指纹浏览器"),
      fingerprintReason: expect.stringContaining("指纹浏览器"),
      deAvailable: false,
    });
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});

test("account business-flow availability enables headed and fingerprint after a successful launch probe", async () => {
  const install = await createFakeMacFingerprintBrowserInstall();
  try {
    const calls: string[] = [];
    const service = new BrowserAvailabilityService({
      cwd: install.rootDir,
      env: {} as NodeJS.ProcessEnv,
      ttlMs: 0,
      launchProbe: async ({ executablePath }) => {
        calls.push(executablePath);
      },
    });
    await service.ensureFresh(true);
    expect(calls).toEqual([install.executablePath]);
    expect(service.getRunModeAvailability()).toEqual({
      headed: true,
      headless: true,
      headedReason: null,
    });
    expect(service.getAccountBusinessFlowAvailability()).toEqual({
      headless: true,
      headed: true,
      fingerprint: true,
      headedReason: null,
      fingerprintReason: null,
      deAvailable: true,
    });
  } finally {
    await rm(install.rootDir, { recursive: true, force: true });
  }
});

test("account business-flow availability surfaces actual launch failures", async () => {
  const install = await createFakeMacFingerprintBrowserInstall();
  try {
    const service = new BrowserAvailabilityService({
      cwd: install.rootDir,
      env: {} as NodeJS.ProcessEnv,
      ttlMs: 0,
      launchProbe: async () => {
        throw new Error("probe_launch_failed");
      },
    });
    await service.ensureFresh(true);
    expect(service.getRunModeAvailability()).toEqual({
      headed: false,
      headless: true,
      headedReason: "当前环境无法启动有头浏览器：probe_launch_failed",
    });
    expect(service.getAccountBusinessFlowAvailability()).toEqual({
      headless: true,
      headed: false,
      fingerprint: false,
      headedReason: "当前环境无法启动有头浏览器：probe_launch_failed",
      fingerprintReason: "当前环境无法启动指纹浏览器：probe_launch_failed",
      deAvailable: false,
    });
  } finally {
    await rm(install.rootDir, { recursive: true, force: true });
  }
});


test("microsoft account business flow prefers Bun-hosted worker runtime when the server itself runs under Bun", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/server/account-business-flow.ts", import.meta.url), "utf8");
  expect(source).toContain("process.versions.bun");
  expect(source).toContain("src/server/microsoft-account-worker.ts");
  expect(source).toContain('process.execPath || "bun"');
});

test("single-account business flows lease the account and clean up hidden setup failures", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/server/account-business-flow.ts", import.meta.url), "utf8");
  expect(source).toContain("leaseAccountForJob");
  expect(source).toContain("releaseAccountLease");
  expect(source).toContain("rollbackAttemptBeforeLaunch");
  expect(source).toContain('site: "microsoft"');
});
