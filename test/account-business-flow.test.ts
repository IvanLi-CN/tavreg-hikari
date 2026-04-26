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

test("account business-flow availability stays conservative while the async probe is still pending", async () => {
  const service = new BrowserAvailabilityService({
    cwd: process.cwd(),
    env: {} as NodeJS.ProcessEnv,
    ttlMs: 0,
    launchProbe: async () => {
      throw new Error("probe should not run for the pending snapshot assertion");
    },
  });
  expect(service.getAccountBusinessFlowAvailability()).toEqual({
    headless: true,
    headed: false,
    fingerprint: false,
    headedReason: "正在检测当前环境的浏览器能力。",
    fingerprintReason: "正在检测当前环境的浏览器能力。",
    deAvailable: false,
  });
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

test("single-account flow lease accepts linked Microsoft accounts", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/storage/app-db.ts", import.meta.url), "utf8");
  const leaseSection = source.slice(source.indexOf("leaseAccountForJob"), source.indexOf("countEligibleAccounts"));
  expect(leaseSection).not.toContain("a.has_api_key = 0");
  expect(leaseSection).toContain("a.lease_job_id IS NULL");
  expect(leaseSection).not.toContain("JOIN account_browser_sessions");
  expect(leaseSection).not.toContain("s.status = 'ready'");
});

test("superseded fingerprint flow waits for the old child close before replacing tracking", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/server/account-business-flow.ts", import.meta.url), "utf8");
  expect(source).toContain("waitForChildClose");
  expect(source).toContain("waitForPromiseSettlement(active.closeHandled");
  expect(source).toContain('signalChildProcess(active.child, "SIGKILL")');
  expect(source).toContain("if (this.active.get(input.key) === active)");
});

test("superseded single-account workers ignore stale close updates after replacement", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/server/account-business-flow.ts", import.meta.url), "utf8");
  expect(source).toContain("isCurrent: () => this.active.get(input.key) === active");
  expect(source).toContain("if (lifecycle.isCurrent())");
  expect(source).toContain("if (this.active.get(input.key) !== active)");
});

test("retained fingerprint flows stay running until the worker exits", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/server/account-business-flow.ts", import.meta.url), "utf8");
  expect(source).toContain('status: "running"');
  expect(source).toContain("browserRetained: true");
});

test("accounts listing does not trigger headed-browser availability probes", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/server/main.ts", import.meta.url), "utf8");
  const accountsGetStart = source.indexOf('if (pathname === "/api/accounts" && req.method === "GET")');
  const accountsGetEnd = source.indexOf('if (pathname === "/api/accounts/group" && req.method === "POST")');
  const accountsGetBlock = source.slice(accountsGetStart, accountsGetEnd);
  expect(accountsGetStart).toBeGreaterThan(-1);
  expect(accountsGetEnd).toBeGreaterThan(accountsGetStart);
  expect(accountsGetBlock).not.toContain("ensureAvailability()");
});

test("microsoft account launcher can start without a preselected proxy node", async () => {
  const { readFile } = await import("node:fs/promises");
  const flowSource = await readFile(new URL("../src/server/account-business-flow.ts", import.meta.url), "utf8");
  const workerSource = await readFile(new URL("../src/server/microsoft-account-worker.ts", import.meta.url), "utf8");
  expect(flowSource).toContain("function buildWorkerScriptArgs(");
  expect(flowSource).toContain('return runtime.bootstrapArgs[0] === "run" ? ["run", workerScriptPath] : ["--import", "tsx", workerScriptPath];');
  expect(flowSource).toContain('const args = selectedProxyNode ? [...workerArgs, "--proxy-node", selectedProxyNode] : [...workerArgs]');
  expect(flowSource).not.toContain("当前账号还没有可复用的代理节点，暂时无法打开微软账号页");
  expect(workerSource).not.toContain("missing --proxy-node");
  expect(workerSource).toContain("if (args.proxyNode) {");
});
