import { expect, test } from "bun:test";
import { chmod, mkdtemp, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  assertUsableFingerprintChromiumExecutablePath,
  isFingerprintChromiumExecutable,
  resolveExplicitChromeExecutablePath,
  requireFingerprintChromiumExecutablePath,
} from "../src/fingerprint-browser.ts";

test("resolves only explicit fingerprint browser paths", () => {
  expect(resolveExplicitChromeExecutablePath(undefined)).toBeUndefined();
  expect(resolveExplicitChromeExecutablePath("   ")).toBeUndefined();
  expect(resolveExplicitChromeExecutablePath(" /opt/fingerprint-browser/chrome ")).toBe("/opt/fingerprint-browser/chrome");
});

test("accepts repository macOS fingerprint Chromium and stable linux fingerprint paths", () => {
  expect(isFingerprintChromiumExecutable("/Users/demo/repo/.tools/Chromium.app/Contents/MacOS/Chromium")).toBe(true);
  expect(isFingerprintChromiumExecutable("/Users/demo/repo/.tools/fingerprint-browser/linux/chrome")).toBe(true);
  expect(isFingerprintChromiumExecutable("/Users/demo/repo/.tools/fingerprint-browser/linux/144.0.7559.132/chrome")).toBe(true);
  expect(isFingerprintChromiumExecutable("/opt/fingerprint-browser/chrome")).toBe(true);
  expect(isFingerprintChromiumExecutable("/usr/bin/google-chrome-stable")).toBe(false);
  expect(isFingerprintChromiumExecutable("/usr/bin/chromium")).toBe(false);
});

test("requires the provided fingerprint browser and validates executability", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-browser-"));
  const dir = path.join(root, "fingerprint-browser");
  const executablePath = path.join(dir, "chrome");
  await mkdir(dir, { recursive: true });
  await writeFile(executablePath, "#!/bin/sh\nexit 0\n", "utf8");
  await chmod(executablePath, 0o755);

  expect(requireFingerprintChromiumExecutablePath(executablePath)).toBe(executablePath);
  expect(assertUsableFingerprintChromiumExecutablePath(executablePath)).toBe(path.resolve(executablePath));
});

test("rejects system Chrome and missing fingerprint browser executables", () => {
  expect(() => requireFingerprintChromiumExecutablePath("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")).toThrow(
    "Only the provided fingerprint browser is allowed.",
  );
  expect(() => requireFingerprintChromiumExecutablePath("/tmp/fingerprint-chrome")).toThrow("Only the provided fingerprint browser is allowed.");
  expect(() => assertUsableFingerprintChromiumExecutablePath("/opt/fingerprint-browser/chrome")).toThrow(
    "fingerprint browser executable does not exist",
  );
});
