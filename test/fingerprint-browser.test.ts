import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  assertUsableFingerprintChromiumExecutablePath,
  isFingerprintChromiumExecutable,
  resolveExplicitChromeExecutablePath,
  requireFingerprintChromiumExecutablePath,
} from "../src/fingerprint-browser.ts";

function sha256Text(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

async function writeLinuxInstallMarker(
  markerRoot: string,
  binaryRelativePath: string,
  binarySha256: string,
  version = "144.0.7559.132",
) {
  await mkdir(markerRoot, { recursive: true });
  await writeFile(
    path.join(markerRoot, ".fingerprint-browser-install.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        installer: "install-fingerprint-browser.sh",
        platform: "linux",
        version,
        binaryRelativePath,
        binarySha256,
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );
}

async function writeMacInstallMarker(
  markerRoot: string,
  binaryRelativePath: string,
  binarySha256: string,
  version = "142.0.7444.175",
) {
  await mkdir(markerRoot, { recursive: true });
  await writeFile(
    path.join(markerRoot, ".fingerprint-browser-install.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        installer: "install-fingerprint-browser.sh",
        platform: "macos",
        version,
        binaryRelativePath,
        binarySha256,
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );
}

async function writeExecutable(executablePath: string, content = "#!/bin/sh\nexit 0\n") {
  await mkdir(path.dirname(executablePath), { recursive: true });
  await writeFile(executablePath, content, "utf8");
  await chmod(executablePath, 0o755);
  return sha256Text(content);
}

test("resolves only explicit fingerprint browser paths", () => {
  expect(resolveExplicitChromeExecutablePath(undefined, "/tmp/no-fingerprint-browser")).toBeUndefined();
  expect(resolveExplicitChromeExecutablePath("   ", "/tmp/no-fingerprint-browser")).toBeUndefined();
  expect(resolveExplicitChromeExecutablePath(" /opt/fingerprint-browser/chrome ")).toBe("/opt/fingerprint-browser/chrome");
});

test("detects the default repo-local fingerprint browser install when env is unset", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-default-root-"));
  const installRoot = path.join(root, ".tools");
  const binaryRelativePath = "Chromium.app/Contents/MacOS/Chromium";
  const executablePath = path.join(installRoot, binaryRelativePath);
  const binarySha256 = await writeExecutable(executablePath);
  await writeMacInstallMarker(installRoot, binaryRelativePath, binarySha256);

  expect(resolveExplicitChromeExecutablePath(undefined, path.join(root, "nested", "dir"))).toBe(executablePath);
});

test("accepts official fingerprint browser installs only when installer markers match", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-official-"));

  const linuxInstallRoot = path.join(root, ".tools", "fingerprint-browser", "linux");
  const linuxVersionDir = path.join(linuxInstallRoot, "144.0.7559.132");
  const linuxBinaryContent = "#!/bin/sh\nexit 0\n";
  const linuxBinarySha256 = await writeExecutable(path.join(linuxVersionDir, "chrome"), linuxBinaryContent);
  await symlink("144.0.7559.132/chrome", path.join(linuxInstallRoot, "chrome"));
  await writeLinuxInstallMarker(linuxInstallRoot, "chrome", linuxBinarySha256);
  await writeLinuxInstallMarker(linuxVersionDir, "chrome", linuxBinarySha256);

  const macInstallRoot = path.join(root, ".tools");
  const macBinaryRelativePath = "Chromium.app/Contents/MacOS/Chromium";
  const macBinarySha256 = await writeExecutable(path.join(macInstallRoot, macBinaryRelativePath));
  await writeMacInstallMarker(macInstallRoot, macBinaryRelativePath, macBinarySha256);

  expect(isFingerprintChromiumExecutable(path.join(linuxInstallRoot, "chrome"))).toBe(true);
  expect(isFingerprintChromiumExecutable(path.join(linuxVersionDir, "chrome"))).toBe(true);
  expect(isFingerprintChromiumExecutable(path.join(macInstallRoot, macBinaryRelativePath))).toBe(true);

  expect(isFingerprintChromiumExecutable("/Users/demo/repo/.tools/Chromium.app/Contents/MacOS/Chromium")).toBe(false);
  expect(isFingerprintChromiumExecutable("/Users/demo/repo/.tools/fingerprint-browser/linux/chrome")).toBe(false);
});

test("accepts custom linux install roots emitted by the official installer", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-custom-root-"));
  const installRoot = path.join(root, "custom-browser-root");
  const binaryContent = "#!/bin/sh\nexit 0\n";
  const binarySha256 = await writeExecutable(path.join(installRoot, "144.0.7559.132", "chrome"), binaryContent);
  await symlink("144.0.7559.132/chrome", path.join(installRoot, "chrome"));
  await writeLinuxInstallMarker(installRoot, "chrome", binarySha256);
  await writeLinuxInstallMarker(path.join(installRoot, "144.0.7559.132"), "chrome", binarySha256);

  expect(isFingerprintChromiumExecutable(path.join(installRoot, "chrome"))).toBe(true);
  expect(isFingerprintChromiumExecutable(path.join(installRoot, "144.0.7559.132", "chrome"))).toBe(true);
});

test("accepts opt-style linux install roots emitted by the official installer", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-opt-root-"));
  const installRoot = path.join(root, "opt", "fingerprint-browser");
  const binaryContent = "#!/bin/sh\nexit 0\n";
  const binarySha256 = await writeExecutable(path.join(installRoot, "144.0.7559.132", "chrome"), binaryContent);
  await symlink("144.0.7559.132/chrome", path.join(installRoot, "chrome"));
  await writeLinuxInstallMarker(installRoot, "chrome", binarySha256);
  await writeLinuxInstallMarker(path.join(installRoot, "144.0.7559.132"), "chrome", binarySha256);

  expect(isFingerprintChromiumExecutable(path.join(installRoot, "chrome"))).toBe(true);
  expect(assertUsableFingerprintChromiumExecutablePath(path.join(installRoot, "chrome"))).toBe(
    path.resolve(path.join(installRoot, "chrome")),
  );
});

test("rejects unrelated chrome wrappers under an installer root", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-wrapper-root-"));
  const installRoot = path.join(root, "custom-browser-root");
  const binarySha256 = sha256Text("#!/bin/sh\nexit 0\n");
  await writeLinuxInstallMarker(installRoot, "chrome", binarySha256);
  await writeLinuxInstallMarker(path.join(installRoot, "144.0.7559.132"), "chrome", binarySha256);

  expect(isFingerprintChromiumExecutable(path.join(installRoot, "helpers", "chrome"))).toBe(false);
  expect(isFingerprintChromiumExecutable(path.join(installRoot, "144.0.7559.132", "helpers", "chrome"))).toBe(false);
});

test("requires the provided fingerprint browser and validates executability", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-browser-"));
  const dir = path.join(root, "custom-browser-root");
  const executablePath = path.join(dir, "chrome");
  const binarySha256 = await writeExecutable(executablePath);
  await writeLinuxInstallMarker(dir, "chrome", binarySha256);

  expect(requireFingerprintChromiumExecutablePath(executablePath)).toBe(executablePath);
  expect(assertUsableFingerprintChromiumExecutablePath(executablePath)).toBe(path.resolve(executablePath));
});

test("rejects linux installs when the executable digest drifts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-browser-drift-"));
  const dir = path.join(root, "custom-browser-root");
  const executablePath = path.join(dir, "chrome");
  const binarySha256 = sha256Text("#!/bin/sh\nexit 0\n");
  await writeExecutable(executablePath, "#!/bin/sh\nexit 99\n");
  await writeLinuxInstallMarker(dir, "chrome", binarySha256);

  expect(isFingerprintChromiumExecutable(executablePath)).toBe(false);
  expect(() => requireFingerprintChromiumExecutablePath(executablePath)).toThrow("Only the provided fingerprint browser is allowed.");
});

test("rejects macOS installs when the executable digest drifts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "fingerprint-browser-macos-drift-"));
  const installRoot = path.join(root, ".tools");
  const binaryRelativePath = "Chromium.app/Contents/MacOS/Chromium";
  const executablePath = path.join(installRoot, binaryRelativePath);
  const binarySha256 = sha256Text("#!/bin/sh\nexit 0\n");
  await writeExecutable(executablePath, "#!/bin/sh\nexit 99\n");
  await writeMacInstallMarker(installRoot, binaryRelativePath, binarySha256);

  expect(isFingerprintChromiumExecutable(executablePath)).toBe(false);
  expect(() => requireFingerprintChromiumExecutablePath(executablePath)).toThrow("Only the provided fingerprint browser is allowed.");
});

test("rejects system Chrome and untrusted fingerprint browser paths", () => {
  expect(() => requireFingerprintChromiumExecutablePath("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")).toThrow(
    "Only the provided fingerprint browser is allowed.",
  );
  expect(() => requireFingerprintChromiumExecutablePath("/tmp/fingerprint-chrome")).toThrow("Only the provided fingerprint browser is allowed.");
  expect(() => assertUsableFingerprintChromiumExecutablePath("/opt/fingerprint-browser/chrome")).toThrow(
    "Only the provided fingerprint browser is allowed.",
  );
});
