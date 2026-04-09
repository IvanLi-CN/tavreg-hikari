import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, mkdir, readFile, readlink, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const repoRoot = path.resolve(import.meta.dir, "..");
const tempRoots: string[] = [];

async function makeTempRoot(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  tempRoots.push(dir);
  return dir;
}

async function sha256(filePath: string): Promise<string> {
  const content = await readFile(filePath);
  return createHash("sha256").update(content).digest("hex");
}

function runInstaller(args: string[], env: NodeJS.ProcessEnv) {
  return spawnSync("bash", ["./scripts/install-fingerprint-browser.sh", ...args], {
    cwd: repoRoot,
    env,
    encoding: "utf8",
  });
}

async function createLinuxFixture(rootDir: string, version = "144.0.7559.132"): Promise<{ archivePath: string; sha: string }> {
  const archiveRootName = `ungoogled-chromium-${version}-1-x86_64_linux`;
  const stagingRoot = path.join(rootDir, archiveRootName);
  const chromePath = path.join(stagingRoot, "chrome");
  await mkdir(stagingRoot, { recursive: true });
  await writeFile(chromePath, "#!/usr/bin/env bash\nexit 0\n", "utf8");
  await chmod(chromePath, 0o755);
  const archivePath = path.join(rootDir, `${archiveRootName}.tar.xz`);
  const result = spawnSync("tar", ["-cJf", archivePath, "-C", rootDir, archiveRootName], { encoding: "utf8" });
  expect(result.status).toBe(0);
  return { archivePath, sha: await sha256(archivePath) };
}

async function writeManifest(
  manifestPath: string,
  payload: { platform: "linux" | "macos"; version: string; url: string; sha256?: string },
): Promise<void> {
  const isLinux = payload.platform === "linux";
  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        schemaVersion: 1,
        defaultVersions: {
          linux: "144.0.7559.132",
          macos: "142.0.7444.175",
        },
        releases: {
          linux: isLinux
            ? {
                [payload.version]: {
                  asset: `fixture-${payload.version}.tar.xz`,
                  downloadUrl: payload.url,
                  sha256: payload.sha256,
                  archiveType: "tar.xz",
                  binaryRelativePath: "chrome",
                  arch: "x86_64",
                },
              }
            : {},
          macos: !isLinux
            ? {
                [payload.version]: {
                  asset: `fixture-${payload.version}.dmg`,
                  downloadUrl: payload.url,
                  sha256: payload.sha256,
                  archiveType: "dmg",
                  bundleName: "Chromium.app",
                  binaryRelativePath: "Contents/MacOS/Chromium",
                },
              }
            : {},
        },
      },
      null,
      2,
    ),
    "utf8",
  );
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

test("linux installer installs, verifies, and reuses the pinned release", async () => {
  const rootDir = await makeTempRoot("fingerprint-linux-");
  const { archivePath, sha } = await createLinuxFixture(rootDir);
  const binarySha = await sha256(path.join(rootDir, "ungoogled-chromium-144.0.7559.132-1-x86_64_linux", "chrome"));
  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  await writeManifest(manifestPath, {
    platform: "linux",
    version: "144.0.7559.132",
    url: pathToFileURL(archivePath).href,
    sha256: sha,
  });

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
  };

  const first = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(first.status).toBe(0);
  expect(first.stdout).toContain(path.join(installRoot, "chrome"));

  const stableLink = await readlink(path.join(installRoot, "chrome"));
  expect(stableLink).toBe("144.0.7559.132/chrome");
  const installMarker = JSON.parse(await readFile(path.join(installRoot, ".fingerprint-browser-install.json"), "utf8"));
  expect(installMarker).toMatchObject({
    schemaVersion: 1,
    installer: "install-fingerprint-browser.sh",
    platform: "linux",
    version: "144.0.7559.132",
    binaryRelativePath: "chrome",
    binarySha256: binarySha,
  });

  await rm(cacheDir, { recursive: true, force: true });
  const verify = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir, "--verify-only"], env);
  expect(verify.status).toBe(0);
  expect(verify.stdout).toContain(path.join(installRoot, "chrome"));

  const second = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(second.status).toBe(0);
  expect(`${second.stdout}\n${second.stderr}`).toContain("already installed");
}, 40_000);

test("linux verify-only accepts pinned older installs after the shared symlink moves to a newer version", async () => {
  const rootDir = await makeTempRoot("fingerprint-linux-multi-");
  const olderVersion = "143.0.7000.0";
  const newerVersion = "144.0.7559.132";
  const olderFixture = await createLinuxFixture(rootDir, olderVersion);
  const newerFixture = await createLinuxFixture(rootDir, newerVersion);
  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        schemaVersion: 1,
        defaultVersions: {
          linux: newerVersion,
          macos: "142.0.7444.175",
        },
        releases: {
          linux: {
            [olderVersion]: {
              asset: `fixture-${olderVersion}.tar.xz`,
              downloadUrl: pathToFileURL(olderFixture.archivePath).href,
              sha256: olderFixture.sha,
              archiveType: "tar.xz",
              binaryRelativePath: "chrome",
              arch: "x86_64",
            },
            [newerVersion]: {
              asset: `fixture-${newerVersion}.tar.xz`,
              downloadUrl: pathToFileURL(newerFixture.archivePath).href,
              sha256: newerFixture.sha,
              archiveType: "tar.xz",
              binaryRelativePath: "chrome",
              arch: "x86_64",
            },
          },
          macos: {},
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
  };

  const installOlder = runInstaller(["--platform", "linux", "--version", olderVersion, "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(installOlder.status).toBe(0);

  const installNewer = runInstaller(["--platform", "linux", "--version", newerVersion, "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(installNewer.status).toBe(0);
  expect(await readlink(path.join(installRoot, "chrome"))).toBe(`${newerVersion}/chrome`);

  const verifyOlder = runInstaller(["--platform", "linux", "--version", olderVersion, "--dest", installRoot, "--cache-dir", cacheDir, "--verify-only"], env);
  expect(verifyOlder.status).toBe(0);
  expect(verifyOlder.stdout).toContain(path.join(installRoot, olderVersion, "chrome"));

  const reuseOlder = runInstaller(["--platform", "linux", "--version", olderVersion, "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(reuseOlder.status).toBe(0);
  expect(`${reuseOlder.stdout}\n${reuseOlder.stderr}`).toContain("already installed");
  expect(reuseOlder.stdout).toContain(path.join(installRoot, olderVersion, "chrome"));
}, 40_000);

test("linux installer reinstalls invalid existing releases before reusing them", async () => {
  const rootDir = await makeTempRoot("fingerprint-linux-stale-");
  const { archivePath, sha } = await createLinuxFixture(rootDir);
  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  const versionDir = path.join(installRoot, "144.0.7559.132");
  await writeManifest(manifestPath, {
    platform: "linux",
    version: "144.0.7559.132",
    url: pathToFileURL(archivePath).href,
    sha256: sha,
  });
  await mkdir(versionDir, { recursive: true });
  await writeFile(path.join(versionDir, "chrome"), "#!/usr/bin/env bash\nexit 7\n", "utf8");
  await chmod(path.join(versionDir, "chrome"), 0o755);
  await Bun.$`ln -sfn 144.0.7559.132/chrome ${path.join(installRoot, "chrome")}`.quiet();

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
  };
  const result = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(result.status).toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toContain("reinstalling invalid linux release");
  expect(await readFile(path.join(versionDir, "chrome"), "utf8")).toContain("exit 0");
}, 20_000);

test("linux installer rejects unsupported Linux host architectures", async () => {
  const rootDir = await makeTempRoot("fingerprint-linux-arch-");
  const { archivePath, sha } = await createLinuxFixture(rootDir, "144.0.7559.132");
  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  await writeManifest(manifestPath, {
    platform: "linux",
    version: "144.0.7559.132",
    url: pathToFileURL(archivePath).href,
    sha256: sha,
  });

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
    FINGERPRINT_BROWSER_HOST_OS: "Linux",
    FINGERPRINT_BROWSER_HOST_ARCH: "arm64",
  };
  const result = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(result.status).toBe(1);
  expect(`${result.stdout}\n${result.stderr}`).toContain("supports only x86_64");
});

test("linux installer rejects checksum mismatch and unsupported versions", async () => {
  const rootDir = await makeTempRoot("fingerprint-linux-bad-");
  const { archivePath } = await createLinuxFixture(rootDir, "144.0.7559.132");
  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  await writeManifest(manifestPath, {
    platform: "linux",
    version: "144.0.7559.132",
    url: pathToFileURL(archivePath).href,
    sha256: "deadbeef",
  });

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
  };
  const badChecksum = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(badChecksum.status).toBe(1);
  expect(`${badChecksum.stdout}\n${badChecksum.stderr}`).toContain("checksum mismatch");

  const unsupportedVersion = runInstaller(["--platform", "linux", "--version", "0.0.0", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(unsupportedVersion.status).toBe(1);
  expect(`${unsupportedVersion.stdout}\n${unsupportedVersion.stderr}`).toContain("Unsupported version for linux");
});

test("linux installer fails closed when manifest digest is missing", async () => {
  const rootDir = await makeTempRoot("fingerprint-linux-missing-sha-");
  const { archivePath } = await createLinuxFixture(rootDir, "144.0.7559.132");
  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  await writeManifest(manifestPath, {
    platform: "linux",
    version: "144.0.7559.132",
    url: pathToFileURL(archivePath).href,
  });

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
  };
  const result = runInstaller(["--platform", "linux", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(result.status).toBe(1);
  expect(`${result.stdout}\n${result.stderr}`).toContain("missing sha256");
});

test.if(process.platform === "darwin")("macOS installer installs and verifies the pinned bundle", async () => {
  const rootDir = await makeTempRoot("fingerprint-macos-");
  const dmgStaging = path.join(rootDir, "dmg-root");
  const bundlePath = path.join(dmgStaging, "Chromium.app");
  const executablePath = path.join(bundlePath, "Contents/MacOS/Chromium");
  await mkdir(path.dirname(executablePath), { recursive: true });
  await writeFile(
    path.join(bundlePath, "Contents/Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Chromium</string>
  <key>CFBundleShortVersionString</key>
  <string>142.0.7444.175</string>
</dict>
</plist>
`,
    "utf8",
  );
  await writeFile(executablePath, "#!/usr/bin/env bash\nexit 0\n", "utf8");
  await chmod(executablePath, 0o755);

  const dmgPath = path.join(rootDir, "fixture.dmg");
  const createResult = spawnSync(
    "hdiutil",
    ["create", "-volname", "Chromium", "-srcfolder", dmgStaging, "-format", "UDZO", dmgPath],
    { encoding: "utf8" },
  );
  expect(createResult.status).toBe(0);

  const manifestPath = path.join(rootDir, "manifest.json");
  const installRoot = path.join(rootDir, "install");
  const cacheDir = path.join(rootDir, "cache");
  await writeManifest(manifestPath, {
    platform: "macos",
    version: "142.0.7444.175",
    url: pathToFileURL(dmgPath).href,
    sha256: await sha256(dmgPath),
  });

  const env = {
    ...process.env,
    FINGERPRINT_BROWSER_MANIFEST_PATH: manifestPath,
  };

  const install = runInstaller(["--platform", "macos", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(install.status).toBe(0);
  expect(install.stdout).toContain(path.join(installRoot, "Chromium.app/Contents/MacOS/Chromium"));

  const verify = runInstaller(["--platform", "macos", "--dest", installRoot, "--cache-dir", cacheDir, "--verify-only"], env);
  expect(verify.status).toBe(0);

  await writeFile(path.join(installRoot, "Chromium.app/Contents/MacOS/Chromium"), "#!/usr/bin/env bash\nexit 9\n", "utf8");
  await chmod(path.join(installRoot, "Chromium.app/Contents/MacOS/Chromium"), 0o755);

  const tamperedVerify = runInstaller(["--platform", "macos", "--dest", installRoot, "--cache-dir", cacheDir, "--verify-only"], env);
  expect(tamperedVerify.status).toBe(1);
  expect(`${tamperedVerify.stdout}\n${tamperedVerify.stderr}`).toContain("macOS fingerprint browser executable drifted");

  const reinstall = runInstaller(["--platform", "macos", "--dest", installRoot, "--cache-dir", cacheDir], env);
  expect(reinstall.status).toBe(0);
  expect(await readFile(path.join(installRoot, "Chromium.app/Contents/MacOS/Chromium"), "utf8")).toContain("exit 0");
}, 40_000);
