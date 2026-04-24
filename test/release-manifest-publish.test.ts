import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dir, "..");
const verifyScript = path.join(repoRoot, ".github/scripts/verify_release_manifest.py");

function runVerify(rawPayload: unknown, extraArgs: string[] = []) {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "verify-release-manifest-"));
  const rawFile = path.join(tempDir, "manifest.json");
  writeFileSync(rawFile, JSON.stringify(rawPayload), "utf8");
  const result = spawnSync(
    "python3",
    [verifyScript, "--ref", "ghcr.io/ivanli-cn/tavreg-hikari:latest", "--raw-file", rawFile, ...extraArgs],
    {
      cwd: repoRoot,
      encoding: "utf8",
    },
  );
  rmSync(tempDir, { recursive: true, force: true });
  return result;
}

test("release manifest verifier accepts a single-platform image index with linux/amd64", () => {
  const result = runVerify({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: "sha256:111",
        size: 1234,
        platform: { os: "linux", architecture: "amd64" },
      },
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: "sha256:222",
        size: 456,
        platform: { os: "unknown", architecture: "unknown" },
      },
    ],
  });

  expect(result.status).toBe(0);
  expect(result.stdout).toContain("[verify-release-manifest] ok");
  expect(result.stdout).toContain("linux/amd64");
});

test("release manifest verifier rejects top-level single manifest media types", () => {
  const result = runVerify({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: "sha256:333",
      size: 321,
    },
    layers: [],
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("expected top-level mediaType to be an image index / manifest list");
});

test("release manifest verifier rejects indexes that do not expose linux/amd64", () => {
  const result = runVerify({
    schemaVersion: 2,
    mediaType: "application/vnd.docker.distribution.manifest.list.v2+json",
    manifests: [
      {
        mediaType: "application/vnd.docker.distribution.manifest.v2+json",
        digest: "sha256:444",
        size: 999,
        platform: { os: "linux", architecture: "arm64" },
      },
    ],
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("missing expected platform linux/amd64");
  expect(result.stderr).toContain("available=linux/arm64");
});
