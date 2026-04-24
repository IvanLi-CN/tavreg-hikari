import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dir, "..");

test("chatgpt page no longer references the removed draft preload api", async () => {
  const appSource = await readFile(path.join(repoRoot, "web/src/App.tsx"), "utf8");
  expect(appSource).not.toContain("/api/chatgpt/draft");
  expect(appSource).not.toContain("shouldLoadChatGptDraft");
  expect(appSource).not.toContain("chatGptDraftBusy");
});

test("chatgpt page still uses implemented job and credential endpoints", async () => {
  const appSource = await readFile(path.join(repoRoot, "web/src/App.tsx"), "utf8");
  expect(appSource).toContain("/api/jobs/current?site=");
  expect(appSource).toContain("/api/chatgpt/credentials?");
  expect(appSource).toContain("/api/chatgpt/credentials/${credentialId}?includeSecrets=1");
  expect(appSource).toContain('/api/chatgpt/credentials/export');
});

test("parallel helper no longer depends on the removed chatgpt draft api", async () => {
  const scriptSource = await readFile(path.join(repoRoot, "scripts/chatgpt_parallel_runner.py"), "utf8");
  expect(scriptSource).not.toContain('/api/chatgpt/draft');
  expect(scriptSource).toContain('api_post("/api/chatgpt/attempt-draft")');
  expect(scriptSource).toContain('Path(__file__).resolve().parents[1]');
});

test("server exposes the runner-only chatgpt attempt draft route", async () => {
  const serverSource = await readFile(path.join(repoRoot, "src/server/main.ts"), "utf8");
  expect(serverSource).toContain('pathname === "/api/chatgpt/attempt-draft" && req.method === "POST"');
  expect(serverSource).toContain('pathname === "/api/chatgpt/credentials/export" && req.method === "POST"');
  expect(serverSource).toContain('httpJson: serverHttpJson');
  expect(serverSource).toContain('rootDomain: DEFAULT_CFMAIL_ROOT_DOMAIN');
});
