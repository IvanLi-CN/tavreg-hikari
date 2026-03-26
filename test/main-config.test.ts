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
  const mainSource = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  const appDbSource = await readFile(path.join(repoRoot, "src/storage/app-db.ts"), "utf8");
  const taskLedgerSource = await readFile(path.join(repoRoot, "src/storage/task-ledger.ts"), "utf8");
  expect(mainSource).not.toContain('from "./storage/app-db.js"');
  expect(mainSource).toContain('await import("./storage/app-db.js")');
  expect(appDbSource).toContain('require("better-sqlite3")');
  expect(appDbSource).not.toContain('require("node:sqlite")');
  expect(taskLedgerSource).toContain('await import("better-sqlite3")');
  expect(taskLedgerSource).not.toContain('await import("node:sqlite")');
});

test("scheduled workers defer successful account finalization to the scheduler exit path", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("if (isScheduledWorker && outcome.status === \"succeeded\") {");
});

test("proof-add handler only provisions mailboxes on the actual add route", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("resolveMicrosoftProofMailboxSession(cfg, proxyUrl, { allowProvision: onAddRoute })");
  expect(source).toContain("if (!onAddRoute && !emailSelector) {");
  expect(source).toContain("if (!emailSelector) {\n    return false;\n  }\n\n  const proofMailbox = proofState.mailbox || (await resolveMicrosoftProofMailboxSession");
});

test("accounts workflow exposes disabled rows and validates proof mailbox saves", async () => {
  const serverSource = await readFile(path.join(repoRoot, "src/server/main.ts"), "utf8");
  const accountsViewSource = await readFile(path.join(repoRoot, "web/src/components/accounts-view.tsx"), "utf8");
  expect(serverSource).toContain("await ensureSavedProofMailbox");
  expect(serverSource).toContain("const unchangedSavedProofMailbox =");
  expect(serverSource).toContain("currentAccount.proofMailboxId === requestedProofMailboxId");
  expect(serverSource).toContain("if (hintedMailboxId && canFallbackToHintedProofMailboxId(error))");
  expect(serverSource).toContain("mailboxId: proofMailboxId,");
  expect(serverSource).toContain('Object.prototype.hasOwnProperty.call(body, "proofMailboxAddress")');
  expect(serverSource).toContain('Object.prototype.hasOwnProperty.call(body, "proofMailboxId")');
  expect(serverSource).toContain('Object.prototype.hasOwnProperty.call(body, "proofMailboxProvider")');
  expect(accountsViewSource).toContain('<SelectItem value="disabled">disabled</SelectItem>');
  expect(accountsViewSource).toContain("disabled · {disabledCount}");
});

test("last-attempt headed failures honor the resolved keep-browser flag without rechecking env", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("const keepOnFailure = Boolean(localErrorMessage) && ctx.keepBrowserOpenOnFailure;");
  expect(source).toContain(
    "const preserveBrowserOnFailure = mode === \"headed\" && Boolean(localErrorMessage) && ctx.keepBrowserOpenOnFailure;",
  );
  expect(source).toContain("(attempt === taskRetryMax && process.stdin.isTTY && process.stdout.isTTY)");
});

test("proof verify only auto-matches non-empty configured mailboxes and fills the masked suffix", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("let target = normalizedAddress ? optionStates.find((option) => normalize(option.value).includes(normalizedAddress)) || null : null;");
  expect(source).toContain("if (!target && normalizedAddress) {");
  expect(source).toContain("emailCompletionValue: missingEmailPart || localPart,");
  expect(source).toContain("proofState.codeRequestedAt ||= proofState.confirmationSubmittedAt;");
  expect(source).toContain("if (inlineCodeSelector) {");
});

test("web admin settings use env only for bootstrap and DB for runtime reads", async () => {
  const source = await readFile(path.join(repoRoot, "src/server/main.ts"), "utf8");
  expect(source).toContain("function buildSettingsCodeDefaults(): AppSettings {");
  expect(source).toContain("function buildInitialSettingsFromEnv(baseDefaults: AppSettings): AppSettings {");
  expect(source).toContain("const settingsDefaults = buildSettingsCodeDefaults();");
  expect(source).toContain("const bootstrapSettings = buildInitialSettingsFromEnv(settingsDefaults);");
  expect(source).toContain("const readSettings = () => db.getSettings(settingsDefaults);");
  expect(source).not.toContain("db.getSettings(getDefaultSettings())");
});
