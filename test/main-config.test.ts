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
    timeout: 15_000,
  });

  expect(result.status).toBe(1);
  expect(`${result.stdout}\n${result.stderr}`).toContain("Invalid env MAIL_PROVIDER: moemail");
}, 20_000);

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

test("macOS headed chrome skips native CDP automation", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain('if (process.platform === "darwin" && mode === "headed") return false;');
});

test("microsoft provider login bypasses identifier challenge gating", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  const start = source.indexOf("async function clickMicrosoftProviderEntry");
  const end = source.indexOf("async function handleMicrosoftAccountPicker");
  const segment = source.slice(start, end);
  expect(segment).toContain("bypassing identifier challenge and submitting provider directly");
  expect(segment).not.toContain("ensureManagedChallengeTokenBeforeSubmit");
});

test("provider login prefers real button clicks before forced form submission", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  const start = source.indexOf("async function submitAuthProviderForm");
  const end = source.indexOf("async function clickMicrosoftProviderEntry");
  const segment = source.slice(start, end);
  expect(segment).toContain('const authProviderSurfacePattern = /auth\\.tavily\\.com\\/u\\/(?:login|signup)\\/identifier/i;');
  expect(segment).toContain("const clickedDirectly = await clickMatchingActionDirectly");
  expect(segment.indexOf("const clickedDirectly = await clickMatchingActionDirectly")).toBeLessThan(
    segment.indexOf('const clicked = await clickMatchingAction'),
  );
  expect(segment.indexOf('const clicked = await clickMatchingAction')).toBeLessThan(
    segment.indexOf("const providerSubmitted = await page.evaluate"),
  );
  expect(segment).toContain("const deadline = Date.now() + 8_000;");
  expect(segment).not.toContain('if (stillShowingProvider && /auth\\.tavily\\.com\\/u\\/login\\/identifier/i.test(currentUrl)) {\n        return false;');
  expect(segment).toContain('log(`${logLabel} provider form submit emitted no signal`)');
  expect(segment).not.toContain("return providerSubmitted;");
});

test("microsoft provider flow treats signup and login identifier as valid provider surfaces", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain('/\\/u\\/(?:login|signup)\\/identifier/i');
  expect(source).toContain("const authProviderSurfacePattern = /auth\\.tavily\\.com\\/u\\/(?:login|signup)\\/identifier/i;");
});

test("microsoft provider flow keeps the login surface and only waits on signup challenge fallbacks", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("async function waitForPassiveMicrosoftProviderReadiness");
  expect(source).toContain('const providerReady = await waitForPassiveMicrosoftProviderReadiness(');
  expect(source).toContain('/\\/u\\/signup\\/identifier/i.test(currentUrl) ? "signup" : "login"');
  expect(source).toContain("const hasConcreteChallengeSurface = (snapshot: AuthChallengeSnapshot | null | undefined): boolean =>");
  expect(source).toContain("if (!hasConcreteChallengeSurface(latest)) {");
  expect(source).toContain('log(`${formKind} provider submit: waiting for passive managed challenge readiness`)');
  expect(source).toContain("if (isManagedChallengeStableForSubmit(latest)) {");
  expect(source).not.toContain('log("login flow: switched to Tavily signup surface before Microsoft provider submit");');
});

test("microsoft account picker only acts on real picker surfaces and ignores recovery or proof shells", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  const start = source.indexOf("async function handleMicrosoftAccountPicker");
  const end = source.indexOf("async function isMicrosoftProofConfirmationSurface");
  const segment = source.slice(start, end);
  expect(segment).toContain('/account\\.live\\.com\\/username\\/recover/i.test(currentUrl)');
  expect(segment).toContain('/account\\.live\\.com\\/identity\\/confirm/i.test(currentUrl)');
  expect(segment).toContain('/account\\.live\\.com\\/proofs\\//i.test(currentUrl)');
  expect(segment).toContain('/login\\.live\\.com\\/logout\\.srf/i.test(currentUrl)');
  expect(segment).toContain("if (await hasVisibleElement(page, 'input[type=\"email\"], input[autocomplete=\"username\"], input[name=\"loginfmt\"], input[name=\"fmt\"]')) {");
  expect(segment).toContain("if (!looksLikeAccountPicker) {\n    return false;\n  }");
  expect(segment.indexOf('log("login flow: switched Microsoft picker to another account");')).toBeLessThan(
    segment.indexOf('log("login flow: selected remembered Microsoft account");'),
  );
  expect(segment).toContain("const looksLikeAccountPicker = await pageContainsAnyText(page, [");
});

test("microsoft login waits out the post-email password window before touching the account picker again", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  const start = source.indexOf("if (await handleMicrosoftUsePasswordShortcut");
  const end = source.indexOf("if (await handleMicrosoftProofAddPrompt");
  const segment = source.slice(start, end);
  expect(segment.indexOf("if (await handleMicrosoftPasswordPrompt(page, password, passwordState))")).toBeLessThan(
    segment.indexOf("if (\n        proofState.postEmailPasswordPriorityUntil"),
  );
  expect(segment.indexOf("if (\n        proofState.postEmailPasswordPriorityUntil")).toBeLessThan(
    segment.indexOf("if (await handleMicrosoftAccountPicker(page, email)) continue;"),
  );
});

test("safeGoto accepts timeout recoveries only after the target document is already interactive", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  const start = source.indexOf("async function safeGoto");
  const end = source.indexOf("async function fillMicrosoftProofOtpInputs");
  const segment = source.slice(start, end);
  expect(segment).toContain('const recoveredAfterTimeout = /Timeout \\d+ms exceeded/i.test(message)');
  expect(segment).toContain('return current === target && readyState !== "loading" && bodyLength > 0;');
  expect(segment).toContain('log(`safeGoto recovered after timeout (${url}) via ready target document`)');
  expect(segment).toContain("const browserErrorCode = await collectBrowserNavigationErrorCode(page);");
});

test("login entry only treats /home as resolved when authenticated signals are present", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("async function hasAuthenticatedHomeSignal(page: any): Promise<boolean> {");
  const start = source.indexOf("async function openAuthFlowEntry");
  const end = source.indexOf("async function waitHomeStable");
  const segment = source.slice(start, end);
  expect(segment).toContain(': /\\/u\\/login\\/identifier|\\/u\\/login\\/password/i;');
  expect(segment).not.toContain('/\\/u\\/login\\/identifier|\\/u\\/login\\/password|app\\.tavily\\.com\\/home/i;');
  expect(segment).toContain("(await hasAuthenticatedHomeSignal(page))");
});

test("microsoft login returns Tavily social-signup continuations instead of re-submitting the provider", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("let visitedMicrosoftAccountSurface = false;");
  expect(source).toContain("visitedMicrosoftAccountSurface = true;");
  expect(source).toContain("const socialSignupContinuationPattern = /auth\\.tavily\\.com\\/u\\/(?:signup\\/identifier|signup\\/password|email-identifier\\/challenge)/i;");
  expect(source).toContain("if (visitedMicrosoftAccountSurface && socialSignupContinuationPattern.test(currentUrl)) {");
  expect(source).toContain('log(`login flow: returned to Tavily social signup continuation ${currentUrl}`);');
});

test("social signup continuation can resume from existing signup surfaces without forcing a new mailbox", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("mailbox: MailboxSession | null,");
  expect(source).toContain("const existingSignupSurface = /\\/u\\/signup\\/identifier|\\/u\\/signup\\/password|\\/u\\/email-identifier\\/challenge/i.test(currentSurface);");
  expect(source).toContain('log(`signup flow: continuing existing auth surface ${currentSurface}`);');
  expect(source).toContain('throw new Error(`social_signup_email_challenge_unexpected:${page.url()}`);');
  expect(source).toContain('log(`login flow: continuing Tavily social signup after Microsoft return ${page.url()}`);');
});

test("action scoring only boosts signup links when the caller is actually looking for signup", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("const wantsSignupAction = compiledPatterns.some((item) => /sign\\s*up|signup|create\\s*account|register|get\\s*started/i.test(item.source));");
  expect(source).toContain("if (wantsSignupAction && /signup|register/i.test(candidate.href)) score = Math.max(score, 95);");
  expect(source).toContain("if (wantsSignupAction && /sign up|create account|register|start for free|get started/i.test(candidate.text)) {");
});

test("provider connection submits are no longer patched with login identifier fields", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("const isProviderConnectionSubmit =");
  expect(source).toContain('/\\/u\\/(?:signup|login)\\/identifier/i.test(requestUrl) &&');
  expect(source).toContain('typeof payload[\"connection\"] === \"string\"');
  expect(source).toContain("if (isProviderConnectionSubmit) {\n          await route.continue();\n          return;\n        }");
  expect(source).toContain("if (!isProviderConnectionSubmit && (!payload[\"email\"] || !String(payload[\"email\"]).trim()) && fallbackEmail) {");
  expect(source).toContain("if (!isProviderConnectionSubmit && (!payload[\"captcha\"] || !String(payload[\"captcha\"]).trim()) && challengeToken) {");
});

test("auth submit flow hydrates challenge tokens from turnstile runtime and patches both captcha fields", async () => {
  const source = await readFile(path.join(repoRoot, "src/main.ts"), "utf8");
  expect(source).toContain("__kohaReadAuthChallengeToken?: () => string;");
  expect(source).toContain('globalState.__kohaReadAuthChallengeToken = () => readTurnstileRuntimeToken();');
  expect(source).toContain('ensureTokenField("cf-turnstile-response", token);');
  expect(source).toContain('!isProviderConnectionSubmit &&');
  expect(source).toContain('(!payload["cf-turnstile-response"] || !String(payload["cf-turnstile-response"]).trim())');
});
