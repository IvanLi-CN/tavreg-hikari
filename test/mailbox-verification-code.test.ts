import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { matchMailboxVerificationCode } from "../src/mailbox-verification-code.ts";
import { pickLatestMailboxVerificationCode } from "../src/server/microsoft-mailbox-verification.ts";
import { AppDatabase } from "../src/storage/app-db.ts";

const tempDirs: string[] = [];

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-mailbox-code-"));
  tempDirs.push(tempDir);
  const appDb = await AppDatabase.open(path.join(tempDir, "app.sqlite"));
  return { appDb };
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const target = tempDirs.pop();
    if (!target) continue;
    await rm(target, { recursive: true, force: true });
  }
});

test("matchMailboxVerificationCode prefers Microsoft proof code signals", () => {
  const match = matchMailboxVerificationCode({
    subject: "Microsoft account security code",
    fromAddress: "account-security-noreply@account.microsoft.com",
    preview: "Use 824631 as your Microsoft account verification code.",
  });

  expect(match).toEqual({
    code: "824631",
    provider: "microsoft",
    evidence: "microsoft_context",
  });
});

test("matchMailboxVerificationCode extracts ChatGPT codes from OpenAI mail", () => {
  const match = matchMailboxVerificationCode({
    subject: "Your ChatGPT code is 481311",
    fromAddress: "noreply@tm.openai.com",
    body: "Enter this temporary verification code to continue: 481311",
  });

  expect(match).toEqual({
    code: "481311",
    provider: "chatgpt",
    evidence: "chatgpt_explicit",
  });
});

test("matchMailboxVerificationCode normalizes Grok hyphenated codes", () => {
  const match = matchMailboxVerificationCode({
    subject: "Your Grok verification code",
    fromAddress: "accounts@x.ai",
    preview: "Use ABC-123 to finish signing in to Grok.",
  });

  expect(match).toEqual({
    code: "ABC123",
    provider: "grok",
    evidence: "grok_hyphenated",
  });
});

test("pickLatestMailboxVerificationCode returns the newest recognizable message", () => {
  const match = pickLatestMailboxVerificationCode([
    {
      subject: "Welcome to Outlook",
      fromAddress: "welcome@example.test",
      bodyPreview: "Thanks for joining.",
      receivedAt: "2026-04-22T10:00:00.000Z",
    },
    {
      subject: "Your ChatGPT code is 111222",
      fromAddress: "noreply@tm.openai.com",
      bodyPreview: "Enter 111222 to continue.",
      receivedAt: "2026-04-22T11:00:00.000Z",
    },
    {
      subject: "Microsoft account security code",
      fromAddress: "account-security-noreply@account.microsoft.com",
      bodyPreview: "Use 333444 as your Microsoft account verification code.",
      receivedAt: "2026-04-22T12:00:00.000Z",
    },
  ]);

  expect(match).toEqual({
    code: "333444",
    provider: "microsoft",
    evidence: "microsoft_context",
  });
});

test("pickLatestMailboxVerificationCode can filter providers for post-SSO mailbox waits", () => {
  const match = pickLatestMailboxVerificationCode(
    [
      {
        subject: "Microsoft account security code",
        fromAddress: "account-security-noreply@account.microsoft.com",
        bodyPreview: "Use 333444 as your Microsoft account verification code.",
        receivedAt: "2026-04-22T12:00:00.000Z",
      },
      {
        subject: "Your Grok verification code",
        fromAddress: "accounts@x.ai",
        bodyPreview: "Use ABC-123 to finish signing in to Grok.",
        receivedAt: "2026-04-22T12:00:05.000Z",
      },
    ],
    { providers: ["grok", "generic"] },
  );

  expect(match).toEqual({
    code: "ABC123",
    provider: "grok",
    evidence: "grok_hyphenated",
  });
});

test("listMailboxMessagesForVerification can still surface the latest code beyond inbox paging cap", async () => {
  const { appDb } = await createTempDb();
  const imported = appDb.importAccounts([{ email: "alpha@example.test", password: "pass-1" }]);
  const accountId = imported.affectedIds[0];
  if (!accountId) throw new Error("missing account id");
  const mailbox = appDb.ensureMailboxForAccount(accountId);

  const messages = [
    {
      graphMessageId: "otp-hidden",
      subject: "Your ChatGPT code is 481311",
      fromAddress: "noreply@tm.openai.com",
      bodyPreview: "Enter this temporary verification code to continue: 481311",
      receivedAt: "2026-04-22T10:00:00.000Z",
    },
    ...Array.from({ length: 130 }, (_, index) => ({
      graphMessageId: `noise-${index + 1}`,
      subject: `Newsletter ${index + 1}`,
      fromAddress: "updates@example.test",
      bodyPreview: "No verification code here.",
      receivedAt: new Date(Date.UTC(2026, 3, 22, 10, 1 + index, 0)).toISOString(),
    })),
  ];
  appDb.upsertMailboxMessages(mailbox.id, messages, { keepLatest: 500 });

  const pagedMatch = pickLatestMailboxVerificationCode(
    appDb.listMailboxMessages(mailbox.id, { limit: 500 }).rows.map((message) => ({
      subject: message.subject,
      fromName: message.fromName,
      fromAddress: message.fromAddress,
      bodyPreview: message.bodyPreview,
      bodyContent: message.bodyContent,
      receivedAt: message.receivedAt,
    })),
  );
  expect(pagedMatch).toBeNull();

  const verificationMatch = pickLatestMailboxVerificationCode(
    appDb.listMailboxMessagesForVerification(mailbox.id, { limit: 500 }).map((message) => ({
      subject: message.subject,
      fromName: message.fromName,
      fromAddress: message.fromAddress,
      bodyPreview: message.bodyPreview,
      bodyContent: message.bodyContent,
      receivedAt: message.receivedAt,
    })),
  );
  expect(verificationMatch).toEqual({
    code: "481311",
    provider: "chatgpt",
    evidence: "chatgpt_explicit",
  });

  const batchedVerificationMatch = pickLatestMailboxVerificationCode(
    (appDb.listMailboxMessagesForVerificationBatch([mailbox.id], { limitPerMailbox: 500 }).get(mailbox.id) || []).map((message) => ({
      subject: message.subject,
      fromName: message.fromName,
      fromAddress: message.fromAddress,
      bodyPreview: message.bodyPreview,
      bodyContent: message.bodyContent,
      receivedAt: message.receivedAt,
    })),
  );
  expect(batchedVerificationMatch).toEqual({
    code: "481311",
    provider: "chatgpt",
    evidence: "chatgpt_explicit",
  });
});
