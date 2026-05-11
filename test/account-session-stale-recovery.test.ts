import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { AppDatabase } from "../src/storage/app-db.js";

const tempDirs: string[] = [];

async function createTempDb() {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "tavreg-hikari-stale-bootstrap-"));
  tempDirs.push(tempDir);
  const dbPath = path.join(tempDir, "app.sqlite");
  const appDb = await AppDatabase.open(dbPath);
  return { appDb, dbPath };
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const tempDir = tempDirs.pop();
    if (!tempDir) continue;
    await rm(tempDir, { recursive: true, force: true });
  }
});

describe("stale account session bootstrap recovery", () => {
  test("marks stale bootstrapping sessions and preparing mailboxes as failed", async () => {
    const { appDb } = await createTempDb();
    const imported = appDb.importAccounts([{ email: "stale@example.test", password: "pass-123" }]);
    const accountId = imported.affectedIds[0]!;
    const mailbox = appDb.ensureMailboxForAccount(accountId);
    appDb.markBrowserSessionBootstrapping(accountId, {
      browserEngine: "chrome",
      proxyNode: "Tokyo-01",
    });

    const rawDb = (appDb as unknown as {
      db: {
        query: (sql: string) => {
          run: (...params: unknown[]) => void;
        };
      };
    }).db;
    rawDb.query("UPDATE account_browser_sessions SET updated_at = '2026-01-01T00:00:00.000Z' WHERE account_id = ?").run(accountId);
    rawDb.query("UPDATE microsoft_mailboxes SET updated_at = '2026-01-01T00:00:00.000Z' WHERE id = ?").run(mailbox.id);

    const changed = appDb.markStaleBrowserSessionBootstrapsAsFailed(60_000, {
      errorCode: "session_bootstrap_stale",
      errorMessage: "账号 bootstrap worker 已超过超时窗口但状态未收敛",
    });

    expect(changed).toBe(1);
    const account = appDb.getAccount(accountId);
    const session = appDb.getBrowserSessionByAccountId(accountId);
    const refreshedMailbox = appDb.getMailbox(mailbox.id);
    expect(account?.lastResultStatus).toBe("failed");
    expect(account?.lastErrorCode).toBe("session_bootstrap_stale");
    expect(session?.status).toBe("failed");
    expect(session?.lastErrorCode).toBe("session_bootstrap_stale");
    expect(refreshedMailbox?.status).toBe("failed");
    expect(refreshedMailbox?.lastErrorCode).toBe("session_bootstrap_stale");
  });
});
