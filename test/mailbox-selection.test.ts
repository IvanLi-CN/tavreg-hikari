import { expect, test } from "bun:test";
import type { MailboxRecord } from "../web/src/lib/app-types.ts";
import { findMailboxForRequestedAccount } from "../web/src/lib/mailbox-selection.ts";

const mailbox = (overrides: Partial<MailboxRecord>): MailboxRecord => ({
  id: 1,
  accountId: 11,
  microsoftEmail: "alpha@example.test",
  groupName: null,
  proofMailboxAddress: null,
  status: "available",
  syncEnabled: true,
  unreadCount: 0,
  graphUserId: null,
  graphUserPrincipalName: null,
  graphDisplayName: null,
  authority: "https://login.microsoftonline.com/common",
  oauthStartedAt: null,
  oauthConnectedAt: null,
  deltaLink: null,
  lastSyncedAt: null,
  lastErrorCode: null,
  lastErrorMessage: null,
  createdAt: "2026-04-19T00:00:00.000Z",
  updatedAt: "2026-04-19T00:00:00.000Z",
  isAuthorized: false,
  latestVerificationCode: null,
  ...overrides,
});

test("findMailboxForRequestedAccount returns the matching mailbox for the requested account", () => {
  const alpha = mailbox({ id: 1, accountId: 11, microsoftEmail: "alpha@example.test" });
  const beta = mailbox({ id: 2, accountId: 22, microsoftEmail: "beta@example.test" });

  expect(findMailboxForRequestedAccount([alpha, beta], 22)).toEqual(beta);
});

test("findMailboxForRequestedAccount keeps the drawer empty when the requested account has no mailbox", () => {
  const alpha = mailbox({ id: 1, accountId: 11, microsoftEmail: "alpha@example.test" });
  const beta = mailbox({ id: 2, accountId: 22, microsoftEmail: "beta@example.test" });

  expect(findMailboxForRequestedAccount([alpha, beta], 33)).toBeNull();
  expect(findMailboxForRequestedAccount([alpha, beta], null)).toBeNull();
});
