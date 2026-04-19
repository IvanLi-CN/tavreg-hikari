import type { MailboxRecord } from "@/lib/app-types";

export function findMailboxForRequestedAccount(
  mailboxes: MailboxRecord[],
  requestedMailboxAccountId: number | null,
): MailboxRecord | null {
  if (requestedMailboxAccountId == null) return null;
  return mailboxes.find((mailbox) => mailbox.accountId === requestedMailboxAccountId) || null;
}
