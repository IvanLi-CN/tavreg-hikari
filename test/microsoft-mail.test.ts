import { describe, expect, test } from "bun:test";

import {
  MicrosoftGraphError,
  getMailboxErrorCode,
  getMailboxErrorMessage,
  toMailboxFailureStatus,
} from "../src/server/microsoft-mail";

describe("Microsoft mail failure helpers", () => {
  test("maps locked opaque errors to locked mailbox state", () => {
    const error = new Error("microsoft_account_locked:microsoft account locked");

    expect(toMailboxFailureStatus(error)).toBe("locked");
    expect(getMailboxErrorCode(error)).toBe("microsoft_account_locked");
    expect(getMailboxErrorMessage(error)).toBe("Microsoft 账户已锁定");
  });

  test("maps opaque reauth errors to invalidated mailbox state", () => {
    const error = new Error("invalid_grant:reauth required");

    expect(toMailboxFailureStatus(error)).toBe("invalidated");
    expect(getMailboxErrorCode(error)).toBe("invalid_grant");
    expect(getMailboxErrorMessage(error)).toBe("invalid_grant:reauth required");
  });

  test("keeps Graph invalidated responses in invalidated mailbox state", () => {
    const error = new MicrosoftGraphError("interaction required", {
      code: "interaction_required",
      status: 400,
    });

    expect(toMailboxFailureStatus(error)).toBe("invalidated");
    expect(getMailboxErrorCode(error)).toBe("interaction_required");
    expect(getMailboxErrorMessage(error)).toBe("interaction required");
  });
});
