import { describe, expect, test } from "bun:test";

import {
  getMicrosoftOauthBrowserOutcome,
  MicrosoftGraphError,
  getMailboxErrorCode,
  getMailboxErrorMessage,
  isMicrosoftOauthCallbackUrl,
  isMicrosoftOauthCompletionUrl,
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

  test("recognizes callback and workspace URLs as valid OAuth completion targets", () => {
    expect(
      isMicrosoftOauthCompletionUrl(
        "https://console.example.test/api/microsoft-mail/oauth/callback?code=abc&state=123",
        "https://console.example.test/api/microsoft-mail/oauth/callback",
      ),
    ).toBe(true);
    expect(
      isMicrosoftOauthCompletionUrl(
        "https://console.example.test/mailboxes?accountId=12&oauth=success",
        "https://console.example.test/api/microsoft-mail/oauth/callback",
      ),
    ).toBe(true);
  });

  test("rejects unrelated intermediate URLs as incomplete OAuth results", () => {
    expect(
      isMicrosoftOauthCompletionUrl(
        "https://login.microsoft.com/consumers/fido/create?mkt=zh-CN",
        "https://console.example.test/api/microsoft-mail/oauth/callback",
      ),
    ).toBe(false);
  });

  test("distinguishes callback transit from final browser oauth outcome", () => {
    const redirectUri = "https://console.example.test/api/microsoft-mail/oauth/callback";

    expect(
      isMicrosoftOauthCallbackUrl(
        "https://console.example.test/api/microsoft-mail/oauth/callback?code=abc&state=123",
        redirectUri,
      ),
    ).toBe(true);
    expect(
      getMicrosoftOauthBrowserOutcome(
        "https://console.example.test/api/microsoft-mail/oauth/callback?code=abc&state=123",
        redirectUri,
      ),
    ).toBeNull();
    expect(
      getMicrosoftOauthBrowserOutcome(
        "https://console.example.test/mailboxes?accountId=12&oauth=success",
        redirectUri,
      ),
    ).toBe("success");
    expect(
      getMicrosoftOauthBrowserOutcome(
        "https://console.example.test/mailboxes?accountId=12&oauth=error",
        redirectUri,
      ),
    ).toBe("error");
  });
});
