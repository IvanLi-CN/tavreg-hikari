import { describe, expect, test } from "bun:test";

import { isMicrosoftPasskeyInterruptUrl } from "../src/microsoft-passkey";

describe("Microsoft passkey detection", () => {
  test("recognizes Microsoft FIDO/passkey interrupt URLs", () => {
    expect(isMicrosoftPasskeyInterruptUrl("https://login.microsoft.com/consumers/fido/create?mkt=zh-CN")).toBe(true);
    expect(isMicrosoftPasskeyInterruptUrl("https://account.live.com/interrupt/passkey/enroll?mkt=zh-CN")).toBe(true);
  });

  test("ignores completed callback URLs", () => {
    expect(
      isMicrosoftPasskeyInterruptUrl(
        "https://tavreg-hikari-dev.ivanli.cc/api/microsoft-mail/oauth/callback?code=abc&state=123",
      ),
    ).toBe(false);
  });
});
