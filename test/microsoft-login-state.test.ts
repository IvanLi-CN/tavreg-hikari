import { describe, expect, test } from "bun:test";
import {
  buildMicrosoftPasswordSurfaceKey,
  classifyMicrosoftFlowInterrupt,
  classifyMicrosoftPasswordError,
  isMicrosoftAuthorizeShellUnready,
  isMicrosoftKeepSignedInPrompt,
  shouldClassifyMicrosoftUnknownRecoveryEmail,
  shouldAttemptMicrosoftProofPasswordFallback,
  shouldRecoverMicrosoftPasskeyToProofCode,
} from "../src/microsoft-login-state.ts";

describe("Microsoft login state", () => {
  test("classifies password rate-limit copy before retrying", () => {
    const classification = classifyMicrosoftPasswordError([
      "You've tried to sign in too many times with an incorrect account or password.",
    ]);

    expect(classification).toEqual({
      code: "microsoft_password_rate_limited",
      message: "You've tried to sign in too many times with an incorrect account or password.",
    });
  });

  test("classifies incorrect password copy", () => {
    const classification = classifyMicrosoftPasswordError(["Your account or password is incorrect."]);

    expect(classification).toEqual({
      code: "microsoft_password_incorrect",
      message: "Your account or password is incorrect.",
    });
  });

  test("classifies microsoft try-again-later interrupt page", () => {
    const classification = classifyMicrosoftFlowInterrupt({
      url: "https://login.live.com/oauth20_authorize.srf?client_id=123",
      title: "Try again later",
      bodyText:
        "The Microsoft account login server has detected too many repeated authentication attempts. Please wait a moment and try again. sErrorCode 80041002",
    });

    expect(classification).toEqual({
      code: "microsoft_auth_try_again_later",
      message:
        "try again later | the microsoft account login server has detected too many repeated authentication attempts. please wait a moment and try again. serrorcode 80041002",
    });
  });

  test("classifies locked Microsoft account abuse page", () => {
    const classification = classifyMicrosoftFlowInterrupt({
      url: "https://account.live.com/Abuse?mkt=EN-US",
      title: "Microsoft account",
      bodyText:
        "Your account has been locked We've detected some activity that violates our Microsoft Services Agreement and have locked your account.",
    });

    expect(classification).toEqual({
      code: "microsoft_account_locked",
      message:
        "microsoft account | your account has been locked we've detected some activity that violates our microsoft services agreement and have locked your account.",
    });
  });

  test("classifies Microsoft identity-confirm secondary verification gate as lockworthy", () => {
    const classification = classifyMicrosoftFlowInterrupt({
      url: "https://account.live.com/identity/confirm?mkt=JA-JP",
      title: "お客様のアカウント保護にご協力ください",
      bodyText:
        "今回のサインインには、通常と異なる点があるようです。たとえば、お客様が新しい場所、新しいデバイス、新しいアプリからサインインしている可能性があります。",
    });

    expect(classification).toEqual({
      code: "microsoft_account_locked",
      message:
        "お客様のアカウント保護にご協力ください | 今回のサインインには、通常と異なる点があるようです。たとえば、お客様が新しい場所、新しいデバイス、新しいアプリからサインインしている可能性があります。".toLowerCase(),
    });
  });

  test("normalizes password surface keys across query churn and inline errors", () => {
    const base = buildMicrosoftPasswordSurfaceKey({
      url: "https://login.live.com/ppsecure/post.srf?client_id=1&context=a",
      title: "Enter your password",
      accountHint: "spencerjeffrey5596@outlook.com",
      bodyText: "Enter your password Forgot your password?",
    });
    const changedQueryAndBody = buildMicrosoftPasswordSurfaceKey({
      url: "https://login.live.com/ppsecure/post.srf?client_id=2&context=b",
      title: "Enter your password",
      accountHint: "spencerjeffrey5596@outlook.com",
      bodyText:
        "Enter your password You've tried to sign in too many times with an incorrect account or password. Forgot your password?",
    });

    expect(changedQueryAndBody).toBe(base);
  });

  test("prefers the configured proof mailbox when the challenge matches it", () => {
    expect(
      shouldAttemptMicrosoftProofPasswordFallback({
        hasConfiguredMailbox: true,
        configuredMailboxMatchesChallenge: true,
        passwordFallbackAttempted: false,
        passwordFallbackBlocked: false,
      }),
    ).toBe(false);
  });

  test("only uses password fallback when no proof mailbox mapping is available", () => {
    expect(
      shouldAttemptMicrosoftProofPasswordFallback({
        hasConfiguredMailbox: false,
        configuredMailboxMatchesChallenge: null,
        passwordFallbackAttempted: false,
        passwordFallbackBlocked: false,
      }),
    ).toBe(true);
  });

  test("uses password fallback when the challenge email does not match the configured mailbox", () => {
    expect(
      shouldAttemptMicrosoftProofPasswordFallback({
        hasConfiguredMailbox: true,
        configuredMailboxMatchesChallenge: false,
        passwordFallbackAttempted: false,
        passwordFallbackBlocked: false,
      }),
    ).toBe(true);
  });

  test("does not retry password fallback after it was already blocked", () => {
    expect(
      shouldAttemptMicrosoftProofPasswordFallback({
        hasConfiguredMailbox: true,
        configuredMailboxMatchesChallenge: false,
        passwordFallbackAttempted: true,
        passwordFallbackBlocked: true,
      }),
    ).toBe(false);
  });

  test("recovers passkey redirect back to proof code only after password fallback was attempted", () => {
    expect(
      shouldRecoverMicrosoftPasskeyToProofCode({
        passwordFallbackAttempted: true,
        passwordFallbackBlocked: false,
      }),
    ).toBe(true);
    expect(
      shouldRecoverMicrosoftPasskeyToProofCode({
        passwordFallbackAttempted: false,
        passwordFallbackBlocked: false,
      }),
    ).toBe(false);
    expect(
      shouldRecoverMicrosoftPasskeyToProofCode({
        passwordFallbackAttempted: true,
        passwordFallbackBlocked: true,
      }),
    ).toBe(false);
  });

  test("keeps identity-confirm surfaces on password fallback when available", () => {
    expect(
      shouldClassifyMicrosoftUnknownRecoveryEmail({
        surfaceKind: "identity_confirm",
        configuredMailboxMatchesChallenge: false,
        hasPasswordFallback: true,
      }),
    ).toBe(false);
  });

  test("keeps verify-email surfaces on password fallback when available", () => {
    expect(
      shouldClassifyMicrosoftUnknownRecoveryEmail({
        surfaceKind: "verify_email",
        configuredMailboxMatchesChallenge: false,
        hasPasswordFallback: true,
      }),
    ).toBe(false);
  });

  test("classifies verify-email mismatch when password fallback is unavailable", () => {
    expect(
      shouldClassifyMicrosoftUnknownRecoveryEmail({
        surfaceKind: "verify_email",
        configuredMailboxMatchesChallenge: false,
        hasPasswordFallback: false,
      }),
    ).toBe(true);
  });

  test("detects blank Microsoft authorize shell that should be reloaded", () => {
    expect(
      isMicrosoftAuthorizeShellUnready({
        url: "https://login.live.com/oauth20_authorize.srf?client_id=123",
        title: "Sign in to your Microsoft account",
        bodyText: "",
      }),
    ).toBe(true);
    expect(
      isMicrosoftAuthorizeShellUnready({
        url: "https://login.live.com/oauth20_authorize.srf?client_id=123",
        title: "Verify your email",
        bodyText: "We'll send a code to ha*****@genq.top",
      }),
    ).toBe(false);
  });

  test("detects localized blank Microsoft authorize shell without visible form copy", () => {
    expect(
      isMicrosoftAuthorizeShellUnready({
        url: "https://login.live.com/oauth20_authorize.srf?client_id=123&ui_locales=zh-TW",
        title: "登入您的 Microsoft 帳戶",
        bodyText: "",
      }),
    ).toBe(true);
    expect(
      isMicrosoftAuthorizeShellUnready({
        url: "https://login.live.com/oauth20_authorize.srf?client_id=123&ui_locales=zh-TW",
        title: "登入您的 Microsoft 帳戶",
        bodyText: "輸入您的密碼",
      }),
    ).toBe(false);
  });

  test("detects traditional Chinese keep-signed-in prompt", () => {
    expect(
      isMicrosoftKeepSignedInPrompt({
        url: "https://login.live.com/ppsecure/post.srf?client_id=123",
        title: "要保持登入嗎?",
        bodyText:
          "ngadilick0360@outlook.com 要保持登入嗎? 不要每次都要重新登入。深入了解 是 否 說明 使用條款 隱私權與 Cookie",
      }),
    ).toBe(true);
  });

  test("does not confuse password prompt with keep-signed-in prompt", () => {
    expect(
      isMicrosoftKeepSignedInPrompt({
        url: "https://login.live.com/ppsecure/post.srf?client_id=123",
        title: "輸入您的密碼",
        bodyText: "輸入您的密碼 忘記密碼?",
      }),
    ).toBe(false);
  });
});
