import { describe, expect, test } from "bun:test";
import {
  MICROSOFT_PASSWORD_SUBMIT_LIMIT,
  buildMicrosoftPasswordSurfaceKey,
  classifyMicrosoftFlowInterrupt,
  classifyMicrosoftProofSurface,
  classifyMicrosoftRecoveryChallenge,
  classifyMicrosoftPasswordError,
  getMicrosoftRecoveryTerminalErrorCode,
  isMicrosoftAuthorizeShellUnready,
  isMicrosoftKeepSignedInPrompt,
  shouldBlockMicrosoftPasswordSubmission,
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

  test("classifies traditional Chinese repeated incorrect-attempt copy as rate-limited", () => {
    const classification = classifyMicrosoftPasswordError(["您已多次使用不正確的帳戶或密碼進行登入。"]);

    expect(classification).toEqual({
      code: "microsoft_password_rate_limited",
      message: "您已多次使用不正確的帳戶或密碼進行登入。",
    });
  });

  test("blocks Microsoft password submission after three attempts", () => {
    expect(MICROSOFT_PASSWORD_SUBMIT_LIMIT).toBe(3);
    expect(shouldBlockMicrosoftPasswordSubmission(0)).toBe(false);
    expect(shouldBlockMicrosoftPasswordSubmission(2)).toBe(false);
    expect(shouldBlockMicrosoftPasswordSubmission(3)).toBe(true);
    expect(shouldBlockMicrosoftPasswordSubmission(4)).toBe(true);
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

  test("does not generic-hard-fail identity-confirm before recovery handling", () => {
    const classification = classifyMicrosoftFlowInterrupt({
      url: "https://account.live.com/identity/confirm?mkt=JA-JP",
      title: "お客様のアカウント保護にご協力ください",
      bodyText:
        "今回のサインインには、通常と異なる点があるようです。たとえば、お客様が新しい場所、新しいデバイス、新しいアプリからサインインしている可能性があります。",
    });

    expect(classification).toBeNull();
  });

  test("normalizes password surface keys across query churn and inline errors", () => {
    const base = buildMicrosoftPasswordSurfaceKey({
      url: "https://login.live.com/ppsecure/post.srf?client_id=1&context=a",
      title: "Enter your password",
      accountHint: "account-hint@example.test",
      bodyText: "Enter your password Forgot your password?",
    });
    const changedQueryAndBody = buildMicrosoftPasswordSurfaceKey({
      url: "https://login.live.com/ppsecure/post.srf?client_id=2&context=b",
      title: "Enter your password",
      accountHint: "account-hint@example.test",
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

  test("maps unresolved identity-confirm recovery to microsoft_account_locked", () => {
    expect(getMicrosoftRecoveryTerminalErrorCode("identity_confirm")).toBe("microsoft_account_locked");
    expect(getMicrosoftRecoveryTerminalErrorCode("verify_email")).toBe("microsoft_unknown_recovery_email");
    expect(getMicrosoftRecoveryTerminalErrorCode("unknown")).toBe("microsoft_unknown_recovery_email");
  });

  test("classifies zh-TW proofs/Add method surfaces as add-flow with provisioning enabled", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=zh-TW",
        title: "讓我們保護您的帳戶",
        bodyText:
          "讓我們保護您的帳戶 您希望新增的安全性資訊為何? 備用電子郵件地址 下一步，我們會傳送安全性驗證碼到您的備用電子郵件地址。",
        hasProofOptionsSelect: true,
      }),
    ).toMatchObject({
      kind: "add_method",
      onProofRoute: true,
      onAddRoute: true,
      allowProvision: true,
    });
  });

  test("keeps proofs/Add surfaces in add flow even when a generic numeric input is also visible", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=zh-TW",
        title: "讓我們保護您的帳戶",
        bodyText: "您希望新增的安全性資訊為何? 備用電子郵件地址 電話號碼",
        hasProofRadio: true,
        hasCodeInput: true,
      }),
    ).toMatchObject({
      kind: "add_method",
      onAddRoute: true,
      allowProvision: true,
    });
  });

  test("classifies zh-TW proofs/Add email-entry surfaces as add-email with provisioning enabled", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=zh-TW",
        title: "讓我們保護您的帳戶",
        bodyText: "讓我們保護您的帳戶 備用電子郵件地址",
        hasAddEmailInput: true,
      }),
    ).toMatchObject({
      kind: "add_email",
      onProofRoute: true,
      onAddRoute: true,
      allowProvision: true,
    });
  });

  test("classifies proofs/Add confirmation surfaces as confirm-email before add flow", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=en-US",
        title: "Verify your email",
        bodyText: "We'll send a code to ha*****@example.com before you continue.",
        hasConfirmationEmailInput: true,
      }),
    ).toMatchObject({
      kind: "confirm_email",
      onAddRoute: true,
      allowProvision: false,
    });
  });

  test("classifies proofs/Add confirmation copy without add-email input as confirm-email", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=en-US",
        title: "Verify your email",
        bodyText: "Verify your email. We'll send a code to your backup email address.",
      }),
    ).toMatchObject({
      kind: "confirm_email",
      onAddRoute: true,
      allowProvision: false,
    });
  });

  test("classifies login.live OAuth confirmation surfaces as confirm-email", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://login.live.com/oauth20_authorize.srf?client_id=3f026981-b1b0-4305-b12f-e60015126b8c",
        title: "Verify your email",
        bodyText:
          "Verify your email. We'll send a code to no*****@mail.ivanli.asia. Already received a code? Use your password.",
        hasConfirmationEmailInput: true,
      }),
    ).toMatchObject({
      kind: "confirm_email",
      onProofRoute: false,
      allowProvision: false,
    });
  });

  test("matches Microsoft recovery challenge against configured proof mailbox", () => {
    expect(
      classifyMicrosoftRecoveryChallenge({
        configuredAddress: "noral18@mail.ivanli.asia",
        title: "Verify your email",
        bodyText: "We'll send a code to no*****@mail.ivanli.asia. To verify this is your email, enter it here.",
        controlText: "Use your password",
      }),
    ).toMatchObject({
      hintedMaskedEmail: "no***@mail.ivanli.asia",
      matchesConfiguredMailbox: true,
      hasPasswordFallback: true,
      surfaceKind: "verify_email",
    });
  });

  test("classifies configured proof mailbox mismatches as unknown recovery email", () => {
    const challenge = classifyMicrosoftRecoveryChallenge({
      configuredAddress: "noral18@mail.ivanli.asia",
      title: "Verify your email",
      bodyText: "We'll send a code to ab*****@mail.ivanli.asia. To verify this is your email, enter it here.",
      controlText: "Use your password",
    });

    expect(challenge).toMatchObject({
      hintedMaskedEmail: "ab***@mail.ivanli.asia",
      matchesConfiguredMailbox: false,
      hasPasswordFallback: true,
      surfaceKind: "verify_email",
    });
    expect(
      shouldClassifyMicrosoftUnknownRecoveryEmail({
        surfaceKind: challenge.surfaceKind,
        configuredMailboxMatchesChallenge: challenge.matchesConfiguredMailbox,
        hasPasswordFallback: false,
      }),
    ).toBe(true);
  });

  test("keeps legacy confirmation copy markers routed to confirm-email", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=ja-JP",
        title: "メールをご確認ください",
        bodyText: "既にコードを受け取りましたか? パスワードを使用する",
      }),
    ).toMatchObject({
      kind: "confirm_email",
      onAddRoute: true,
      allowProvision: false,
    });
  });

  test("keeps verify-choice surfaces out of add-flow provisioning", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Verify?mkt=en-US",
        title: "Help us protect your account",
        bodyText: "We need to verify your identity before you can sign in.",
        hasProofRadio: true,
      }),
    ).toMatchObject({
      kind: "verify_choice",
      onProofRoute: true,
      onVerifyRoute: true,
      allowProvision: false,
    });
  });

  test("keeps non-add proof email prompts out of auto-provisioning", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Verify?mkt=en-US",
        title: "Verify your email",
        bodyText: "Enter your alternate email address before we send a code.",
        hasAddEmailInput: true,
      }),
    ).toMatchObject({
      kind: "add_email",
      onVerifyRoute: true,
      allowProvision: false,
    });
  });

  test("keeps proof-radio surfaces in verify flow even when #iProofEmail is also visible", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Verify?mkt=en-US",
        title: "Verify your email",
        bodyText: "Select a proof option and enter the missing part of the email address.",
        hasProofRadio: true,
        hasConfirmationEmailInput: true,
      }),
    ).toMatchObject({
      kind: "verify_choice",
      allowProvision: false,
    });
  });

  test("keeps add-email surfaces in add flow even when verify-your-email copy is present", () => {
    expect(
      classifyMicrosoftProofSurface({
        url: "https://account.live.com/proofs/Add?mkt=en-US",
        title: "Verify your email",
        bodyText: "Verify your email before continuing. Enter your backup email address.",
        hasAddEmailInput: true,
      }),
    ).toMatchObject({
      kind: "add_email",
      onAddRoute: true,
      allowProvision: true,
    });
  });

  test("classifies unknown proof routes as explicit unclassified diagnostics", () => {
    const classification = classifyMicrosoftProofSurface({
      url: "https://account.live.com/proofs/Add?mkt=fr-FR",
      title: "Microsoft account",
      bodyText: "Surface inconnue sans selecteur attendu",
    });

    expect(classification.kind).toBe("unclassified");
    expect(classification.onProofRoute).toBe(true);
    expect(classification.allowProvision).toBe(false);
    expect(classification.matchedSignals).toContain("route:proof");
    expect(classification.matchedSignals).toContain("route:add");
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
          "signin-hint@example.test 要保持登入嗎? 不要每次都要重新登入。深入了解 是 否 說明 使用條款 隱私權與 Cookie",
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
