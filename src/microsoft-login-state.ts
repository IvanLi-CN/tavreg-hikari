export interface MicrosoftPasswordErrorClassification {
  code: "microsoft_password_rate_limited" | "microsoft_password_incorrect";
  message: string;
}

export interface MicrosoftFlowInterruptClassification {
  code: "microsoft_auth_try_again_later" | "microsoft_account_locked";
  message: string;
}

export interface MicrosoftProofPasswordFallbackInput {
  hasConfiguredMailbox: boolean;
  configuredMailboxMatchesChallenge?: boolean | null;
  passwordFallbackAttempted: boolean;
  passwordFallbackBlocked: boolean;
}

export interface MicrosoftPasskeyProofRecoveryInput {
  passwordFallbackAttempted: boolean;
  passwordFallbackBlocked: boolean;
}

export type MicrosoftRecoverySurfaceKind = "verify_email" | "identity_confirm" | "unknown";

export interface MicrosoftUnknownRecoveryEmailInput {
  surfaceKind: MicrosoftRecoverySurfaceKind;
  configuredMailboxMatchesChallenge?: boolean | null;
  hasPasswordFallback: boolean;
}

export interface MicrosoftKeepSignedInPromptInput {
  url?: string;
  title?: string;
  bodyText?: string;
}

function normalizeText(value: string | undefined | null): string {
  return String(value || "")
    .replace(/[\u200e\u200f\u202a-\u202e]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function buildUrlSignature(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin.toLowerCase()}${parsed.pathname.toLowerCase()}`;
  } catch {
    return normalizeText(url);
  }
}

function derivePasswordBodyHint(bodyText: string): string {
  const normalized = normalizeText(bodyText);
  if (!normalized) return "";
  if (/enter your password|输入你的密码/i.test(normalized)) return "enter-password";
  if (/forgot your password|忘记密码/i.test(normalized)) return "forgot-password";
  if (/security code|verification code|验证码|安全代码/i.test(normalized)) return "security-code";
  if (/protect your account|保护你的帐户|保护你的账户/i.test(normalized)) return "protect-account";
  return normalized.slice(0, 120);
}

export function classifyMicrosoftPasswordError(errors: string[]): MicrosoftPasswordErrorClassification | null {
  const joined = errors
    .map((text) => text.replace(/\s+/g, " ").trim())
    .filter((text) => text.length > 0)
    .join(" | ")
    .trim();
  if (!joined) return null;
  if (/too many times|too many attempts|try again later|请稍后重试/i.test(joined)) {
    return { code: "microsoft_password_rate_limited", message: joined };
  }
  if (
    /incorrect account or password|account or password is incorrect|incorrect password|wrong password|invalid password|密码不正确|帐户或密码不正确/i.test(
      joined,
    )
  ) {
    return { code: "microsoft_password_incorrect", message: joined };
  }
  return null;
}

export function classifyMicrosoftFlowInterrupt(input: {
  url: string;
  title?: string;
  bodyText?: string;
}): MicrosoftFlowInterruptClassification | null {
  const url = normalizeText(input.url);
  if (!/login\.live\.com|account\.live\.com|login\.microsoft\.com/i.test(url)) {
    return null;
  }
  const title = normalizeText(input.title);
  const bodyText = normalizeText(input.bodyText);
  const combined = [title, bodyText].filter((part) => part.length > 0).join(" | ");
  if (!combined) return null;
  if (
    /try again later|too many repeated authentication attempts|please wait a moment and try again|serrorcode.?80041002|80041002|请稍后重试/i.test(
      combined,
    )
  ) {
    return {
      code: "microsoft_auth_try_again_later",
      message: combined,
    };
  }
  if (
    /account\.live\.com\/abuse/i.test(url) ||
    /your account has been locked|we've detected some activity that violates our microsoft services agreement and have locked your account|account has been locked|帐户已被锁定|账户已被锁定/i.test(
      combined,
    )
  ) {
    return {
      code: "microsoft_account_locked",
      message: combined,
    };
  }
  return null;
}

export function buildMicrosoftPasswordSurfaceKey(input: {
  url: string;
  title?: string;
  bodyText?: string;
  accountHint?: string;
}): string {
  const location = buildUrlSignature(input.url);
  const title = normalizeText(input.title).slice(0, 120);
  const account = normalizeText(input.accountHint).replace(/\s+/g, "").slice(0, 160);
  const bodyHint = derivePasswordBodyHint(input.bodyText || "");
  return [location, title, account, bodyHint].filter((part) => part.length > 0).join("|");
}

export function shouldAttemptMicrosoftProofPasswordFallback(
  input: MicrosoftProofPasswordFallbackInput,
): boolean {
  if (input.passwordFallbackBlocked || input.passwordFallbackAttempted) {
    return false;
  }
  if (input.hasConfiguredMailbox && input.configuredMailboxMatchesChallenge === true) {
    return false;
  }
  return true;
}

export function shouldRecoverMicrosoftPasskeyToProofCode(
  input: MicrosoftPasskeyProofRecoveryInput,
): boolean {
  return input.passwordFallbackAttempted && !input.passwordFallbackBlocked;
}

export function shouldClassifyMicrosoftUnknownRecoveryEmail(
  input: MicrosoftUnknownRecoveryEmailInput,
): boolean {
  if (input.configuredMailboxMatchesChallenge === true) {
    return false;
  }
  if (input.hasPasswordFallback) {
    return false;
  }
  if (input.surfaceKind === "identity_confirm") {
    return true;
  }
  return input.configuredMailboxMatchesChallenge === false;
}

export function getMicrosoftRecoveryTerminalErrorCode(
  surfaceKind: MicrosoftRecoverySurfaceKind,
): "microsoft_account_locked" | "microsoft_unknown_recovery_email" {
  return surfaceKind === "identity_confirm" ? "microsoft_account_locked" : "microsoft_unknown_recovery_email";
}

export function isMicrosoftAuthorizeShellUnready(input: {
  url: string;
  title?: string;
  bodyText?: string;
}): boolean {
  if (!/login\.live\.com\/oauth20_authorize\.srf/i.test(input.url)) {
    return false;
  }
  const title = normalizeText(input.title);
  const bodyText = normalizeText(input.bodyText);
  const hasVisibleFlowCopy =
    /verify your email|we'll send a code|enter your password|keep me signed in|use your password|sign in with password|security code|protect your account|验证码|驗證碼|密碼|密码|保護|保护|コード|確認|パスワード/i.test(
      bodyText,
    );
  if (hasVisibleFlowCopy) {
    return false;
  }
  if (
    title &&
    !/sign in to your microsoft account|登入您的 microsoft 帳戶|登录你的 microsoft 帐户|登录到你的 microsoft 帐户|microsoft アカウントにサインイン/i.test(
      title,
    )
  ) {
    return false;
  }
  return bodyText.length <= 16;
}

export function isMicrosoftKeepSignedInPrompt(input: MicrosoftKeepSignedInPromptInput): boolean {
  const url = normalizeText(input.url);
  if (url && !/login\.live\.com|account\.live\.com|login\.microsoft\.com/i.test(url)) {
    return false;
  }
  const combined = [input.title, input.bodyText]
    .map((value) => normalizeText(value))
    .filter((part) => part.length > 0)
    .join(" | ");
  if (!combined) {
    return false;
  }
  return /stay signed in|keep me signed in|keep signed in|skip having to sign in every time|保持登录状态|保持登入状态|要保持登录吗|要保持登入嗎|不要每次都要重新登录|不要每次都要重新登入|サインインしたままにする/i.test(
    combined,
  );
}
