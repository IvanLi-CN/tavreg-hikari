export interface MicrosoftPasswordErrorClassification {
  code: "microsoft_password_rate_limited" | "microsoft_password_incorrect";
  message: string;
}

export interface MicrosoftFlowInterruptClassification {
  code: "microsoft_auth_try_again_later";
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
  if (input.surfaceKind === "identity_confirm") {
    return true;
  }
  return input.configuredMailboxMatchesChallenge === false && !input.hasPasswordFallback;
}

export function isMicrosoftAuthorizeShellUnready(input: {
  url: string;
  title?: string;
  bodyText?: string;
}): boolean {
  if (!/login\.live\.com\/oauth20_authorize\.srf/i.test(input.url)) {
    return false;
  }
  if (!/sign in to your microsoft account/i.test(normalizeText(input.title))) {
    return false;
  }
  return normalizeText(input.bodyText).length <= 16;
}
