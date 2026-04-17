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
export type MicrosoftProofSurfaceKind =
  | "none"
  | "add_method"
  | "add_email"
  | "confirm_email"
  | "verify_choice"
  | "code_entry"
  | "unclassified";

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

export interface MicrosoftProofSurfaceInput {
  url: string;
  title?: string;
  bodyText?: string;
  hasProofOptionsSelect?: boolean;
  hasAddEmailInput?: boolean;
  hasConfirmationEmailInput?: boolean;
  hasProofRadio?: boolean;
  hasCodeInput?: boolean;
}

export interface MicrosoftProofSurfaceClassification {
  kind: MicrosoftProofSurfaceKind;
  onProofRoute: boolean;
  onAddRoute: boolean;
  onVerifyRoute: boolean;
  allowProvision: boolean;
  matchedSignals: string[];
}

export const MICROSOFT_PASSWORD_SUBMIT_LIMIT = 3;

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

function testPattern(normalizedText: string, pattern: RegExp): boolean {
  return pattern.test(normalizedText);
}

const MICROSOFT_PROOF_ADD_COPY = [
  /what security info would you like to add/i,
  /你想添加哪些安全信息/i,
  /您希望新增的安全性資訊為何/i,
  /what kind of security info would you like to add/i,
  /backup email/i,
  /alternate email/i,
  /备用电子邮件地址/i,
  /備用電子郵件地址/i,
] as const;

const MICROSOFT_PROOF_CONFIRM_COPY = [
  /verify your email/i,
  /we[’']?ll send a code to/i,
  /already received a code/i,
  /验证你的电子邮件/i,
  /驗證您的電子郵件/i,
  /我們將把驗證碼傳送到/i,
  /我們將傳送代碼到/i,
  /メールをご確認ください/i,
  /コードを送信します/i,
] as const;

const MICROSOFT_PROOF_VERIFY_COPY = [
  /help us protect your account/i,
  /protect your account/i,
  /let.?s protect your account/i,
  /让我们来保护你的帐户/i,
  /讓我們保護您的帳戶/i,
  /verify online/i,
  /i don[’']?t have these any more/i,
  /我不再拥有这些信息/i,
  /これらはもうありません/i,
] as const;

const MICROSOFT_PROOF_CODE_COPY = [
  /security code/i,
  /verification code/i,
  /enter code/i,
  /one-time code/i,
  /验证码/i,
  /驗證碼/i,
  /安全代码/i,
  /コード/i,
] as const;

function hasPatternMatch(normalizedText: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => testPattern(normalizedText, pattern));
}

function pushSignal(target: string[], condition: boolean, signal: string): void {
  if (condition) {
    target.push(signal);
  }
}

export function classifyMicrosoftPasswordError(errors: string[]): MicrosoftPasswordErrorClassification | null {
  const joined = errors
    .map((text) => text.replace(/\s+/g, " ").trim())
    .filter((text) => text.length > 0)
    .join(" | ")
    .trim();
  if (!joined) return null;
  if (
    /too many times|too many attempts|try again later|请稍后重试|您已多次使用不正確的帳戶或密碼進行登入|您已多次使用不正确的帐户或密码进行登录|您已多次使用不正确的账户或密码进行登录/i.test(
      joined,
    )
  ) {
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

export function shouldBlockMicrosoftPasswordSubmission(totalSubmittedCount: number): boolean {
  return totalSubmittedCount >= MICROSOFT_PASSWORD_SUBMIT_LIMIT;
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
  const bodyHint = title ? "" : derivePasswordBodyHint(input.bodyText || "");
  return [location, title || bodyHint || "password"].filter((part) => part.length > 0).join("|");
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

export function classifyMicrosoftProofSurface(
  input: MicrosoftProofSurfaceInput,
): MicrosoftProofSurfaceClassification {
  const url = normalizeText(input.url);
  const title = normalizeText(input.title);
  const bodyText = normalizeText(input.bodyText);
  const combined = [title, bodyText].filter((part) => part.length > 0).join(" | ");
  const onProofRoute = /account\.live\.com\/proofs\//i.test(url);
  const onAddRoute = /account\.live\.com\/proofs\/add/i.test(url);
  const onVerifyRoute = /account\.live\.com\/proofs\/verify/i.test(url);
  const hasAddCopy = hasPatternMatch(combined, MICROSOFT_PROOF_ADD_COPY);
  const hasConfirmCopy = hasPatternMatch(combined, MICROSOFT_PROOF_CONFIRM_COPY);
  const hasVerifyCopy = hasPatternMatch(combined, MICROSOFT_PROOF_VERIFY_COPY);
  const hasCodeCopy = hasPatternMatch(combined, MICROSOFT_PROOF_CODE_COPY);

  const matchedSignals: string[] = [];
  pushSignal(matchedSignals, onProofRoute, "route:proof");
  pushSignal(matchedSignals, onAddRoute, "route:add");
  pushSignal(matchedSignals, onVerifyRoute, "route:verify");
  pushSignal(matchedSignals, !!input.hasProofOptionsSelect, "selector:#iProofOptions");
  pushSignal(matchedSignals, !!input.hasAddEmailInput, "selector:#EmailAddress");
  pushSignal(matchedSignals, !!input.hasConfirmationEmailInput, "selector:#iProofEmail");
  pushSignal(matchedSignals, !!input.hasProofRadio, "selector:proof-radio");
  pushSignal(matchedSignals, !!input.hasCodeInput, "selector:otp-input");
  pushSignal(matchedSignals, hasAddCopy, "copy:add");
  pushSignal(matchedSignals, hasConfirmCopy, "copy:confirm");
  pushSignal(matchedSignals, hasVerifyCopy, "copy:verify");
  pushSignal(matchedSignals, hasCodeCopy, "copy:code");

  let kind: MicrosoftProofSurfaceKind = "none";
  if (input.hasCodeInput || (onProofRoute && hasCodeCopy && !input.hasAddEmailInput && !input.hasConfirmationEmailInput)) {
    kind = "code_entry";
  } else if (
    input.hasProofOptionsSelect ||
    (onAddRoute && hasAddCopy && !input.hasAddEmailInput) ||
    (onAddRoute && input.hasProofRadio && !input.hasAddEmailInput && !input.hasConfirmationEmailInput)
  ) {
    kind = "add_method";
  } else if (
    (input.hasAddEmailInput && (onProofRoute || input.hasProofOptionsSelect || hasAddCopy || hasConfirmCopy)) ||
    (onAddRoute && (hasAddCopy || hasConfirmCopy))
  ) {
    kind = "add_email";
  } else if (onVerifyRoute && input.hasProofRadio) {
    kind = "verify_choice";
  } else if (input.hasConfirmationEmailInput || (onProofRoute && hasConfirmCopy)) {
    kind = "confirm_email";
  } else if (input.hasProofRadio) {
    kind = "verify_choice";
  } else if (onVerifyRoute || (onProofRoute && hasVerifyCopy)) {
    kind = "verify_choice";
  } else if (onProofRoute || hasAddCopy || hasConfirmCopy || hasVerifyCopy || hasCodeCopy) {
    kind = "unclassified";
  }

  return {
    kind,
    onProofRoute,
    onAddRoute,
    onVerifyRoute,
    allowProvision: kind === "add_method" || kind === "add_email",
    matchedSignals,
  };
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
