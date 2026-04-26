export interface MicrosoftAccountSurfaceSnapshot {
  url: string;
  title: string;
  bodyText: string;
  visibleActions: string[];
}

export interface MicrosoftAccountSurfaceAssessment {
  authenticated: boolean;
  requiresLogin: boolean;
  reason: string;
  strongAuthSignals: string[];
  weakAuthSignals: string[];
  loginSignals: string[];
}

const SIGN_IN_PATTERNS = [/\bsign in\b/i, /\blog in\b/i, /登录/, /登入/, /继续登录/, /继续登入/];
const CREATE_ACCOUNT_PATTERNS = [/create account/i, /create one/i, /创建账户/i, /创建帐户/i, /建立帳戶/i, /创建一个/i];
const LOGIN_COPY_PATTERNS = [
  /sign in to (?:your )?microsoft account/i,
  /sign in to access/i,
  /log in to (?:your )?microsoft account/i,
  /登录到你的 microsoft 帐户/i,
  /登录到 microsoft 帐户/i,
  /登入 microsoft 帳戶/i,
];
const STRONG_AUTH_SIGNALS: Array<{ label: string; pattern: RegExp }> = [
  { label: 'services_subscriptions', pattern: /services?\s*(?:&|and)\s*subscriptions|服务和订阅|服務和訂閱/i },
  { label: 'devices', pattern: /\bdevices?\b|\bdevice safety\b|设备|裝置/i },
  { label: 'payment_options', pattern: /payment options?|付款选项|付款方式|付款選項/i },
  { label: 'order_history', pattern: /order history|订单历史|訂單記錄|訂單歷史/i },
  { label: 'family', pattern: /family safety|family group|家人安全|家庭安全|家庭群組/i },
  { label: 'rewards', pattern: /microsoft rewards|rewards dashboard|奖励中心|獎勵中心|rewards/i },
  { label: 'your_info', pattern: /your info|profile info|个人资料|個人資料|你的信息|帳戶資訊/i },
];
const WEAK_AUTH_SIGNALS: Array<{ label: string; pattern: RegExp }> = [
  { label: 'security', pattern: /\bsecurity\b|安全/i },
  { label: 'privacy', pattern: /\bprivacy\b|隐私|隱私/i },
  { label: 'subscriptions', pattern: /\bsubscriptions?\b|订阅|訂閱/i },
  { label: 'billing', pattern: /\bbilling\b|账单|帳單/i },
];

function normalizeText(value: string): string {
  return String(value || '')
    .replace(/[\u200e\u200f\u202a-\u202e]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

export function isMicrosoftLoginSurfaceUrl(url: string): boolean {
  const raw = String(url || '').trim();
  if (!raw) return false;
  try {
    const hostname = new URL(raw).hostname.toLowerCase();
    return hostname === 'login.live.com'
      || hostname === 'account.live.com'
      || hostname === 'login.microsoft.com'
      || hostname === 'login.microsoftonline.com'
      || hostname.endsWith('.b2clogin.com');
  } catch {
    return /^(?:https?:\/\/)?(?:login\.live\.com|account\.live\.com|login\.microsoft\.com|login\.microsoftonline\.com)(?:\/|$)/i.test(raw)
      || /^(?:https?:\/\/)?[a-z0-9.-]+\.b2clogin\.com(?:\/|$)/i.test(raw);
  }
}

export function isMicrosoftAccountAuthIntermediateUrl(url: string): boolean {
  try {
    const parsed = new URL(String(url || ''));
    return /^https:\/\/account\.microsoft\.com$/i.test(parsed.origin) && /^\/auth\//i.test(parsed.pathname || '/');
  } catch {
    return false;
  }
}

export function isMicrosoftAccountHomeUrl(url: string): boolean {
  try {
    const parsed = new URL(String(url || ''));
    if (!/^https:\/\/account\.microsoft\.com$/i.test(parsed.origin)) {
      return false;
    }
    return !/^\/auth\//i.test(parsed.pathname || '/');
  } catch {
    return false;
  }
}

export function assessMicrosoftAccountSurface(input: MicrosoftAccountSurfaceSnapshot): MicrosoftAccountSurfaceAssessment {
  const url = String(input.url || '');
  const combinedText = normalizeText([input.title, input.bodyText].join(' '));
  const actionTexts = dedupe((input.visibleActions || []).map((value) => normalizeText(value)).filter(Boolean));

  const strongAuthSignals = dedupe(
    STRONG_AUTH_SIGNALS.filter((item) => item.pattern.test(combinedText)).map((item) => item.label),
  );
  const weakAuthSignals = dedupe(
    WEAK_AUTH_SIGNALS.filter((item) => item.pattern.test(combinedText)).map((item) => item.label),
  );
  const loginSignals = dedupe([
    ...(actionTexts.some((text) => SIGN_IN_PATTERNS.some((pattern) => pattern.test(text))) ? ['visible_sign_in'] : []),
    ...(actionTexts.some((text) => CREATE_ACCOUNT_PATTERNS.some((pattern) => pattern.test(text))) ? ['visible_create_account'] : []),
    ...(LOGIN_COPY_PATTERNS.some((pattern) => pattern.test(combinedText)) ? ['login_copy'] : []),
  ]);

  if (isMicrosoftLoginSurfaceUrl(url)) {
    return {
      authenticated: false,
      requiresLogin: true,
      reason: 'microsoft_login_surface',
      strongAuthSignals,
      weakAuthSignals,
      loginSignals: dedupe([...loginSignals, 'login_surface']),
    };
  }

  if (!isMicrosoftAccountHomeUrl(url)) {
    return {
      authenticated: false,
      requiresLogin: false,
      reason: 'not_microsoft_account_home',
      strongAuthSignals,
      weakAuthSignals,
      loginSignals,
    };
  }

  const authenticated = loginSignals.length === 0 && (strongAuthSignals.length >= 2 || (strongAuthSignals.length >= 1 && weakAuthSignals.length >= 1));
  if (authenticated) {
    return {
      authenticated: true,
      requiresLogin: false,
      reason: 'authenticated_account_home',
      strongAuthSignals,
      weakAuthSignals,
      loginSignals,
    };
  }

  if (loginSignals.length > 0) {
    return {
      authenticated: false,
      requiresLogin: true,
      reason: 'account_home_login_required',
      strongAuthSignals,
      weakAuthSignals,
      loginSignals,
    };
  }

  return {
    authenticated: false,
    requiresLogin: false,
    reason: 'account_home_missing_authenticated_signals',
    strongAuthSignals,
    weakAuthSignals,
    loginSignals,
  };
}

export function formatMicrosoftAccountSurfaceSummary(
  input: MicrosoftAccountSurfaceSnapshot,
  assessment: MicrosoftAccountSurfaceAssessment,
): string {
  const parts = [
    `url=${input.url || ''}`,
    `reason=${assessment.reason}`,
    `strong=${assessment.strongAuthSignals.join('|') || '-'}`,
    `weak=${assessment.weakAuthSignals.join('|') || '-'}`,
    `login=${assessment.loginSignals.join('|') || '-'}`,
  ];
  return parts.join(' ');
}
