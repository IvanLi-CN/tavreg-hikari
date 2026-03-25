export type PageKey = "dashboard" | "accounts" | "apiKeys" | "proxies";

export type JobStatus = "idle" | "running" | "paused" | "completing" | "completed" | "failed";
export type AccountExtractorProvider = "zhanghaoya" | "shanyouxiang";
export type AccountExtractorAccountType = "outlook";

export type AccountRecord = {
  id: number;
  microsoftEmail: string;
  passwordPlaintext?: string | null;
  passwordMasked: string;
  proofMailboxProvider: "moemail" | null;
  proofMailboxAddress: string | null;
  proofMailboxId: string | null;
  hasApiKey: boolean;
  importedAt: string;
  updatedAt: string;
  importSource: string;
  accountSource: "manual" | "zhanghaoya" | "shanyouxiang";
  sourceRawPayload: string | null;
  lastUsedAt: string | null;
  lastResultStatus: string;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: string | null;
  groupName: string | null;
  disabledAt: string | null;
  disabledReason: string | null;
};

export type AccountsPayload = {
  rows: AccountRecord[];
  total: number;
  page: number;
  pageSize: number;
  summary: {
    ready: number;
    linked: number;
    failed: number;
    disabled: number;
  };
  groups: string[];
};

export type ImportDecision = "create" | "update_password" | "keep_existing" | "input_duplicate" | "invalid";

export type AccountImportPreviewItem = {
  lineNumber: number;
  rawLine: string;
  email: string;
  normalizedEmail: string;
  password: string;
  decision: ImportDecision;
  note: string;
  duplicateOfLine?: number;
  existingAccountId?: number;
  existingHasApiKey?: boolean;
  groupName?: string | null;
};

export type AccountImportPreviewPayload = {
  items: AccountImportPreviewItem[];
  effectiveEntries: Array<{ email: string; password: string }>;
  summary: {
    parsed: number;
    invalid: number;
    create: number;
    updatePassword: number;
    keepExisting: number;
    inputDuplicate: number;
  };
};

export type AccountImportPayload = {
  summary: {
    created: number;
    updated: number;
    total: number;
  };
  affectedIds: number[];
  revealedAccounts: Array<{
    id: number;
    microsoftEmail: string;
    passwordPlaintext: string;
    passwordMasked: string;
  }>;
};

export type AccountProofMailboxUpdatePayload = {
  ok: true;
  account: AccountRecord;
};

export type AccountUpdatePayload = {
  ok: true;
  account: AccountRecord;
};

export type ApiKeyRecord = {
  id: number;
  accountId: number;
  microsoftEmail: string;
  groupName: string | null;
  apiKeyMasked: string;
  apiKeyPrefix: string;
  status: string;
  extractedAt: string;
  lastVerifiedAt: string | null;
};

export type ApiKeysPayload = {
  rows: ApiKeyRecord[];
  total: number;
  page: number;
  pageSize: number;
  summary: {
    active: number;
    revoked: number;
  };
  groups: string[];
};

export type ApiKeyExportItem = {
  id: number;
  apiKey: string;
  extractedIp: string | null;
};

export type ApiKeyExportPayload = {
  items: ApiKeyExportItem[];
  content: string;
};

export type AttemptRecord = {
  id: number;
  accountId: number;
  accountEmail: string | null;
  status: string;
  stage: string;
  proxyNode: string | null;
  proxyIp: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  startedAt: string;
  completedAt: string | null;
};

export type JobSnapshot = {
  job: null | {
    id: number;
    status: JobStatus;
    runMode: "headed" | "headless";
    need: number;
    parallel: number;
    maxAttempts: number;
    successCount: number;
    failureCount: number;
    skipCount: number;
    launchedCount: number;
    autoExtractSources: AccountExtractorProvider[];
    autoExtractQuantity: number;
    autoExtractMaxWaitSec: number;
    autoExtractAccountType: AccountExtractorAccountType;
    startedAt: string;
    pausedAt: string | null;
    completedAt: string | null;
    lastError: string | null;
  };
  activeAttempts: AttemptRecord[];
  recentAttempts: AttemptRecord[];
  eligibleCount: number;
  autoExtractState: AutoExtractState | null;
};

export type AutoExtractState = {
  phase: "idle" | "waiting" | "extracting";
  enabledSources: AccountExtractorProvider[];
  accountType: AccountExtractorAccountType;
  currentRoundTarget: number;
  acceptedCount: number;
  rawAttemptCount: number;
  attemptBudget: number;
  remainingWaitSec: number;
  maxWaitSec: number;
  startedAt: string | null;
  lastProvider: AccountExtractorProvider | null;
  lastMessage: string | null;
  updatedAt: string | null;
};

export type ProxySettings = {
  subscriptionUrl: string;
  groupName: string;
  routeGroupName: string;
  checkUrl: string;
  timeoutMs: number;
  maxLatencyMs: number;
  apiPort: number;
  mixedPort: number;
  serverHost: string;
  serverPort: number;
  defaultRunMode: "headed" | "headless";
  defaultNeed: number;
  defaultParallel: number;
  defaultMaxAttempts: number;
};

export type ProxyNode = {
  id: number;
  nodeName: string;
  isSelected: boolean;
  lastStatus: string | null;
  lastLatencyMs: number | null;
  lastEgressIp: string | null;
  lastCountry: string | null;
  lastCity: string | null;
  lastOrg: string | null;
  lastCheckedAt: string | null;
  lastSelectedAt: string | null;
  success24h: number;
};

export type ProxyPayload = {
  settings: ProxySettings;
  selectedName: string | null;
  nodes: ProxyNode[];
  syncError?: string | null;
};

export type EventRecord = {
  type: string;
  timestamp: string;
  payload: Record<string, unknown>;
};

export type JobDraft = {
  runMode: "headed" | "headless";
  need: number;
  parallel: number;
  maxAttempts: number;
  autoExtractSources: AccountExtractorProvider[];
  autoExtractQuantity: number;
  autoExtractMaxWaitSec: number;
  autoExtractAccountType: AccountExtractorAccountType;
};

export type AccountExtractorSettings = {
  extractorZhanghaoyaKey: string;
  extractorShanyouxiangKey: string;
  defaultAutoExtractSources: AccountExtractorProvider[];
  defaultAutoExtractQuantity: number;
  defaultAutoExtractMaxWaitSec: number;
  defaultAutoExtractAccountType: AccountExtractorAccountType;
  availability: {
    zhanghaoya: boolean;
    shanyouxiang: boolean;
  };
};

export type AccountExtractorSettingsPayload = {
  ok: true;
  settings: AccountExtractorSettings;
};

export type AccountExtractHistoryItem = {
  id: number;
  batchId: number;
  provider: AccountExtractorProvider;
  rawPayload: string;
  email: string | null;
  password: string | null;
  parseStatus: "parsed" | "invalid";
  acceptStatus: "accepted" | "rejected";
  rejectReason: string | null;
  importedAccountId: number | null;
  createdAt: string;
};

export type AccountExtractHistoryBatch = {
  id: number;
  jobId: number | null;
  provider: AccountExtractorProvider;
  accountType: AccountExtractorAccountType;
  requestedUsableCount: number;
  attemptBudget: number;
  acceptedCount: number;
  status: "accepted" | "rejected" | "invalid_key" | "insufficient_stock" | "parse_failed" | "error";
  errorMessage: string | null;
  rawResponse: string | null;
  maskedKey: string | null;
  startedAt: string;
  completedAt: string | null;
  items: AccountExtractHistoryItem[];
};

export type AccountExtractorHistoryPayload = {
  rows: AccountExtractHistoryBatch[];
  total: number;
  page: number;
  pageSize: number;
};

export type AccountExtractorHistoryQuery = {
  provider: "" | AccountExtractorProvider;
  status: string;
  q: string;
  page: number;
  pageSize: number;
};

export type AccountQuery = {
  q: string;
  status: string;
  hasApiKey: string;
  groupName: string;
  page: number;
  pageSize: number;
};

export type ApiKeyQuery = {
  q: string;
  status: string;
  groupName: string;
  page: number;
  pageSize: number;
};

export type ProxyCheckScope = "current" | "all";
