export type PageKey = "dashboard" | "accounts" | "apiKeys" | "proxies";
export type ProviderTarget = "tavily" | "chatgpt";
export type ArtifactType = "api_key" | "access_token";

export type JobStatus = "idle" | "running" | "paused" | "completing" | "completed" | "failed";

export type AccountTargetState = {
  target: ProviderTarget;
  status: string;
  hasArtifact: boolean;
  artifactId: number | null;
  artifactType: ArtifactType | null;
  artifactPreview: string | null;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: string | null;
};

export type AccountRecord = {
  id: number;
  microsoftEmail: string;
  passwordPlaintext?: string | null;
  passwordMasked: string;
  hasApiKey: boolean;
  importedAt: string;
  updatedAt: string;
  importSource: string;
  lastUsedAt: string | null;
  lastResultStatus: string;
  lastResultAt: string | null;
  lastErrorCode: string | null;
  skipReason: string | null;
  groupName: string | null;
  disabledAt: string | null;
  targetStates: Record<ProviderTarget, AccountTargetState>;
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

export type ApiKeyRecord = {
  id: number;
  accountId: number;
  microsoftEmail: string;
  apiKeyMasked: string;
  apiKeyPrefix: string;
  status: string;
  extractedAt: string;
  lastVerifiedAt: string | null;
};

export type ArtifactRecord = {
  id: number;
  accountId: number;
  microsoftEmail: string;
  target: ProviderTarget;
  artifactType: ArtifactType;
  preview: string;
  status: string;
  extractedAt: string;
  lastVerifiedAt: string | null;
  metadataJson: string | null;
};

export type ApiKeysPayload = {
  rows: ArtifactRecord[];
  total: number;
  page: number;
  pageSize: number;
  summary: {
    active: number;
    revoked: number;
  };
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
  target: ProviderTarget | null;
  sequenceIndex: number;
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
    startedAt: string;
    pausedAt: string | null;
    completedAt: string | null;
    lastError: string | null;
    targets: ProviderTarget[];
  };
  activeAttempts: AttemptRecord[];
  recentAttempts: AttemptRecord[];
  eligibleCount: number;
  completedTargetSteps: number;
  totalTargetSteps: number;
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
  targets: ProviderTarget[];
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
  target: string;
  artifactType: string;
  page: number;
  pageSize: number;
};

export type ProxyCheckScope = "current" | "all";
