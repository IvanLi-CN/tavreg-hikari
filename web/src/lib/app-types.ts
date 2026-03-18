export type PageKey = "dashboard" | "accounts" | "apiKeys" | "proxies";

export type JobStatus = "idle" | "running" | "paused" | "completing" | "completed" | "failed";

export type AccountRecord = {
  id: number;
  microsoftEmail: string;
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
  disabledAt: string | null;
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
    startedAt: string;
    pausedAt: string | null;
    completedAt: string | null;
    lastError: string | null;
  };
  activeAttempts: AttemptRecord[];
  recentAttempts: AttemptRecord[];
  eligibleCount: number;
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
};

export type AccountQuery = {
  q: string;
  status: string;
  hasApiKey: string;
};

export type ApiKeyQuery = {
  q: string;
  status: string;
};

export type ProxyCheckScope = "current" | "all";
