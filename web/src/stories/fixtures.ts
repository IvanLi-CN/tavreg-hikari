import type {
  AccountExtractHistoryBatch,
  AccountExtractorHistoryPayload,
  AccountExtractorProvider,
  AccountExtractorSettings,
  AccountRecord,
  AccountsPayload,
  ApiKeyRecord,
  ApiKeysPayload,
  EventRecord,
  JobSnapshot,
  MailboxMessageDetail,
  MailboxMessageSummary,
  MailboxRecord,
  MicrosoftGraphSettings,
  ProxyPayload,
} from "@/lib/app-types";

export const sampleJob: JobSnapshot = {
  job: {
    id: 17,
    status: "running",
    runMode: "headed",
    need: 5,
    parallel: 2,
    maxAttempts: 9,
    successCount: 2,
    failureCount: 1,
    skipCount: 1,
    launchedCount: 4,
    autoExtractSources: ["zhanghaoya", "shankeyun"],
    autoExtractQuantity: 2,
    autoExtractMaxWaitSec: 45,
    autoExtractAccountType: "outlook",
    startedAt: "2026-03-18T07:20:00.000Z",
    pausedAt: null,
    completedAt: null,
    lastError: null,
  },
  activeAttempts: [
    {
      id: 201,
      accountId: 1,
      accountEmail: "alpha@outlook.com",
      status: "running",
      stage: "extract_api_key",
      proxyNode: "Tokyo-01",
      proxyIp: "34.91.22.10",
      errorCode: null,
      errorMessage: null,
      startedAt: "2026-03-18T07:23:00.000Z",
      completedAt: null,
    },
  ],
  recentAttempts: [
    {
      id: 198,
      accountId: 4,
      accountEmail: "delta@outlook.com",
      status: "failed",
      stage: "oauth_redirect",
      proxyNode: "Seoul-02",
      proxyIp: "52.11.12.44",
      errorCode: "oauth-timeout",
      errorMessage: "OAuth redirect timed out",
      startedAt: "2026-03-18T07:18:00.000Z",
      completedAt: "2026-03-18T07:19:00.000Z",
    },
    {
      id: 197,
      accountId: 2,
      accountEmail: "beta@outlook.com",
      status: "completed",
      stage: "done",
      proxyNode: "Tokyo-01",
      proxyIp: "34.91.22.10",
      errorCode: null,
      errorMessage: null,
      startedAt: "2026-03-18T07:10:00.000Z",
      completedAt: "2026-03-18T07:14:00.000Z",
    },
  ],
  eligibleCount: 22,
  autoExtractState: {
    phase: "waiting",
    enabledSources: ["zhanghaoya", "shankeyun"],
    accountType: "outlook",
    currentRoundTarget: 2,
    acceptedCount: 1,
    rawAttemptCount: 2,
    attemptBudget: 5,
    inFlightCount: 1,
    remainingWaitSec: 31,
    maxWaitSec: 45,
    startedAt: "2026-03-18T07:24:00.000Z",
    lastProvider: "zhanghaoya",
    lastMessage: "账号鸭 accepted 1 usable account(s)",
    updatedAt: "2026-03-18T07:24:32.000Z",
  },
};

export const sampleEvents: EventRecord[] = [
  {
    type: "attempt.updated",
    timestamp: "2026-03-18T07:24:20.000Z",
    payload: {
      attemptId: 201,
      stage: "extract_api_key",
      proxyNode: "Tokyo-01",
    },
  },
  {
    type: "job.updated",
    timestamp: "2026-03-18T07:22:00.000Z",
    payload: {
      status: "running",
      successCount: 2,
      launchedCount: 4,
    },
  },
];

export const sampleAccounts = {
  total: 6,
  page: 1,
  pageSize: 20,
  summary: {
    ready: 1,
    linked: 1,
    failed: 1,
    disabled: 3,
  },
  groups: ["default", "linked", "failed-pool", "manual-hold", "retry-pool"],
  rows: [
    {
      id: 1,
      microsoftEmail: "alpha@outlook.com",
      passwordPlaintext: "pass-456",
      passwordMasked: "****s456",
      proofMailboxProvider: "moemail",
      proofMailboxAddress: "alpha-proof@mail-us.707079.xyz",
      proofMailboxId: "mailbox-alpha-001",
      hasApiKey: false,
      importedAt: "2026-03-18T07:00:00.000Z",
      updatedAt: "2026-03-18T07:23:00.000Z",
      importSource: "manual",
      accountSource: "manual",
      sourceRawPayload: null,
      lastUsedAt: null,
      lastResultStatus: "ready",
      lastResultAt: null,
      lastErrorCode: null,
      skipReason: null,
      groupName: "default",
      disabledAt: null,
      disabledReason: null,
      mailboxStatus: "preparing",
      mailboxLastSyncedAt: null,
      mailboxLastErrorCode: null,
      mailboxUnreadCount: 3,
      browserSession: {
        id: 101,
        status: "bootstrapping",
        profilePath: "/workspace/output/browser-profiles/accounts/1/chrome",
        browserEngine: "chrome",
        proxyNode: "Tokyo-01",
        proxyIp: "34.91.22.10",
        proxyCountry: "JP",
        proxyRegion: "Tokyo",
        proxyCity: "Tokyo",
        proxyTimezone: "Asia/Tokyo",
        lastBootstrappedAt: null,
        lastUsedAt: null,
        lastErrorCode: null,
        lastErrorMessage: null,
        createdAt: "2026-03-18T07:00:00.000Z",
        updatedAt: "2026-03-18T07:23:00.000Z",
      },
    },
    {
      id: 2,
      microsoftEmail: "beta@outlook.com",
      passwordPlaintext: "pass-789",
      passwordMasked: "****s789",
      proofMailboxProvider: "moemail",
      proofMailboxAddress: "beta-proof@mail-us.707079.xyz",
      proofMailboxId: "mailbox-beta-002",
      hasApiKey: true,
      importedAt: "2026-03-18T06:55:00.000Z",
      updatedAt: "2026-03-18T07:15:00.000Z",
      importSource: "manual",
      accountSource: "manual",
      sourceRawPayload: null,
      lastUsedAt: "2026-03-18T07:12:00.000Z",
      lastResultStatus: "succeeded",
      lastResultAt: "2026-03-18T07:14:00.000Z",
      lastErrorCode: null,
      skipReason: "has_api_key",
      groupName: "linked",
      disabledAt: null,
      disabledReason: null,
      mailboxStatus: "available",
      mailboxLastSyncedAt: "2026-03-18T07:16:00.000Z",
      mailboxLastErrorCode: null,
      mailboxUnreadCount: 0,
      browserSession: {
        id: 102,
        status: "ready",
        profilePath: "/workspace/output/browser-profiles/accounts/2/chrome",
        browserEngine: "chrome",
        proxyNode: "Tokyo-01",
        proxyIp: "34.91.22.10",
        proxyCountry: "JP",
        proxyRegion: "Tokyo",
        proxyCity: "Tokyo",
        proxyTimezone: "Asia/Tokyo",
        lastBootstrappedAt: "2026-03-18T07:11:00.000Z",
        lastUsedAt: "2026-03-18T07:12:00.000Z",
        lastErrorCode: null,
        lastErrorMessage: null,
        createdAt: "2026-03-18T06:55:00.000Z",
        updatedAt: "2026-03-18T07:16:00.000Z",
      },
    },
    {
      id: 3,
      microsoftEmail: "gamma@outlook.com",
      passwordPlaintext: "pass-111",
      passwordMasked: "****x111",
      proofMailboxProvider: null,
      proofMailboxAddress: null,
      proofMailboxId: null,
      hasApiKey: false,
      importedAt: "2026-03-18T06:30:00.000Z",
      updatedAt: "2026-03-18T07:05:00.000Z",
      importSource: "manual",
      accountSource: "shanyouxiang",
      sourceRawPayload: "gamma@outlook.com----pass-111",
      lastUsedAt: "2026-03-18T06:59:00.000Z",
      lastResultStatus: "disabled",
      lastResultAt: "2026-03-18T07:01:00.000Z",
      lastErrorCode: "microsoft_account_locked",
      skipReason: "microsoft_account_locked",
      groupName: "failed-pool",
      disabledAt: "2026-03-18T07:01:00.000Z",
      disabledReason: "Microsoft 账户已锁定",
      mailboxStatus: "locked",
      mailboxLastSyncedAt: "2026-03-18T06:58:00.000Z",
      mailboxLastErrorCode: "microsoft_account_locked",
      mailboxUnreadCount: 0,
      browserSession: {
        id: 103,
        status: "blocked",
        profilePath: "/workspace/output/browser-profiles/accounts/3/chrome",
        browserEngine: "chrome",
        proxyNode: "Seoul-02",
        proxyIp: "52.11.12.44",
        proxyCountry: "KR",
        proxyRegion: "Seoul",
        proxyCity: "Seoul",
        proxyTimezone: "Asia/Seoul",
        lastBootstrappedAt: "2026-03-18T06:40:00.000Z",
        lastUsedAt: "2026-03-18T06:59:00.000Z",
        lastErrorCode: "microsoft_account_locked",
        lastErrorMessage: "Microsoft 账户已锁定",
        createdAt: "2026-03-18T06:30:00.000Z",
        updatedAt: "2026-03-18T07:05:00.000Z",
      },
    },
    {
      id: 4,
      microsoftEmail: "delta@outlook.com",
      passwordPlaintext: "pass-999",
      passwordMasked: "****s999",
      proofMailboxProvider: "moemail",
      proofMailboxAddress: "delta-proof@mail-us.707079.xyz",
      proofMailboxId: "mailbox-delta-004",
      hasApiKey: false,
      importedAt: "2026-03-18T06:20:00.000Z",
      updatedAt: "2026-03-18T07:02:00.000Z",
      importSource: "manual",
      accountSource: "zhanghaoya",
      sourceRawPayload: "delta@outlook.com:pass-999",
      lastUsedAt: "2026-03-18T06:58:00.000Z",
      lastResultStatus: "failed",
      lastResultAt: "2026-03-18T07:02:00.000Z",
      lastErrorCode: "browser_proxy_ip_mismatch",
      skipReason: null,
      groupName: "retry-pool",
      disabledAt: null,
      disabledReason: null,
      mailboxStatus: "invalidated",
      mailboxLastSyncedAt: "2026-03-18T06:55:00.000Z",
      mailboxLastErrorCode: "oauth_timeout",
      mailboxUnreadCount: 0,
      browserSession: {
        id: 104,
        status: "failed",
        profilePath: "/workspace/output/browser-profiles/accounts/4/chrome",
        browserEngine: "chrome",
        proxyNode: "Tokyo-02",
        proxyIp: "34.91.22.55",
        proxyCountry: "JP",
        proxyRegion: "Tokyo",
        proxyCity: "Tokyo",
        proxyTimezone: "Asia/Tokyo",
        lastBootstrappedAt: "2026-03-18T06:50:00.000Z",
        lastUsedAt: "2026-03-18T06:58:00.000Z",
        lastErrorCode: "oauth_timeout",
        lastErrorMessage: "OAuth redirect timed out",
        createdAt: "2026-03-18T06:20:00.000Z",
        updatedAt: "2026-03-18T07:02:00.000Z",
      },
    },
    {
      id: 5,
      microsoftEmail: "omega@outlook.com",
      passwordPlaintext: "pass-222",
      passwordMasked: "****x222",
      proofMailboxProvider: null,
      proofMailboxAddress: null,
      proofMailboxId: null,
      hasApiKey: false,
      importedAt: "2026-03-18T06:10:00.000Z",
      updatedAt: "2026-03-18T06:48:00.000Z",
      importSource: "manual",
      accountSource: "manual",
      sourceRawPayload: null,
      lastUsedAt: "2026-03-18T06:40:00.000Z",
      lastResultStatus: "disabled",
      lastResultAt: "2026-03-18T06:48:00.000Z",
      lastErrorCode: "microsoft_password_incorrect",
      skipReason: "microsoft_password_incorrect",
      groupName: "failed-pool",
      disabledAt: null,
      disabledReason: null,
      mailboxStatus: "invalidated",
      mailboxLastSyncedAt: null,
      mailboxLastErrorCode: "microsoft_password_incorrect",
      mailboxUnreadCount: 0,
      browserSession: {
        id: 105,
        status: "blocked",
        profilePath: "/workspace/output/browser-profiles/accounts/5/chrome",
        browserEngine: "chrome",
        proxyNode: "Osaka-03",
        proxyIp: "41.22.18.90",
        proxyCountry: "JP",
        proxyRegion: "Osaka",
        proxyCity: "Osaka",
        proxyTimezone: "Asia/Tokyo",
        lastBootstrappedAt: "2026-03-18T06:38:00.000Z",
        lastUsedAt: "2026-03-18T06:40:00.000Z",
        lastErrorCode: "microsoft_password_incorrect",
        lastErrorMessage: "Microsoft password incorrect",
        createdAt: "2026-03-18T06:10:00.000Z",
        updatedAt: "2026-03-18T06:48:00.000Z",
      },
    },
    {
      id: 6,
      microsoftEmail: "manual-hold@outlook.com",
      passwordPlaintext: "pass-333",
      passwordMasked: "****d333",
      proofMailboxProvider: "moemail",
      proofMailboxAddress: "manual-proof@mail-us.707079.xyz",
      proofMailboxId: "mailbox-manual-006",
      hasApiKey: false,
      importedAt: "2026-03-18T05:55:00.000Z",
      updatedAt: "2026-03-18T06:46:00.000Z",
      importSource: "manual",
      accountSource: "manual",
      sourceRawPayload: null,
      lastUsedAt: "2026-03-18T06:35:00.000Z",
      lastResultStatus: "disabled",
      lastResultAt: "2026-03-18T06:46:00.000Z",
      lastErrorCode: null,
      skipReason: null,
      groupName: "manual-hold",
      disabledAt: "2026-03-18T06:46:00.000Z",
      disabledReason: "人工复核中",
      mailboxStatus: "available",
      mailboxLastSyncedAt: "2026-03-18T06:44:00.000Z",
      mailboxLastErrorCode: null,
      mailboxUnreadCount: 2,
      browserSession: {
        id: 106,
        status: "ready",
        profilePath: "/workspace/output/browser-profiles/accounts/6/chrome",
        browserEngine: "chrome",
        proxyNode: "Tokyo-03",
        proxyIp: "34.91.88.10",
        proxyCountry: "JP",
        proxyRegion: "Tokyo",
        proxyCity: "Tokyo",
        proxyTimezone: "Asia/Tokyo",
        lastBootstrappedAt: "2026-03-18T06:30:00.000Z",
        lastUsedAt: "2026-03-18T06:35:00.000Z",
        lastErrorCode: null,
        lastErrorMessage: null,
        createdAt: "2026-03-18T05:55:00.000Z",
        updatedAt: "2026-03-18T06:46:00.000Z",
      },
    },
  ],
} satisfies AccountsPayload;

export const sampleMicrosoftGraphSettings: MicrosoftGraphSettings = {
  microsoftGraphClientId: "7c7740fd-43e6-4a19-a0ef-6a921d54b102",
  microsoftGraphClientSecretMasked: "************c0de",
  microsoftGraphRedirectUri: "https://tavreg-hikari.ivanli.cc/api/microsoft-mail/oauth/callback",
  microsoftGraphAuthority: "common",
  configured: true,
};

export const sampleMailboxes: MailboxRecord[] = [
  {
    id: 101,
    accountId: 1,
    microsoftEmail: "alpha@outlook.com",
    groupName: "default",
    proofMailboxAddress: "alpha-proof@mail-us.707079.xyz",
    status: "preparing",
    syncEnabled: true,
    graphUserId: null,
    graphUserPrincipalName: null,
    graphDisplayName: null,
    authority: "common",
    oauthStartedAt: null,
    oauthConnectedAt: null,
    deltaLink: null,
    unreadCount: 3,
    lastSyncedAt: null,
    lastErrorCode: null,
    lastErrorMessage: null,
    createdAt: "2026-03-18T07:00:00.000Z",
    updatedAt: "2026-03-18T07:23:00.000Z",
    isAuthorized: false,
  },
  {
    id: 102,
    accountId: 2,
    microsoftEmail: "beta@outlook.com",
    groupName: "linked",
    proofMailboxAddress: "beta-proof@mail-us.707079.xyz",
    status: "available",
    syncEnabled: true,
    graphUserId: "graph-user-beta",
    graphUserPrincipalName: "beta@outlook.com",
    graphDisplayName: "Beta",
    authority: "common",
    oauthStartedAt: null,
    oauthConnectedAt: "2026-03-18T07:13:00.000Z",
    deltaLink: "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$deltatoken=beta",
    unreadCount: 1,
    lastSyncedAt: "2026-03-18T07:16:00.000Z",
    lastErrorCode: null,
    lastErrorMessage: null,
    createdAt: "2026-03-18T06:55:00.000Z",
    updatedAt: "2026-03-18T07:16:00.000Z",
    isAuthorized: true,
  },
  {
    id: 103,
    accountId: 3,
    microsoftEmail: "gamma@outlook.com",
    groupName: "failed-pool",
    proofMailboxAddress: null,
    status: "locked",
    syncEnabled: true,
    graphUserId: "graph-user-gamma",
    graphUserPrincipalName: "gamma@outlook.com",
    graphDisplayName: "Gamma",
    authority: "common",
    oauthStartedAt: null,
    oauthConnectedAt: "2026-03-18T06:20:00.000Z",
    deltaLink: null,
    unreadCount: 0,
    lastSyncedAt: "2026-03-18T06:58:00.000Z",
    lastErrorCode: "microsoft_account_locked",
    lastErrorMessage: "Microsoft 账户已锁定",
    createdAt: "2026-03-18T06:30:00.000Z",
    updatedAt: "2026-03-18T07:05:00.000Z",
    isAuthorized: true,
  },
];

export const sampleMailboxMessages: MailboxMessageSummary[] = [
  {
    id: 301,
    mailboxId: 102,
    graphMessageId: "graph-msg-301",
    internetMessageId: "<msg-301@example.com>",
    conversationId: "conv-1",
    subject: "Your verification code",
    fromName: "Microsoft account team",
    fromAddress: "account-security-noreply@account.microsoft.com",
    receivedAt: "2026-03-18T07:15:00.000Z",
    isRead: false,
    hasAttachments: false,
    bodyContentType: "html",
    bodyPreview: "Use 824631 as your Microsoft account verification code.",
    webLink: "https://outlook.office.com/mail/id/graph-msg-301",
    updatedAt: "2026-03-18T07:15:10.000Z",
  },
  {
    id: 302,
    mailboxId: 102,
    graphMessageId: "graph-msg-302",
    internetMessageId: "<msg-302@example.com>",
    conversationId: "conv-2",
    subject: "Welcome to Outlook",
    fromName: "Outlook",
    fromAddress: "welcome@outlook.com",
    receivedAt: "2026-03-18T06:00:00.000Z",
    isRead: true,
    hasAttachments: false,
    bodyContentType: "text",
    bodyPreview: "Thanks for trying the new inbox experience.",
    webLink: "https://outlook.office.com/mail/id/graph-msg-302",
    updatedAt: "2026-03-18T06:00:05.000Z",
  },
];

const firstSampleMailboxMessage = sampleMailboxMessages[0]!;

export const sampleMailboxMessageDetail: MailboxMessageDetail = {
  ...firstSampleMailboxMessage,
  bodyContent:
    "<div><p>Hello Beta,</p><p>Your verification code is <strong>824631</strong>.</p><p>This code expires in 10 minutes.</p></div>",
};

export const sampleApiKeys: ApiKeysPayload = {
  total: 2,
  page: 1,
  pageSize: 20,
  summary: {
    active: 1,
    revoked: 1,
  },
  groups: ["linked", "ops"],
  rows: [
    {
      id: 1,
      accountId: 2,
      microsoftEmail: "beta@outlook.com",
      groupName: "linked",
      apiKeyMasked: "tvly-****-af3x",
      apiKeyPrefix: "tvly-prod",
      status: "active",
      extractedAt: "2026-03-18T07:14:00.000Z",
      lastVerifiedAt: "2026-03-18T07:16:00.000Z",
    },
    {
      id: 2,
      accountId: 5,
      microsoftEmail: "omega@outlook.com",
      groupName: "ops",
      apiKeyMasked: "tvly-****-mm9p",
      apiKeyPrefix: "tvly-sbx",
      status: "revoked",
      extractedAt: "2026-03-17T15:40:00.000Z",
      lastVerifiedAt: "2026-03-18T00:10:00.000Z",
    },
  ],
};

export const sampleProxies: ProxyPayload = {
  settings: {
    subscriptionUrl: "https://example.com/subscription.yaml",
    groupName: "Auto",
    routeGroupName: "Global",
    checkUrl: "https://www.gstatic.com/generate_204",
    timeoutMs: 1000,
    maxLatencyMs: 480,
    apiPort: 9090,
    mixedPort: 7890,
    serverHost: "127.0.0.1",
    serverPort: 9090,
    defaultRunMode: "headed",
    defaultNeed: 5,
    defaultParallel: 2,
    defaultMaxAttempts: 9,
  },
  selectedName: "Tokyo-01",
  nodes: [
    {
      id: 1,
      nodeName: "Tokyo-01",
      isSelected: true,
      lastStatus: "active",
      lastLatencyMs: 184,
      lastEgressIp: "34.91.22.10",
      lastCountry: "Japan",
      lastRegion: "Tokyo",
      lastCity: "Tokyo",
      lastOrg: "ExampleNet",
      lastCheckedAt: "2026-03-18T07:20:00.000Z",
      lastSelectedAt: "2026-03-18T07:18:00.000Z",
      lastLeasedAt: "2026-03-18T07:23:00.000Z",
      success24h: 8,
    },
    {
      id: 2,
      nodeName: "Seoul-02",
      isSelected: false,
      lastStatus: "warning",
      lastLatencyMs: 531,
      lastEgressIp: "52.11.12.44",
      lastCountry: "South Korea",
      lastRegion: "Seoul",
      lastCity: "Seoul",
      lastOrg: "TransitCloud",
      lastCheckedAt: "2026-03-18T07:19:00.000Z",
      lastSelectedAt: null,
      lastLeasedAt: "2026-03-18T06:40:00.000Z",
      success24h: 2,
    },
  ],
};

export const sampleExtractorSettings: AccountExtractorSettings = {
  extractorZhanghaoyaKey: "zhya-demo-key-001",
  extractorShanyouxiangKey: "shan-demo-key-001",
  extractorShankeyunKey: "shanke-demo-key-001",
  extractorHotmail666Key: "hotmail666-demo-key-001",
  defaultAutoExtractSources: ["zhanghaoya", "hotmail666"],
  defaultAutoExtractQuantity: 1,
  defaultAutoExtractMaxWaitSec: 60,
  defaultAutoExtractAccountType: "outlook",
  availability: {
    zhanghaoya: true,
    shanyouxiang: true,
    shankeyun: true,
    hotmail666: false,
  },
};

export const sampleExtractorHistory: AccountExtractorHistoryPayload = {
  total: 4,
  page: 1,
  pageSize: 10,
  rows: [
    {
      id: 11,
      jobId: 17,
      provider: "zhanghaoya",
      accountType: "outlook",
      requestedUsableCount: 1,
      attemptBudget: 4,
      acceptedCount: 1,
      status: "accepted",
      errorMessage: null,
      rawResponse: "{\"Code\":200,\"Message\":\"Success\",\"Data\":\"fresh@outlook.com:pass-777\"}",
      maskedKey: "zhya********0001",
      startedAt: "2026-03-18T07:24:00.000Z",
      completedAt: "2026-03-18T07:24:01.000Z",
      items: [
        {
          id: 101,
          batchId: 11,
          provider: "zhanghaoya",
          rawPayload: "fresh@outlook.com:pass-777",
          email: "fresh@outlook.com",
          password: "pass-777",
          parseStatus: "parsed",
          acceptStatus: "accepted",
          rejectReason: null,
          importedAccountId: 51,
          createdAt: "2026-03-18T07:24:01.000Z",
        },
      ],
    },
    {
      id: 10,
      jobId: 17,
      provider: "shanyouxiang",
      accountType: "outlook",
      requestedUsableCount: 1,
      attemptBudget: 4,
      acceptedCount: 0,
      status: "rejected",
      errorMessage: "already_attempted",
      rawResponse: "retry@outlook.com----pass-123",
      maskedKey: "shan********0001",
      startedAt: "2026-03-18T07:23:00.000Z",
      completedAt: "2026-03-18T07:23:01.000Z",
      items: [
        {
          id: 100,
          batchId: 10,
          provider: "shanyouxiang",
          rawPayload: "retry@outlook.com----pass-123",
          email: "retry@outlook.com",
          password: "pass-123",
          parseStatus: "parsed",
          acceptStatus: "rejected",
          rejectReason: "already_attempted",
          importedAccountId: 3,
          createdAt: "2026-03-18T07:23:01.000Z",
        },
      ],
    },
    {
      id: 9,
      jobId: 17,
      provider: "shankeyun",
      accountType: "outlook",
      requestedUsableCount: 1,
      attemptBudget: 4,
      acceptedCount: 1,
      status: "accepted",
      errorMessage: null,
      rawResponse: "fresh-sk@outlook.com----pass-999--------refresh-token----client-id",
      maskedKey: "shan********0002",
      startedAt: "2026-03-18T07:22:00.000Z",
      completedAt: "2026-03-18T07:22:01.000Z",
      items: [
        {
          id: 99,
          batchId: 9,
          provider: "shankeyun",
          rawPayload: "fresh-sk@outlook.com----pass-999--------refresh-token----client-id",
          email: "fresh-sk@outlook.com",
          password: "pass-999",
          parseStatus: "parsed",
          acceptStatus: "accepted",
          rejectReason: null,
          importedAccountId: 52,
          createdAt: "2026-03-18T07:22:01.000Z",
        },
      ],
    },
    {
      id: 8,
      jobId: 17,
      provider: "hotmail666",
      accountType: "outlook",
      requestedUsableCount: 1,
      attemptBudget: 4,
      acceptedCount: 0,
      status: "insufficient_stock",
      errorMessage: "剩余次数不足，当前剩余: 0",
      rawResponse: "{\"success\":false,\"message\":\"剩余次数不足，当前剩余: 0\"}",
      maskedKey: "hotm********0001",
      startedAt: "2026-03-18T07:21:00.000Z",
      completedAt: "2026-03-18T07:21:01.000Z",
      items: [],
    },
  ],
};

const extractorStatusCycle = [
  "insufficient_stock",
  "rejected",
  "accepted",
  "invalid_key",
  "parse_failed",
  "error",
] as const satisfies readonly AccountExtractHistoryBatch["status"][];

function repeatSegment(prefix: string, seed: number, count: number): string {
  return Array.from({ length: count }, (_, index) => `${prefix}-${seed}-${index}-${"X".repeat((index % 5) + 8)}`).join(" | ");
}

function buildExtractorMaskedKey(provider: AccountExtractorProvider, batchId: number): string {
  const prefix = provider === "zhanghaoya" ? "zhya" : "shan";
  return `${prefix}${String(batchId).padStart(4, "0")}${"*".repeat(30)}${String(batchId).padStart(4, "0")}`;
}

function buildExtractorErrorMessage(status: AccountExtractHistoryBatch["status"], batchId: number): string | null {
  if (status === "accepted") return null;
  if (status === "insufficient_stock") {
    return `库存不足，当前批次无法满足 requested 数量。${repeatSegment("stock", batchId, 8)}`;
  }
  if (status === "rejected") {
    return `存在重复、已尝试或不符合当前 job 约束的账号。${repeatSegment("reject", batchId, 7)}`;
  }
  if (status === "invalid_key") {
    return `站点 KEY 校验失败，请重新保存后再尝试。${repeatSegment("key", batchId, 6)}`;
  }
  if (status === "parse_failed") {
    return `上游返回存在不可解析原始行，已保留原始负载用于排查。${repeatSegment("parse", batchId, 7)}`;
  }
  return `站点返回了非预期错误，请稍后重试。${repeatSegment("provider", batchId, 8)}`;
}

function buildExtractorRawResponse(status: AccountExtractHistoryBatch["status"], batchId: number): string | null {
  if (status === "invalid_key") {
    return JSON.stringify({
      status: -1,
      msg: "invalid_key",
      detail: repeatSegment("invalid-key", batchId, 12),
    });
  }
  if (status === "accepted") {
    return JSON.stringify({
      status: 0,
      msg: "ok",
      data: {
        mails: Array.from({ length: 3 }, (_, index) => ({
          email: `batch${batchId}-usable-${index}@outlook.com`,
          password: `A${batchId}-${index}-${"P".repeat(5)}`,
        })),
      },
      trace: repeatSegment("accepted-trace", batchId, 14),
    });
  }
  return JSON.stringify({
    status: -1,
    msg: status,
    detail: repeatSegment(`detail-${status}`, batchId, 16),
    trace: repeatSegment(`trace-${status}`, batchId + 1, 16),
  });
}

export function createSampleExtractorHistory(options?: {
  total?: number;
  page?: number;
  pageSize?: number;
  rowCount?: number;
  statuses?: Array<AccountExtractHistoryBatch["status"]>;
}): AccountExtractorHistoryPayload {
  const page = options?.page ?? 1;
  const pageSize = options?.pageSize ?? 10;
  const rowCount = Math.max(0, Math.min(options?.rowCount ?? pageSize, pageSize));
  const total = options?.total ?? 6862;
  const statuses: readonly AccountExtractHistoryBatch["status"][] = options?.statuses?.length ? options.statuses : extractorStatusCycle;

  return {
    total,
    page,
    pageSize,
    rows: Array.from({ length: rowCount }, (_, index) => {
      const batchId = 6861 - (page - 1) * pageSize - index;
      const provider: AccountExtractorProvider = index % 2 === 0 ? "shanyouxiang" : "zhanghaoya";
      const status = statuses[index % statuses.length] as AccountExtractHistoryBatch["status"];
      const requestedUsableCount = (index % 4) + 1;
      const itemCount = status === "invalid_key" || status === "insufficient_stock" ? 0 : (index % 7) || 6;
      const acceptedCount = status === "accepted" ? Math.max(1, Math.min(requestedUsableCount, Math.max(1, itemCount - 1))) : 0;

      return {
        id: batchId,
        jobId: 123,
        provider,
        accountType: "outlook",
        requestedUsableCount,
        attemptBudget: requestedUsableCount + 3 + (index % 3),
        acceptedCount,
        status,
        errorMessage: buildExtractorErrorMessage(status, batchId),
        rawResponse: buildExtractorRawResponse(status, batchId),
        maskedKey: buildExtractorMaskedKey(provider, batchId),
        startedAt: `2026-03-27T19:${String(10 + index).padStart(2, "0")}:54.000Z`,
        completedAt: `2026-03-27T19:${String(11 + index).padStart(2, "0")}:12.000Z`,
        items: Array.from({ length: itemCount }, (_, itemIndex) => {
          const parseStatus = status === "parse_failed" && itemIndex >= Math.max(1, itemCount - 2) ? "invalid" : "parsed";
          const acceptStatus = parseStatus === "parsed" && itemIndex < acceptedCount ? "accepted" : "rejected";
          const email = parseStatus === "invalid" ? null : `batch${batchId}-candidate-${itemIndex}@${itemIndex % 2 === 0 ? "outlook.com" : "hotmail.com"}`;
          const password = parseStatus === "invalid" ? null : `P${batchId}-${itemIndex}-${"K".repeat(6)}`;

          return {
            id: batchId * 10 + itemIndex,
            batchId,
            provider,
            rawPayload:
              parseStatus === "invalid"
                ? `RAW-LINE-${batchId}-${itemIndex} :: ${repeatSegment("raw-invalid", batchId + itemIndex, 12)}`
                : `${email}:${password} :: ${repeatSegment("raw", batchId + itemIndex, 10)}`,
            email,
            password,
            parseStatus,
            acceptStatus,
            rejectReason:
              acceptStatus === "accepted"
                ? null
                : status === "rejected"
                  ? `already_attempted :: ${repeatSegment("reject-reason", batchId + itemIndex, 8)}`
                  : status === "parse_failed"
                    ? `parse_failed :: ${repeatSegment("parse-reason", batchId + itemIndex, 7)}`
                    : status === "error"
                      ? `provider_error :: ${repeatSegment("provider-reason", batchId + itemIndex, 8)}`
                      : status === "invalid_key"
                        ? "invalid_key"
                        : "insufficient_stock",
            importedAccountId: acceptStatus === "accepted" ? batchId + itemIndex : null,
            createdAt: `2026-03-27T19:${String(12 + index).padStart(2, "0")}:${String(10 + itemIndex).padStart(2, "0")}.000Z`,
          };
        }),
      };
    }),
  };
}

export const sampleExtractorHistoryDense = createSampleExtractorHistory();

export const sampleExtractorHistoryFailureMatrix = createSampleExtractorHistory({
  total: 126,
  rowCount: 6,
  statuses: ["insufficient_stock", "rejected", "invalid_key", "parse_failed", "error"],
});

export const sampleExtractorHistoryEmpty: AccountExtractorHistoryPayload = {
  total: 0,
  page: 1,
  pageSize: 10,
  rows: [],
};
