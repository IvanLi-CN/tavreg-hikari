import { useEffect, useMemo, useRef, useState } from "react";
import { AccountsView } from "@/components/accounts-view";
import { AppShell } from "@/components/app-shell";
import {
  ChatGptUpstreamSettingsDialog,
  type ChatGptUpstreamSettingsDialogDraft,
} from "@/components/chatgpt-upstream-settings-dialog";
import { ChatGptView } from "@/components/chatgpt-view";
import { DashboardView } from "@/components/dashboard-view";
import { GrokView } from "@/components/grok-view";
import { KeysView } from "@/components/keys-view";
import { MailboxSettingsView } from "@/components/mailbox-settings-view";
import { MailboxesView } from "@/components/mailboxes-view";
import { ProxiesView } from "@/components/proxies-view";
import { buildImportCommitEntries, parseImportContent } from "@/lib/account-import";
import { buildApiKeyExportFilename } from "@/lib/api-key-export";
import { createDefaultAccountQuery } from "@/lib/account-query";
import { pickProxySettingsUpdate } from "@/lib/app-types";
import { buildCodexVibeMonitorCredentialJson } from "@/lib/chatgpt-credential-format";
import type {
  AccountBatchBootstrapMode,
  AccountBatchBootstrapPreviewPayload,
  AccountRecord,
  AccountExtractorHistoryPayload,
  AccountExtractorHistoryQuery,
  AccountExtractorRunDraft,
  AccountExtractorRuntime,
  AccountExtractorRuntimePayload,
  AccountExtractorSettings,
  AccountExtractorSettingsPayload,
  AccountImportPayload,
  AccountImportPreviewPayload,
  AccountSessionRebootstrapRequest,
  AccountUpdatePayload,
  AccountQuery,
  AccountsPayload,
  ChatGptCredentialDetailPayload,
  ChatGptCredentialRecord,
  ChatGptCredentialQuery,
  ChatGptCredentialSort,
  ChatGptCredentialsPayload,
  ChatGptJobDraft,
  ChatGptCredentialSupplementPayload,
  ChatGptUpstreamSettings,
  ChatGptUpstreamSettingsPayload,
  ChatGptUpstreamSettingsUpdate,
  GrokApiKeyExportPayload,
  GrokApiKeyQuery,
  GrokApiKeysPayload,
  ApiKeyExportPayload,
  ApiKeysPayload,
  ApiKeyQuery,
  EventRecord,
  ExtractorSseState,
  JobControlAction,
  JobControlOptions,
  JobDraft,
  JobSnapshot,
  MailboxMessageDetail,
  MailboxMessageDetailPayload,
  MailboxMessageSummary,
  MailboxMessagesPayload,
  MailboxRecord,
  MailboxesPayload,
  MailboxSyncPayload,
  MicrosoftGraphSettings,
  MicrosoftGraphSettingsPayload,
  PageKey,
  JobSite,
  ProxyCheckScope,
  ProxyCheckState,
  ProxyPayload,
  ProxySettingsUpdate,
  RunModeAvailability,
} from "@/lib/app-types";
import { jobToDraft, normalizeJobDraft } from "@/lib/job-draft";
import {
  clampRunModeToAvailability,
  createPendingRunModeAvailability,
  resolvePendingRunModeAvailabilityFallback,
} from "@/lib/run-mode";
import { getPageFromPathname, isMailboxSettingsPath, normalizeAppPath } from "@/lib/routes";

async function api<T>(input: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(input, {
    headers: {
      "content-type": "application/json",
      ...(init?.headers || {}),
    },
    ...init,
  });
  if (!resp.ok) {
    const payload = (await resp.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error || `${resp.status} ${resp.statusText}`);
  }
  return (await resp.json()) as T;
}

function usePathname() {
  const [locationState, setLocationState] = useState(() => ({
    pathname: normalizeAppPath(window.location.pathname),
    search: window.location.search || "",
  }));

  useEffect(() => {
    const handlePopstate = () =>
      setLocationState({
        pathname: normalizeAppPath(window.location.pathname),
        search: window.location.search || "",
      });
    window.addEventListener("popstate", handlePopstate);
    return () => window.removeEventListener("popstate", handlePopstate);
  }, []);

  return {
    pathname: locationState.pathname,
    search: locationState.search,
    navigate(next: string) {
      const url = new URL(next, window.location.origin);
      const normalizedPath = normalizeAppPath(url.pathname);
      const normalizedSearch = url.search || "";
      if (normalizedPath === locationState.pathname && normalizedSearch === locationState.search) return;
      window.history.pushState({}, "", `${normalizedPath}${normalizedSearch}`);
      setLocationState({ pathname: normalizedPath, search: normalizedSearch });
    },
  };
}

function mergeIds(current: number[], next: number[]): number[] {
  return Array.from(new Set([...current, ...next]));
}

function buildChatGptCredentialExportFilename(now = new Date()): string {
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");
  return `chatgpt-keys-${year}${month}${day}-${hours}${minutes}${seconds}.json`;
}

function mergeAccountIntoAccountsPayload(current: AccountsPayload, account: AccountRecord): AccountsPayload {
  const rowIndex = current.rows.findIndex((row) => row.id === account.id);
  if (rowIndex < 0) return current;
  const nextRows = [...current.rows];
  nextRows[rowIndex] = account;
  return {
    ...current,
    rows: nextRows,
  };
}

function createIdleExtractorRuntime(): AccountExtractorRuntime {
  return {
    status: "idle",
    enabledSources: [],
    accountType: "outlook",
    requestedUsableCount: 0,
    acceptedCount: 0,
    rawAttemptCount: 0,
    attemptBudget: 0,
    inFlightCount: 0,
    remainingWaitSec: 0,
    maxWaitSec: 0,
    startedAt: null,
    lastProvider: null,
    lastMessage: null,
    updatedAt: null,
    errorMessage: null,
    lastBatchId: null,
  };
}

function createEmptyBatchBootstrapPreview(mode: AccountBatchBootstrapMode = "pending_only"): AccountBatchBootstrapPreviewPayload {
  return {
    ok: true,
    mode,
    requestedCount: 0,
    queueIds: [],
    items: [],
    summary: {
      queueableCount: 0,
      blockedCount: 0,
      alreadyBootstrappedCount: 0,
      bootstrappingCount: 0,
      missingCount: 0,
    },
  };
}

function isExtractorRuntimeTerminal(runtime: AccountExtractorRuntime): boolean {
  return runtime.status === "idle" || runtime.status === "stopped" || runtime.status === "succeeded" || runtime.status === "failed";
}

function createIdleJobSnapshot(site: JobSite): JobSnapshot {
  return {
    site,
    job: null,
    activeAttempts: [],
    recentAttempts: [],
    eligibleCount: 0,
    autoExtractState: null,
    runModeAvailability: createPendingRunModeAvailability(),
    cooldown: null,
  };
}

function createEmptyChatGptUpstreamSettings(): ChatGptUpstreamSettings {
  return {
    baseUrl: "",
    apiKeyMasked: "",
    hasApiKey: false,
    configured: false,
    groupHistory: [],
    baseUrlSource: "unset",
    apiKeySource: "unset",
  };
}

function createChatGptUpstreamSettingsDialogDraft(
  settings: ChatGptUpstreamSettings | null,
): ChatGptUpstreamSettingsDialogDraft {
  return {
    baseUrl: settings?.baseUrlSource === "db" ? settings.baseUrl : "",
    apiKey: "",
    clearBaseUrl: false,
    clearApiKey: false,
  };
}

export function App() {
  const { pathname, search, navigate } = usePathname();
  const [job, setJob] = useState<JobSnapshot>(() => createIdleJobSnapshot("tavily"));
  const [grokJob, setGrokJob] = useState<JobSnapshot>(() => createIdleJobSnapshot("grok"));
  const [chatGptJob, setChatGptJob] = useState<JobSnapshot>(() => createIdleJobSnapshot("chatgpt"));
  const [chatGptJobDraft, setChatGptJobDraft] = useState<ChatGptJobDraft>({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    upstreamGroupName: "",
  });
  const [chatGptCredentials, setChatGptCredentials] = useState<ChatGptCredentialRecord[]>([]);
  const [chatGptUpstreamSettings, setChatGptUpstreamSettings] = useState<ChatGptUpstreamSettings>(createEmptyChatGptUpstreamSettings);
  const [chatGptUpstreamSettingsOpen, setChatGptUpstreamSettingsOpen] = useState(false);
  const [chatGptUpstreamSettingsDraft, setChatGptUpstreamSettingsDraft] = useState<ChatGptUpstreamSettingsDialogDraft>(() =>
    createChatGptUpstreamSettingsDialogDraft(null),
  );
  const [chatGptUpstreamSettingsBusy, setChatGptUpstreamSettingsBusy] = useState(false);
  const [chatGptUpstreamSettingsError, setChatGptUpstreamSettingsError] = useState<string | null>(null);
  const [chatGptBatchSupplementOpen, setChatGptBatchSupplementOpen] = useState(false);
  const [chatGptBatchSupplementGroupName, setChatGptBatchSupplementGroupName] = useState("");
  const [chatGptBatchSupplementBusy, setChatGptBatchSupplementBusy] = useState(false);
  const [chatGptBatchSupplementResult, setChatGptBatchSupplementResult] = useState<ChatGptCredentialSupplementPayload | null>(null);
  const [revealedChatGptCredential, setRevealedChatGptCredential] = useState<ChatGptCredentialRecord | null>(null);
  const [grokApiKeys, setGrokApiKeys] = useState<GrokApiKeysPayload>({
    ok: true,
    rows: [],
    total: 0,
    page: 1,
    pageSize: 20,
    summary: { active: 0, revoked: 0 },
  });
  const [accounts, setAccounts] = useState<AccountsPayload>({
    rows: [],
    total: 0,
    page: 1,
    pageSize: 20,
    summary: { ready: 0, linked: 0, failed: 0, disabled: 0 },
    groups: [],
  });
  const [apiKeys, setApiKeys] = useState<ApiKeysPayload>({
    rows: [],
    total: 0,
    page: 1,
    pageSize: 20,
    summary: { active: 0, revoked: 0 },
    groups: [],
  });
  const [microsoftGraphSettings, setMicrosoftGraphSettings] = useState<MicrosoftGraphSettings | null>(null);
  const [microsoftGraphSettingsDraft, setMicrosoftGraphSettingsDraft] = useState({
    microsoftGraphClientId: "",
    microsoftGraphClientSecret: "",
    microsoftGraphRedirectUri: "",
    microsoftGraphAuthority: "common",
  });
  const [mailboxes, setMailboxes] = useState<MailboxRecord[]>([]);
  const [selectedMailboxId, setSelectedMailboxId] = useState<number | null>(null);
  const [mailboxMessages, setMailboxMessages] = useState<MailboxMessagesPayload>({
    ok: true,
    mailbox: {
      id: 0,
      accountId: 0,
      microsoftEmail: "",
      groupName: null,
      proofMailboxAddress: null,
      status: "preparing",
      syncEnabled: true,
      graphUserId: null,
      graphUserPrincipalName: null,
      graphDisplayName: null,
      authority: "common",
      oauthStartedAt: null,
      oauthConnectedAt: null,
      deltaLink: null,
      unreadCount: 0,
      lastSyncedAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      createdAt: "",
      updatedAt: "",
      isAuthorized: false,
    },
    rows: [],
    total: 0,
    offset: 0,
    limit: 50,
    hasMore: false,
  });
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(null);
  const [selectedMessageDetail, setSelectedMessageDetail] = useState<MailboxMessageDetail | null>(null);
  const [proxies, setProxies] = useState<ProxyPayload | null>(null);
  const [extractorSettings, setExtractorSettings] = useState<AccountExtractorSettings | null>(null);
  const [extractorHistory, setExtractorHistory] = useState<AccountExtractorHistoryPayload>({
    rows: [],
    total: 0,
    page: 1,
    pageSize: 10,
  });
  const [extractorRuntime, setExtractorRuntime] = useState<AccountExtractorRuntime>(createIdleExtractorRuntime);
  const [extractorRunDraft, setExtractorRunDraft] = useState<AccountExtractorRunDraft>({
    sources: [],
    quantity: 1,
    maxWaitSec: 60,
    accountType: "outlook",
  });
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [importContent, setImportContent] = useState("");
  const [importGroupName, setImportGroupName] = useState("");
  const [batchGroupName, setBatchGroupName] = useState("");
  const [importPreview, setImportPreview] = useState<AccountImportPreviewPayload | null>(null);
  const [importPreviewOpen, setImportPreviewOpen] = useState(false);
  const [selectedAccountIds, setSelectedAccountIds] = useState<number[]>([]);
  const [selectedApiKeyIds, setSelectedApiKeyIds] = useState<number[]>([]);
  const [selectedGrokApiKeyIds, setSelectedGrokApiKeyIds] = useState<number[]>([]);
  const [selectedChatGptCredentialIds, setSelectedChatGptCredentialIds] = useState<number[]>([]);
  const [revealedPasswordsById, setRevealedPasswordsById] = useState<Record<number, string>>({});
  const [jobDraft, setJobDraft] = useState<JobDraft>({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 5,
    autoExtractSources: [],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "outlook",
  });
  const [grokJobDraft, setGrokJobDraft] = useState<JobDraft>({
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 5,
    autoExtractSources: [],
    autoExtractQuantity: 1,
    autoExtractMaxWaitSec: 60,
    autoExtractAccountType: "outlook",
  });
  const [accountQuery, setAccountQuery] = useState<AccountQuery>(() => createDefaultAccountQuery());
  const [apiKeyQuery, setApiKeyQuery] = useState<ApiKeyQuery>({
    q: "",
    status: "",
    groupName: "",
    sortBy: "extractedAt",
    sortDir: "desc",
    page: 1,
    pageSize: 20,
  });
  const [grokApiKeyQuery, setGrokApiKeyQuery] = useState<GrokApiKeyQuery>({
    q: "",
    status: "",
    sortBy: "extractedAt",
    sortDir: "desc",
    page: 1,
    pageSize: 20,
  });
  const [chatGptCredentialQuery, setChatGptCredentialQuery] = useState<ChatGptCredentialQuery>({
    q: "",
    expiryStatus: "",
  });
  const [chatGptCredentialSort, setChatGptCredentialSort] = useState<ChatGptCredentialSort>({
    sortBy: "createdAt",
    sortDir: "desc",
  });
  const [extractorHistoryQuery, setExtractorHistoryQuery] = useState<AccountExtractorHistoryQuery>({
    provider: "",
    status: "",
    q: "",
    page: 1,
    pageSize: 10,
  });
  const [proxyCheckScope, setProxyCheckScope] = useState<ProxyCheckScope>("all");
  const [jobDraftTouched, setJobDraftTouched] = useState(false);
  const [chatGptJobDraftTouched, setChatGptJobDraftTouched] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [batchBusy, setBatchBusy] = useState(false);
  const [apiKeyExportOpen, setApiKeyExportOpen] = useState(false);
  const [apiKeyExportContent, setApiKeyExportContent] = useState("");
  const [apiKeyExportBusy, setApiKeyExportBusy] = useState(false);
  const [grokApiKeyExportOpen, setGrokApiKeyExportOpen] = useState(false);
  const [grokApiKeyExportContent, setGrokApiKeyExportContent] = useState("");
  const [grokApiKeyExportBusy, setGrokApiKeyExportBusy] = useState(false);
  const [chatGptExportOpen, setChatGptExportOpen] = useState(false);
  const [chatGptExportContent, setChatGptExportContent] = useState("");
  const [chatGptExportBusy, setChatGptExportBusy] = useState(false);
  const [extractorSettingsBusy, setExtractorSettingsBusy] = useState(false);
  const [extractorHistoryBusy, setExtractorHistoryBusy] = useState(false);
  const [extractorRunBusy, setExtractorRunBusy] = useState(false);
  const [extractorRunDraftTouched, setExtractorRunDraftTouched] = useState(false);
  const [extractorSseState, setExtractorSseState] = useState<ExtractorSseState>("connecting");
  const [graphSettingsBusy, setGraphSettingsBusy] = useState(false);
  const [mailboxesBusy, setMailboxesBusy] = useState(false);
  const [messagesBusy, setMessagesBusy] = useState(false);
  const [messageBusy, setMessageBusy] = useState(false);
  const [accountConnectBusy, setAccountConnectBusy] = useState(false);
  const [accountConnectProgress, setAccountConnectProgress] = useState<{ current: number; total: number } | null>(null);
  const [batchBootstrapPreview, setBatchBootstrapPreview] = useState<AccountBatchBootstrapPreviewPayload>(createEmptyBatchBootstrapPreview);
  const [batchBootstrapPreviewBusy, setBatchBootstrapPreviewBusy] = useState(false);
  const [activeBatchBootstrapMode, setActiveBatchBootstrapMode] = useState<AccountBatchBootstrapMode | null>(null);
  const [connectingAccountIds, setConnectingAccountIds] = useState<number[]>([]);
  const [syncingMailboxId, setSyncingMailboxId] = useState<number | null>(null);
  const [accountsRefreshVersion, setAccountsRefreshVersion] = useState(0);
  const [grokJobBusy, setGrokJobBusy] = useState(false);
  const [chatGptJobBusy, setChatGptJobBusy] = useState(false);
  const [chatGptCredentialBusy, setChatGptCredentialBusy] = useState(false);

  const activePage = useMemo<PageKey>(() => getPageFromPathname(pathname), [pathname]);
  const isMailboxSettingsPage = useMemo(() => isMailboxSettingsPath(pathname), [pathname]);
  const isMailboxWorkspacePage = activePage === "mailboxes" && !isMailboxSettingsPage;
  const mailboxSelectionRef = useRef<number | null>(null);
  const autoSyncedMailboxIdsRef = useRef<number[]>([]);

  const selectedMailbox = useMemo(
    () => mailboxes.find((mailbox) => mailbox.id === selectedMailboxId) || null,
    [mailboxes, selectedMailboxId],
  );
  const accountQueryRef = useRef(accountQuery);
  const apiKeyQueryRef = useRef(apiKeyQuery);
  const grokApiKeyQueryRef = useRef(grokApiKeyQuery);
  const chatGptCredentialQueryRef = useRef(chatGptCredentialQuery);
  const chatGptCredentialSortRef = useRef(chatGptCredentialSort);
  const extractorHistoryQueryRef = useRef(extractorHistoryQuery);
  const extractorRuntimeRef = useRef(extractorRuntime);
  const activePageRef = useRef(activePage);
  const importCommitEntries = useMemo(
    () => buildImportCommitEntries(importPreview, importGroupName),
    [importGroupName, importPreview],
  );

  const currentPageIds = accounts.rows.map((row) => row.id);
  const selectedOnCurrentPageCount = currentPageIds.filter((id) => selectedAccountIds.includes(id)).length;
  const allCurrentPageSelected = currentPageIds.length > 0 && selectedOnCurrentPageCount === currentPageIds.length;

  const refreshJob = async (site: JobSite = "tavily") => {
    const snapshot = await api<JobSnapshot>(`/api/jobs/current?site=${site}`);
    if (site === "chatgpt") {
      setChatGptJob(snapshot);
      return;
    }
    if (site === "grok") {
      setGrokJob(snapshot);
      return;
    }
    setJob(snapshot);
  };
  const refreshChatGptCredentials = async (
    nextQuery = chatGptCredentialQueryRef.current,
    nextSort = chatGptCredentialSortRef.current,
  ) => {
    const params = new URLSearchParams();
    if (nextQuery.q) params.set("q", nextQuery.q);
    if (nextQuery.expiryStatus) params.set("expiryStatus", nextQuery.expiryStatus);
    params.set("sortBy", nextSort.sortBy);
    params.set("sortDir", nextSort.sortDir);
    const payload = await api<ChatGptCredentialsPayload>(`/api/chatgpt/credentials?${params.toString()}`);
    setChatGptCredentials(payload.rows);
  };
  const refreshChatGptUpstreamSettings = async () => {
    const payload = await api<ChatGptUpstreamSettingsPayload>("/api/chatgpt/upstream-settings");
    setChatGptUpstreamSettings(payload.settings);
    setChatGptUpstreamSettingsDraft((current) =>
      current.apiKey || current.clearApiKey || current.clearBaseUrl || current.baseUrl
        ? current
        : createChatGptUpstreamSettingsDialogDraft(payload.settings),
    );
  };
  const refreshAccounts = async (nextQuery = accountQuery) => {
    const params = new URLSearchParams();
    if (nextQuery.q) params.set("q", nextQuery.q);
    if (nextQuery.status) params.set("status", nextQuery.status);
    if (nextQuery.hasApiKey) params.set("hasApiKey", nextQuery.hasApiKey);
    if (nextQuery.sessionStatus) params.set("sessionStatus", nextQuery.sessionStatus);
    if (nextQuery.mailboxStatus) params.set("mailboxStatus", nextQuery.mailboxStatus);
    if (nextQuery.groupName) params.set("groupName", nextQuery.groupName);
    if (nextQuery.sortBy) params.set("sortBy", nextQuery.sortBy);
    if (nextQuery.sortBy && nextQuery.sortDir) params.set("sortDir", nextQuery.sortDir);
    params.set("page", String(nextQuery.page));
    params.set("pageSize", String(nextQuery.pageSize));

    const payload = await api<AccountsPayload>(`/api/accounts?${params.toString()}`);
    if (payload.rows.length === 0 && payload.total > 0 && nextQuery.page > 1) {
      setAccountQuery((current) => ({ ...current, page: current.page - 1 }));
      return;
    }
    setAccounts(payload);
    setAccountsRefreshVersion((current) => current + 1);
  };
  const previewBatchBootstrap = async (
    ids: number[],
    mode: AccountBatchBootstrapMode = "pending_only",
  ) =>
    api<AccountBatchBootstrapPreviewPayload>("/api/accounts/session-bootstrap/preview", {
      method: "POST",
      body: JSON.stringify({ ids, mode }),
    });
  const refreshApiKeys = async (nextQuery = apiKeyQuery) => {
    const params = new URLSearchParams();
    if (nextQuery.q) params.set("q", nextQuery.q);
    if (nextQuery.status) params.set("status", nextQuery.status);
    if (nextQuery.groupName) params.set("groupName", nextQuery.groupName);
    params.set("sortBy", nextQuery.sortBy);
    params.set("sortDir", nextQuery.sortDir);
    params.set("page", String(nextQuery.page));
    params.set("pageSize", String(nextQuery.pageSize));
    const payload = await api<ApiKeysPayload>(`/api/api-keys?${params.toString()}`);
    if (payload.rows.length === 0 && payload.total > 0 && nextQuery.page > 1) {
      setApiKeyQuery((current) => ({ ...current, page: current.page - 1 }));
      return;
    }
    setApiKeys(payload);
  };
  const refreshGrokApiKeys = async (nextQuery = grokApiKeyQueryRef.current) => {
    const params = new URLSearchParams();
    if (nextQuery.q) params.set("q", nextQuery.q);
    if (nextQuery.status) params.set("status", nextQuery.status);
    params.set("sortBy", nextQuery.sortBy);
    params.set("sortDir", nextQuery.sortDir);
    params.set("page", String(nextQuery.page));
    params.set("pageSize", String(nextQuery.pageSize));
    const payload = await api<GrokApiKeysPayload>(`/api/grok/keys?${params.toString()}`);
    if (payload.rows.length === 0 && payload.total > 0 && nextQuery.page > 1) {
      setGrokApiKeyQuery((current) => ({ ...current, page: current.page - 1 }));
      return;
    }
    setGrokApiKeys(payload);
  };
  const refreshProxies = async () => {
    const payload = await api<ProxyPayload>("/api/proxies");
    setProxies(payload);
  };
  const applyProxyEventPayload = (payload: { checkState?: ProxyCheckState; nodes?: ProxyPayload["nodes"] }) => {
    setProxies((current) => {
      if (!current) return current;
      return {
        ...current,
        nodes: Array.isArray(payload.nodes) ? payload.nodes : current.nodes,
        checkState: payload.checkState || current.checkState,
      };
    });
  };
  const refreshExtractorSettings = async () => {
    const payload = await api<AccountExtractorSettingsPayload>("/api/account-extractors/settings");
    setExtractorSettings(payload.settings);
  };
  const refreshExtractorRuntime = async () => {
    const payload = await api<AccountExtractorRuntimePayload>("/api/account-extractors/runtime");
    setExtractorRuntime(payload.runtime);
  };
  const refreshExtractorHistory = async (nextQuery = extractorHistoryQuery) => {
    try {
      setExtractorHistoryBusy(true);
      const params = new URLSearchParams();
      if (nextQuery.provider) params.set("provider", nextQuery.provider);
      if (nextQuery.status) params.set("status", nextQuery.status);
      if (nextQuery.q) params.set("q", nextQuery.q);
      params.set("page", String(nextQuery.page));
      params.set("pageSize", String(nextQuery.pageSize));
      const payload = await api<AccountExtractorHistoryPayload>(`/api/account-extractors/history?${params.toString()}`);
      if (payload.rows.length === 0 && payload.total > 0 && nextQuery.page > 1) {
        setExtractorHistoryQuery((current) => ({ ...current, page: current.page - 1 }));
        return;
      }
      setExtractorHistory(payload);
    } finally {
      setExtractorHistoryBusy(false);
    }
  };
  const refreshMicrosoftGraphSettings = async () => {
    const payload = await api<MicrosoftGraphSettingsPayload>("/api/microsoft-mail/settings");
    setMicrosoftGraphSettings(payload.settings);
    setMicrosoftGraphSettingsDraft({
      microsoftGraphClientId: payload.settings.microsoftGraphClientId,
      microsoftGraphClientSecret: "",
      microsoftGraphRedirectUri: payload.settings.microsoftGraphRedirectUri,
      microsoftGraphAuthority: payload.settings.microsoftGraphAuthority || "common",
    });
  };
  const refreshMailboxes = async () => {
    try {
      setMailboxesBusy(true);
      const payload = await api<MailboxesPayload>("/api/microsoft-mail/mailboxes");
      setMailboxes(payload.rows);
    } finally {
      setMailboxesBusy(false);
    }
  };
  const refreshMailboxMessages = async (mailboxId: number, options?: { offset?: number; append?: boolean }) => {
    try {
      setMessagesBusy(true);
      const params = new URLSearchParams();
      params.set("limit", "50");
      params.set("offset", String(options?.offset || 0));
      const payload = await api<MailboxMessagesPayload>(`/api/microsoft-mail/mailboxes/${mailboxId}/messages?${params.toString()}`);
      setMailboxMessages((current) =>
        options?.append
          ? {
              ...payload,
              rows: [...current.rows, ...payload.rows.filter((row) => !current.rows.some((currentRow) => currentRow.id === row.id))],
            }
          : payload,
      );
    } finally {
      setMessagesBusy(false);
    }
  };
  const refreshMailboxMessageDetail = async (messageId: number) => {
    try {
      setMessageBusy(true);
      const payload = await api<MailboxMessageDetailPayload>(`/api/microsoft-mail/messages/${messageId}`);
      setSelectedMessageDetail(payload.message);
    } finally {
      setMessageBusy(false);
    }
  };

  const refreshMailboxAccountState = async () => {
    await Promise.all([refreshAccounts(accountQueryRef.current), refreshMailboxes()]);
  };

  const ensureChatGptCredentialDetail = async (credential: ChatGptCredentialRecord): Promise<ChatGptCredentialRecord> => {
    if (credential.accessToken && credential.refreshToken && credential.idToken) {
      return credential;
    }
    const payload = await api<ChatGptCredentialDetailPayload>(`/api/chatgpt/credentials/${credential.id}?includeSecrets=1`);
    return payload.credential;
  };

  const handleChatGptJobDraftChange = (patch: Partial<ChatGptJobDraft>) => {
    setChatGptJobDraftTouched(true);
    setChatGptJobDraft((current) => {
      const requestedRunMode = patch.runMode === "headless" || patch.runMode === "headed" ? patch.runMode : current.runMode;
      const runMode = clampRunModeToAvailability(requestedRunMode, chatGptJob.runModeAvailability);
      const need = Math.max(1, Math.trunc(patch.need ?? current.need));
      const parallel = Math.max(1, Math.trunc(patch.parallel ?? current.parallel));
      const requestedMaxAttempts = Math.max(1, Math.trunc(patch.maxAttempts ?? current.maxAttempts));
      const maxAttempts = requestedMaxAttempts >= need ? requestedMaxAttempts : Math.max(need, Math.ceil(need * 1.5));
      return {
        runMode,
        need,
        parallel,
        maxAttempts,
        upstreamGroupName:
          patch.upstreamGroupName === undefined ? current.upstreamGroupName : patch.upstreamGroupName.trim(),
      };
    });
  };

  const handleChatGptJobAction = async (action: JobControlAction, options?: JobControlOptions) => {
    try {
      setChatGptJobBusy(true);
      setError(null);
      const body: Record<string, unknown> = {
        site: "chatgpt",
        action,
      };
      if (action === "start" || action === "update_limits") {
        const nextJobDraft = (options?.draft as ChatGptJobDraft | undefined) || chatGptJobDraft;
        body.runMode = clampRunModeToAvailability(nextJobDraft.runMode, chatGptJob.runModeAvailability);
        body.need = nextJobDraft.need;
        body.parallel = nextJobDraft.parallel;
        body.maxAttempts = nextJobDraft.maxAttempts;
        body.upstreamGroupName = nextJobDraft.upstreamGroupName || null;
      }
      if (action === "force_stop") {
        body.confirmForceStop = true;
      }
      const payload = await api<{ ok: true; job?: JobSnapshot["job"] }>("/api/jobs/current/control", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (payload.job && (action === "start" || action === "update_limits")) {
        setChatGptJobDraft({
          runMode: clampRunModeToAvailability(payload.job.runMode, chatGptJob.runModeAvailability),
          need: payload.job.need,
          parallel: payload.job.parallel,
          maxAttempts: payload.job.maxAttempts,
          upstreamGroupName: payload.job.upstreamGroupName || "",
        });
        setChatGptJobDraftTouched(false);
      }
      await Promise.all([
        refreshJob("chatgpt"),
        refreshChatGptCredentials(chatGptCredentialQueryRef.current, chatGptCredentialSortRef.current),
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatGptJobBusy(false);
    }
  };

  const handleRevealChatGptCredential = async (credentialId: number) => {
    try {
      setChatGptCredentialBusy(true);
      setError(null);
      const payload = await api<ChatGptCredentialDetailPayload>(`/api/chatgpt/credentials/${credentialId}?includeSecrets=1`);
      setRevealedChatGptCredential(payload.credential);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatGptCredentialBusy(false);
    }
  };

  const handleCopyChatGptCredential = async (credential: ChatGptCredentialRecord) => {
    try {
      setChatGptCredentialBusy(true);
      setError(null);
      const detail = await ensureChatGptCredentialDetail(credential);
      const content = buildCodexVibeMonitorCredentialJson(detail);
      await navigator.clipboard.writeText(content);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatGptCredentialBusy(false);
    }
  };

  const handleExportChatGptCredential = async (credential: ChatGptCredentialRecord) => {
    try {
      setChatGptCredentialBusy(true);
      setError(null);
      const detail = await ensureChatGptCredentialDetail(credential);
      const content = buildCodexVibeMonitorCredentialJson(detail);
      const blob = new Blob([content], { type: "application/json;charset=utf-8" });
      const objectUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `chatgpt-credential-${detail.id}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatGptCredentialBusy(false);
    }
  };

  const handleToggleChatGptCredentialSelection = (credentialId: number, checked: boolean) => {
    setSelectedChatGptCredentialIds((current) => (checked ? mergeIds(current, [credentialId]) : current.filter((id) => id !== credentialId)));
  };

  const handleToggleChatGptCredentialPageSelection = (checked: boolean) => {
    const currentPageCredentialIds = chatGptCredentials.map((row) => row.id);
    if (checked) {
      setSelectedChatGptCredentialIds((current) => mergeIds(current, currentPageCredentialIds));
      return;
    }
    setSelectedChatGptCredentialIds((current) => current.filter((id) => !currentPageCredentialIds.includes(id)));
  };

  const handleOpenChatGptCredentialExport = async () => {
    if (selectedChatGptCredentialIds.length === 0) return;
    try {
      setChatGptExportBusy(true);
      setError(null);
      const detailRows = (
        await Promise.all(
          selectedChatGptCredentialIds.map(async (credentialId) => {
            const credential = chatGptCredentials.find((row) => row.id === credentialId);
            if (!credential) return null;
            return await ensureChatGptCredentialDetail(credential);
          }),
        )
      ).filter((row): row is ChatGptCredentialRecord => Boolean(row));

      if (detailRows.length === 0) {
        setError("选中的 ChatGPT keys 已不存在");
        return;
      }

      const content = JSON.stringify(
        detailRows.map((row) => JSON.parse(buildCodexVibeMonitorCredentialJson(row))),
        null,
        2,
      );
      setChatGptExportContent(content);
      setChatGptExportOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatGptExportBusy(false);
    }
  };

  const handleCopyChatGptExport = async () => {
    if (!chatGptExportContent) return;
    try {
      setError(null);
      await navigator.clipboard.writeText(chatGptExportContent);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleSaveChatGptExport = () => {
    if (!chatGptExportContent) return;
    const blob = new Blob([chatGptExportContent], { type: "application/json;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = buildChatGptCredentialExportFilename();
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => window.URL.revokeObjectURL(url), 0);
  };

  const handleOpenChatGptUpstreamSettings = () => {
    setChatGptUpstreamSettingsDraft(createChatGptUpstreamSettingsDialogDraft(chatGptUpstreamSettings));
    setChatGptUpstreamSettingsError(null);
    setChatGptUpstreamSettingsOpen(true);
  };

  const handleSaveChatGptUpstreamSettings = async () => {
    try {
      setChatGptUpstreamSettingsBusy(true);
      setChatGptUpstreamSettingsError(null);
      setError(null);
      const patch: ChatGptUpstreamSettingsUpdate = {};
      if (chatGptUpstreamSettingsDraft.baseUrl.trim()) {
        patch.baseUrl = chatGptUpstreamSettingsDraft.baseUrl.trim();
      }
      if (chatGptUpstreamSettingsDraft.apiKey.trim()) {
        patch.apiKey = chatGptUpstreamSettingsDraft.apiKey.trim();
      }
      if (chatGptUpstreamSettingsDraft.clearBaseUrl) {
        patch.clearBaseUrl = true;
      }
      if (chatGptUpstreamSettingsDraft.clearApiKey) {
        patch.clearApiKey = true;
      }
      const payload = await api<ChatGptUpstreamSettingsPayload>("/api/chatgpt/upstream-settings", {
        method: "POST",
        body: JSON.stringify(patch),
      });
      setChatGptUpstreamSettings(payload.settings);
      setChatGptUpstreamSettingsDraft(createChatGptUpstreamSettingsDialogDraft(payload.settings));
      setChatGptUpstreamSettingsOpen(false);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setChatGptUpstreamSettingsError(message);
      setError(message);
    } finally {
      setChatGptUpstreamSettingsBusy(false);
    }
  };

  const handleOpenChatGptBatchSupplement = () => {
    setChatGptBatchSupplementResult(null);
    setChatGptBatchSupplementOpen(true);
  };

  const handleSubmitChatGptBatchSupplement = async () => {
    if (selectedChatGptCredentialIds.length === 0 || !chatGptBatchSupplementGroupName.trim()) return;
    try {
      setChatGptBatchSupplementBusy(true);
      setError(null);
      const payload = await api<ChatGptCredentialSupplementPayload>("/api/chatgpt/credentials/supplement", {
        method: "POST",
        body: JSON.stringify({
          ids: selectedChatGptCredentialIds,
          groupName: chatGptBatchSupplementGroupName.trim(),
        }),
      });
      setChatGptBatchSupplementResult(payload);
      await refreshChatGptUpstreamSettings();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChatGptBatchSupplementBusy(false);
    }
  };

  useEffect(() => {
    void Promise.all([
      refreshJob("tavily"),
      refreshJob("grok"),
      refreshJob("chatgpt"),
      refreshChatGptCredentials(),
      refreshChatGptUpstreamSettings(),
      refreshAccounts(),
      refreshApiKeys(),
      refreshGrokApiKeys(),
      refreshProxies(),
      refreshExtractorSettings(),
      refreshExtractorRuntime(),
      refreshExtractorHistory(),
      refreshMicrosoftGraphSettings(),
      refreshMailboxes(),
    ]).catch((err) => {
      setJob((current) => ({
        ...current,
        runModeAvailability: resolvePendingRunModeAvailabilityFallback(current.runModeAvailability),
      }));
      setChatGptJob((current) => ({
        ...current,
        runModeAvailability: resolvePendingRunModeAvailabilityFallback(current.runModeAvailability),
      }));
      setError(err instanceof Error ? err.message : String(err));
    });
  }, []);

  useEffect(() => {
    if (job.job || !proxies || !extractorSettings || jobDraftTouched) return;
    setJobDraft(normalizeJobDraft({
      runMode: clampRunModeToAvailability(proxies.settings.defaultRunMode, job.runModeAvailability),
      need: proxies.settings.defaultNeed,
      parallel: proxies.settings.defaultParallel,
      maxAttempts: proxies.settings.defaultMaxAttempts,
      autoExtractSources: extractorSettings.defaultAutoExtractSources,
      autoExtractQuantity: extractorSettings.defaultAutoExtractQuantity,
      autoExtractMaxWaitSec: extractorSettings.defaultAutoExtractMaxWaitSec,
      autoExtractAccountType: extractorSettings.defaultAutoExtractAccountType,
    }));
  }, [extractorSettings, job.job, job.runModeAvailability, jobDraftTouched, proxies]);

  useEffect(() => {
    if (!job.job || jobDraftTouched) return;
    const nextJob = job.job;
    setJobDraft({
      ...jobToDraft(nextJob),
      runMode: clampRunModeToAvailability(nextJob.runMode, job.runModeAvailability),
    });
  }, [job.job, job.runModeAvailability, jobDraftTouched]);

  useEffect(() => {
    if (!chatGptJob.job) return;
    setChatGptJobDraft({
      runMode: clampRunModeToAvailability(chatGptJob.job.runMode, chatGptJob.runModeAvailability),
      need: chatGptJob.job.need,
      parallel: chatGptJob.job.parallel,
      maxAttempts: chatGptJob.job.maxAttempts,
      upstreamGroupName: chatGptJob.job.upstreamGroupName || "",
    });
    setChatGptJobDraftTouched(false);
  }, [chatGptJob.job, chatGptJob.runModeAvailability]);

  useEffect(() => {
    if (chatGptJob.job || chatGptJobDraftTouched) return;
    const preferredRunMode = clampRunModeToAvailability("headed", chatGptJob.runModeAvailability);
    setChatGptJobDraft((current) => (current.runMode === preferredRunMode ? current : { ...current, runMode: preferredRunMode }));
  }, [chatGptJob.job, chatGptJob.runModeAvailability, chatGptJobDraftTouched]);

  useEffect(() => {
    if (job.runModeAvailability.headed || jobDraft.runMode !== "headed") return;
    setJobDraft((current) => ({ ...current, runMode: "headless" }));
  }, [job.runModeAvailability.headed, jobDraft.runMode]);

  useEffect(() => {
    if (chatGptJob.runModeAvailability.headed || chatGptJobDraft.runMode !== "headed") return;
    setChatGptJobDraft((current) => ({ ...current, runMode: "headless" }));
  }, [chatGptJob.runModeAvailability.headed, chatGptJobDraft.runMode]);

  useEffect(() => {
    const currentJob = grokJob.job;
    if (currentJob) {
      setGrokJobDraft((current) =>
        normalizeJobDraft({
          ...current,
          runMode: currentJob.runMode,
          need: currentJob.need,
          parallel: currentJob.parallel,
          maxAttempts: currentJob.maxAttempts,
          autoExtractSources: [],
        }),
      );
      return;
    }
    if (!proxies) return;
    setGrokJobDraft((current) =>
      normalizeJobDraft({
        ...current,
        runMode: proxies.settings.defaultRunMode,
        need: proxies.settings.defaultNeed,
        parallel: proxies.settings.defaultParallel,
        maxAttempts: proxies.settings.defaultMaxAttempts,
        autoExtractSources: [],
      }),
    );
  }, [grokJob.job, proxies]);

  useEffect(() => {
    if (!extractorSettings || extractorRunDraftTouched) return;
    setExtractorRunDraft({
      sources: extractorSettings.defaultAutoExtractSources,
      quantity: extractorSettings.defaultAutoExtractQuantity,
      maxWaitSec: extractorSettings.defaultAutoExtractMaxWaitSec,
      accountType: extractorSettings.defaultAutoExtractAccountType,
    });
  }, [extractorRunDraftTouched, extractorSettings]);

  useEffect(() => {
    accountQueryRef.current = accountQuery;
  }, [accountQuery]);

  useEffect(() => {
    apiKeyQueryRef.current = apiKeyQuery;
  }, [apiKeyQuery]);

  useEffect(() => {
    grokApiKeyQueryRef.current = grokApiKeyQuery;
  }, [grokApiKeyQuery]);

  useEffect(() => {
    chatGptCredentialQueryRef.current = chatGptCredentialQuery;
  }, [chatGptCredentialQuery]);

  useEffect(() => {
    chatGptCredentialSortRef.current = chatGptCredentialSort;
  }, [chatGptCredentialSort]);

  useEffect(() => {
    extractorHistoryQueryRef.current = extractorHistoryQuery;
  }, [extractorHistoryQuery]);

  useEffect(() => {
    extractorRuntimeRef.current = extractorRuntime;
  }, [extractorRuntime]);

  useEffect(() => {
    activePageRef.current = activePage;
  }, [activePage]);

  useEffect(() => {
    mailboxSelectionRef.current = selectedMailboxId;
  }, [selectedMailboxId]);

  useEffect(() => {
    const socket = new WebSocket(`${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/api/events/ws`);
    socket.onmessage = (event) => {
      const next = JSON.parse(event.data) as EventRecord;
      setEvents((current) => [next, ...current].slice(0, 60));
      if (next.type === "job.updated" || next.type === "attempt.updated") {
        void Promise.all([refreshJob("tavily"), refreshJob("grok"), refreshJob("chatgpt")]);
        void refreshGrokApiKeys(grokApiKeyQueryRef.current);
        void refreshChatGptCredentials(chatGptCredentialQueryRef.current, chatGptCredentialSortRef.current);
      }
      if (next.type === "chatgpt.upstream-settings.updated") {
        void refreshChatGptUpstreamSettings();
      }
      if (next.type === "account.updated") {
        void refreshAccounts(accountQueryRef.current);
        void refreshApiKeys(apiKeyQueryRef.current);
        void refreshMailboxes();
      }
      if (next.type === "mailbox.updated") {
        void refreshMailboxes();
        if (mailboxSelectionRef.current) {
          void refreshMailboxMessages(mailboxSelectionRef.current);
        }
      }
      if ((next.type === "job.updated" || next.type === "account.updated") && activePageRef.current === "accounts") {
        void refreshExtractorHistory(extractorHistoryQueryRef.current);
      }
      if (next.type === "proxy.updated" && activePageRef.current !== "proxies") {
        void refreshProxies();
      }
    };
    socket.onerror = () => setError("WebSocket disconnected");
    return () => socket.close();
  }, []);

  useEffect(() => {
    if (activePage !== "accounts") {
      setExtractorSseState("closed");
      return;
    }
    setExtractorSseState("connecting");
    const source = new EventSource("/api/accounts/events");
    source.onopen = () => {
      setExtractorSseState("open");
    };
    source.onmessage = (event) => {
      try {
        const next = JSON.parse(event.data) as EventRecord;
        if (next.type === "extractor.updated") {
          const runtime = (next.payload.runtime || createIdleExtractorRuntime()) as AccountExtractorRuntime;
          const previous = extractorRuntimeRef.current;
          setExtractorRuntime(runtime);
          if (
            runtime.lastBatchId !== previous.lastBatchId
            || (runtime.status !== previous.status && isExtractorRuntimeTerminal(runtime))
          ) {
            void refreshExtractorHistory(extractorHistoryQueryRef.current);
          }
          return;
        }
        if (next.type === "account.updated") {
          void refreshAccounts(accountQueryRef.current);
          void refreshExtractorHistory(extractorHistoryQueryRef.current);
          return;
        }
        if (next.type === "mailbox.updated") {
          void refreshAccounts(accountQueryRef.current);
          return;
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    };
    source.onerror = () => {
      setExtractorSseState("error");
    };
    return () => {
      source.close();
      setExtractorSseState("closed");
    };
  }, [activePage]);

  useEffect(() => {
    if (activePage !== "proxies") {
      return;
    }
    const source = new EventSource("/api/proxies/events");
    source.onmessage = (event) => {
      try {
        const next = JSON.parse(event.data) as EventRecord;
        if (
          next.type === "proxy.updated"
          || next.type === "proxy.check.state"
          || next.type === "proxy.check.started"
          || next.type === "proxy.check.progress"
          || next.type === "proxy.check.completed"
          || next.type === "proxy.check.failed"
        ) {
          applyProxyEventPayload(next.payload as { checkState?: ProxyCheckState; nodes?: ProxyPayload["nodes"] });
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    };
    source.onerror = () => {
      // keep the last rendered proxy snapshot instead of forcing a blocking reload loop
    };
    return () => {
      source.close();
    };
  }, [activePage]);

  useEffect(() => {
    void refreshAccounts(accountQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [accountQuery]);

  useEffect(() => {
    if (activePage !== "accounts") return;
    const ids = Array.from(new Set(selectedAccountIds.filter((id) => Number.isInteger(id) && id > 0)));
    if (ids.length === 0) {
      setBatchBootstrapPreview(createEmptyBatchBootstrapPreview());
      setBatchBootstrapPreviewBusy(false);
      return;
    }
    let cancelled = false;
    setBatchBootstrapPreviewBusy(true);
    void previewBatchBootstrap(ids, "pending_only")
      .then((payload) => {
        if (cancelled) return;
        setBatchBootstrapPreview(payload);
      })
      .catch((err) => {
        if (cancelled) return;
        setBatchBootstrapPreview(createEmptyBatchBootstrapPreview());
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) {
          setBatchBootstrapPreviewBusy(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activePage, selectedAccountIds, accountsRefreshVersion]);

  useEffect(() => {
    void refreshApiKeys().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [apiKeyQuery]);

  useEffect(() => {
    void refreshGrokApiKeys(grokApiKeyQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [grokApiKeyQuery]);

  useEffect(() => {
    void refreshChatGptCredentials(chatGptCredentialQuery, chatGptCredentialSort).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [chatGptCredentialQuery, chatGptCredentialSort]);

  useEffect(() => {
    const existingIds = new Set(grokApiKeys.rows.map((row) => row.id));
    setSelectedGrokApiKeyIds((current) => current.filter((id) => existingIds.has(id)));
  }, [grokApiKeys]);

  useEffect(() => {
    const existingIds = new Set(chatGptCredentials.map((row) => row.id));
    setSelectedChatGptCredentialIds((current) => current.filter((id) => existingIds.has(id)));
  }, [chatGptCredentials]);

  useEffect(() => {
    void refreshExtractorHistory(extractorHistoryQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [extractorHistoryQuery]);

  useEffect(() => {
    if (!isMailboxWorkspacePage) return;
    const params = new URLSearchParams(search);
    const accountId = Number(params.get("accountId") || 0);
    if (Number.isInteger(accountId) && accountId > 0) {
      const matched = mailboxes.find((mailbox) => mailbox.accountId === accountId);
      if (matched && matched.id !== selectedMailboxId) {
        setSelectedMailboxId(matched.id);
        setSelectedMessageId(null);
        setSelectedMessageDetail(null);
        return;
      }
    }
    if (mailboxes.length === 0) {
      if (selectedMailboxId !== null) {
        setSelectedMailboxId(null);
      }
      setSelectedMessageId(null);
      setSelectedMessageDetail(null);
      setMailboxMessages((current) => ({
        ...current,
        rows: [],
        total: 0,
        offset: 0,
        hasMore: false,
      }));
      return;
    }
    if (selectedMailboxId != null && !mailboxes.some((mailbox) => mailbox.id === selectedMailboxId)) {
      const firstMailbox = mailboxes[0];
      if (!firstMailbox) return;
      setSelectedMailboxId(firstMailbox.id);
      setSelectedMessageId(null);
      setSelectedMessageDetail(null);
      return;
    }
    if (selectedMailboxId == null && mailboxes.length > 0) {
      const firstMailbox = mailboxes[0];
      if (!firstMailbox) return;
      setSelectedMailboxId(firstMailbox.id);
      setSelectedMessageId(null);
      setSelectedMessageDetail(null);
    }
  }, [isMailboxWorkspacePage, mailboxes, search, selectedMailboxId]);

  useEffect(() => {
    if (!isMailboxWorkspacePage || !selectedMailboxId) return;
    void refreshMailboxMessages(selectedMailboxId).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [isMailboxWorkspacePage, selectedMailboxId]);

  useEffect(() => {
    if (!selectedMailbox || !isMailboxWorkspacePage) return;
    if (selectedMailbox.status === "preparing" && !selectedMailbox.lastSyncedAt && selectedMailbox.isAuthorized) {
      if (autoSyncedMailboxIdsRef.current.includes(selectedMailbox.id)) return;
      autoSyncedMailboxIdsRef.current = mergeIds(autoSyncedMailboxIdsRef.current, [selectedMailbox.id]);
      void handleSyncMailbox(selectedMailbox.id).catch((err) => setError(err instanceof Error ? err.message : String(err)));
    }
  }, [isMailboxWorkspacePage, selectedMailbox]);

  useEffect(() => {
    if (!isMailboxWorkspacePage) return;
    const outcome = new URLSearchParams(search).get("oauth");
    if (outcome === "error") {
      setError("Microsoft OAuth 授权失败，请检查 Graph 设置后重试。");
      return;
    }
    if (outcome === "success") {
      setError(null);
    }
  }, [isMailboxWorkspacePage, search]);

  const handleOpenImportPreview = async () => {
    const parsed = parseImportContent(importContent);
    if (parsed.entries.length === 0 && parsed.invalidRows.length === 0) {
      setError("没有识别到可导入的账号数据");
      return;
    }

    try {
      setPreviewBusy(true);
      setError(null);
      const preview = await api<AccountImportPreviewPayload>("/api/accounts/import-preview", {
        method: "POST",
        body: JSON.stringify(parsed),
      });
      setImportPreview(preview);
      setImportPreviewOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPreviewBusy(false);
    }
  };

  const handleConfirmImport = async () => {
    if (!importPreview || importCommitEntries.length === 0) return;
    try {
      setImportBusy(true);
      setError(null);
      setAccountQuery((current) => ({ ...current, page: 1 }));
      const payload = await api<AccountImportPayload>("/api/accounts/import", {
        method: "POST",
        body: JSON.stringify({
          entries: importCommitEntries,
          groupName: importGroupName || null,
        }),
      });
      setSelectedAccountIds((current) => mergeIds(current, payload.affectedIds));
      setRevealedPasswordsById((current) => {
        const next = { ...current };
        for (const account of payload.revealedAccounts) {
          next[account.id] = account.passwordPlaintext;
        }
        return next;
      });
      setImportContent("");
      setImportPreviewOpen(false);
      setImportPreview(null);
      await refreshAccounts({ ...accountQuery, page: 1 });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setImportBusy(false);
    }
  };

  const updateJobDraft = (patch: Partial<JobDraft>) => {
    setJobDraftTouched(true);
    setJobDraft((current) =>
      normalizeJobDraft({
        ...current,
        ...patch,
        runMode: clampRunModeToAvailability(
          patch.runMode === "headless" || patch.runMode === "headed" ? patch.runMode : current.runMode,
          job.runModeAvailability,
        ),
      }),
    );
  };

  const handleJobAction = async (action: JobControlAction, options?: JobControlOptions) => {
    try {
      setError(null);
      const draft = options?.draft || jobDraft;
      const normalizedDraft = {
        ...draft,
        runMode: clampRunModeToAvailability(draft.runMode, job.runModeAvailability),
      };
      const payload = await api<{ ok: true; job?: JobSnapshot["job"] }>("/api/jobs/current/control", {
        method: "POST",
        body: JSON.stringify({
          site: "tavily",
          action,
          ...(options?.confirmForceStop ? { confirmForceStop: true } : {}),
          ...normalizedDraft,
        }),
      });
      if (payload.job) {
        setJobDraft({
          ...jobToDraft(payload.job),
          runMode: clampRunModeToAvailability(payload.job.runMode, job.runModeAvailability),
        });
        setJobDraftTouched(false);
      }
      await refreshJob("tavily");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleGrokJobAction = async (action: JobControlAction, options?: JobControlOptions) => {
    try {
      setGrokJobBusy(true);
      setError(null);
      const draft = options?.draft || grokJobDraft;
      await api<{ ok: true; job?: JobSnapshot["job"] }>("/api/jobs/current/control", {
        method: "POST",
        body: JSON.stringify({
          site: "grok",
          action,
          ...(options?.confirmForceStop ? { confirmForceStop: true } : {}),
          runMode: draft.runMode,
          need: draft.need,
          parallel: draft.parallel,
          maxAttempts: draft.maxAttempts,
        }),
      });
      await refreshJob("grok");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGrokJobBusy(false);
    }
  };

  const handleSaveExtractorSettings = async (patch: Partial<AccountExtractorSettings>) => {
    try {
      setExtractorSettingsBusy(true);
      setError(null);
      const payload = await api<AccountExtractorSettingsPayload>("/api/account-extractors/settings", {
        method: "POST",
        body: JSON.stringify(patch),
      });
      setExtractorSettings(payload.settings);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setExtractorSettingsBusy(false);
    }
  };

  const handleRunExtractor = async () => {
    try {
      setExtractorRunBusy(true);
      setError(null);
      const payload = await api<AccountExtractorRuntimePayload>("/api/account-extractors/run", {
        method: "POST",
        body: JSON.stringify(extractorRunDraft),
      });
      setExtractorRuntime(payload.runtime);
      await refreshExtractorHistory(extractorHistoryQueryRef.current);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExtractorRunBusy(false);
    }
  };

  const handleStopExtractor = async () => {
    try {
      setExtractorRunBusy(true);
      setError(null);
      const payload = await api<AccountExtractorRuntimePayload>("/api/account-extractors/stop", {
        method: "POST",
      });
      setExtractorRuntime(payload.runtime);
      await refreshExtractorHistory(extractorHistoryQueryRef.current);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExtractorRunBusy(false);
    }
  };

  const handleSaveProxySettings = async (settingsOverride?: ProxySettingsUpdate) => {
    if (!proxies && !settingsOverride) return;
    try {
      setError(null);
      const payload = await api<ProxyPayload>("/api/proxies/settings", {
        method: "POST",
        body: JSON.stringify(settingsOverride || (proxies ? pickProxySettingsUpdate(proxies.settings) : undefined)),
      });
      setProxies(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleProxyCheck = async () => {
    try {
      setError(null);
      const payload = await api<{ ok: true; accepted: boolean; checkState: ProxyCheckState }>("/api/proxies/check", {
        method: "POST",
        body: JSON.stringify({ scope: proxyCheckScope }),
      });
      applyProxyEventPayload({ checkState: payload.checkState });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleCheckSingleNode = async (nodeName: string) => {
    try {
      setError(null);
      const payload = await api<{ ok: true; accepted: boolean; checkState: ProxyCheckState }>("/api/proxies/check", {
        method: "POST",
        body: JSON.stringify({ scope: "node", nodeName }),
      });
      applyProxyEventPayload({ checkState: payload.checkState });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const updateProxySettings = <K extends keyof ProxySettingsUpdate>(key: K, value: ProxySettingsUpdate[K]) => {
    setProxies((current) => (current ? { ...current, settings: { ...current.settings, [key]: value } } : current));
  };

  const handleAccountQueryChange = (next: AccountQuery) => {
    setAccountQuery(next);
  };

  const handleToggleSelection = (accountId: number, checked: boolean) => {
    setSelectedAccountIds((current) => (checked ? mergeIds(current, [accountId]) : current.filter((id) => id !== accountId)));
  };

  const handleTogglePageSelection = (checked: boolean) => {
    if (checked) {
      setSelectedAccountIds((current) => mergeIds(current, currentPageIds));
      return;
    }
    setSelectedAccountIds((current) => current.filter((id) => !currentPageIds.includes(id)));
  };

  const handleApplyBatchGroup = async () => {
    if (selectedAccountIds.length === 0) return;
    try {
      setBatchBusy(true);
      setError(null);
      await api("/api/accounts/group", {
        method: "POST",
        body: JSON.stringify({ ids: selectedAccountIds, groupName: batchGroupName || null }),
      });
      await refreshAccounts();
      setBatchGroupName("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBatchBusy(false);
    }
  };

  const handleDeleteSelected = async () => {
    if (selectedAccountIds.length === 0) return;
    try {
      setBatchBusy(true);
      setError(null);
      const payload = await api<{ deleted: number; blockedIds: number[] }>("/api/accounts", {
        method: "DELETE",
        body: JSON.stringify({ ids: selectedAccountIds }),
      });
      setRevealedPasswordsById((current) => {
        const next = { ...current };
        for (const accountId of selectedAccountIds.filter((id) => !payload.blockedIds.includes(id))) {
          delete next[accountId];
        }
        return next;
      });
      setSelectedAccountIds(payload.blockedIds);
      if (payload.blockedIds.length > 0) {
        setError("部分账号无法删除：这些账号正在运行中或已经关联 API key。");
      }
      await refreshAccounts();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBatchBusy(false);
    }
  };

  const handleToggleApiKeySelection = (apiKeyId: number, checked: boolean) => {
    setSelectedApiKeyIds((current) => (checked ? mergeIds(current, [apiKeyId]) : current.filter((id) => id !== apiKeyId)));
  };

  const handleToggleApiKeyPageSelection = (checked: boolean) => {
    const currentPageApiKeyIds = apiKeys.rows.map((row) => row.id);
    if (checked) {
      setSelectedApiKeyIds((current) => mergeIds(current, currentPageApiKeyIds));
      return;
    }
    setSelectedApiKeyIds((current) => current.filter((id) => !currentPageApiKeyIds.includes(id)));
  };

  const handleOpenApiKeyExport = async () => {
    if (selectedApiKeyIds.length === 0) return;
    try {
      setApiKeyExportBusy(true);
      setError(null);
      const payload = await api<ApiKeyExportPayload>("/api/api-keys/export", {
        method: "POST",
        body: JSON.stringify({ ids: selectedApiKeyIds }),
      });
      if (payload.items.length === 0) {
        setError("选中的 API key 已不存在");
        return;
      }
      setApiKeyExportContent(payload.content);
      setApiKeyExportOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setApiKeyExportBusy(false);
    }
  };

  const handleCopyApiKeyExport = async () => {
    if (!apiKeyExportContent) return;
    try {
      setError(null);
      await navigator.clipboard.writeText(apiKeyExportContent);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleSaveApiKeyExport = () => {
    if (!apiKeyExportContent) return;
    const blob = new Blob([apiKeyExportContent], { type: "text/plain;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = buildApiKeyExportFilename();
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => window.URL.revokeObjectURL(url), 0);
  };

  const handleToggleGrokApiKeySelection = (apiKeyId: number, checked: boolean) => {
    setSelectedGrokApiKeyIds((current) => (checked ? mergeIds(current, [apiKeyId]) : current.filter((id) => id !== apiKeyId)));
  };

  const handleToggleGrokApiKeyPageSelection = (checked: boolean) => {
    const currentPageApiKeyIds = grokApiKeys.rows.map((row) => row.id);
    if (checked) {
      setSelectedGrokApiKeyIds((current) => mergeIds(current, currentPageApiKeyIds));
      return;
    }
    setSelectedGrokApiKeyIds((current) => current.filter((id) => !currentPageApiKeyIds.includes(id)));
  };

  const handleOpenGrokApiKeyExport = async () => {
    if (selectedGrokApiKeyIds.length === 0) return;
    try {
      setGrokApiKeyExportBusy(true);
      setError(null);
      const payload = await api<GrokApiKeyExportPayload>("/api/grok/keys/export", {
        method: "POST",
        body: JSON.stringify({ ids: selectedGrokApiKeyIds }),
      });
      if (payload.items.length === 0) {
        setError("选中的 Grok API key 已不存在");
        return;
      }
      setGrokApiKeyExportContent(payload.content);
      setGrokApiKeyExportOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGrokApiKeyExportBusy(false);
    }
  };

  const handleCopyGrokApiKeyExport = async () => {
    if (!grokApiKeyExportContent) return;
    try {
      setError(null);
      await navigator.clipboard.writeText(grokApiKeyExportContent);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const resolveGrokCopyField = async (apiKeyId: number, field: "email" | "password" | "sso") => {
    const payload = await api<GrokApiKeyExportPayload>("/api/grok/keys/export", {
      method: "POST",
      body: JSON.stringify({ ids: [apiKeyId] }),
    });
    const item = payload.items[0];
    if (!item) {
      throw new Error("选中的 Grok 记录已不存在");
    }
    const value = field === "email" ? item.email : field === "password" ? item.password : item.sso;
    if (!value?.trim()) {
      throw new Error(`当前记录没有可复制的${field === "email" ? "邮箱" : field === "password" ? "密码" : "SSO"}`);
    }
    return value;
  };

  const handleSaveGrokApiKeyExport = () => {
    if (!grokApiKeyExportContent) return;
    const blob = new Blob([grokApiKeyExportContent], { type: "text/plain;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `grok-${buildApiKeyExportFilename()}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => window.URL.revokeObjectURL(url), 0);
  };

  const handleSaveProofMailbox = async (accountId: number, proofMailboxAddress: string | null, proofMailboxId?: string | null) => {
    try {
      setBatchBusy(true);
      setError(null);
      await api<AccountUpdatePayload>(`/api/accounts/${accountId}`, {
        method: "PATCH",
        body: JSON.stringify({
          proofMailboxProvider: proofMailboxAddress ? "cfmail" : null,
          proofMailboxAddress,
          proofMailboxId: proofMailboxAddress ? (proofMailboxId ?? null) : null,
        }),
      });
      await refreshAccounts(accountQueryRef.current);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setBatchBusy(false);
    }
  };

  const handleSaveAvailability = async (accountId: number, disabled: boolean, disabledReason: string | null) => {
    try {
      setBatchBusy(true);
      setError(null);
      await api<AccountUpdatePayload>(`/api/accounts/${accountId}`, {
        method: "PATCH",
        body: JSON.stringify({
          disabled,
          disabledReason,
        }),
      });
      await refreshAccounts(accountQueryRef.current);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setBatchBusy(false);
    }
  };

  const handleSaveMicrosoftGraphSettings = async () => {
    try {
      setGraphSettingsBusy(true);
      setError(null);
      const payload = await api<MicrosoftGraphSettingsPayload>("/api/microsoft-mail/settings", {
        method: "POST",
        body: JSON.stringify(microsoftGraphSettingsDraft),
      });
      setMicrosoftGraphSettings(payload.settings);
      setMicrosoftGraphSettingsDraft((current) => ({
        ...current,
        microsoftGraphClientId: payload.settings.microsoftGraphClientId,
        microsoftGraphClientSecret: "",
        microsoftGraphRedirectUri: payload.settings.microsoftGraphRedirectUri,
        microsoftGraphAuthority: payload.settings.microsoftGraphAuthority || "common",
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setGraphSettingsBusy(false);
    }
  };

  const handleOpenMailbox = (accountId: number) => {
    navigate(`/mailboxes?accountId=${accountId}`);
  };

  const startMailboxConnectionForAccount = async (accountId: number, options?: { force?: boolean; proxyNode?: string | null }) => {
    const requestBody: AccountSessionRebootstrapRequest = { force: options?.force !== false };
    if (options?.proxyNode !== undefined) {
      requestBody.proxyNode = options.proxyNode;
    }
    const payload = await api<AccountUpdatePayload>(`/api/accounts/${accountId}/session/rebootstrap`, {
      method: "POST",
      body: JSON.stringify(requestBody),
    });
    setAccounts((current) => mergeAccountIntoAccountsPayload(current, payload.account));
    const refreshResults = await Promise.allSettled([
      refreshAccounts(accountQueryRef.current),
      refreshMailboxes(),
      refreshProxies(),
    ]);
    const accountRefreshError = refreshResults[0].status === "rejected" ? refreshResults[0].reason : null;
    const mailboxRefreshError = refreshResults[1].status === "rejected" ? refreshResults[1].reason : null;
    const proxyRefreshError = refreshResults[2].status === "rejected" ? refreshResults[2].reason : null;
    if (proxyRefreshError) {
      console.warn(
        "[accounts] refreshProxies failed after session rebootstrap queued:",
        proxyRefreshError instanceof Error ? proxyRefreshError.message : String(proxyRefreshError),
      );
    }
    if (accountRefreshError) {
      throw accountRefreshError;
    }
    if (mailboxRefreshError) {
      throw mailboxRefreshError;
    }
    return payload;
  };

  const handleConnectAccount = async (accountId: number) => {
    try {
      setAccountConnectBusy(true);
      setAccountConnectProgress({ current: 1, total: 1 });
      setActiveBatchBootstrapMode(null);
      setConnectingAccountIds([accountId]);
      setError(null);
      await startMailboxConnectionForAccount(accountId, { force: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setConnectingAccountIds([]);
      setAccountConnectProgress(null);
      setAccountConnectBusy(false);
    }
  };

  const handleSwitchAccountSessionProxy = async (accountId: number, proxyNode: string) => {
    try {
      setAccountConnectBusy(true);
      setAccountConnectProgress({ current: 1, total: 1 });
      setActiveBatchBootstrapMode(null);
      setConnectingAccountIds([accountId]);
      setError(null);
      await startMailboxConnectionForAccount(accountId, { force: true, proxyNode });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setConnectingAccountIds([]);
      setAccountConnectProgress(null);
      setAccountConnectBusy(false);
    }
  };

  const handleConnectSelectedAccounts = async (mode: AccountBatchBootstrapMode = "pending_only") => {
    if (selectedAccountIds.length === 0) return;
    const uniqueSelectedIds = Array.from(new Set(selectedAccountIds.filter((id) => Number.isInteger(id) && id > 0)));
    let preview: AccountBatchBootstrapPreviewPayload;
    try {
      setError(null);
      preview = await previewBatchBootstrap(uniqueSelectedIds, mode);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    const queue = preview.queueIds;
    if (queue.length === 0) {
      const parts: string[] = [];
      if (preview.summary.blockedCount > 0) {
        parts.push(`已跳过 ${preview.summary.blockedCount} 个锁定、禁用或占用中的账号`);
      }
      if (preview.summary.bootstrappingCount > 0) {
        parts.push(`已跳过 ${preview.summary.bootstrappingCount} 个正在 Bootstrap 或排队中的账号`);
      }
      if (preview.summary.alreadyBootstrappedCount > 0 && mode === "pending_only") {
        parts.push(`所选账号里有 ${preview.summary.alreadyBootstrappedCount} 个已 Bootstrap 成功`);
      }
      setError(parts.join("；") || "当前没有可执行的 Bootstrap 目标");
      return;
    }
    const emailById = new Map(
      preview.items
        .filter((item) => item.accountId != null)
        .map((item) => [item.accountId as number, item.microsoftEmail || `#${item.accountId}`]),
    );
    const failedAccounts: string[] = [];
    let revalidatedSkipCount = 0;
    try {
      setAccountConnectBusy(true);
      setActiveBatchBootstrapMode(mode);
      setError(null);
      for (let index = 0; index < queue.length; index += 1) {
        const accountId = queue[index]!;
        const accountLabel = emailById.get(accountId) || `#${accountId}`;
        setAccountConnectProgress({ current: index + 1, total: queue.length });
        setConnectingAccountIds([accountId]);
        try {
          const payload = await startMailboxConnectionForAccount(accountId, { force: mode === "force" });
          if (!payload.queued) {
            revalidatedSkipCount += 1;
          }
        } catch {
          failedAccounts.push(accountLabel);
        }
      }
      if (
        failedAccounts.length > 0
        || revalidatedSkipCount > 0
        || preview.summary.blockedCount > 0
        || preview.summary.bootstrappingCount > 0
        || (preview.summary.alreadyBootstrappedCount > 0 && mode === "pending_only")
      ) {
        const parts: string[] = [];
        if (failedAccounts.length > 0) {
          parts.push(`部分账号 Bootstrap 失败：${failedAccounts.slice(0, 4).join("、")}${failedAccounts.length > 4 ? " 等" : ""}`);
        }
        if (revalidatedSkipCount > 0) {
          parts.push(`已跳过 ${revalidatedSkipCount} 个执行前状态已变化的账号`);
        }
        if (preview.summary.blockedCount > 0) {
          parts.push(`已跳过 ${preview.summary.blockedCount} 个锁定、禁用或占用中的账号`);
        }
        if (preview.summary.bootstrappingCount > 0) {
          parts.push(`已跳过 ${preview.summary.bootstrappingCount} 个正在 Bootstrap 或排队中的账号`);
        }
        if (preview.summary.alreadyBootstrappedCount > 0 && mode === "pending_only") {
          parts.push(`已跳过 ${preview.summary.alreadyBootstrappedCount} 个已 Bootstrap 成功的账号`);
        }
        setError(parts.join("；"));
      }
    } finally {
      setConnectingAccountIds([]);
      setAccountConnectProgress(null);
      setActiveBatchBootstrapMode(null);
      setAccountConnectBusy(false);
      await refreshMailboxAccountState().catch((err) => setError(err instanceof Error ? err.message : String(err)));
    }
  };

  const handleOpenMailboxSettings = () => {
    navigate("/mailboxes/settings");
  };

  const handleBackToMailboxes = () => {
    if (selectedMailbox) {
      navigate(`/mailboxes?accountId=${selectedMailbox.accountId}`);
      return;
    }
    navigate("/mailboxes");
  };

  const handleSelectMailbox = (mailboxId: number) => {
    const mailbox = mailboxes.find((item) => item.id === mailboxId) || null;
    setSelectedMailboxId(mailboxId);
    setSelectedMessageId(null);
    setSelectedMessageDetail(null);
    if (mailbox) {
      navigate(`/mailboxes?accountId=${mailbox.accountId}`);
    }
  };

  const handleSyncMailbox = async (mailboxId: number) => {
    try {
      setSyncingMailboxId(mailboxId);
      setError(null);
      await api<MailboxSyncPayload>(`/api/microsoft-mail/mailboxes/${mailboxId}/sync`, {
        method: "POST",
      });
      await refreshMailboxes();
      await refreshMailboxMessages(mailboxId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setSyncingMailboxId(null);
    }
  };

  const handleLoadMoreMailboxMessages = async () => {
    if (!selectedMailbox) return;
    try {
      setError(null);
      await refreshMailboxMessages(selectedMailbox.id, {
        offset: mailboxMessages.rows.length,
        append: true,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    }
  };

  const handleSelectMailboxMessage = async (messageId: number) => {
    try {
      setSelectedMessageId(messageId);
      setError(null);
      await refreshMailboxMessageDetail(messageId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    }
  };

  useEffect(() => {
    if (!isMailboxWorkspacePage) return;
    if (!mailboxMessages.rows.length) {
      setSelectedMessageId(null);
      setSelectedMessageDetail(null);
      return;
    }
    if (selectedMessageId && mailboxMessages.rows.some((row) => row.id === selectedMessageId)) {
      return;
    }
    const firstMessageId = mailboxMessages.rows[0]?.id || null;
    if (firstMessageId) {
      setSelectedMessageId(firstMessageId);
      void refreshMailboxMessageDetail(firstMessageId).catch((err) => setError(err instanceof Error ? err.message : String(err)));
    }
  }, [isMailboxWorkspacePage, mailboxMessages.rows, selectedMessageId]);

  return (
    <AppShell
      activePage={activePage}
      error={error}
      onNavigate={(page) =>
        navigate(
          page === "tavily" ? "/" : page === "keys" ? "/keys" : `/${page}`,
        )
      }
    >
      {activePage === "tavily" ? (
        <DashboardView
          job={job}
          events={events}
          jobDraft={jobDraft}
          runModeAvailability={job.runModeAvailability}
          extractorAvailability={
            extractorSettings?.availability || {
              zhanghaoya: false,
              shanyouxiang: false,
              shankeyun: false,
              hotmail666: false,
            }
          }
          onJobDraftChange={updateJobDraft}
          onJobAction={handleJobAction}
        />
      ) : null}

      {activePage === "grok" ? (
        <GrokView
          job={grokJob}
          jobDraft={grokJobDraft}
          jobBusy={grokJobBusy}
          onJobDraftChange={(patch) =>
            setGrokJobDraft((current) =>
              normalizeJobDraft({
                ...current,
                ...patch,
                autoExtractSources: [],
              }),
            )
          }
          onJobAction={handleGrokJobAction}
        />
      ) : null}

      {activePage === "chatgpt" ? (
        <ChatGptView
          jobDraft={chatGptJobDraft}
          job={chatGptJob}
          runModeAvailability={chatGptJob.runModeAvailability}
          jobBusy={chatGptJobBusy}
          draftTouched={chatGptJobDraftTouched}
          groupOptions={chatGptUpstreamSettings.groupHistory}
          onJobDraftChange={handleChatGptJobDraftChange}
          onJobAction={handleChatGptJobAction}
        />
      ) : null}

      {activePage === "accounts" ? (
        <AccountsView
          accounts={accounts}
          importContent={importContent}
          importGroupName={importGroupName}
          batchGroupName={batchGroupName}
          preview={importPreview}
          previewCommitCount={importCommitEntries.length}
          previewOpen={importPreviewOpen}
          query={accountQuery}
          selectedIds={selectedAccountIds}
          revealedPasswordsById={revealedPasswordsById}
          importBusy={importBusy}
          previewBusy={previewBusy}
          batchBusy={batchBusy}
          connectBusy={accountConnectBusy}
          connectProgress={accountConnectProgress}
          batchBootstrapPreview={batchBootstrapPreview}
          batchBootstrapPreviewBusy={batchBootstrapPreviewBusy}
          activeBatchBootstrapMode={activeBatchBootstrapMode}
          extractorSettings={extractorSettings}
          extractorSettingsBusy={extractorSettingsBusy}
          extractorRuntime={extractorRuntime}
          extractorRunDraft={extractorRunDraft}
          extractorRunBusy={extractorRunBusy}
          extractorSseState={extractorSseState}
          extractorHistory={extractorHistory}
          extractorHistoryQuery={extractorHistoryQuery}
          extractorHistoryBusy={extractorHistoryBusy}
          allCurrentPageSelected={allCurrentPageSelected}
          graphSettingsConfigured={microsoftGraphSettings?.configured ?? false}
          connectingAccountIds={connectingAccountIds}
          proxyNodes={proxies?.nodes || []}
          proxyCheckState={proxies?.checkState || null}
          onImportContentChange={setImportContent}
          onImportGroupChange={setImportGroupName}
          onBatchGroupNameChange={setBatchGroupName}
          onOpenPreview={handleOpenImportPreview}
          onPreviewOpenChange={(open) => {
            setImportPreviewOpen(open);
            if (!open) setImportPreview(null);
          }}
          onConfirmImport={handleConfirmImport}
          onQueryChange={handleAccountQueryChange}
          onToggleSelection={handleToggleSelection}
          onTogglePageSelection={handleTogglePageSelection}
          onApplyBatchGroup={handleApplyBatchGroup}
          onDeleteSelected={handleDeleteSelected}
          onClearSelection={() => setSelectedAccountIds([])}
          onConnectAccount={handleConnectAccount}
          onConnectSelectedAccounts={handleConnectSelectedAccounts}
          onCheckProxyNode={handleCheckSingleNode}
          onSwitchSessionProxy={handleSwitchAccountSessionProxy}
          onSaveProofMailbox={handleSaveProofMailbox}
          onSaveAvailability={handleSaveAvailability}
          onSaveExtractorSettings={handleSaveExtractorSettings}
          onExtractorRunDraftChange={(patch) => {
            setExtractorRunDraftTouched(true);
            setExtractorRunDraft((current) => ({
              ...current,
              ...patch,
            }));
          }}
          onRunExtractor={handleRunExtractor}
          onStopExtractor={handleStopExtractor}
          onExtractorHistoryQueryChange={setExtractorHistoryQuery}
          onRefreshExtractorHistory={() => refreshExtractorHistory(extractorHistoryQueryRef.current)}
          onOpenMailbox={handleOpenMailbox}
        />
      ) : null}

      {activePage === "mailboxes" ? (
        isMailboxSettingsPage ? (
          <MailboxSettingsView
            settings={microsoftGraphSettings}
            settingsDraft={microsoftGraphSettingsDraft}
            settingsBusy={graphSettingsBusy}
            onSettingsDraftChange={(patch) =>
              setMicrosoftGraphSettingsDraft((current) => ({
                ...current,
                ...patch,
              }))
            }
            onSaveSettings={handleSaveMicrosoftGraphSettings}
            onBack={handleBackToMailboxes}
          />
        ) : (
          <MailboxesView
            settingsConfigured={microsoftGraphSettings?.configured ?? false}
            mailboxes={mailboxes}
            selectedMailbox={selectedMailbox}
            messages={mailboxMessages.rows}
            messagesTotal={mailboxMessages.total}
            messagesHasMore={mailboxMessages.hasMore}
            messagesBusy={messagesBusy || mailboxesBusy}
            selectedMessageId={selectedMessageId}
            messageDetail={selectedMessageDetail}
            messageBusy={messageBusy}
            syncingMailboxId={syncingMailboxId}
            onOpenSettings={handleOpenMailboxSettings}
            onSelectMailbox={handleSelectMailbox}
            onSyncMailbox={handleSyncMailbox}
            onLoadMoreMessages={handleLoadMoreMailboxMessages}
            onSelectMessage={handleSelectMailboxMessage}
          />
        )
      ) : null}

      {activePage === "keys" ? (
        <KeysView
          tavily={{
            apiKeys,
            query: apiKeyQuery,
            selectedIds: selectedApiKeyIds,
            exportOpen: apiKeyExportOpen,
            exportContent: apiKeyExportContent,
            exportBusy: apiKeyExportBusy,
            onQueryChange: setApiKeyQuery,
            onToggleSelection: handleToggleApiKeySelection,
            onTogglePageSelection: handleToggleApiKeyPageSelection,
            onClearSelection: () => setSelectedApiKeyIds([]),
            onOpenExport: handleOpenApiKeyExport,
            onExportOpenChange: setApiKeyExportOpen,
            onCopyExport: handleCopyApiKeyExport,
            onSaveExport: handleSaveApiKeyExport,
          }}
          grok={{
            apiKeys: grokApiKeys,
            query: grokApiKeyQuery,
            selectedIds: selectedGrokApiKeyIds,
            exportOpen: grokApiKeyExportOpen,
            exportContent: grokApiKeyExportContent,
            exportBusy: grokApiKeyExportBusy,
            onQueryChange: setGrokApiKeyQuery,
            onToggleSelection: handleToggleGrokApiKeySelection,
            onTogglePageSelection: handleToggleGrokApiKeyPageSelection,
            onClearSelection: () => setSelectedGrokApiKeyIds([]),
            onOpenExport: handleOpenGrokApiKeyExport,
            onExportOpenChange: setGrokApiKeyExportOpen,
            onCopyExport: handleCopyGrokApiKeyExport,
            onSaveExport: handleSaveGrokApiKeyExport,
            onResolveCopyField: async (apiKeyId, field) => {
              try {
                setError(null);
                return await resolveGrokCopyField(apiKeyId, field);
              } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
                throw err;
              }
            },
          }}
          chatgpt={{
            credentials: chatGptCredentials,
            query: chatGptCredentialQuery,
            sort: chatGptCredentialSort,
            credentialBusy: chatGptCredentialBusy,
            selectedIds: selectedChatGptCredentialIds,
            exportOpen: chatGptExportOpen,
            exportContent: chatGptExportContent,
            exportBusy: chatGptExportBusy,
            groupOptions: chatGptUpstreamSettings.groupHistory,
            upstreamSettingsConfigured: chatGptUpstreamSettings.configured,
            batchSupplementOpen: chatGptBatchSupplementOpen,
            batchSupplementBusy: chatGptBatchSupplementBusy,
            batchSupplementGroupName: chatGptBatchSupplementGroupName,
            batchSupplementResult: chatGptBatchSupplementResult,
            onQueryChange: setChatGptCredentialQuery,
            onSortChange: setChatGptCredentialSort,
            onToggleSelection: handleToggleChatGptCredentialSelection,
            onTogglePageSelection: handleToggleChatGptCredentialPageSelection,
            onClearSelection: () => setSelectedChatGptCredentialIds([]),
            onOpenExport: handleOpenChatGptCredentialExport,
            onExportOpenChange: setChatGptExportOpen,
            onCopyExport: handleCopyChatGptExport,
            onSaveExport: handleSaveChatGptExport,
            onCopyCredential: handleCopyChatGptCredential,
            onExportCredential: handleExportChatGptCredential,
            onBatchSupplementOpenChange: (open) => {
              setChatGptBatchSupplementOpen(open);
              if (!open) {
                setChatGptBatchSupplementResult(null);
              }
            },
            onBatchSupplementGroupNameChange: setChatGptBatchSupplementGroupName,
            onOpenBatchSupplement: handleOpenChatGptBatchSupplement,
            onSubmitBatchSupplement: handleSubmitChatGptBatchSupplement,
            onOpenUpstreamSettings: handleOpenChatGptUpstreamSettings,
          }}
        />
      ) : null}

      {activePage === "proxies" && proxies ? (
        <ProxiesView
          proxies={proxies}
          proxyCheckScope={proxyCheckScope}
          onProxyCheckScopeChange={setProxyCheckScope}
          onProxySettingsChange={updateProxySettings}
          onSaveProxySettings={handleSaveProxySettings}
          onCheckScope={handleProxyCheck}
          onCheckNode={handleCheckSingleNode}
        />
      ) : null}

      <ChatGptUpstreamSettingsDialog
        open={chatGptUpstreamSettingsOpen}
        onOpenChange={(open) => {
          setChatGptUpstreamSettingsOpen(open);
          if (!open) {
            setChatGptUpstreamSettingsError(null);
          }
        }}
        settings={chatGptUpstreamSettings}
        draft={chatGptUpstreamSettingsDraft}
        saveBusy={chatGptUpstreamSettingsBusy}
        error={chatGptUpstreamSettingsError}
        onDraftChange={(patch) => setChatGptUpstreamSettingsDraft((current) => ({ ...current, ...patch }))}
        onSave={handleSaveChatGptUpstreamSettings}
      />
    </AppShell>
  );
}
