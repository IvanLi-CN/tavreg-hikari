import { useEffect, useMemo, useRef, useState } from "react";
import { AccountsView } from "@/components/accounts-view";
import { ApiKeysView } from "@/components/api-keys-view";
import { AppShell } from "@/components/app-shell";
import { DashboardView } from "@/components/dashboard-view";
import { MailboxSettingsView } from "@/components/mailbox-settings-view";
import { MailboxesView } from "@/components/mailboxes-view";
import { ProxiesView } from "@/components/proxies-view";
import { buildImportCommitEntries, parseImportContent } from "@/lib/account-import";
import { buildApiKeyExportFilename } from "@/lib/api-key-export";
import type {
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
  AccountUpdatePayload,
  AccountQuery,
  AccountsPayload,
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
  ProxyCheckScope,
  ProxyPayload,
  ProxySettings,
} from "@/lib/app-types";
import { jobToDraft, normalizeJobDraft } from "@/lib/job-draft";
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

function isLockedBatchConnectAccount(account: Pick<AccountRecord, "skipReason" | "lastErrorCode">): boolean {
  return (
    String(account.skipReason || "").trim() === "microsoft_account_locked"
    || /^microsoft_account_locked/i.test(String(account.lastErrorCode || "").trim())
  );
}

function isBatchConnectBlockedAccount(
  account: Pick<AccountRecord, "disabledAt" | "skipReason" | "lastErrorCode" | "browserSession">,
): boolean {
  return Boolean(account.disabledAt) || isLockedBatchConnectAccount(account) || account.browserSession?.status === "bootstrapping";
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

function isExtractorRuntimeTerminal(runtime: AccountExtractorRuntime): boolean {
  return runtime.status === "idle" || runtime.status === "stopped" || runtime.status === "succeeded" || runtime.status === "failed";
}

export function App() {
  const { pathname, search, navigate } = usePathname();
  const [job, setJob] = useState<JobSnapshot>({
    job: null,
    activeAttempts: [],
    recentAttempts: [],
    eligibleCount: 0,
    autoExtractState: null,
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
  const [accountQuery, setAccountQuery] = useState<AccountQuery>({
    q: "",
    status: "",
    hasApiKey: "",
    groupName: "",
    sortBy: "",
    sortDir: "desc",
    page: 1,
    pageSize: 20,
  });
  const [apiKeyQuery, setApiKeyQuery] = useState<ApiKeyQuery>({ q: "", status: "", groupName: "", page: 1, pageSize: 20 });
  const [extractorHistoryQuery, setExtractorHistoryQuery] = useState<AccountExtractorHistoryQuery>({
    provider: "",
    status: "",
    q: "",
    page: 1,
    pageSize: 10,
  });
  const [proxyCheckScope, setProxyCheckScope] = useState<ProxyCheckScope>("current");
  const [jobDraftTouched, setJobDraftTouched] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [batchBusy, setBatchBusy] = useState(false);
  const [apiKeyExportOpen, setApiKeyExportOpen] = useState(false);
  const [apiKeyExportContent, setApiKeyExportContent] = useState("");
  const [apiKeyExportBusy, setApiKeyExportBusy] = useState(false);
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
  const [connectingAccountIds, setConnectingAccountIds] = useState<number[]>([]);
  const [syncingMailboxId, setSyncingMailboxId] = useState<number | null>(null);

  const activePage = useMemo<PageKey>(() => getPageFromPathname(pathname), [pathname]);
  const isMailboxSettingsPage = useMemo(() => isMailboxSettingsPath(pathname), [pathname]);
  const isMailboxWorkspacePage = activePage === "mailboxes" && !isMailboxSettingsPage;
  const mailboxSelectionRef = useRef<number | null>(null);
  const autoSyncedMailboxIdsRef = useRef<number[]>([]);

  const selectedProxy = useMemo(
    () => proxies?.nodes.find((node) => node.isSelected) || null,
    [proxies],
  );
  const selectedMailbox = useMemo(
    () => mailboxes.find((mailbox) => mailbox.id === selectedMailboxId) || null,
    [mailboxes, selectedMailboxId],
  );
  const accountQueryRef = useRef(accountQuery);
  const apiKeyQueryRef = useRef(apiKeyQuery);
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

  const refreshJob = async () => setJob(await api<JobSnapshot>("/api/jobs/current"));
  const refreshAccounts = async (nextQuery = accountQuery) => {
    const params = new URLSearchParams();
    if (nextQuery.q) params.set("q", nextQuery.q);
    if (nextQuery.status) params.set("status", nextQuery.status);
    if (nextQuery.hasApiKey) params.set("hasApiKey", nextQuery.hasApiKey);
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
  };
  const refreshApiKeys = async (nextQuery = apiKeyQuery) => {
    const params = new URLSearchParams();
    if (nextQuery.q) params.set("q", nextQuery.q);
    if (nextQuery.status) params.set("status", nextQuery.status);
    if (nextQuery.groupName) params.set("groupName", nextQuery.groupName);
    params.set("page", String(nextQuery.page));
    params.set("pageSize", String(nextQuery.pageSize));
    const payload = await api<ApiKeysPayload>(`/api/api-keys?${params.toString()}`);
    if (payload.rows.length === 0 && payload.total > 0 && nextQuery.page > 1) {
      setApiKeyQuery((current) => ({ ...current, page: current.page - 1 }));
      return;
    }
    setApiKeys(payload);
  };
  const refreshProxies = async () => {
    const payload = await api<ProxyPayload>("/api/proxies");
    setProxies(payload);
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

  useEffect(() => {
    void Promise.all([
      refreshJob(),
      refreshAccounts(),
      refreshApiKeys(),
      refreshProxies(),
      refreshExtractorSettings(),
      refreshExtractorRuntime(),
      refreshExtractorHistory(),
      refreshMicrosoftGraphSettings(),
      refreshMailboxes(),
    ]).catch((err) => {
      setError(err instanceof Error ? err.message : String(err));
    });
  }, []);

  useEffect(() => {
    if (job.job || !proxies || !extractorSettings || jobDraftTouched) return;
    setJobDraft(normalizeJobDraft({
      runMode: proxies.settings.defaultRunMode,
      need: proxies.settings.defaultNeed,
      parallel: proxies.settings.defaultParallel,
      maxAttempts: proxies.settings.defaultMaxAttempts,
      autoExtractSources: extractorSettings.defaultAutoExtractSources,
      autoExtractQuantity: extractorSettings.defaultAutoExtractQuantity,
      autoExtractMaxWaitSec: extractorSettings.defaultAutoExtractMaxWaitSec,
      autoExtractAccountType: extractorSettings.defaultAutoExtractAccountType,
    }));
  }, [extractorSettings, job.job, jobDraftTouched, proxies]);

  useEffect(() => {
    if (!job.job || jobDraftTouched) return;
    setJobDraft(jobToDraft(job.job));
  }, [job.job, jobDraftTouched]);

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
        void refreshJob();
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
      if (next.type === "proxy.updated" || next.type === "proxy.check.completed") {
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
    void refreshAccounts(accountQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [accountQuery]);

  useEffect(() => {
    void refreshApiKeys().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [apiKeyQuery]);

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
    setJobDraft((current) => normalizeJobDraft({ ...current, ...patch }));
  };

  const handleJobAction = async (action: JobControlAction, options?: JobControlOptions) => {
    try {
      setError(null);
      const draft = options?.draft || jobDraft;
      const payload = await api<{ ok: true; job?: JobSnapshot["job"] }>("/api/jobs/current/control", {
        method: "POST",
        body: JSON.stringify({
          action,
          ...(options?.confirmForceStop ? { confirmForceStop: true } : {}),
          ...draft,
        }),
      });
      if (payload.job) {
        setJobDraft(jobToDraft(payload.job));
        setJobDraftTouched(false);
      }
      await refreshJob();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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

  const handleSaveProxySettings = async (settingsOverride?: ProxySettings) => {
    if (!proxies && !settingsOverride) return;
    try {
      setError(null);
      await api("/api/proxies/settings", {
        method: "POST",
        body: JSON.stringify(settingsOverride || proxies?.settings),
      });
      await refreshProxies();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleProxyCheck = async () => {
    try {
      setError(null);
      await api("/api/proxies/check", {
        method: "POST",
        body: JSON.stringify({ scope: proxyCheckScope }),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleSelectNode = async (nodeName: string) => {
    try {
      setError(null);
      await api("/api/proxies/select", {
        method: "POST",
        body: JSON.stringify({ nodeName }),
      });
      await refreshProxies();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleCheckSingleNode = async (nodeName: string) => {
    try {
      setError(null);
      await api("/api/proxies/check", {
        method: "POST",
        body: JSON.stringify({ scope: "node", nodeName }),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const updateProxySettings = <K extends keyof ProxySettings>(key: K, value: ProxySettings[K]) => {
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
  const handleSaveProofMailbox = async (accountId: number, proofMailboxAddress: string | null, proofMailboxId?: string | null) => {
    try {
      setBatchBusy(true);
      setError(null);
      await api<AccountUpdatePayload>(`/api/accounts/${accountId}`, {
        method: "PATCH",
        body: JSON.stringify({
          proofMailboxProvider: proofMailboxAddress ? "moemail" : null,
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

  const startMailboxConnectionForAccount = async (accountId: number) => {
    const payload = await api<AccountUpdatePayload>(`/api/accounts/${accountId}/session/rebootstrap`, {
      method: "POST",
    });
    await refreshMailboxAccountState();
    return payload;
  };

  const handleConnectAccount = async (accountId: number) => {
    try {
      setAccountConnectBusy(true);
      setAccountConnectProgress({ current: 1, total: 1 });
      setConnectingAccountIds([accountId]);
      setError(null);
      await startMailboxConnectionForAccount(accountId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setConnectingAccountIds([]);
      setAccountConnectProgress(null);
      setAccountConnectBusy(false);
    }
  };

  const handleConnectSelectedAccounts = async () => {
    if (selectedAccountIds.length === 0) return;
    const uniqueSelectedIds = Array.from(new Set(selectedAccountIds));
    const queue = uniqueSelectedIds.filter((accountId) => {
      const account = accounts.rows.find((row) => row.id === accountId);
      return !account || !isBatchConnectBlockedAccount(account);
    });
    const skippedAccounts = uniqueSelectedIds.length - queue.length;
    if (queue.length === 0) {
      setError(skippedAccounts > 0 ? "所选账号都已锁定或禁用，无法发起连接" : null);
      return;
    }
    const failedAccounts: string[] = [];
    try {
      setAccountConnectBusy(true);
      setError(null);
      for (let index = 0; index < queue.length; index += 1) {
        const accountId = queue[index]!;
        const accountLabel = accounts.rows.find((row) => row.id === accountId)?.microsoftEmail || `#${accountId}`;
        setAccountConnectProgress({ current: index + 1, total: queue.length });
        setConnectingAccountIds([accountId]);
        try {
          await startMailboxConnectionForAccount(accountId);
        } catch {
          failedAccounts.push(accountLabel);
        }
      }
      if (failedAccounts.length > 0 || skippedAccounts > 0) {
        const parts: string[] = [];
        if (failedAccounts.length > 0) {
          parts.push(`部分账号连接失败：${failedAccounts.slice(0, 4).join("、")}${failedAccounts.length > 4 ? " 等" : ""}`);
        }
        if (skippedAccounts > 0) {
          parts.push(`已跳过 ${skippedAccounts} 个锁定或禁用账号`);
        }
        setError(parts.join("；"));
      }
    } finally {
      setConnectingAccountIds([]);
      setAccountConnectProgress(null);
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
          page === "dashboard" ? "/" : page === "apiKeys" ? "/api-keys" : `/${page}`,
        )
      }
    >
      {activePage === "dashboard" ? (
        <DashboardView
          job={job}
          events={events}
          jobDraft={jobDraft}
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

      {activePage === "apiKeys" ? (
        <ApiKeysView
          apiKeys={apiKeys}
          query={apiKeyQuery}
          selectedIds={selectedApiKeyIds}
          exportOpen={apiKeyExportOpen}
          exportContent={apiKeyExportContent}
          exportBusy={apiKeyExportBusy}
          onQueryChange={setApiKeyQuery}
          onToggleSelection={handleToggleApiKeySelection}
          onTogglePageSelection={handleToggleApiKeyPageSelection}
          onClearSelection={() => setSelectedApiKeyIds([])}
          onOpenExport={handleOpenApiKeyExport}
          onExportOpenChange={setApiKeyExportOpen}
          onCopyExport={handleCopyApiKeyExport}
          onSaveExport={handleSaveApiKeyExport}
        />
      ) : null}

      {activePage === "proxies" && proxies ? (
        <ProxiesView
          proxies={proxies}
          selectedProxy={selectedProxy}
          proxyCheckScope={proxyCheckScope}
          onProxyCheckScopeChange={setProxyCheckScope}
          onProxySettingsChange={updateProxySettings}
          onSaveProxySettings={handleSaveProxySettings}
          onCheckScope={handleProxyCheck}
          onSelectNode={handleSelectNode}
          onCheckNode={handleCheckSingleNode}
        />
      ) : null}
    </AppShell>
  );
}
