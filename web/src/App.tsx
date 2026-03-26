import { useEffect, useMemo, useRef, useState } from "react";
import { AccountsView } from "@/components/accounts-view";
import { ApiKeysView } from "@/components/api-keys-view";
import { AppShell } from "@/components/app-shell";
import { DashboardView } from "@/components/dashboard-view";
import { ProxiesView } from "@/components/proxies-view";
import { buildImportCommitEntries, parseImportContent } from "@/lib/account-import";
import { buildApiKeyExportFilename } from "@/lib/api-key-export";
import type {
  AccountExtractorHistoryPayload,
  AccountExtractorHistoryQuery,
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
  JobDraft,
  JobSnapshot,
  PageKey,
  ProxyCheckScope,
  ProxyPayload,
  ProxySettings,
} from "@/lib/app-types";
import { jobToDraft, normalizeJobDraft } from "@/lib/job-draft";
import { getPageFromPathname, normalizeAppPath } from "@/lib/routes";

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
  const [pathname, setPathname] = useState(() => normalizeAppPath(window.location.pathname));

  useEffect(() => {
    const handlePopstate = () => setPathname(normalizeAppPath(window.location.pathname));
    window.addEventListener("popstate", handlePopstate);
    return () => window.removeEventListener("popstate", handlePopstate);
  }, []);

  return {
    pathname,
    navigate(next: string) {
      const normalized = normalizeAppPath(next);
      if (normalized === pathname) return;
      window.history.pushState({}, "", normalized);
      setPathname(normalized);
    },
  };
}

function mergeIds(current: number[], next: number[]): number[] {
  return Array.from(new Set([...current, ...next]));
}

export function App() {
  const { pathname, navigate } = usePathname();
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
  const [proxies, setProxies] = useState<ProxyPayload | null>(null);
  const [extractorSettings, setExtractorSettings] = useState<AccountExtractorSettings | null>(null);
  const [extractorHistory, setExtractorHistory] = useState<AccountExtractorHistoryPayload>({
    rows: [],
    total: 0,
    page: 1,
    pageSize: 10,
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
  const [accountQuery, setAccountQuery] = useState<AccountQuery>({ q: "", status: "", hasApiKey: "", groupName: "", page: 1, pageSize: 20 });
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

  const activePage = useMemo<PageKey>(() => getPageFromPathname(pathname), [pathname]);

  const selectedProxy = useMemo(
    () => proxies?.nodes.find((node) => node.isSelected) || null,
    [proxies],
  );
  const accountQueryRef = useRef(accountQuery);
  const apiKeyQueryRef = useRef(apiKeyQuery);
  const extractorHistoryQueryRef = useRef(extractorHistoryQuery);
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

  useEffect(() => {
    void Promise.all([refreshJob(), refreshAccounts(), refreshApiKeys(), refreshProxies(), refreshExtractorSettings(), refreshExtractorHistory()]).catch((err) => {
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
    accountQueryRef.current = accountQuery;
  }, [accountQuery]);

  useEffect(() => {
    apiKeyQueryRef.current = apiKeyQuery;
  }, [apiKeyQuery]);

  useEffect(() => {
    extractorHistoryQueryRef.current = extractorHistoryQuery;
  }, [extractorHistoryQuery]);

  useEffect(() => {
    activePageRef.current = activePage;
  }, [activePage]);

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
    void refreshAccounts(accountQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [accountQuery]);

  useEffect(() => {
    void refreshApiKeys().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [apiKeyQuery]);

  useEffect(() => {
    void refreshExtractorHistory(extractorHistoryQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [extractorHistoryQuery]);

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

  const handleJobAction = async (action: "start" | "pause" | "resume" | "update_limits") => {
    try {
      setError(null);
      const payload = await api<{ ok: true; job?: JobSnapshot["job"] }>("/api/jobs/current/control", {
        method: "POST",
        body: JSON.stringify({
          action,
          ...jobDraft,
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

  const handleSaveProxySettings = async () => {
    if (!proxies) return;
    try {
      setError(null);
      await api("/api/proxies/settings", {
        method: "POST",
        body: JSON.stringify(proxies.settings),
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
  return (
    <AppShell activePage={activePage} error={error} onNavigate={(page) => navigate(page === "dashboard" ? "/" : page === "apiKeys" ? "/api-keys" : `/${page}`)}>
      {activePage === "dashboard" ? (
        <DashboardView
          job={job}
          events={events}
          jobDraft={jobDraft}
          extractorAvailability={extractorSettings?.availability || { zhanghaoya: false, shanyouxiang: false }}
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
          extractorSettings={extractorSettings}
          extractorSettingsBusy={extractorSettingsBusy}
          extractorHistory={extractorHistory}
          extractorHistoryQuery={extractorHistoryQuery}
          extractorHistoryBusy={extractorHistoryBusy}
          allCurrentPageSelected={allCurrentPageSelected}
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
          onSaveProofMailbox={handleSaveProofMailbox}
          onSaveAvailability={handleSaveAvailability}
          onSaveExtractorSettings={handleSaveExtractorSettings}
          onExtractorHistoryQueryChange={setExtractorHistoryQuery}
          onRefreshExtractorHistory={() => refreshExtractorHistory(extractorHistoryQueryRef.current)}
        />
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
