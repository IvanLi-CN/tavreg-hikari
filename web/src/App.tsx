import { useEffect, useMemo, useState } from "react";
import { AccountsView } from "@/components/accounts-view";
import { ApiKeysView } from "@/components/api-keys-view";
import { AppShell } from "@/components/app-shell";
import { DashboardView } from "@/components/dashboard-view";
import { ProxiesView } from "@/components/proxies-view";
import { parseImportContent } from "@/lib/account-import";
import type {
  AccountImportPayload,
  AccountImportPreviewPayload,
  AccountQuery,
  AccountsPayload,
  ApiKeyQuery,
  ApiKeyRecord,
  EventRecord,
  JobDraft,
  JobSnapshot,
  PageKey,
  ProxyCheckScope,
  ProxyPayload,
  ProxySettings,
} from "@/lib/app-types";

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
  const [pathname, setPathname] = useState(window.location.pathname);

  useEffect(() => {
    const handlePopstate = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", handlePopstate);
    return () => window.removeEventListener("popstate", handlePopstate);
  }, []);

  return {
    pathname,
    navigate(next: string) {
      if (next === pathname) return;
      window.history.pushState({}, "", next);
      setPathname(next);
    },
  };
}

function mergeIds(current: number[], next: number[]): number[] {
  return Array.from(new Set([...current, ...next]));
}

export function App() {
  const { pathname, navigate } = usePathname();
  const [job, setJob] = useState<JobSnapshot>({ job: null, activeAttempts: [], recentAttempts: [], eligibleCount: 0 });
  const [accounts, setAccounts] = useState<AccountsPayload>({ rows: [], total: 0, page: 1, pageSize: 20, groups: [] });
  const [apiKeys, setApiKeys] = useState<{ rows: ApiKeyRecord[]; total: number }>({ rows: [], total: 0 });
  const [proxies, setProxies] = useState<ProxyPayload | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [importContent, setImportContent] = useState("");
  const [importGroupName, setImportGroupName] = useState("");
  const [batchGroupName, setBatchGroupName] = useState("");
  const [importPreview, setImportPreview] = useState<AccountImportPreviewPayload | null>(null);
  const [importPreviewOpen, setImportPreviewOpen] = useState(false);
  const [selectedAccountIds, setSelectedAccountIds] = useState<number[]>([]);
  const [revealedPasswordsById, setRevealedPasswordsById] = useState<Record<number, string>>({});
  const [jobDraft, setJobDraft] = useState<JobDraft>({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 5 });
  const [accountQuery, setAccountQuery] = useState<AccountQuery>({ q: "", status: "", hasApiKey: "", groupName: "", page: 1, pageSize: 20 });
  const [apiKeyQuery, setApiKeyQuery] = useState<ApiKeyQuery>({ q: "", status: "" });
  const [proxyCheckScope, setProxyCheckScope] = useState<ProxyCheckScope>("current");
  const [jobDraftTouched, setJobDraftTouched] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [batchBusy, setBatchBusy] = useState(false);

  const activePage = useMemo<PageKey>(() => {
    if (pathname === "/accounts") return "accounts";
    if (pathname === "/api-keys") return "apiKeys";
    if (pathname === "/proxies") return "proxies";
    return "dashboard";
  }, [pathname]);

  const selectedProxy = useMemo(
    () => proxies?.nodes.find((node) => node.isSelected) || null,
    [proxies],
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
  const refreshApiKeys = async () => {
    const params = new URLSearchParams();
    if (apiKeyQuery.q) params.set("q", apiKeyQuery.q);
    if (apiKeyQuery.status) params.set("status", apiKeyQuery.status);
    setApiKeys(await api<{ rows: ApiKeyRecord[]; total: number }>(`/api/api-keys?${params.toString()}`));
  };
  const refreshProxies = async () => {
    const payload = await api<ProxyPayload>("/api/proxies");
    setProxies(payload);
  };

  useEffect(() => {
    void Promise.all([refreshJob(), refreshAccounts(), refreshApiKeys(), refreshProxies()]).catch((err) => {
      setError(err instanceof Error ? err.message : String(err));
    });
  }, []);

  useEffect(() => {
    if (!proxies || jobDraftTouched) return;
    setJobDraft({
      runMode: proxies.settings.defaultRunMode,
      need: proxies.settings.defaultNeed,
      parallel: proxies.settings.defaultParallel,
      maxAttempts: proxies.settings.defaultMaxAttempts,
    });
  }, [jobDraftTouched, proxies]);

  useEffect(() => {
    const socket = new WebSocket(`${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/api/events/ws`);
    socket.onmessage = (event) => {
      const next = JSON.parse(event.data) as EventRecord;
      setEvents((current) => [next, ...current].slice(0, 60));
      if (next.type === "job.updated" || next.type === "attempt.updated") {
        void refreshJob();
      }
      if (next.type === "account.updated") {
        void refreshAccounts();
        void refreshApiKeys();
      }
      if (next.type === "proxy.updated" || next.type === "proxy.check.completed") {
        void refreshProxies();
      }
    };
    socket.onerror = () => setError("WebSocket disconnected");
    return () => socket.close();
  }, [accountQuery, apiKeyQuery]);

  useEffect(() => {
    void refreshAccounts(accountQuery).catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [accountQuery]);

  useEffect(() => {
    void refreshApiKeys().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [apiKeyQuery]);

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
    if (!importPreview) return;
    try {
      setImportBusy(true);
      setError(null);
      setAccountQuery((current) => ({ ...current, page: 1 }));
      const payload = await api<AccountImportPayload>("/api/accounts/import", {
        method: "POST",
        body: JSON.stringify({
          entries: importPreview.effectiveEntries,
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
    setJobDraft((current) => ({ ...current, ...patch }));
  };

  const handleJobAction = async (action: "start" | "pause" | "resume" | "update_limits") => {
    try {
      setError(null);
      await api("/api/jobs/current/control", {
        method: "POST",
        body: JSON.stringify({
          action,
          ...jobDraft,
        }),
      });
      await refreshJob();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
      await refreshProxies();
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
      await refreshProxies();
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

  return (
    <AppShell activePage={activePage} error={error} onNavigate={(page) => navigate(page === "dashboard" ? "/" : page === "apiKeys" ? "/api-keys" : `/${page}`)}>
      {activePage === "dashboard" ? (
        <DashboardView
          job={job}
          events={events}
          jobDraft={jobDraft}
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
          previewOpen={importPreviewOpen}
          query={accountQuery}
          selectedIds={selectedAccountIds}
          revealedPasswordsById={revealedPasswordsById}
          importBusy={importBusy}
          previewBusy={previewBusy}
          batchBusy={batchBusy}
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
        />
      ) : null}

      {activePage === "apiKeys" ? (
        <ApiKeysView
          apiKeys={apiKeys}
          query={apiKeyQuery}
          onQueryChange={setApiKeyQuery}
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
