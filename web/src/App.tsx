import { useEffect, useMemo, useState } from "react";
import { AccountsView } from "@/components/accounts-view";
import { ApiKeysView } from "@/components/api-keys-view";
import { AppShell } from "@/components/app-shell";
import { DashboardView } from "@/components/dashboard-view";
import { ProxiesView } from "@/components/proxies-view";
import type {
  AccountQuery,
  AccountRecord,
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

export function App() {
  const { pathname, navigate } = usePathname();
  const [job, setJob] = useState<JobSnapshot>({ job: null, activeAttempts: [], recentAttempts: [], eligibleCount: 0 });
  const [accounts, setAccounts] = useState<{ rows: AccountRecord[]; total: number }>({ rows: [], total: 0 });
  const [apiKeys, setApiKeys] = useState<{ rows: ApiKeyRecord[]; total: number }>({ rows: [], total: 0 });
  const [proxies, setProxies] = useState<ProxyPayload | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [importContent, setImportContent] = useState("");
  const [jobDraft, setJobDraft] = useState<JobDraft>({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 5 });
  const [accountQuery, setAccountQuery] = useState<AccountQuery>({ q: "", status: "", hasApiKey: "" });
  const [apiKeyQuery, setApiKeyQuery] = useState<ApiKeyQuery>({ q: "", status: "" });
  const [proxyCheckScope, setProxyCheckScope] = useState<ProxyCheckScope>("current");
  const [jobDraftTouched, setJobDraftTouched] = useState(false);

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

  const refreshJob = async () => setJob(await api<JobSnapshot>("/api/jobs/current"));
  const refreshAccounts = async () => {
    const params = new URLSearchParams();
    if (accountQuery.q) params.set("q", accountQuery.q);
    if (accountQuery.status) params.set("status", accountQuery.status);
    if (accountQuery.hasApiKey) params.set("hasApiKey", accountQuery.hasApiKey);
    setAccounts(await api<{ rows: AccountRecord[]; total: number }>(`/api/accounts?${params.toString()}`));
  };
  const refreshApiKeys = async () => {
    const params = new URLSearchParams();
    if (apiKeyQuery.q) params.set("q", apiKeyQuery.q);
    if (apiKeyQuery.status) params.set("status", apiKeyQuery.status);
    setApiKeys(await api<{ rows: ApiKeyRecord[]; total: number }>(`/api/api-keys?${params.toString()}`));
  };
  const refreshProxies = async () => setProxies(await api<ProxyPayload>("/api/proxies"));

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
      }
      if (next.type === "proxy.updated" || next.type === "proxy.check.completed") {
        void refreshProxies();
      }
    };
    socket.onerror = () => setError("WebSocket disconnected");
    return () => socket.close();
  }, [accountQuery.hasApiKey, accountQuery.q, accountQuery.status, apiKeyQuery.q, apiKeyQuery.status]);

  useEffect(() => {
    void refreshAccounts().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [accountQuery]);

  useEffect(() => {
    void refreshApiKeys().catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, [apiKeyQuery]);

  const handleImport = async () => {
    try {
      setError(null);
      await api("/api/accounts/import", {
        method: "POST",
        body: JSON.stringify({ content: importContent }),
      });
      setImportContent("");
      await refreshAccounts();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
          query={accountQuery}
          onImportContentChange={setImportContent}
          onImport={handleImport}
          onQueryChange={setAccountQuery}
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
