import { useEffect, useMemo, useState } from "react";

type JobStatus = "idle" | "running" | "paused" | "completing" | "completed" | "failed";
type AccountRecord = {
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

type ApiKeyRecord = {
  id: number;
  accountId: number;
  microsoftEmail: string;
  apiKeyMasked: string;
  apiKeyPrefix: string;
  status: string;
  extractedAt: string;
  lastVerifiedAt: string | null;
};

type AttemptRecord = {
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

type JobSnapshot = {
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

type ProxySettings = {
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

type ProxyNode = {
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

type ProxyPayload = {
  settings: ProxySettings;
  selectedName: string | null;
  nodes: ProxyNode[];
};

type EventRecord = {
  type: string;
  timestamp: string;
  payload: Record<string, unknown>;
};

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

function formatDate(value: string | null | undefined): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatLocation(node: ProxyNode): string {
  return [node.lastCountry, node.lastCity, node.lastOrg].filter(Boolean).join(" / ") || "-";
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

function NavLink(props: { active: boolean; onClick: () => void; children: string }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      className={`rounded-full px-4 py-2 text-sm font-medium transition ${
        props.active ? "bg-cyan-400 text-slate-950" : "bg-slate-900 text-slate-300 hover:bg-slate-800"
      }`}
    >
      {props.children}
    </button>
  );
}

function StatCard(props: { label: string; value: string | number; tone?: "default" | "good" | "warn" | "bad" }) {
  const toneClass =
    props.tone === "good"
      ? "text-emerald-300"
      : props.tone === "warn"
        ? "text-amber-300"
        : props.tone === "bad"
          ? "text-rose-300"
          : "text-white";
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-[0.2em] text-slate-400">{props.label}</div>
      <div className={`mt-3 text-3xl font-semibold ${toneClass}`}>{props.value}</div>
    </div>
  );
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
  const [jobDraft, setJobDraft] = useState({ runMode: "headed", need: 1, parallel: 1, maxAttempts: 5 });
  const [accountQuery, setAccountQuery] = useState({ q: "", status: "", hasApiKey: "" });
  const [apiKeyQuery, setApiKeyQuery] = useState({ q: "", status: "" });
  const [proxyCheckScope, setProxyCheckScope] = useState<"current" | "all">("current");
  const [jobDraftTouched, setJobDraftTouched] = useState(false);

  const activePage = useMemo(() => {
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

  const updateJobDraft = (patch: Partial<typeof jobDraft>) => {
    setJobDraftTouched(true);
    setJobDraft((current) => ({ ...current, ...patch }));
  };

  const handleJobAction = async (action: string) => {
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

  return (
    <div className="min-h-dvh bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.18),_transparent_28%),linear-gradient(180deg,_#020617_0%,_#0f172a_100%)] text-slate-100">
      <div className="mx-auto flex min-h-dvh w-full max-w-screen-2xl flex-col px-4 py-6 sm:px-6 lg:px-8">
        <header className="mb-6 flex flex-col gap-4 rounded-[28px] border border-white/10 bg-slate-950/70 px-5 py-5 shadow-2xl shadow-cyan-950/30 backdrop-blur md:flex-row md:items-center md:justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.25em] text-cyan-300/80">Tavreg Hikari</div>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Web 管理台</h1>
            <p className="mt-2 text-sm text-slate-400">账号池、主流程、代理状态统一在一个本机控制面里。</p>
          </div>
          <nav className="flex flex-wrap gap-2">
            <NavLink active={activePage === "dashboard"} onClick={() => navigate("/")}>
              主流程
            </NavLink>
            <NavLink active={activePage === "accounts"} onClick={() => navigate("/accounts")}>
              微软账号
            </NavLink>
            <NavLink active={activePage === "apiKeys"} onClick={() => navigate("/api-keys")}>
              API Keys
            </NavLink>
            <NavLink active={activePage === "proxies"} onClick={() => navigate("/proxies")}>
              代理节点
            </NavLink>
          </nav>
        </header>

        {error ? <div className="mb-4 rounded-2xl border border-rose-400/40 bg-rose-950/50 px-4 py-3 text-sm text-rose-200">{error}</div> : null}

        {activePage === "dashboard" ? (
          <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
            <div className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard label="Job 状态" value={job.job?.status || "idle"} tone={job.job?.status === "completed" ? "good" : job.job?.status === "failed" ? "bad" : "default"} />
                <StatCard label="成功 / 目标" value={`${job.job?.successCount || 0} / ${job.job?.need || 0}`} tone="good" />
                <StatCard label="并行 / 已发起" value={`${job.job?.parallel || 0} / ${job.job?.launchedCount || 0}`} tone="warn" />
                <StatCard label="待派发账号" value={job.eligibleCount} />
              </div>

              <div className="card">
                <div className="flex flex-col gap-3 md:flex-row md:items-end">
                  <label className="field">
                    <span>Run Mode</span>
                    <select name="job-run-mode" value={jobDraft.runMode} onChange={(event) => updateJobDraft({ runMode: event.target.value as "headed" | "headless" })}>
                      <option value="headed">headed</option>
                      <option value="headless">headless</option>
                    </select>
                  </label>
                  <label className="field">
                    <span>Need</span>
                    <input name="job-need" type="number" min={1} value={jobDraft.need} onChange={(event) => updateJobDraft({ need: Number(event.target.value) || 1 })} />
                  </label>
                  <label className="field">
                    <span>Parallel</span>
                    <input name="job-parallel" type="number" min={1} value={jobDraft.parallel} onChange={(event) => updateJobDraft({ parallel: Number(event.target.value) || 1 })} />
                  </label>
                  <label className="field">
                    <span>Max Attempts</span>
                    <input name="job-max-attempts" type="number" min={1} value={jobDraft.maxAttempts} onChange={(event) => updateJobDraft({ maxAttempts: Number(event.target.value) || 1 })} />
                  </label>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button className="primary-button" onClick={() => void handleJobAction("start")}>启动</button>
                  <button className="secondary-button" onClick={() => void handleJobAction("pause")}>暂停</button>
                  <button className="secondary-button" onClick={() => void handleJobAction("resume")}>恢复</button>
                  <button className="secondary-button" onClick={() => void handleJobAction("update_limits")}>应用调参</button>
                </div>
              </div>

              <div className="card">
                <div className="section-title">运行中 Attempts</div>
                <div className="mt-4 overflow-x-auto">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>账号</th>
                        <th>状态</th>
                        <th>阶段</th>
                        <th>代理节点</th>
                        <th>出口 IP</th>
                        <th>开始时间</th>
                      </tr>
                    </thead>
                    <tbody>
                      {job.activeAttempts.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="empty-cell">当前没有运行中的 attempt。</td>
                        </tr>
                      ) : (
                        job.activeAttempts.map((attempt) => (
                          <tr key={attempt.id}>
                            <td>{attempt.id}</td>
                            <td>{attempt.accountEmail || `#${attempt.accountId}`}</td>
                            <td>{attempt.status}</td>
                            <td>{attempt.stage}</td>
                            <td>{attempt.proxyNode || "-"}</td>
                            <td>{attempt.proxyIp || "-"}</td>
                            <td>{formatDate(attempt.startedAt)}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="card">
                <div className="section-title">最近 Attempts</div>
                <div className="mt-4 space-y-3">
                  {job.recentAttempts.slice(0, 8).map((attempt) => (
                    <div key={attempt.id} className="rounded-2xl border border-white/8 bg-slate-900/70 p-3">
                      <div className="flex items-center justify-between gap-4">
                        <div className="font-medium text-white">Attempt #{attempt.id}</div>
                        <div className="text-xs uppercase tracking-[0.2em] text-slate-400">{attempt.status}</div>
                      </div>
                      <div className="mt-2 text-sm text-slate-300">{attempt.accountEmail || `账号 #${attempt.accountId}`} · {attempt.proxyNode || "未绑定代理"}</div>
                      <div className="mt-1 text-xs text-slate-500">{attempt.errorCode || attempt.stage}</div>
                    </div>
                  ))}
                  {job.recentAttempts.length === 0 ? <div className="empty-panel">还没有历史 attempt。</div> : null}
                </div>
              </div>

              <div className="card">
                <div className="section-title">实时事件日志</div>
                <div className="mt-4 max-h-[30rem] space-y-3 overflow-auto pr-1">
                  {events.length === 0 ? <div className="empty-panel">WebSocket 事件会显示在这里。</div> : null}
                  {events.map((event, index) => (
                    <div key={`${event.timestamp}-${index}`} className="rounded-2xl border border-white/8 bg-slate-900/70 p-3 text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium text-cyan-200">{event.type}</span>
                        <span className="text-xs text-slate-500">{formatDate(event.timestamp)}</span>
                      </div>
                      <pre className="mt-2 overflow-x-auto text-xs text-slate-400">{JSON.stringify(event.payload, null, 2)}</pre>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        ) : null}

        {activePage === "accounts" ? (
          <section className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
            <div className="card">
              <div className="section-title">导入微软账号</div>
              <p className="mt-2 text-sm text-slate-400">每行一个账号，格式固定为 <code>email,password</code>。</p>
              <textarea
                name="account-import"
                className="mt-4 min-h-64 w-full rounded-3xl border border-white/10 bg-slate-950/80 px-4 py-4 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500"
                placeholder="example@outlook.com,password123"
                value={importContent}
                onChange={(event) => setImportContent(event.target.value)}
              />
              <button className="primary-button mt-4" onClick={() => void handleImport()}>导入并去重</button>
            </div>

            <div className="card">
              <div className="flex flex-col gap-3 md:flex-row">
                <label className="field">
                  <span>搜索</span>
                  <input name="account-query" value={accountQuery.q} onChange={(event) => setAccountQuery((current) => ({ ...current, q: event.target.value }))} placeholder="邮箱" />
                </label>
                <label className="field">
                  <span>状态</span>
                  <select name="account-status" value={accountQuery.status} onChange={(event) => setAccountQuery((current) => ({ ...current, status: event.target.value }))}>
                    <option value="">全部</option>
                    <option value="ready">ready</option>
                    <option value="running">running</option>
                    <option value="succeeded">succeeded</option>
                    <option value="failed">failed</option>
                    <option value="skipped_has_key">skipped_has_key</option>
                  </select>
                </label>
                <label className="field">
                  <span>Has API Key</span>
                  <select name="account-has-api-key" value={accountQuery.hasApiKey} onChange={(event) => setAccountQuery((current) => ({ ...current, hasApiKey: event.target.value }))}>
                    <option value="">全部</option>
                    <option value="true">true</option>
                    <option value="false">false</option>
                  </select>
                </label>
              </div>
              <div className="mt-4 overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>邮箱</th>
                      <th>密码</th>
                      <th>Has Key</th>
                      <th>最近状态</th>
                      <th>导入时间</th>
                      <th>最近使用</th>
                      <th>跳过原因</th>
                    </tr>
                  </thead>
                  <tbody>
                    {accounts.rows.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="empty-cell">还没有账号记录。</td>
                      </tr>
                    ) : (
                      accounts.rows.map((row) => (
                        <tr key={row.id}>
                          <td>{row.microsoftEmail}</td>
                          <td>{row.passwordMasked}</td>
                          <td>{row.hasApiKey ? "yes" : "no"}</td>
                          <td>{row.lastResultStatus}</td>
                          <td>{formatDate(row.importedAt)}</td>
                          <td>{formatDate(row.lastUsedAt)}</td>
                          <td>{row.skipReason || "-"}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        ) : null}

        {activePage === "apiKeys" ? (
          <section className="card">
            <div className="flex flex-col gap-3 md:flex-row">
              <label className="field">
                <span>搜索</span>
                <input name="api-key-query" value={apiKeyQuery.q} onChange={(event) => setApiKeyQuery((current) => ({ ...current, q: event.target.value }))} placeholder="邮箱或前缀" />
              </label>
              <label className="field">
                <span>状态</span>
                <select name="api-key-status" value={apiKeyQuery.status} onChange={(event) => setApiKeyQuery((current) => ({ ...current, status: event.target.value }))}>
                  <option value="">全部</option>
                  <option value="active">active</option>
                  <option value="revoked">revoked</option>
                  <option value="unknown">unknown</option>
                </select>
              </label>
            </div>
            <div className="mt-4 overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>账号</th>
                    <th>Key 前缀</th>
                    <th>Key 遮罩</th>
                    <th>状态</th>
                    <th>提取时间</th>
                    <th>最近验证</th>
                  </tr>
                </thead>
                <tbody>
                  {apiKeys.rows.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="empty-cell">还没有 API key 记录。</td>
                    </tr>
                  ) : (
                    apiKeys.rows.map((row) => (
                      <tr key={row.id}>
                        <td>{row.microsoftEmail}</td>
                        <td>{row.apiKeyPrefix}</td>
                        <td>{row.apiKeyMasked}</td>
                        <td>{row.status}</td>
                        <td>{formatDate(row.extractedAt)}</td>
                        <td>{formatDate(row.lastVerifiedAt)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        ) : null}

        {activePage === "proxies" && proxies ? (
          <section className="grid gap-4 xl:grid-cols-[0.85fr_1.15fr]">
            <div className="space-y-4">
              <div className="card">
                <div className="section-title">订阅设置</div>
                <div className="mt-4 grid gap-3">
                  <label className="field">
                    <span>Subscription URL</span>
                    <input name="proxy-subscription-url" value={proxies.settings.subscriptionUrl} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, subscriptionUrl: event.target.value } } : current)} />
                  </label>
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="field">
                      <span>Group Name</span>
                      <input name="proxy-group-name" value={proxies.settings.groupName} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, groupName: event.target.value } } : current)} />
                    </label>
                    <label className="field">
                      <span>Route Group</span>
                      <input name="proxy-route-group-name" value={proxies.settings.routeGroupName} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, routeGroupName: event.target.value } } : current)} />
                    </label>
                    <label className="field">
                      <span>Check URL</span>
                      <input name="proxy-check-url" value={proxies.settings.checkUrl} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, checkUrl: event.target.value } } : current)} />
                    </label>
                    <label className="field">
                      <span>Timeout (ms)</span>
                      <input name="proxy-timeout-ms" type="number" value={proxies.settings.timeoutMs} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, timeoutMs: Number(event.target.value) || 1000 } } : current)} />
                    </label>
                    <label className="field">
                      <span>Max Latency (ms)</span>
                      <input name="proxy-max-latency-ms" type="number" value={proxies.settings.maxLatencyMs} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, maxLatencyMs: Number(event.target.value) || 100 } } : current)} />
                    </label>
                    <label className="field">
                      <span>API Port</span>
                      <input name="proxy-api-port" type="number" value={proxies.settings.apiPort} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, apiPort: Number(event.target.value) || 1 } } : current)} />
                    </label>
                    <label className="field">
                      <span>Mixed Port</span>
                      <input name="proxy-mixed-port" type="number" value={proxies.settings.mixedPort} onChange={(event) => setProxies((current) => current ? { ...current, settings: { ...current.settings, mixedPort: Number(event.target.value) || 1 } } : current)} />
                    </label>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button className="primary-button" onClick={() => void handleSaveProxySettings()}>保存并同步</button>
                  <button className="secondary-button" onClick={() => setProxyCheckScope("current")}>当前节点</button>
                  <button className="secondary-button" onClick={() => setProxyCheckScope("all")}>全部节点</button>
                  <button className="secondary-button" onClick={() => void handleProxyCheck()}>执行检查</button>
                </div>
              </div>

              <div className="card">
                <div className="section-title">当前状态</div>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <StatCard label="当前节点" value={proxies.selectedName || "未选择"} />
                  <StatCard label="节点总数" value={proxies.nodes.length} />
                  <StatCard label="当前延迟" value={selectedProxy?.lastLatencyMs == null ? "-" : `${selectedProxy.lastLatencyMs}ms`} />
                  <StatCard label="当前出口 IP" value={selectedProxy?.lastEgressIp || "-"} />
                </div>
                <div className="mt-4 rounded-2xl border border-white/8 bg-slate-900/70 p-4 text-sm text-slate-300">
                  <div>地区: {selectedProxy ? formatLocation(selectedProxy) : "-"}</div>
                  <div className="mt-2">最后检查: {formatDate(selectedProxy?.lastCheckedAt)}</div>
                  <div className="mt-2">24h 成功提取: {selectedProxy?.success24h ?? 0}</div>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="section-title">节点列表</div>
              <div className="mt-4 overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>节点</th>
                      <th>状态</th>
                      <th>延迟</th>
                      <th>出口 IP</th>
                      <th>地理信息</th>
                      <th>24h 成功</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {proxies.nodes.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="empty-cell">还没有代理节点。</td>
                      </tr>
                    ) : (
                      proxies.nodes.map((node) => (
                        <tr key={node.id}>
                          <td>
                            <div className="font-medium text-white">{node.nodeName}</div>
                            {node.isSelected ? <div className="mt-1 text-xs text-cyan-300">当前选中</div> : null}
                          </td>
                          <td>{node.lastStatus || "-"}</td>
                          <td>{node.lastLatencyMs == null ? "-" : `${node.lastLatencyMs}ms`}</td>
                          <td>{node.lastEgressIp || "-"}</td>
                          <td>{[node.lastCountry, node.lastCity].filter(Boolean).join(" / ") || "-"}</td>
                          <td>{node.success24h}</td>
                          <td>
                            <div className="flex flex-wrap gap-2">
                              <button className="secondary-button !px-3 !py-2" onClick={() => void handleSelectNode(node.nodeName)}>切换</button>
                              <button className="secondary-button !px-3 !py-2" onClick={() => void handleCheckSingleNode(node.nodeName)}>检查</button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        ) : null}
      </div>
    </div>
  );
}
