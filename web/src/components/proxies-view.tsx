import { useRef } from "react";
import { flushSync } from "react-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import { pickProxySettingsUpdate, type ProxyCheckScope, type ProxyNode, type ProxyPayload, type ProxySettingsUpdate } from "@/lib/app-types";
import { formatDate, formatLocation } from "@/lib/format";

function normalizeProxyStatus(status: string | null | undefined): string {
  return String(status || "").trim().toLowerCase();
}

function getProxyCheckStatusMeta(status: string) {
  if (status === "running") return { label: "检查中", tone: "text-sky-300" };
  if (status === "completed") return { label: "已完成", tone: "text-emerald-300" };
  if (status === "failed") return { label: "检查失败", tone: "text-rose-300" };
  return { label: "空闲", tone: "text-slate-300" };
}

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

export function ProxiesView({
  proxies,
  proxyCheckScope,
  onProxyCheckScopeChange,
  onProxySettingsChange,
  onSaveProxySettings,
  onCheckScope,
  onCheckNode,
}: {
  proxies: ProxyPayload;
  proxyCheckScope: ProxyCheckScope;
  onProxyCheckScopeChange: (scope: ProxyCheckScope) => void;
  onProxySettingsChange: <K extends keyof ProxySettingsUpdate>(key: K, value: ProxySettingsUpdate[K]) => void;
  onSaveProxySettings: (settings?: ProxySettingsUpdate) => void;
  onCheckScope: () => void;
  onCheckNode: (nodeName: string) => void;
}) {
  const timeoutRef = useRef<BufferedNumberInputHandle>(null);
  const maxLatencyRef = useRef<BufferedNumberInputHandle>(null);
  const apiPortRef = useRef<BufferedNumberInputHandle>(null);
  const mixedPortRef = useRef<BufferedNumberInputHandle>(null);

  const commitSettingsInputs = (): ProxySettingsUpdate => ({
    ...pickProxySettingsUpdate(proxies.settings),
    timeoutMs: timeoutRef.current?.commit() ?? proxies.settings.timeoutMs,
    maxLatencyMs: maxLatencyRef.current?.commit() ?? proxies.settings.maxLatencyMs,
    apiPort: apiPortRef.current?.commit() ?? proxies.settings.apiPort,
    mixedPort: mixedPortRef.current?.commit() ?? proxies.settings.mixedPort,
  });

  const handleSaveClick = () => {
    let committedSettings: ProxySettingsUpdate = pickProxySettingsUpdate(proxies.settings);
    flushSync(() => {
      committedSettings = commitSettingsInputs();
    });
    onSaveProxySettings(committedSettings);
  };

  const healthyCount = proxies.nodes.filter((node) => ["ok", "succeeded", "running"].includes(normalizeProxyStatus(node.lastStatus))).length;
  const checkedCount = proxies.nodes.filter((node) => Boolean(node.lastCheckedAt)).length;
  const recentlyLeasedNode = [...proxies.nodes].filter((node) => Boolean(node.lastLeasedAt)).sort((left, right) => Date.parse(right.lastLeasedAt || "") - Date.parse(left.lastLeasedAt || ""))[0] || null;
  const checkState = proxies.checkState;
  const checkBusy = checkState.status === "running";
  const checkStatusMeta = getProxyCheckStatusMeta(checkState.status);

  return (
    <section className="grid gap-4 xl:grid-cols-[0.88fr_1.12fr]">
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>订阅设置</CardTitle>
            <CardDescription>保存后会同步节点列表，并按当前范围执行检查。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {proxies.syncError ? (
              <div className="rounded-2xl border border-amber-400/20 bg-amber-400/10 px-4 py-3 text-sm text-amber-100">
                当前展示的是缓存设置/节点，最近一次同步失败：{proxies.syncError}
              </div>
            ) : null}
            <Field label="Subscription URL">
              <Input value={proxies.settings.subscriptionUrl} onChange={(event) => onProxySettingsChange("subscriptionUrl", event.target.value)} />
            </Field>
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Group Name">
                <Input value={proxies.settings.groupName} onChange={(event) => onProxySettingsChange("groupName", event.target.value)} />
              </Field>
              <Field label="Route Group">
                <Input value={proxies.settings.routeGroupName} onChange={(event) => onProxySettingsChange("routeGroupName", event.target.value)} />
              </Field>
              <Field label="Check URL">
                <Input value={proxies.settings.checkUrl} onChange={(event) => onProxySettingsChange("checkUrl", event.target.value)} />
              </Field>
              <Field label="Timeout (ms)">
                <BufferedNumberInput
                  ref={timeoutRef}
                  min={1000}
                  value={proxies.settings.timeoutMs}
                  onCommit={(value) => onProxySettingsChange("timeoutMs", value)}
                />
              </Field>
              <Field label="Max Latency (ms)">
                <BufferedNumberInput
                  ref={maxLatencyRef}
                  min={100}
                  value={proxies.settings.maxLatencyMs}
                  onCommit={(value) => onProxySettingsChange("maxLatencyMs", value)}
                />
              </Field>
              <Field label="API Port">
                <BufferedNumberInput ref={apiPortRef} min={1} value={proxies.settings.apiPort} onCommit={(value) => onProxySettingsChange("apiPort", value)} />
              </Field>
              <Field label="Mixed Port">
                <BufferedNumberInput
                  ref={mixedPortRef}
                  min={1}
                  value={proxies.settings.mixedPort}
                  onCommit={(value) => onProxySettingsChange("mixedPort", value)}
                />
              </Field>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={handleSaveClick} disabled={checkBusy}>保存并同步</Button>
              <Select value={proxyCheckScope} onValueChange={(value) => onProxyCheckScopeChange(value as ProxyCheckScope)}>
                <SelectTrigger className="w-[11rem]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部节点</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" onClick={onCheckScope} disabled={checkBusy}>执行检查</Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>检查进度</CardTitle>
            <CardDescription>代理页通过 SSE 接收实时进度；检查期间会锁定保存与重复检查入口。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4 text-sm text-slate-300">
              <div className="flex items-center justify-between gap-3">
                <span className="text-slate-500">当前状态</span>
                <span className={checkStatusMeta.tone}>{checkStatusMeta.label}</span>
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-white/8 bg-slate-950/40 px-3 py-2">
                  <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">进度</div>
                  <div className="mt-1 text-lg font-semibold text-white">{checkState.completed}/{checkState.total}</div>
                </div>
                <div className="rounded-2xl border border-white/8 bg-slate-950/40 px-3 py-2">
                  <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">并发</div>
                  <div className="mt-1 text-lg font-semibold text-white">{checkState.activeWorkers}/{checkState.concurrency}</div>
                </div>
                <div className="rounded-2xl border border-white/8 bg-slate-950/40 px-3 py-2">
                  <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">成功 / 失败</div>
                  <div className="mt-1 text-lg font-semibold text-white">{checkState.succeeded} / {checkState.failed}</div>
                </div>
                <div className="rounded-2xl border border-white/8 bg-slate-950/40 px-3 py-2">
                  <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">开始时间</div>
                  <div className="mt-1 text-sm text-white">{formatDate(checkState.startedAt)}</div>
                </div>
              </div>
              <div className="mt-3">
                <div className="text-slate-500">当前活跃节点</div>
                <div className="mt-1 text-sm text-white">
                  {checkState.currentNodeNames.length > 0 ? checkState.currentNodeNames.join("、") : "—"}
                </div>
              </div>
              <div className="mt-3">
                <div className="text-slate-500">完成时间</div>
                <div className="mt-1 text-sm text-white">{formatDate(checkState.finishedAt)}</div>
              </div>
              {checkState.error ? (
                <div className="mt-3 rounded-2xl border border-rose-400/20 bg-rose-500/[0.08] px-3 py-2 text-sm text-rose-100">
                  最近错误：{checkState.error}
                </div>
              ) : null}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>库存摘要</CardTitle>
            <CardDescription>业务任务会自动选择健康节点，并优先避开并发重复节点与出口 IP。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <MetricCard label="节点总数" value={proxies.nodes.length} />
              <MetricCard label="健康节点" value={healthyCount} />
              <MetricCard label="已检查节点" value={checkedCount} />
              <MetricCard label="最近租约" value={recentlyLeasedNode?.nodeName || "—"} />
            </div>
            <div className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4 text-sm text-slate-300">
              <div>自动调度: <span className="ml-2 text-emerald-300">已启用</span></div>
              <div className="mt-3">最近租约时间: {formatDate(recentlyLeasedNode?.lastLeasedAt)}</div>
              <div className="mt-3">最近租约地区: {recentlyLeasedNode ? formatLocation(recentlyLeasedNode) : "—"}</div>
              <div className="mt-3">24h 成功总数: {proxies.nodes.reduce((sum, node) => sum + node.success24h, 0)}</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>节点列表</CardTitle>
          <CardDescription>仅保留库存与诊断能力；业务任务不会读取任何手动切换状态。</CardDescription>
        </CardHeader>
        <CardContent>
          {proxies.nodes.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              还没有代理节点。
            </div>
          ) : (
            <>
              <div className="space-y-3 md:hidden">
                {proxies.nodes.map((node) => (
                  <article key={node.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="font-medium text-white">{node.nodeName}</div>
                      <StatusBadge status={node.lastStatus} />
                    </div>
                    <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">延迟</dt>
                        <dd>{node.lastLatencyMs == null ? "—" : `${node.lastLatencyMs}ms`}</dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">出口 IP</dt>
                        <dd>{node.lastEgressIp || "—"}</dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">地理信息</dt>
                        <dd className="text-right">{formatLocation(node)}</dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-slate-500">24h 成功</dt>
                        <dd>{node.success24h}</dd>
                      </div>
                    </dl>
                    <div className="mt-4 flex flex-wrap gap-2">
                      <Button variant="outline" size="sm" onClick={() => onCheckNode(node.nodeName)} disabled={checkBusy}>检查</Button>
                    </div>
                  </article>
                ))}
              </div>
              <div className="hidden md:block">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>节点</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>延迟</TableHead>
                      <TableHead>出口 IP</TableHead>
                      <TableHead>地理信息</TableHead>
                      <TableHead>24h 成功</TableHead>
                      <TableHead>操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {proxies.nodes.map((node) => (
                      <TableRow key={node.id}>
                        <TableCell><div className="font-medium text-white">{node.nodeName}</div></TableCell>
                        <TableCell><StatusBadge status={node.lastStatus} /></TableCell>
                        <TableCell>{node.lastLatencyMs == null ? "—" : `${node.lastLatencyMs}ms`}</TableCell>
                        <TableCell>{node.lastEgressIp || "—"}</TableCell>
                        <TableCell>{formatLocation(node)}</TableCell>
                        <TableCell>{node.success24h}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-2">
                            <Button variant="outline" size="sm" onClick={() => onCheckNode(node.nodeName)} disabled={checkBusy}>检查</Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </section>
  );
}
