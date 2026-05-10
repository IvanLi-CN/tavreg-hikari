import { useRef } from "react";
import { flushSync } from "react-dom";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import { pickProxySettingsUpdate, type ProxyBrokerCatalogNode, type ProxyBrokerIpMetadata, type ProxyPayload, type ProxySettingsUpdate } from "@/lib/app-types";
import { formatDate, formatLocation } from "@/lib/format";

const PROBE_MAX_AGE_MS = 30 * 60 * 1000;

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function metadataIp(node: ProxyBrokerCatalogNode, metadata: ProxyBrokerIpMetadata | null | undefined): string {
  return String(metadata?.ip || node.primary_ip || node.resolved_ips[0] || "").trim();
}

function primaryMetadata(node: ProxyBrokerCatalogNode): ProxyBrokerIpMetadata | null {
  const rows = node.ip_metadata || [];
  const primaryIp = String(node.primary_ip || node.resolved_ips[0] || "").trim();
  if (primaryIp) {
    const matched = rows.find((metadata) => metadataIp(node, metadata) === primaryIp);
    if (matched) return matched;
  }
  return rows[0] || null;
}

function metadataLatency(metadata: ProxyBrokerIpMetadata | null | undefined): number | null {
  const median = typeof metadata?.median_latency_ms === "number" ? metadata.median_latency_ms : null;
  const last = typeof metadata?.last_latency_ms === "number" ? metadata.last_latency_ms : null;
  return median ?? last;
}

function probeStatus(node: ProxyBrokerCatalogNode, metadata: ProxyBrokerIpMetadata | null): string {
  if (metadata?.last_probe_ok === true && !probeFresh(metadata)) return "stale";
  if (metadata?.last_probe_ok === true) return "ok";
  if (metadata?.last_probe_ok === false) return "fail";
  return node.can_open_session ? "unknown" : "blocked";
}

function probeUpdatedAtMs(metadata: ProxyBrokerIpMetadata | null | undefined): number | null {
  const value = metadata?.probe_updated_at;
  if (typeof value === "number" && Number.isFinite(value)) return value < 10_000_000_000 ? value * 1000 : value;
  if (typeof value === "string" && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function probeFresh(metadata: ProxyBrokerIpMetadata | null | undefined): boolean {
  const updatedAtMs = probeUpdatedAtMs(metadata);
  return updatedAtMs != null && Date.now() - updatedAtMs <= PROBE_MAX_AGE_MS;
}

function formatLatency(value: number | null): string {
  return typeof value === "number" && Number.isFinite(value) ? `${value} ms` : "-";
}

function formatProbeTimeParts(value: string | number | null | undefined): { date: string; time: string } | null {
  let date: Date | null = null;
  if (typeof value === "number" && Number.isFinite(value)) {
    date = new Date(value < 10_000_000_000 ? value * 1000 : value);
  } else if (typeof value === "string" && value.trim()) {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) date = parsed;
  }
  if (!date || Number.isNaN(date.getTime())) return null;
  return {
    date: date.toLocaleDateString(),
    time: date.toLocaleTimeString(),
  };
}

function ProbeTime({ value }: { value: string | number | null | undefined }) {
  const parts = formatProbeTimeParts(value);
  if (!parts) return <span>-</span>;
  return (
    <div className="inline-grid min-w-[7.5rem] grid-rows-2 gap-0.5 font-mono tabular-nums leading-tight text-slate-100">
      <span className="whitespace-nowrap">{parts.date}</span>
      <span className="whitespace-nowrap text-slate-300">{parts.time}</span>
    </div>
  );
}

export function ProxiesView({
  proxies,
  onProxySettingsChange,
  onSaveProxySettings,
  onCheckScope,
}: {
  proxies: ProxyPayload;
  onProxySettingsChange: <K extends keyof ProxySettingsUpdate>(key: K, value: ProxySettingsUpdate[K]) => void;
  onSaveProxySettings: (settings?: ProxySettingsUpdate) => void;
  onCheckScope: () => void;
}) {
  const timeoutRef = useRef<BufferedNumberInputHandle>(null);
  const maxLatencyRef = useRef<BufferedNumberInputHandle>(null);
  const catalogNodes = proxies.broker.catalogGroups.flatMap((group) => group.nodes);
  const activeSessions = proxies.broker.sessions;
  const healthyNodeCount = catalogNodes.filter((node) => {
    const metadata = primaryMetadata(node);
    const latency = metadataLatency(metadata);
    return metadata?.last_probe_ok === true && probeFresh(metadata) && latency != null && latency <= proxies.settings.maxLatencyMs;
  }).length;

  const commitSettingsInputs = (): ProxySettingsUpdate => ({
    ...pickProxySettingsUpdate(proxies.settings),
    timeoutMs: timeoutRef.current?.commit() ?? proxies.settings.timeoutMs,
    maxLatencyMs: maxLatencyRef.current?.commit() ?? proxies.settings.maxLatencyMs,
  });

  const handleSaveClick = () => {
    let committedSettings: ProxySettingsUpdate = pickProxySettingsUpdate(proxies.settings);
    flushSync(() => {
      committedSettings = commitSettingsInputs();
    });
    onSaveProxySettings(committedSettings);
  };

  return (
    <section className="grid gap-4 xl:grid-cols-[0.78fr_1.22fr]">
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Proxy Broker</CardTitle>
            <CardDescription>业务任务会向 Broker 创建 mixed listener session，不再启动本地 Mihomo 代理池。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {proxies.syncError ? (
              <div className="rounded-lg border border-amber-400/20 bg-amber-400/10 px-4 py-3 text-sm text-amber-100">
                Broker 同步失败：{proxies.syncError}
              </div>
            ) : null}
            <div className="grid gap-3">
              <Field label="Broker Base URL">
                <Input value={proxies.settings.proxyBrokerBaseUrl} readOnly />
              </Field>
              <Field label="Profile ID">
                <Input value={proxies.settings.proxyBrokerProfileId} onChange={(event) => onProxySettingsChange("proxyBrokerProfileId", event.target.value)} />
              </Field>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
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
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={handleSaveClick}>保存 Broker 设置</Button>
              <Button variant="outline" onClick={onCheckScope}>
                <RefreshCw className="mr-2 size-4" />
                刷新探测
              </Button>
            </div>
            <div className="rounded-lg border border-white/8 bg-[#0d1728]/70 p-4 text-sm text-slate-300">
              <div>API key: <span className={proxies.broker.apiKeyConfigured ? "text-emerald-300" : "text-rose-300"}>{proxies.broker.apiKeyConfigured ? "已配置" : "未配置"}</span></div>
              <div className="mt-2">Profile: <span className="text-white">{proxies.broker.profileId || "Tavily"}</span></div>
              <div className="mt-2">Base URL: <span className="break-all text-white">{proxies.broker.baseUrl}</span></div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>运行摘要</CardTitle>
            <CardDescription>这里显示 Broker 当前可用节点与已打开 listener session。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <MetricCard label="Catalog 节点" value={catalogNodes.length} />
              <MetricCard label="健康低延迟" value={healthyNodeCount} />
              <MetricCard label="活动 Session" value={activeSessions.length} />
              <MetricCard label="缓存快照" value={proxies.nodes.length} />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Broker Catalog</CardTitle>
            <CardDescription>按 Broker 返回的 profile catalog 展示节点探测状态、延迟和 session 可开性。</CardDescription>
          </CardHeader>
          <CardContent>
            {catalogNodes.length === 0 ? (
              <div className="rounded-lg border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                暂无 Broker catalog。确认 `PROXY_BROKER_API_KEY` 和 profile 后刷新。
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>节点</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>主 IP</TableHead>
                    <TableHead>探测</TableHead>
                    <TableHead>中位/最近延迟</TableHead>
                    <TableHead>探测时间</TableHead>
                    <TableHead>Session</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {catalogNodes.map((node) => {
                    const metadata = primaryMetadata(node);
                    return (
                      <TableRow key={node.node_id}>
                        <TableCell>
                          <div className="font-medium text-white">{node.proxy_name}</div>
                          <div className="text-xs text-slate-500">{node.node_id}</div>
                        </TableCell>
                        <TableCell>{node.proxy_type}</TableCell>
                        <TableCell>
                          <div>{metadataIp(node, metadata) || "-"}</div>
                          <div className="text-xs text-slate-500">解析 {node.resolved_ips.length}</div>
                        </TableCell>
                        <TableCell><StatusBadge status={probeStatus(node, metadata)} /></TableCell>
                        <TableCell>
                          <div>{formatLatency(typeof metadata?.median_latency_ms === "number" ? metadata.median_latency_ms : null)}</div>
                          <div className="text-xs text-slate-500">最近 {formatLatency(typeof metadata?.last_latency_ms === "number" ? metadata.last_latency_ms : null)}</div>
                        </TableCell>
                        <TableCell><ProbeTime value={metadata?.probe_updated_at} /></TableCell>
                        <TableCell><StatusBadge status={node.can_open_session ? "available" : "blocked"} /></TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>活动 Sessions</CardTitle>
            <CardDescription>这些 listener 由 Broker 管理，任务结束时会关闭对应 session。</CardDescription>
          </CardHeader>
          <CardContent>
            {activeSessions.length === 0 ? (
              <div className="rounded-lg border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                当前没有活动 session。
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Session</TableHead>
                    <TableHead>地址</TableHead>
                    <TableHead>节点</TableHead>
                    <TableHead>出口 IP</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {activeSessions.map((session) => (
                    <TableRow key={session.session_id}>
                      <TableCell>{session.session_id}</TableCell>
                      <TableCell>{session.display_address}</TableCell>
                      <TableCell>{session.proxy_name}</TableCell>
                      <TableCell>{session.selected_ip}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>历史诊断快照</CardTitle>
            <CardDescription>保留最近节点状态、出口 IP 与 24h 成功数，便于和旧 attempt 记录关联。</CardDescription>
          </CardHeader>
          <CardContent>
            {proxies.nodes.length === 0 ? (
              <div className="rounded-lg border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                暂无历史快照。
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>节点</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>出口 IP</TableHead>
                    <TableHead>地区</TableHead>
                    <TableHead>最近检查</TableHead>
                    <TableHead>24h 成功</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {proxies.nodes.map((node) => (
                    <TableRow key={node.id}>
                      <TableCell><div className="font-medium text-white">{node.nodeName}</div></TableCell>
                      <TableCell><StatusBadge status={node.lastStatus} /></TableCell>
                      <TableCell>{node.lastEgressIp || "-"}</TableCell>
                      <TableCell>{formatLocation(node)}</TableCell>
                      <TableCell>{formatDate(node.lastCheckedAt)}</TableCell>
                      <TableCell>{node.success24h}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
