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
import { pickProxySettingsUpdate, type ProxyPayload, type ProxySettingsUpdate } from "@/lib/app-types";
import { formatDate, formatLocation } from "@/lib/format";

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
              <Field label="Geo Check URL">
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
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={handleSaveClick}>保存 Broker 设置</Button>
              <Button variant="outline" onClick={onCheckScope}>
                <RefreshCw className="mr-2 size-4" />
                刷新 Catalog
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
              <MetricCard label="节点组" value={proxies.broker.catalogGroups.length} />
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
            <CardDescription>按 Broker 返回的 profile catalog 展示节点、解析 IP 和 session 可用性。</CardDescription>
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
                    <TableHead>解析 IP</TableHead>
                    <TableHead>可开 Session</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {catalogNodes.map((node) => (
                    <TableRow key={node.node_id}>
                      <TableCell>
                        <div className="font-medium text-white">{node.proxy_name}</div>
                        <div className="text-xs text-slate-500">{node.node_id}</div>
                      </TableCell>
                      <TableCell>{node.proxy_type}</TableCell>
                      <TableCell>{node.primary_ip || node.resolved_ips[0] || "-"}</TableCell>
                      <TableCell>{node.resolved_ips.length}</TableCell>
                      <TableCell><StatusBadge status={node.can_open_session ? "ok" : "blocked"} /></TableCell>
                    </TableRow>
                  ))}
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
