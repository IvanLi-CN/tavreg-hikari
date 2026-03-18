import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { ProxyCheckScope, ProxyNode, ProxyPayload, ProxySettings } from "@/lib/app-types";
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
  selectedProxy,
  proxyCheckScope,
  onProxyCheckScopeChange,
  onProxySettingsChange,
  onSaveProxySettings,
  onCheckScope,
  onSelectNode,
  onCheckNode,
}: {
  proxies: ProxyPayload;
  selectedProxy: ProxyNode | null;
  proxyCheckScope: ProxyCheckScope;
  onProxyCheckScopeChange: (scope: ProxyCheckScope) => void;
  onProxySettingsChange: <K extends keyof ProxySettings>(key: K, value: ProxySettings[K]) => void;
  onSaveProxySettings: () => void;
  onCheckScope: () => void;
  onSelectNode: (nodeName: string) => void;
  onCheckNode: (nodeName: string) => void;
}) {
  return (
    <section className="grid gap-4 xl:grid-cols-[0.88fr_1.12fr]">
      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>订阅设置</CardTitle>
            <CardDescription>保存后会同步节点列表，并按当前范围执行检查。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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
                <Input type="number" value={proxies.settings.timeoutMs} onChange={(event) => onProxySettingsChange("timeoutMs", Number(event.target.value) || 1000)} />
              </Field>
              <Field label="Max Latency (ms)">
                <Input type="number" value={proxies.settings.maxLatencyMs} onChange={(event) => onProxySettingsChange("maxLatencyMs", Number(event.target.value) || 100)} />
              </Field>
              <Field label="API Port">
                <Input type="number" value={proxies.settings.apiPort} onChange={(event) => onProxySettingsChange("apiPort", Number(event.target.value) || 1)} />
              </Field>
              <Field label="Mixed Port">
                <Input type="number" value={proxies.settings.mixedPort} onChange={(event) => onProxySettingsChange("mixedPort", Number(event.target.value) || 1)} />
              </Field>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={onSaveProxySettings}>保存并同步</Button>
              <Select value={proxyCheckScope} onValueChange={(value) => onProxyCheckScopeChange(value as ProxyCheckScope)}>
                <SelectTrigger className="w-[11rem]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="current">当前节点</SelectItem>
                  <SelectItem value="all">全部节点</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" onClick={onCheckScope}>执行检查</Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>当前状态</CardTitle>
            <CardDescription>同步出口 IP、节点延迟与 24 小时成功提取数。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <MetricCard label="当前节点" value={proxies.selectedName || "未选择"} />
              <MetricCard label="节点总数" value={proxies.nodes.length} />
              <MetricCard label="当前延迟" value={selectedProxy?.lastLatencyMs == null ? "—" : `${selectedProxy.lastLatencyMs}ms`} />
              <MetricCard label="当前出口 IP" value={selectedProxy?.lastEgressIp || "—"} />
            </div>
            <div className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4 text-sm text-slate-300">
              <div>状态: <span className="ml-2 inline-flex"><StatusBadge status={selectedProxy?.lastStatus} /></span></div>
              <div className="mt-3">地区: {selectedProxy ? formatLocation(selectedProxy) : "—"}</div>
              <div className="mt-3">最后检查: {formatDate(selectedProxy?.lastCheckedAt)}</div>
              <div className="mt-3">24h 成功提取: {selectedProxy?.success24h ?? 0}</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>节点列表</CardTitle>
          <CardDescription>可以切换当前节点，也可以单独检查某一个节点。</CardDescription>
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
                      <div>
                        <div className="font-medium text-white">{node.nodeName}</div>
                        {node.isSelected ? <div className="mt-1 text-xs text-cyan-300">当前选中</div> : null}
                      </div>
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
                      <Button variant="secondary" size="sm" onClick={() => onSelectNode(node.nodeName)}>切换</Button>
                      <Button variant="outline" size="sm" onClick={() => onCheckNode(node.nodeName)}>检查</Button>
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
                        <TableCell>
                          <div className="font-medium text-white">{node.nodeName}</div>
                          {node.isSelected ? <div className="mt-1 text-xs text-cyan-300">当前选中</div> : null}
                        </TableCell>
                        <TableCell><StatusBadge status={node.lastStatus} /></TableCell>
                        <TableCell>{node.lastLatencyMs == null ? "—" : `${node.lastLatencyMs}ms`}</TableCell>
                        <TableCell>{node.lastEgressIp || "—"}</TableCell>
                        <TableCell>{formatLocation(node)}</TableCell>
                        <TableCell>{node.success24h}</TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-2">
                            <Button variant="secondary" size="sm" onClick={() => onSelectNode(node.nodeName)}>切换</Button>
                            <Button variant="outline" size="sm" onClick={() => onCheckNode(node.nodeName)}>检查</Button>
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
