import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { EventRecord, JobDraft, JobSnapshot, ProviderTarget } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

const targetLabels: Record<ProviderTarget, string> = {
  tavily: "Tavily",
  chatgpt: "ChatGPT",
};

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

export function DashboardView({
  job,
  events,
  jobDraft,
  onJobDraftChange,
  onJobAction,
}: {
  job: JobSnapshot;
  events: EventRecord[];
  jobDraft: JobDraft;
  onJobDraftChange: (patch: Partial<JobDraft>) => void;
  onJobAction: (action: "start" | "pause" | "resume" | "update_limits") => void;
}) {
  const currentTargets = job.job?.targets || jobDraft.targets;
  const toggleTarget = (target: ProviderTarget, checked: boolean) => {
    if (checked) {
      onJobDraftChange({ targets: Array.from(new Set([...jobDraft.targets, target])) });
      return;
    }
    if (jobDraft.targets.length <= 1) return;
    onJobDraftChange({ targets: jobDraft.targets.filter((item) => item !== target) });
  };

  return (
    <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Job 状态"
            value={job.job?.status || "idle"}
            tone={job.job?.status === "completed" ? "good" : job.job?.status === "failed" ? "bad" : "default"}
          />
          <MetricCard label="成功 / 目标" value={`${job.job?.successCount || 0} / ${job.job?.need || 0}`} tone="good" />
          <MetricCard label="目标步骤" value={`${job.completedTargetSteps} / ${job.totalTargetSteps}`} tone="warn" />
          <MetricCard label="待派发账号" value={job.eligibleCount} />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>任务控制</CardTitle>
            <CardDescription>运行中支持软暂停、动态调整并行数与需求值。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 lg:grid-cols-4">
              <Field label="Run Mode">
                <Select value={jobDraft.runMode} onValueChange={(value) => onJobDraftChange({ runMode: value as JobDraft["runMode"] })}>
                  <SelectTrigger>
                    <SelectValue placeholder="选择模式" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="headed">headed</SelectItem>
                    <SelectItem value="headless">headless</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Need">
                <Input type="number" min={1} value={jobDraft.need} onChange={(event) => onJobDraftChange({ need: Number(event.target.value) || 1 })} />
              </Field>
              <Field label="Parallel">
                <Input type="number" min={1} value={jobDraft.parallel} onChange={(event) => onJobDraftChange({ parallel: Number(event.target.value) || 1 })} />
              </Field>
              <Field label="Max Attempts">
                <Input type="number" min={1} value={jobDraft.maxAttempts} onChange={(event) => onJobDraftChange({ maxAttempts: Number(event.target.value) || 1 })} />
              </Field>
            </div>
            <div className="rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
              <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Targets</div>
              <div className="mt-3 flex flex-wrap gap-4">
                {(["tavily", "chatgpt"] as ProviderTarget[]).map((target) => (
                  <label key={target} className="flex items-center gap-3 rounded-full border border-white/8 px-4 py-2 text-sm text-slate-200">
                    <Checkbox
                      checked={jobDraft.targets.includes(target)}
                      onCheckedChange={(checked) => toggleTarget(target, checked === true)}
                      aria-label={`target-${target}`}
                    />
                    <span>{targetLabels[target]}</span>
                  </label>
                ))}
              </div>
              <div className="mt-3 text-sm text-slate-400">当前任务目标：{currentTargets.map((target) => targetLabels[target]).join(" / ")}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => onJobAction("start")}>启动</Button>
              <Button variant="secondary" onClick={() => onJobAction("pause")}>暂停</Button>
              <Button variant="secondary" onClick={() => onJobAction("resume")}>恢复</Button>
              <Button variant="outline" onClick={() => onJobAction("update_limits")}>应用调参</Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>运行中 Attempts</CardTitle>
            <CardDescription>这里显示当前正在处理的账号与代理节点。</CardDescription>
          </CardHeader>
          <CardContent>
            {job.activeAttempts.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                当前没有运行中的 attempt。
              </div>
            ) : (
              <>
                <div className="space-y-3 md:hidden">
                  {job.activeAttempts.map((attempt) => (
                    <article key={attempt.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-sm font-medium text-white">Attempt #{attempt.id}</div>
                          <div className="mt-1 break-all text-sm text-slate-300">{attempt.accountEmail || `#${attempt.accountId}`}</div>
                        </div>
                        <StatusBadge status={attempt.status} />
                      </div>
                      <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                        <div className="flex items-center justify-between gap-3">
                          <dt className="text-slate-500">阶段</dt>
                          <dd>{attempt.stage}</dd>
                        </div>
                        <div className="flex items-center justify-between gap-3">
                          <dt className="text-slate-500">目标</dt>
                          <dd>{attempt.target || "—"}</dd>
                        </div>
                        <div className="flex items-center justify-between gap-3">
                          <dt className="text-slate-500">代理节点</dt>
                          <dd>{attempt.proxyNode || "—"}</dd>
                        </div>
                        <div className="flex items-center justify-between gap-3">
                          <dt className="text-slate-500">出口 IP</dt>
                          <dd>{attempt.proxyIp || "—"}</dd>
                        </div>
                        <div className="flex items-center justify-between gap-3">
                          <dt className="text-slate-500">开始时间</dt>
                          <dd>{formatDate(attempt.startedAt)}</dd>
                        </div>
                      </dl>
                    </article>
                  ))}
                </div>
                <div className="hidden md:block">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>ID</TableHead>
                        <TableHead>账号</TableHead>
                        <TableHead>状态</TableHead>
                        <TableHead>阶段</TableHead>
                        <TableHead>目标</TableHead>
                        <TableHead>代理节点</TableHead>
                        <TableHead>出口 IP</TableHead>
                        <TableHead>开始时间</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {job.activeAttempts.map((attempt) => (
                        <TableRow key={attempt.id}>
                          <TableCell>#{attempt.id}</TableCell>
                          <TableCell className="break-all">{attempt.accountEmail || `#${attempt.accountId}`}</TableCell>
                          <TableCell><StatusBadge status={attempt.status} /></TableCell>
                          <TableCell>{attempt.stage}</TableCell>
                          <TableCell>{attempt.target || "—"}</TableCell>
                          <TableCell>{attempt.proxyNode || "—"}</TableCell>
                          <TableCell>{attempt.proxyIp || "—"}</TableCell>
                          <TableCell>{formatDate(attempt.startedAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>最近 Attempts</CardTitle>
            <CardDescription>快速确认最近成功、失败与代理分布。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {job.recentAttempts.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                还没有历史 attempt。
              </div>
            ) : (
              job.recentAttempts.slice(0, 8).map((attempt) => (
                <article key={attempt.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="font-medium text-white">Attempt #{attempt.id}</div>
                    <StatusBadge status={attempt.status} />
                  </div>
                  <div className="mt-3 text-sm text-slate-300">
                    {attempt.accountEmail || `账号 #${attempt.accountId}`} · {attempt.target || "unknown"} · {attempt.proxyNode || "未绑定代理"}
                  </div>
                  <div className="mt-2 text-xs text-slate-500">{attempt.errorCode || attempt.stage}</div>
                </article>
              ))
            )}
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle>实时事件日志</CardTitle>
            <CardDescription>WebSocket 推送的主流程、账号与代理事件。</CardDescription>
          </CardHeader>
          <Separator />
          <CardContent className="pt-4">
            <ScrollArea className="h-[32rem] pr-2">
              <div className="space-y-3">
                {events.length === 0 ? (
                  <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                    WebSocket 事件会显示在这里。
                  </div>
                ) : (
                  events.map((event, index) => (
                    <article key={`${event.timestamp}-${index}`} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4 text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium text-cyan-200">{event.type}</span>
                        <span className="text-xs text-slate-500">{formatDate(event.timestamp)}</span>
                      </div>
                      <pre className="mt-3 overflow-x-auto text-xs leading-5 text-slate-400">{JSON.stringify(event.payload, null, 2)}</pre>
                    </article>
                  ))
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
