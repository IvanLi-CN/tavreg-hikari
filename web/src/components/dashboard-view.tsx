import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { EventRecord, JobDraft, JobSnapshot } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

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
          <MetricCard label="并行 / 已发起" value={`${job.job?.parallel || 0} / ${job.job?.launchedCount || 0}`} tone="warn" />
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
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>账号</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>阶段</TableHead>
                  <TableHead>代理节点</TableHead>
                  <TableHead>出口 IP</TableHead>
                  <TableHead>开始时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {job.activeAttempts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8 text-center text-slate-400">当前没有运行中的 attempt。</TableCell>
                  </TableRow>
                ) : (
                  job.activeAttempts.map((attempt) => (
                    <TableRow key={attempt.id}>
                      <TableCell>#{attempt.id}</TableCell>
                      <TableCell className="break-all">{attempt.accountEmail || `#${attempt.accountId}`}</TableCell>
                      <TableCell><StatusBadge status={attempt.status} /></TableCell>
                      <TableCell>{attempt.stage}</TableCell>
                      <TableCell>{attempt.proxyNode || "—"}</TableCell>
                      <TableCell>{attempt.proxyIp || "—"}</TableCell>
                      <TableCell>{formatDate(attempt.startedAt)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
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
                    {attempt.accountEmail || `账号 #${attempt.accountId}`} · {attempt.proxyNode || "未绑定代理"}
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
