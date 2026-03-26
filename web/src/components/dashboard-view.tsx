import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { AccountExtractorProvider, EventRecord, JobDraft, JobSnapshot } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function extractorProviderLabel(provider: AccountExtractorProvider): string {
  return provider === "zhanghaoya" ? "账号鸭" : "闪邮箱";
}

function autoExtractPhaseLabel(phase: JobSnapshot["autoExtractState"] extends infer T ? T extends { phase: infer P } ? P : never : never) {
  if (phase === "extracting") return "提取中";
  if (phase === "waiting") return "等待中";
  return "空闲";
}

export function DashboardView({
  job,
  events,
  jobDraft,
  extractorAvailability,
  onJobDraftChange,
  onJobAction,
}: {
  job: JobSnapshot;
  events: EventRecord[];
  jobDraft: JobDraft;
  extractorAvailability: {
    zhanghaoya: boolean;
    shanyouxiang: boolean;
  };
  onJobDraftChange: (patch: Partial<JobDraft>) => void;
  onJobAction: (action: "start" | "pause" | "resume" | "update_limits") => void;
}) {
  const toggleExtractorSource = (provider: AccountExtractorProvider, checked: boolean) => {
    const current = new Set(jobDraft.autoExtractSources);
    if (checked) current.add(provider);
    else current.delete(provider);
    onJobDraftChange({ autoExtractSources: Array.from(current) });
  };

  const autoExtractHint = job.autoExtractState
    ? `${autoExtractPhaseLabel(job.autoExtractState.phase)} · 可用补号 ${job.autoExtractState.acceptedCount}/${job.autoExtractState.currentRoundTarget} · 原始请求 ${job.autoExtractState.rawAttemptCount}/${job.autoExtractState.attemptBudget} · 并发 ${job.autoExtractState.inFlightCount}/4 · 剩余 ${job.autoExtractState.remainingWaitSec}s`
    : jobDraft.autoExtractSources.length > 0
      ? `已启用 · 目标 ${jobDraft.autoExtractQuantity} · 超时 ${jobDraft.autoExtractMaxWaitSec}s · 单源 500ms/次 · 最多 4 并发`
      : "未启用自动提取";

  return (
    <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
      <div className="min-w-0 space-y-4">
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
            <div className="rounded-[24px] border border-cyan-400/18 bg-cyan-400/[0.04] p-4">
              <div className="flex min-w-0 flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-white">自动提取微软账号</div>
                  <div className="mt-1 text-sm text-slate-400">
                    缺号时每个号源按 500ms 派发 1 个请求，每次只提取 1 个账号，最多 4 个请求同时进行；超时或补够即停，极端情况下最多多提取 3 个。
                  </div>
                </div>
                <Badge
                  variant={jobDraft.autoExtractSources.length > 0 ? "info" : "neutral"}
                  className="max-w-full whitespace-normal break-words px-3 py-1.5 text-left text-[0.68rem] leading-5 normal-case tracking-[0.08em]"
                >
                  {autoExtractHint}
                </Badge>
              </div>
              <div className="mt-4 grid gap-3 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,0.7fr)_minmax(0,0.7fr)_minmax(0,0.6fr)]">
                <div className="grid gap-3 sm:grid-cols-2">
                  {([
                    ["zhanghaoya", "账号鸭", extractorAvailability.zhanghaoya],
                    ["shanyouxiang", "闪邮箱", extractorAvailability.shanyouxiang],
                  ] as const).map(([provider, label, available]) => {
                    const checked = jobDraft.autoExtractSources.includes(provider);
                    return (
                      <label
                        key={provider}
                        className={`flex items-start gap-3 rounded-2xl border px-4 py-3 ${
                          checked ? "border-cyan-300/30 bg-cyan-300/8" : "border-white/8 bg-white/[0.03]"
                        } ${!available && !checked ? "opacity-60" : ""}`}
                      >
                        <Checkbox
                          checked={checked}
                          disabled={!available && !checked}
                          onCheckedChange={(value) => toggleExtractorSource(provider, value === true)}
                          aria-label={`toggle-${provider}`}
                        />
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-white">{label}</div>
                          <div className="mt-1 text-xs text-slate-400">{available ? "KEY 已配置" : "缺少 KEY，请先去微软账号页配置"}</div>
                        </div>
                      </label>
                    );
                  })}
                </div>
                <Field label="Auto Quantity">
                  <Input
                    type="number"
                    min={1}
                    disabled={jobDraft.autoExtractSources.length === 0}
                    value={jobDraft.autoExtractQuantity}
                    onChange={(event) => onJobDraftChange({ autoExtractQuantity: Number(event.target.value) || 1 })}
                  />
                </Field>
                <Field label="Max Wait Sec">
                  <Input
                    type="number"
                    min={1}
                    disabled={jobDraft.autoExtractSources.length === 0}
                    value={jobDraft.autoExtractMaxWaitSec}
                    onChange={(event) => onJobDraftChange({ autoExtractMaxWaitSec: Number(event.target.value) || 1 })}
                  />
                </Field>
                <Field label="Account Type">
                  <Input value={jobDraft.autoExtractAccountType} readOnly />
                </Field>
              </div>
              {job.autoExtractState?.lastMessage ? (
                <div className="mt-3 text-sm text-slate-400">
                  最近提取状态：{job.autoExtractState.lastProvider ? `${extractorProviderLabel(job.autoExtractState.lastProvider)} · ` : ""}
                  {job.autoExtractState.lastMessage}
                </div>
              ) : null}
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

      <div className="min-w-0 space-y-4">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>最近 Attempts</CardTitle>
            <CardDescription>快速确认最近成功、失败与代理分布。</CardDescription>
          </CardHeader>
          <CardContent className="min-w-0 space-y-3">
            {job.recentAttempts.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                还没有历史 attempt。
              </div>
            ) : (
              job.recentAttempts.slice(0, 8).map((attempt) => (
                <article key={attempt.id} className="min-w-0 rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                  <div className="flex min-w-0 items-start justify-between gap-4">
                    <div className="min-w-0 font-medium text-white">Attempt #{attempt.id}</div>
                    <StatusBadge status={attempt.status} />
                  </div>
                  <div className="mt-3 break-all text-sm text-slate-300">
                    {attempt.accountEmail || `账号 #${attempt.accountId}`} · {attempt.proxyNode || "未绑定代理"}
                  </div>
                  <div className="mt-2 break-all text-xs text-slate-500">{attempt.errorCode || attempt.stage}</div>
                </article>
              ))
            )}
          </CardContent>
        </Card>

        <Card className="min-w-0 overflow-hidden">
          <CardHeader>
            <CardTitle>实时事件日志</CardTitle>
            <CardDescription>WebSocket 推送的主流程、账号与代理事件。</CardDescription>
          </CardHeader>
          <Separator />
          <CardContent className="min-w-0 pt-4">
            <ScrollArea className="h-[32rem] min-w-0 pr-2">
              <div className="min-w-0 space-y-3">
                {events.length === 0 ? (
                  <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                    WebSocket 事件会显示在这里。
                  </div>
                ) : (
                  events.map((event, index) => (
                    <article key={`${event.timestamp}-${index}`} className="min-w-0 rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4 text-sm">
                      <div className="flex min-w-0 items-start justify-between gap-3">
                        <span className="min-w-0 break-all font-medium text-cyan-200">{event.type}</span>
                        <span className="shrink-0 text-xs text-slate-500">{formatDate(event.timestamp)}</span>
                      </div>
                      <pre className="mt-3 max-w-full overflow-x-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-400">
                        {JSON.stringify(event.payload, null, 2)}
                      </pre>
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
