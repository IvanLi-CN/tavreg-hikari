import { useRef, useState } from "react";
import { flushSync } from "react-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { AccountExtractorProvider, EventRecord, JobControlAction, JobControlOptions, JobDraft, JobSnapshot } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { normalizeJobDraft } from "@/lib/job-draft";
import {
  canForceStop,
  canGracefullyStop,
  canUpdateJobLimits,
  primaryJobActionDisabled,
  resolvePrimaryJobAction,
  resolvePrimaryJobLabel,
  resolveStopHint,
} from "@/lib/job-controls";

const EXTRACTOR_PROVIDER_OPTIONS = [
  { provider: "zhanghaoya", label: "账号鸭" },
  { provider: "shanyouxiang", label: "闪邮箱" },
  { provider: "shankeyun", label: "闪客云" },
  { provider: "hotmail666", label: "Hotmail666" },
] as const satisfies Array<{ provider: AccountExtractorProvider; label: string }>;
const EXTRACTOR_ACCOUNT_TYPE_OPTIONS = [
  { value: "outlook", label: "Outlook" },
  { value: "hotmail", label: "Hotmail" },
] as const;
const AUTO_EXTRACT_WORKERS_PER_PROVIDER = 3;

function extractorAccountTypeLabel(accountType: JobDraft["autoExtractAccountType"]): string {
  return EXTRACTOR_ACCOUNT_TYPE_OPTIONS.find((option) => option.value === accountType)?.label || accountType;
}

function Field(props: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function extractorProviderLabel(provider: AccountExtractorProvider): string {
  return EXTRACTOR_PROVIDER_OPTIONS.find((item) => item.provider === provider)?.label || provider;
}

function autoExtractPhaseLabel(phase: JobSnapshot["autoExtractState"] extends infer T ? T extends { phase: infer P } ? P : never : never) {
  if (phase === "extracting") return "提取中";
  if (phase === "waiting") return "等待中";
  return "空闲";
}

function formatRawAttemptProgress(rawAttemptCount: number, attemptBudget: number): string {
  return attemptBudget > 0 ? `${rawAttemptCount}/${attemptBudget}` : String(rawAttemptCount);
}

function formatAutoExtractConcurrency(inFlightCount: number, sourceCount: number): string {
  return `${inFlightCount}/${Math.max(0, sourceCount) * AUTO_EXTRACT_WORKERS_PER_PROVIDER}`;
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
    shankeyun: boolean;
    hotmail666: boolean;
  };
  onJobDraftChange: (patch: Partial<JobDraft>) => void;
  onJobAction: (action: JobControlAction, options?: JobControlOptions) => void | Promise<void>;
}) {
  const needRef = useRef<BufferedNumberInputHandle>(null);
  const parallelRef = useRef<BufferedNumberInputHandle>(null);
  const maxAttemptsRef = useRef<BufferedNumberInputHandle>(null);
  const autoExtractQuantityRef = useRef<BufferedNumberInputHandle>(null);
  const autoExtractMaxWaitSecRef = useRef<BufferedNumberInputHandle>(null);
  const [forceStopDialogOpen, setForceStopDialogOpen] = useState(false);

  const toggleExtractorSource = (provider: AccountExtractorProvider, checked: boolean) => {
    const current = new Set(jobDraft.autoExtractSources);
    if (checked) current.add(provider);
    else current.delete(provider);
    onJobDraftChange({ autoExtractSources: Array.from(current) });
  };

  const commitDraftInputs = (): JobDraft =>
    normalizeJobDraft({
      ...jobDraft,
      need: needRef.current?.commit() ?? jobDraft.need,
      parallel: parallelRef.current?.commit() ?? jobDraft.parallel,
      maxAttempts: maxAttemptsRef.current?.commit() ?? jobDraft.maxAttempts,
      autoExtractQuantity: autoExtractQuantityRef.current?.commit() ?? jobDraft.autoExtractQuantity,
      autoExtractMaxWaitSec: autoExtractMaxWaitSecRef.current?.commit() ?? jobDraft.autoExtractMaxWaitSec,
    });

  const handleJobActionClick = (action: JobControlAction, options?: JobControlOptions) => {
    if (action === "start" || action === "update_limits") {
      let committedDraft = jobDraft;
      flushSync(() => {
        committedDraft = commitDraftInputs();
      });
      void onJobAction(action, { ...(options || {}), draft: committedDraft });
      return;
    }
    void onJobAction(action, options);
  };

  const autoExtractHint = job.autoExtractState
    ? `${autoExtractPhaseLabel(job.autoExtractState.phase)} · 类型 ${extractorAccountTypeLabel(job.autoExtractState.accountType)} · 可用补号 ${job.autoExtractState.acceptedCount}/${job.autoExtractState.currentRoundTarget} · 原始请求 ${formatRawAttemptProgress(job.autoExtractState.rawAttemptCount, job.autoExtractState.attemptBudget)} · 并发 ${formatAutoExtractConcurrency(job.autoExtractState.inFlightCount, job.autoExtractState.enabledSources.length)} · 剩余 ${job.autoExtractState.remainingWaitSec}s`
    : jobDraft.autoExtractSources.length > 0
      ? `已启用 · 类型 ${extractorAccountTypeLabel(jobDraft.autoExtractAccountType)} · 目标 ${jobDraft.autoExtractQuantity} · 超时 ${jobDraft.autoExtractMaxWaitSec}s · 单源 3 worker · 500ms/次`
      : "未启用自动提取";
  const currentStatus = job.job?.status ?? null;
  const primaryAction = resolvePrimaryJobAction(currentStatus);
  const primaryLabel = resolvePrimaryJobLabel(currentStatus);
  const primaryDisabled = primaryJobActionDisabled(currentStatus);
  const stopHint = resolveStopHint(currentStatus);

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
                <BufferedNumberInput ref={needRef} min={1} value={jobDraft.need} onCommit={(value) => onJobDraftChange({ need: value })} />
              </Field>
              <Field label="Parallel">
                <BufferedNumberInput
                  ref={parallelRef}
                  min={1}
                  value={jobDraft.parallel}
                  onCommit={(value) => onJobDraftChange({ parallel: value })}
                />
              </Field>
              <Field label="Max Attempts">
                <BufferedNumberInput
                  ref={maxAttemptsRef}
                  min={1}
                  value={jobDraft.maxAttempts}
                  onCommit={(value) => onJobDraftChange({ maxAttempts: value })}
                />
              </Field>
            </div>
            <div className="rounded-[24px] border border-cyan-400/18 bg-cyan-400/[0.04] p-4">
              <div className="flex min-w-0 flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-white">自动提取微软账号</div>
                  <div className="mt-1 text-sm text-slate-400">
                    缺号时每个号源最多保持 3 个 worker 在途；同源按 500ms 节奏补位发起请求，每次只提取 1 个账号；单请求 5 秒超时，补够或超时就停。
                  </div>
                </div>
                <Badge
                  variant={jobDraft.autoExtractSources.length > 0 ? "info" : "neutral"}
                  className="max-w-full whitespace-normal break-words px-3 py-1.5 text-left text-[0.68rem] leading-5 normal-case tracking-[0.08em]"
                >
                  {autoExtractHint}
                </Badge>
              </div>
              <div className="mt-4 space-y-4">
                <section className="rounded-[22px] border border-white/8 bg-[#0b1727]/72 p-4">
                  <div className="flex min-w-0 flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Sources</div>
                      <div className="mt-1 text-sm text-slate-300">选择参与轮转补号的渠道。</div>
                    </div>
                    <Badge variant={jobDraft.autoExtractSources.length > 0 ? "info" : "neutral"} className="normal-case tracking-[0.08em]">
                      已启用 {jobDraft.autoExtractSources.length} / {EXTRACTOR_PROVIDER_OPTIONS.length}
                    </Badge>
                  </div>
                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    {EXTRACTOR_PROVIDER_OPTIONS.map(({ provider, label }) => {
                      const available = extractorAvailability[provider];
                      const checked = jobDraft.autoExtractSources.includes(provider);
                      return (
                        <label
                          key={provider}
                          className={`flex min-w-0 items-center gap-3 rounded-2xl border px-4 py-3 transition ${
                            checked ? "border-cyan-300/30 bg-cyan-300/8" : "border-white/8 bg-white/[0.03]"
                          } ${!available && !checked ? "opacity-60" : ""}`}
                        >
                          <Checkbox
                            checked={checked}
                            disabled={!available && !checked}
                            onCheckedChange={(value) => toggleExtractorSource(provider, value === true)}
                            aria-label={`toggle-${provider}`}
                          />
                          <div className="min-w-0 flex-1">
                            <div className="flex min-w-0 flex-wrap items-center gap-2">
                              <div className="truncate text-sm font-medium text-white">{label}</div>
                              <Badge
                                variant={checked ? "info" : available ? "neutral" : "warning"}
                                className="shrink-0 normal-case tracking-[0.08em]"
                              >
                                {checked ? "已启用" : available ? "待启用" : "未配置"}
                              </Badge>
                            </div>
                            <div className="mt-1 text-xs text-slate-400">
                              {available
                                ? checked
                                  ? "当前任务会参与轮转补号"
                                  : "KEY 已配置，可随时启用"
                                : "缺少 KEY，请先去微软账号页配置"}
                            </div>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </section>

                <section className="rounded-[22px] border border-white/8 bg-[#0b1727]/72 p-4">
                  <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Strategy</div>
                  <div className="mt-1 text-sm text-slate-300">补号上限、等待时间与账号类型。</div>
                  <div className="mt-4 grid gap-3 md:grid-cols-3">
                    <Field label="Auto Quantity">
                      <BufferedNumberInput
                        ref={autoExtractQuantityRef}
                        min={1}
                        disabled={jobDraft.autoExtractSources.length === 0}
                        value={jobDraft.autoExtractQuantity}
                        onCommit={(value) => onJobDraftChange({ autoExtractQuantity: value })}
                      />
                    </Field>
                    <Field label="Max Wait Sec">
                      <BufferedNumberInput
                        ref={autoExtractMaxWaitSecRef}
                        min={1}
                        disabled={jobDraft.autoExtractSources.length === 0}
                        value={jobDraft.autoExtractMaxWaitSec}
                        onCommit={(value) => onJobDraftChange({ autoExtractMaxWaitSec: value })}
                      />
                    </Field>
                    <Field label="Account Type">
                      <Select
                        value={jobDraft.autoExtractAccountType}
                        onValueChange={(value) => onJobDraftChange({ autoExtractAccountType: value as JobDraft["autoExtractAccountType"] })}
                        disabled={jobDraft.autoExtractSources.length === 0}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="选择账号类型" />
                        </SelectTrigger>
                        <SelectContent>
                          {EXTRACTOR_ACCOUNT_TYPE_OPTIONS.map((option) => (
                            <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                  </div>
                  <div className="mt-4 rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
                    自动提取关闭时不会发起任何补号请求；开启后仅把新增进入当前 job 可调度池的账号计为有效补货。
                  </div>
                </section>
              </div>
              {job.autoExtractState?.lastMessage ? (
                <div className="mt-4 rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
                  最近提取状态：{job.autoExtractState.lastProvider ? `${extractorProviderLabel(job.autoExtractState.lastProvider)} · ` : ""}
                  {job.autoExtractState.lastMessage}
                </div>
              ) : null}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() => {
                  if (!primaryAction) return;
                  handleJobActionClick(primaryAction);
                }}
                disabled={primaryDisabled}
              >
                {primaryLabel}
              </Button>
              {canGracefullyStop(currentStatus) || currentStatus === "stopping" ? (
                <Button
                  variant="secondary"
                  onClick={() => handleJobActionClick("stop")}
                  disabled={currentStatus === "stopping"}
                >
                  {currentStatus === "stopping" ? "停止中" : "停止"}
                </Button>
              ) : null}
              {canForceStop(currentStatus) || currentStatus === "force_stopping" ? (
                <Button
                  variant="danger"
                  onClick={() => setForceStopDialogOpen(true)}
                  disabled={currentStatus === "force_stopping"}
                >
                  {currentStatus === "force_stopping" ? "强停中" : "强行停止"}
                </Button>
              ) : null}
              <Button
                variant="outline"
                onClick={() => handleJobActionClick("update_limits")}
                disabled={!canUpdateJobLimits(currentStatus)}
              >
                应用调参
              </Button>
            </div>
            {stopHint ? (
              <div className="rounded-2xl border border-amber-300/18 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-100">
                {stopHint}
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Dialog open={forceStopDialogOpen} onOpenChange={setForceStopDialogOpen}>
          <DialogContent className="w-[min(92vw,34rem)]">
            <DialogHeader>
              <DialogTitle>确认强行停止</DialogTitle>
              <DialogDescription>
                强行停止会立即中断当前 worker 与补号请求；已经在跑的 attempt 会标记为“已停止”，不会继续自然收尾。
              </DialogDescription>
            </DialogHeader>
            <div className="px-6 text-sm leading-6 text-slate-300">
              只有在优雅停止仍无法尽快收束时才建议使用这一步，别乱点哦。
            </div>
            <DialogFooter>
              <Button variant="secondary" onClick={() => setForceStopDialogOpen(false)}>
                取消
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  void onJobAction("force_stop", { confirmForceStop: true });
                  setForceStopDialogOpen(false);
                }}
              >
                确认强停
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

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
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-white">Attempt #{attempt.id}</div>
                          <div
                            className="mt-1 truncate whitespace-nowrap text-sm text-slate-300"
                            title={attempt.accountEmail || `#${attempt.accountId}`}
                          >
                            {attempt.accountEmail || `#${attempt.accountId}`}
                          </div>
                        </div>
                        <StatusBadge status={attempt.status} />
                      </div>
                      <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-3">
                          <dt className="text-slate-500">阶段</dt>
                          <dd className="truncate whitespace-nowrap text-right" title={attempt.stage}>
                            {attempt.stage}
                          </dd>
                        </div>
                        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-3">
                          <dt className="text-slate-500">代理节点</dt>
                          <dd className="truncate whitespace-nowrap text-right" title={attempt.proxyNode || "—"}>
                            {attempt.proxyNode || "—"}
                          </dd>
                        </div>
                        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-3">
                          <dt className="text-slate-500">出口 IP</dt>
                          <dd className="truncate whitespace-nowrap text-right font-mono text-[0.92rem]" title={attempt.proxyIp || "—"}>
                            {attempt.proxyIp || "—"}
                          </dd>
                        </div>
                        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-3">
                          <dt className="text-slate-500">开始时间</dt>
                          <dd className="whitespace-nowrap text-right">{formatDate(attempt.startedAt)}</dd>
                        </div>
                      </dl>
                    </article>
                  ))}
                </div>
                <div className="hidden md:block">
                  <div className="overflow-hidden rounded-[24px] border border-white/8 bg-[rgba(15,23,42,0.62)] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                    <div className="grid grid-cols-[5.5rem_minmax(0,2.2fr)_10rem_minmax(0,1fr)] gap-4 border-b border-white/8 bg-white/[0.03] px-4 py-3 text-left text-xs font-medium tracking-[0.14em] uppercase text-slate-400">
                      <div>ID</div>
                      <div>账号</div>
                      <div>状态</div>
                      <div>阶段</div>
                    </div>
                    <div>
                      {job.activeAttempts.map((attempt) => (
                        <article key={attempt.id} className="border-b border-white/8 px-4 py-4 text-slate-100 transition duration-200 last:border-b-0 hover:bg-white/[0.03]">
                          <div className="grid grid-cols-[5.5rem_minmax(0,2.2fr)_10rem_minmax(0,1fr)] items-center gap-4">
                            <div className="whitespace-nowrap">#{attempt.id}</div>
                            <div className="min-w-0">
                              <span
                                className="block truncate whitespace-nowrap font-medium text-slate-100"
                                title={attempt.accountEmail || `#${attempt.accountId}`}
                              >
                                {attempt.accountEmail || `#${attempt.accountId}`}
                              </span>
                            </div>
                            <div className="whitespace-nowrap">
                              <StatusBadge status={attempt.status} />
                            </div>
                            <div className="min-w-0">
                              <span className="block truncate whitespace-nowrap" title={attempt.stage}>
                                {attempt.stage}
                              </span>
                            </div>
                          </div>
                          <dl className="mt-3 grid grid-cols-3 gap-4 text-xs">
                            <div className="min-w-0">
                              <dt className="mb-1 uppercase tracking-[0.14em] text-slate-500">代理节点</dt>
                              <dd className="truncate whitespace-nowrap text-sm text-slate-200" title={attempt.proxyNode || "—"}>
                                {attempt.proxyNode || "—"}
                              </dd>
                            </div>
                            <div className="min-w-0">
                              <dt className="mb-1 uppercase tracking-[0.14em] text-slate-500">出口 IP</dt>
                              <dd className="truncate whitespace-nowrap font-mono text-sm text-slate-200" title={attempt.proxyIp || "—"}>
                                {attempt.proxyIp || "—"}
                              </dd>
                            </div>
                            <div className="min-w-0">
                              <dt className="mb-1 uppercase tracking-[0.14em] text-slate-500">开始时间</dt>
                              <dd className="truncate whitespace-nowrap text-sm text-slate-200" title={formatDate(attempt.startedAt)}>
                                {formatDate(attempt.startedAt)}
                              </dd>
                            </div>
                          </dl>
                        </article>
                      ))}
                    </div>
                  </div>
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
