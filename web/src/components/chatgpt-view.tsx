import { type ReactNode, useRef } from "react";
import { flushSync } from "react-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { ChatGptJobDraft, JobSnapshot, RunModeAvailability } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { isRunModeAvailabilityPending } from "@/lib/run-mode";

function Field(props: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function summarizeAttempt(attempt: JobSnapshot["activeAttempts"][number] | JobSnapshot["recentAttempts"][number]) {
  return [attempt.stage, attempt.proxyNode, attempt.errorCode].filter(Boolean).join(" · ") || "等待浏览器输出";
}

function normalizeMaxAttempts(need: number, maxAttempts: number): number {
  if (maxAttempts >= need) {
    return maxAttempts;
  }
  return Math.max(need, Math.ceil(need * 1.5));
}

function statusTone(status: string): "default" | "good" | "warn" | "bad" {
  if (status === "completed") return "good";
  if (status === "failed") return "bad";
  if (["running", "stopping", "force_stopping"].includes(status)) return "warn";
  return "default";
}

export function ChatGptView({
  jobDraft,
  job,
  runModeAvailability,
  jobBusy,
  onJobDraftChange,
  onStart,
  onStop,
  onForceStop,
}: {
  jobDraft: ChatGptJobDraft;
  job: JobSnapshot;
  runModeAvailability: RunModeAvailability;
  jobBusy: boolean;
  onJobDraftChange: (patch: Partial<ChatGptJobDraft>) => void;
  onStart: (draft: ChatGptJobDraft) => void | Promise<void>;
  onStop: () => void | Promise<void>;
  onForceStop: () => void | Promise<void>;
}) {
  const needRef = useRef<BufferedNumberInputHandle>(null);
  const parallelRef = useRef<BufferedNumberInputHandle>(null);
  const maxAttemptsRef = useRef<BufferedNumberInputHandle>(null);
  const status = job.job?.status || "idle";
  const cooldown = job.cooldown?.active ? job.cooldown : null;
  const runModeAvailabilityPending = isRunModeAvailabilityPending(runModeAvailability);
  const canStart = (!job.job || ["completed", "failed", "stopped"].includes(status)) && !cooldown && !runModeAvailabilityPending;
  const canStop = status === "running";
  const canForceStop = ["running", "stopping", "force_stopping"].includes(status);
  const jobConfigLocked = Boolean(job.job && !["completed", "failed", "stopped"].includes(status));
  const effectiveRunMode = jobConfigLocked ? (job.job?.runMode || jobDraft.runMode) : jobDraft.runMode;
  const effectiveNeed = jobConfigLocked ? (job.job?.need || jobDraft.need) : jobDraft.need;
  const effectiveParallel = jobConfigLocked ? (job.job?.parallel || jobDraft.parallel) : jobDraft.parallel;
  const effectiveMaxAttempts = jobConfigLocked ? (job.job?.maxAttempts || jobDraft.maxAttempts) : jobDraft.maxAttempts;

  const commitJobDraft = (): ChatGptJobDraft => {
    const need = needRef.current?.commit() ?? jobDraft.need;
    const parallel = parallelRef.current?.commit() ?? jobDraft.parallel;
    const maxAttempts = maxAttemptsRef.current?.commit() ?? jobDraft.maxAttempts;
    return {
      runMode: jobDraft.runMode,
      need,
      parallel,
      maxAttempts: normalizeMaxAttempts(need, maxAttempts),
    };
  };

  const handleStartClick = () => {
    let committedDraft = jobDraft;
    flushSync(() => {
      committedDraft = commitJobDraft();
      onJobDraftChange(committedDraft);
    });
    void onStart(committedDraft);
  };

  return (
    <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.16fr)_minmax(0,0.84fr)]">
      <div className="min-w-0 space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="任务状态" value={status} tone={statusTone(status)} />
          <MetricCard label="成功 / 目标" value={`${job.job?.successCount || 0} / ${effectiveNeed}`} tone="good" />
          <MetricCard label="并行 / 已发起" value={`${effectiveParallel} / ${job.job?.launchedCount || 0}`} tone="warn" />
          <MetricCard label="运行中" value={job.activeAttempts.length} />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>任务控制</CardTitle>
            <CardDescription>
              ChatGPT 页负责批量任务控制；生成结果统一在 <span className="font-medium text-slate-200">Keys &gt; ChatGPT</span> 查看。
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 lg:grid-cols-4">
              <Field label="Run Mode">
                <Select
                  value={jobDraft.runMode}
                  onValueChange={(value) => onJobDraftChange({ runMode: value as ChatGptJobDraft["runMode"] })}
                  disabled={jobConfigLocked || runModeAvailabilityPending}
                >
                  <SelectTrigger aria-label="Run Mode">
                    <SelectValue placeholder="选择模式" />
                  </SelectTrigger>
                  <SelectContent>
                    {runModeAvailability.headed ? <SelectItem value="headed">headed</SelectItem> : null}
                    <SelectItem value="headless">headless</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Need">
                <BufferedNumberInput
                  ref={needRef}
                  min={1}
                  disabled={jobConfigLocked}
                  value={jobDraft.need}
                  onCommit={(value) => onJobDraftChange({ need: value })}
                />
              </Field>
              <Field label="Parallel">
                <BufferedNumberInput
                  ref={parallelRef}
                  min={1}
                  disabled={jobConfigLocked}
                  value={jobDraft.parallel}
                  onCommit={(value) => onJobDraftChange({ parallel: value })}
                />
              </Field>
              <Field label="Max Attempts">
                <BufferedNumberInput
                  ref={maxAttemptsRef}
                  min={1}
                  disabled={jobConfigLocked}
                  value={jobDraft.maxAttempts}
                  onCommit={(value) => onJobDraftChange({ maxAttempts: value })}
                />
              </Field>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <Badge variant="info">mode: {effectiveRunMode}</Badge>
              <Badge variant="neutral">need: {effectiveNeed}</Badge>
              <Badge variant="neutral">parallel: {effectiveParallel}</Badge>
              <Badge variant="neutral">max attempts: {effectiveMaxAttempts}</Badge>
              <span>{effectiveRunMode === "headless" ? "当前将以无头浏览器模式批量运行" : "当前将以有头浏览器模式批量运行"}</span>
            </div>
            {runModeAvailabilityPending ? (
              <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
                正在检测当前环境的浏览器能力，稍后才能开始任务。
              </div>
            ) : !runModeAvailability.headed ? (
              <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
                当前环境仅支持 <span className="font-medium text-slate-200">headless</span>。{runModeAvailability.headedReason || "有头浏览器不可用。"}
              </div>
            ) : null}
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
              每个 attempt 都会预生成独立邮箱与注册资料；单个 attempt 内若发生页面跳转或登录重试，只会继续复用它自己的那份资料，不会跨 attempt 共享。
            </div>
            {cooldown ? (
              <div className="rounded-2xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
                检测到最近一次授权链触发了 challenge。请等到 {formatDate(cooldown.until)} 之后再重新开始。
              </div>
            ) : null}
            {job.job?.lastError ? (
              <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
                最近错误：<span className="font-medium text-slate-200">{job.job.lastError}</span>
              </div>
            ) : null}
            <div className="flex flex-wrap gap-3">
              <Button disabled={!canStart || jobBusy} onClick={handleStartClick}>
                {jobBusy ? "提交中..." : job.job ? "重新开始" : "开始"}
              </Button>
              <Button variant="outline" disabled={!canStop || jobBusy} onClick={() => void onStop()}>
                停止
              </Button>
              <Button variant="danger" disabled={!canForceStop || jobBusy} onClick={() => void onForceStop()}>
                强制停止
              </Button>
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
                          <dl className="mt-3 grid grid-cols-2 gap-4 text-xs">
                            <div className="min-w-0">
                              <dt className="mb-1 uppercase tracking-[0.14em] text-slate-500">代理节点</dt>
                              <dd className="truncate whitespace-nowrap text-sm text-slate-200" title={attempt.proxyNode || "—"}>
                                {attempt.proxyNode || "—"}
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
            <CardDescription>快速确认最近成功、失败与节点分布。</CardDescription>
          </CardHeader>
          <CardContent className="min-w-0 space-y-3">
            {job.recentAttempts.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                还没有 attempt 历史。
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
      </div>
    </section>
  );
}
