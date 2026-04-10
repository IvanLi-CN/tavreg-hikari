import { type ReactNode, useRef } from "react";
import { flushSync } from "react-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { StatusBadge } from "@/components/status-badge";
import type { ChatGptJobDraft, JobSnapshot } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

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

export function ChatGptView({
  jobDraft,
  job,
  jobBusy,
  onJobDraftChange,
  onStart,
  onStop,
  onForceStop,
}: {
  jobDraft: ChatGptJobDraft;
  job: JobSnapshot;
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
  const canStart = (!job.job || ["completed", "failed", "stopped"].includes(status)) && !cooldown;
  const canStop = status === "running";
  const canForceStop = ["running", "stopping", "force_stopping"].includes(status);
  const jobConfigLocked = Boolean(job.job && !["completed", "failed", "stopped"].includes(status));
  const effectiveNeed = job.job?.need || jobDraft.need;
  const effectiveParallel = job.job?.parallel || jobDraft.parallel;
  const effectiveMaxAttempts = job.job?.maxAttempts || jobDraft.maxAttempts;

  const commitJobDraft = (): ChatGptJobDraft => {
    const need = needRef.current?.commit() ?? jobDraft.need;
    const parallel = parallelRef.current?.commit() ?? jobDraft.parallel;
    const maxAttempts = maxAttemptsRef.current?.commit() ?? jobDraft.maxAttempts;
    return {
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
    <section className="min-w-0 space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>ChatGPT 浏览器流</CardTitle>
          <CardDescription>
            这里仅负责批量流程控制与运行态；生成结果统一在 <span className="font-medium text-slate-200">Keys &gt; ChatGPT</span> 查看。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-3">
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
            <Badge variant="info">mode: headed</Badge>
            <Badge variant="neutral">need: {effectiveNeed}</Badge>
            <Badge variant="neutral">parallel: {effectiveParallel}</Badge>
            <Badge variant="neutral">max attempts: {effectiveMaxAttempts}</Badge>
            <span>attempt 资料会在任务启动时按批次自动生成</span>
          </div>
          <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
            每个 attempt 都会预生成独立邮箱与注册资料；单个 attempt 内若发生页面跳转或登录重试，只会继续复用它自己的那份资料，不会跨 attempt 共享。
          </div>
          {cooldown ? (
            <div className="rounded-2xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
              检测到最近一次授权链触发了 challenge。请等到 {formatDate(cooldown.until)} 之后再重新开始。
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
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>当前任务</CardTitle>
              <CardDescription>
                批量模式下会并发拉起多个 headed attempt；每个 attempt 使用独立自动生成资料，缺少 refresh token 仍直接判失败。
              </CardDescription>
            </div>
            <StatusBadge status={status} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">成功 / 目标</div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {job.job?.successCount || 0} / {job.job?.need || jobDraft.need}
              </div>
            </div>
            <div className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">已发起 / 预算</div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {job.job?.launchedCount || 0} / {job.job?.maxAttempts || jobDraft.maxAttempts}
              </div>
            </div>
            <div className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">最近错误</div>
              <div className="mt-2 text-sm text-slate-200">{job.job?.lastError || "—"}</div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Active Attempts</div>
            {job.activeAttempts.length > 0 ? (
              job.activeAttempts.map((attempt) => (
                <div key={attempt.id} className="rounded-3xl border border-cyan-400/15 bg-cyan-400/[0.04] p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium text-white">{attempt.accountEmail || `attempt #${attempt.id}`}</div>
                      <div className="mt-1 text-sm text-slate-400">{summarizeAttempt(attempt)}</div>
                    </div>
                    <StatusBadge status={attempt.status} />
                  </div>
                </div>
              ))
            ) : (
              <div className="rounded-3xl border border-dashed border-white/10 px-4 py-6 text-sm text-slate-500">当前没有运行中的浏览器 attempt。</div>
            )}
          </div>

          <Separator className="bg-white/8" />

          <div className="space-y-3">
            <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Recent Attempts</div>
            {job.recentAttempts.length > 0 ? (
              job.recentAttempts.map((attempt) => (
                <div key={attempt.id} className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium text-white">{attempt.accountEmail || `attempt #${attempt.id}`}</div>
                      <div className="mt-1 text-sm text-slate-400">{summarizeAttempt(attempt)}</div>
                    </div>
                    <StatusBadge status={attempt.status} />
                  </div>
                </div>
              ))
            ) : (
              <div className="rounded-3xl border border-dashed border-white/10 px-4 py-6 text-sm text-slate-500">还没有 attempt 历史。</div>
            )}
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
