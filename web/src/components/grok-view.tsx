import { useRef, useState, type ReactNode } from "react";
import { flushSync } from "react-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { ForceStopDialog } from "@/components/force-stop-dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import type { JobControlAction, JobControlOptions, JobDraft, JobSnapshot } from "@/lib/app-types";
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

function Field(props: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function summarizeAttempt(attempt: JobSnapshot["activeAttempts"][number] | JobSnapshot["recentAttempts"][number]) {
  return [attempt.stage, attempt.proxyNode, attempt.proxyIp, attempt.errorCode].filter(Boolean).join(" · ") || "等待浏览器输出";
}

function describeCooldownReason(reason: string | null | undefined): string {
  const normalized = String(reason || "").trim();
  return normalized || "检测到共享邮箱 provider 冷却中。";
}

export function GrokView({
  job,
  jobDraft,
  jobBusy,
  onJobDraftChange,
  onJobAction,
  onOpenKeysView,
}: {
  job: JobSnapshot;
  jobDraft: JobDraft;
  jobBusy: boolean;
  onJobDraftChange: (patch: Partial<JobDraft>) => void;
  onJobAction: (action: JobControlAction, options?: JobControlOptions) => void | Promise<void>;
  onOpenKeysView: () => void;
}) {
  const needRef = useRef<BufferedNumberInputHandle>(null);
  const parallelRef = useRef<BufferedNumberInputHandle>(null);
  const maxAttemptsRef = useRef<BufferedNumberInputHandle>(null);
  const [forceStopDialogOpen, setForceStopDialogOpen] = useState(false);

  const commitDraftInputs = (): JobDraft =>
    normalizeJobDraft({
      ...jobDraft,
      need: needRef.current?.commit() ?? jobDraft.need,
      parallel: parallelRef.current?.commit() ?? jobDraft.parallel,
      maxAttempts: maxAttemptsRef.current?.commit() ?? jobDraft.maxAttempts,
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

  const currentStatus = job.job?.status ?? null;
  const cooldown = job.cooldown?.active ? job.cooldown : null;
  const primaryAction = resolvePrimaryJobAction(currentStatus);
  const primaryLabel = resolvePrimaryJobLabel(currentStatus);
  const primaryDisabled = primaryJobActionDisabled(currentStatus) || (primaryAction === "start" && Boolean(cooldown));
  const stopHint = resolveStopHint(currentStatus);

  return (
    <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.14fr)_minmax(22rem,0.86fr)]">
      <div className="min-w-0 space-y-4">
        <div className="flex justify-end">
          <Button variant="outline" onClick={onOpenKeysView}>
            查看 Keys
          </Button>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Job 状态"
            value={job.job?.status || "idle"}
            tone={job.job?.status === "completed" ? "good" : job.job?.status === "failed" ? "bad" : "default"}
          />
          <MetricCard label="成功 / 目标" value={`${job.job?.successCount || 0} / ${job.job?.need || 0}`} tone="good" />
          <MetricCard label="并发 / 已发起" value={`${job.job?.parallel || 0} / ${job.job?.launchedCount || 0}`} tone="warn" />
          <MetricCard label="失败 / 上限" value={`${job.job?.failureCount || 0} / ${job.job?.maxAttempts || 0}`} tone="default" />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Grok 批量任务</CardTitle>
            <CardDescription>按参考项目批量跑注册链路，成功定义是拿到可导出的 SSO。</CardDescription>
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
                <BufferedNumberInput ref={parallelRef} min={1} value={jobDraft.parallel} onCommit={(value) => onJobDraftChange({ parallel: value })} />
              </Field>
              <Field label="Max Attempts">
                <BufferedNumberInput ref={maxAttemptsRef} min={1} value={jobDraft.maxAttempts} onCommit={(value) => onJobDraftChange({ maxAttempts: value })} />
              </Field>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <Badge variant="info">accounts.x.ai → sso</Badge>
              <Badge variant="neutral">batch mode</Badge>
              <Badge variant="neutral">project mailbox + Turnstile solver</Badge>
              <Badge variant="warning">除 sso 外其余 cookies 仅写 attempt 工件</Badge>
            </div>

            <div className="flex flex-wrap gap-3">
              <Button
                disabled={primaryDisabled || jobBusy}
                onClick={() => {
                  if (!primaryAction) return;
                  handleJobActionClick(primaryAction);
                }}
              >
                {jobBusy ? "提交中..." : primaryLabel}
              </Button>
              <Button
                variant="secondary"
                disabled={!canUpdateJobLimits(currentStatus) || jobBusy}
                onClick={() => handleJobActionClick("update_limits")}
              >
                更新限制
              </Button>
              <Button variant="outline" disabled={!canGracefullyStop(currentStatus) || jobBusy} onClick={() => handleJobActionClick("stop")}>
                停止
              </Button>
              <Button variant="danger" disabled={!canForceStop(currentStatus) || jobBusy} onClick={() => setForceStopDialogOpen(true)}>
                强制停止
              </Button>
            </div>

            {stopHint ? (
              <div className="rounded-2xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
                {stopHint}
              </div>
            ) : null}
            {cooldown ? (
              <div className="rounded-2xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
                {describeCooldownReason(cooldown.reason)} 请等到 {formatDate(cooldown.until)} 之后再重新开始。
              </div>
            ) : null}
            {job.job?.lastError ? (
              <div className="rounded-2xl border border-rose-300/20 bg-rose-300/[0.06] px-4 py-3 text-sm text-rose-50">
                最近错误：{job.job.lastError}
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>当前 Attempt</CardTitle>
            <CardDescription>展示正在跑的浏览器 attempt、代理节点与阶段。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
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
                  <div className="mt-3 text-xs text-slate-500">开始于 {formatDate(attempt.startedAt)}</div>
                </div>
              ))
            ) : (
              <div className="rounded-3xl border border-dashed border-white/10 px-4 py-6 text-sm text-slate-500">当前没有运行中的 Grok attempt。</div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="min-w-0 space-y-4">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>Attempt 历史</CardTitle>
            <CardDescription>最近 20 条 attempt 历史，便于回溯验证码、SSO 与 set-cookie 阶段。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
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
                  <Separator className="my-3 bg-white/8" />
                  <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500">
                    <span>开始：{formatDate(attempt.startedAt)}</span>
                    <span>完成：{formatDate(attempt.completedAt)}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="rounded-3xl border border-dashed border-white/10 px-4 py-6 text-sm text-slate-500">还没有 Grok attempt 历史。</div>
            )}
          </CardContent>
        </Card>
      </div>

      <ForceStopDialog
        open={forceStopDialogOpen}
        onOpenChange={setForceStopDialogOpen}
        taskLabel="Grok"
        scopeLabel="当前任务"
        onConfirm={() => {
          handleJobActionClick("force_stop", { confirmForceStop: true });
        }}
      />
    </section>
  );
}
