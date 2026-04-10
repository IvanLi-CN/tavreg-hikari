import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { StatusBadge } from "@/components/status-badge";
import type { ChatGptDraft, JobSnapshot } from "@/lib/app-types";
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

export function ChatGptView({
  draft,
  job,
  draftBusy,
  jobBusy,
  onDraftChange,
  onRegenerateDraft,
  onStart,
  onStop,
  onForceStop,
}: {
  draft: ChatGptDraft | null;
  job: JobSnapshot;
  draftBusy: boolean;
  jobBusy: boolean;
  onDraftChange: (patch: Partial<ChatGptDraft>) => void;
  onRegenerateDraft: () => void | Promise<void>;
  onStart: () => void | Promise<void>;
  onStop: () => void | Promise<void>;
  onForceStop: () => void | Promise<void>;
}) {
  const status = job.job?.status || "idle";
  const cooldown = job.cooldown?.active ? job.cooldown : null;
  const canStart = (!job.job || ["completed", "failed", "stopped"].includes(status)) && !cooldown;
  const canStop = status === "running";
  const canForceStop = ["running", "stopping", "force_stopping"].includes(status);

  return (
    <section className="min-w-0 space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>ChatGPT 浏览器流</CardTitle>
          <CardDescription>固定有头模式，专门用于单账号排障；生成后的 keys 记录改到 Keys &gt; ChatGPT 查看。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="邮箱">
              <Input
                value={draft?.email || ""}
                placeholder="cf-mail mailbox"
                onChange={(event) => onDraftChange({ email: event.target.value })}
              />
            </Field>
            <Field label="密码">
              <Input
                value={draft?.password || ""}
                placeholder="auto generated password"
                onChange={(event) => onDraftChange({ password: event.target.value })}
              />
            </Field>
            <Field label="昵称">
              <Input
                value={draft?.nickname || ""}
                placeholder="Nova123"
                onChange={(event) => onDraftChange({ nickname: event.target.value })}
              />
            </Field>
            <Field label="出生日期">
              <Input
                type="date"
                min="1990-01-01"
                max="2005-12-31"
                value={draft?.birthDate || ""}
                onChange={(event) => onDraftChange({ birthDate: event.target.value })}
              />
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <Badge variant="info">mode: headed</Badge>
            <Badge variant="neutral">need: 1</Badge>
            <Badge variant="neutral">parallel: 1</Badge>
            <Badge variant="neutral">max attempts: 1</Badge>
            <span>默认值生成于 {formatDate(draft?.generatedAt)}</span>
          </div>
          {cooldown ? (
            <div className="rounded-2xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
              检测到最近一次授权链触发了 challenge。请等到 {formatDate(cooldown.until)} 之后再重新开始。
            </div>
          ) : null}
          <div className="flex flex-wrap gap-3">
            <Button variant="secondary" disabled={draftBusy || jobBusy} onClick={() => void onRegenerateDraft()}>
              {draftBusy ? "生成中..." : "重新生成默认值"}
            </Button>
            <Button disabled={!canStart || !draft || draftBusy || jobBusy} onClick={() => void onStart()}>
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
              <CardDescription>只接受完整凭据包；缺少 refresh token 直接判失败。</CardDescription>
            </div>
            <StatusBadge status={status} />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">成功 / 目标</div>
              <div className="mt-2 text-2xl font-semibold text-white">
                {job.job?.successCount || 0} / {job.job?.need || 1}
              </div>
            </div>
            <div className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">已发起</div>
              <div className="mt-2 text-2xl font-semibold text-white">{job.job?.launchedCount || 0}</div>
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
