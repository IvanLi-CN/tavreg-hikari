import { type ReactNode, useRef } from "react";
import { flushSync } from "react-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BufferedNumberInput, type BufferedNumberInputHandle } from "@/components/ui/buffered-number-input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import type { ChatGptCredentialRecord, ChatGptDraft, ChatGptJobDraft, JobSnapshot } from "@/lib/app-types";
import { buildCodexVibeMonitorCredentialJson } from "@/lib/chatgpt-credential-format";
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

function buildCredentialDetail(credential: ChatGptCredentialRecord | null): string {
  if (!credential) {
    return "";
  }
  return buildCodexVibeMonitorCredentialJson(credential);
}

function normalizeMaxAttempts(need: number, maxAttempts: number): number {
  if (maxAttempts >= need) {
    return maxAttempts;
  }
  return Math.max(need, Math.ceil(need * 1.5));
}

export function ChatGptView({
  draft,
  jobDraft,
  job,
  credentials,
  revealedCredential,
  draftBusy,
  jobBusy,
  credentialBusy,
  onDraftChange,
  onJobDraftChange,
  onRegenerateDraft,
  onStart,
  onStop,
  onForceStop,
  onRevealCredential,
  onCopyCredential,
  onExportCredential,
}: {
  draft: ChatGptDraft | null;
  jobDraft: ChatGptJobDraft;
  job: JobSnapshot;
  credentials: ChatGptCredentialRecord[];
  revealedCredential: ChatGptCredentialRecord | null;
  draftBusy: boolean;
  jobBusy: boolean;
  credentialBusy: boolean;
  onDraftChange: (patch: Partial<ChatGptDraft>) => void;
  onJobDraftChange: (patch: Partial<ChatGptJobDraft>) => void;
  onRegenerateDraft: () => void | Promise<void>;
  onStart: (draft: ChatGptJobDraft) => void | Promise<void>;
  onStop: () => void | Promise<void>;
  onForceStop: () => void | Promise<void>;
  onRevealCredential: (credentialId: number) => void | Promise<void>;
  onCopyCredential: (credential: ChatGptCredentialRecord) => void | Promise<void>;
  onExportCredential: (credential: ChatGptCredentialRecord) => void | Promise<void>;
}) {
  const needRef = useRef<BufferedNumberInputHandle>(null);
  const parallelRef = useRef<BufferedNumberInputHandle>(null);
  const maxAttemptsRef = useRef<BufferedNumberInputHandle>(null);
  const status = job.job?.status || "idle";
  const cooldown = job.cooldown?.active ? job.cooldown : null;
  const canStart = (!job.job || ["completed", "failed", "stopped"].includes(status)) && !cooldown;
  const canStop = status === "running";
  const canForceStop = ["running", "stopping", "force_stopping"].includes(status);
  const credentialDetail = buildCredentialDetail(revealedCredential);
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
    <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
      <div className="min-w-0 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>ChatGPT 浏览器流</CardTitle>
            <CardDescription>支持批量目标、并发与尝试预算；首个 attempt 使用当前草稿，其余 attempt 自动复用资料模板并生成新的 cf-mail 邮箱。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="邮箱">
                <Input
                  value={draft?.email || ""}
                  placeholder="cf-mail mailbox"
                  disabled={jobConfigLocked}
                  onChange={(event) => onDraftChange({ email: event.target.value })}
                />
              </Field>
              <Field label="密码">
                <Input
                  value={draft?.password || ""}
                  placeholder="auto generated password"
                  disabled={jobConfigLocked}
                  onChange={(event) => onDraftChange({ password: event.target.value })}
                />
              </Field>
              <Field label="昵称">
                <Input
                  value={draft?.nickname || ""}
                  placeholder="Nova123"
                  disabled={jobConfigLocked}
                  onChange={(event) => onDraftChange({ nickname: event.target.value })}
                />
              </Field>
              <Field label="出生日期">
                <Input
                  type="date"
                  min="1990-01-01"
                  max="2005-12-31"
                  value={draft?.birthDate || ""}
                  disabled={jobConfigLocked}
                  onChange={(event) => onDraftChange({ birthDate: event.target.value })}
                />
              </Field>
            </div>
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
              <span>默认草稿生成于 {formatDate(draft?.generatedAt)}</span>
            </div>
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-400">
              当目标或最大尝试大于 1 时，系统会在启动时为额外 attempt 预留独立邮箱，并沿用当前密码 / 昵称 / 生日模板，避免批量时重复占用同一个 mailbox。
            </div>
            {cooldown ? (
              <div className="rounded-2xl border border-amber-300/20 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
                检测到最近一次授权链触发了 challenge。请等到 {formatDate(cooldown.until)} 之后再重新开始。
              </div>
            ) : null}
            <div className="flex flex-wrap gap-3">
              <Button variant="secondary" disabled={draftBusy || jobBusy || jobConfigLocked} onClick={() => void onRegenerateDraft()}>
                {draftBusy ? "生成中..." : "重新生成默认值"}
              </Button>
              <Button disabled={!canStart || !draft || draftBusy || jobBusy} onClick={handleStartClick}>
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
                <CardDescription>批量模式下会并发拉起多个 headed attempt；缺少 refresh token 仍直接判失败。</CardDescription>
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
      </div>

      <div className="min-w-0 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>最近凭据</CardTitle>
            <CardDescription>列表默认只显示掩码；需要显式 reveal 后才能复制或导出明文。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {credentials.length > 0 ? (
              credentials.map((credential) => {
                const isRevealed = revealedCredential?.id === credential.id && Boolean(revealedCredential.accessToken);
                return (
                  <div key={credential.id} className="rounded-3xl border border-white/8 bg-white/[0.03] p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium text-white">{credential.email}</div>
                        <div className="mt-2 grid gap-2 text-xs text-slate-400">
                          <div>access: <span className="font-mono text-slate-200">{credential.accessTokenMasked}</span></div>
                          <div>refresh: <span className="font-mono text-slate-200">{credential.refreshTokenMasked}</span></div>
                          <div>id: <span className="font-mono text-slate-200">{credential.idTokenMasked}</span></div>
                          <div>account id: <span className="font-mono text-slate-200">{credential.accountId || "—"}</span></div>
                          <div>expires: <span className="text-slate-200">{formatDate(credential.expiresAt)}</span></div>
                        </div>
                      </div>
                      <div className="flex flex-wrap justify-end gap-2">
                        <Button
                          variant={isRevealed ? "outline" : "secondary"}
                          size="sm"
                          disabled={credentialBusy}
                          onClick={() => void onRevealCredential(credential.id)}
                        >
                          {isRevealed ? "已显示" : "显示凭据"}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!isRevealed || credentialBusy}
                          onClick={() => void onCopyCredential(revealedCredential || credential)}
                        >
                          复制 JSON
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!isRevealed || credentialBusy}
                          onClick={() => void onExportCredential(revealedCredential || credential)}
                        >
                          导出 JSON
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="rounded-3xl border border-dashed border-white/10 px-4 py-8 text-sm text-slate-500">
                任务成功后，这里会显示完整凭据包的最近记录。
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>明文详情</CardTitle>
            <CardDescription>当前仅在你主动 reveal 之后，才把完整 token JSON 拉到页面里。</CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              readOnly
              value={credentialDetail}
              placeholder="选择一条凭据后，明文 JSON 会显示在这里。"
              className="min-h-[360px] font-mono text-xs leading-6"
            />
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
