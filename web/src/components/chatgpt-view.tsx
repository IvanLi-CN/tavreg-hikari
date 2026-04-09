import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import type { ChatGptCredentialRecord, ChatGptDraft, JobSnapshot } from "@/lib/app-types";
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

export function ChatGptView({
  draft,
  job,
  credentials,
  revealedCredential,
  draftBusy,
  jobBusy,
  credentialBusy,
  onDraftChange,
  onRegenerateDraft,
  onStart,
  onStop,
  onForceStop,
  onRevealCredential,
  onCopyCredential,
  onExportCredential,
}: {
  draft: ChatGptDraft | null;
  job: JobSnapshot;
  credentials: ChatGptCredentialRecord[];
  revealedCredential: ChatGptCredentialRecord | null;
  draftBusy: boolean;
  jobBusy: boolean;
  credentialBusy: boolean;
  onDraftChange: (patch: Partial<ChatGptDraft>) => void;
  onRegenerateDraft: () => void | Promise<void>;
  onStart: () => void | Promise<void>;
  onStop: () => void | Promise<void>;
  onForceStop: () => void | Promise<void>;
  onRevealCredential: (credentialId: number) => void | Promise<void>;
  onCopyCredential: (credential: ChatGptCredentialRecord) => void | Promise<void>;
  onExportCredential: (credential: ChatGptCredentialRecord) => void | Promise<void>;
}) {
  const status = job.job?.status || "idle";
  const cooldown = job.cooldown?.active ? job.cooldown : null;
  const canStart = (!job.job || ["completed", "failed", "stopped"].includes(status)) && !cooldown;
  const canStop = status === "running";
  const canForceStop = ["running", "stopping", "force_stopping"].includes(status);
  const credentialDetail = buildCredentialDetail(revealedCredential);

  return (
    <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
      <div className="min-w-0 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>ChatGPT 浏览器流</CardTitle>
            <CardDescription>固定有头模式，专门用于单账号排障与完整凭据落盘。</CardDescription>
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
                检测到最近一次授权链触发了 challenge，已进入冷却。
                {" "}
                请等到 {formatDate(cooldown.until)} 之后再重新开始。
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
