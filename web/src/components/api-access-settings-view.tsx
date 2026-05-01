import { useEffect, useMemo, useState } from "react";
import { CloudDownload, KeyRound, RefreshCcw, Save, ShieldOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { CopyIconButton, type CopyButtonStatus } from "@/components/ui/copy-icon-button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import type { IntegrationApiKeyRecord, UpstreamSyncSettings, UpstreamSyncSettingsUpdate } from "@/lib/app-types";

type EditorMode =
  | { kind: "create" }
  | {
      kind: "rotate";
      record: IntegrationApiKeyRecord;
    };

export type RevealedIntegrationApiSecret = {
  mode: "create" | "rotate";
  record: IntegrationApiKeyRecord;
  plainTextKey: string;
};

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function statusBadgeVariant(status: IntegrationApiKeyRecord["status"]): "success" | "danger" {
  return status === "active" ? "success" : "danger";
}

export function ApiAccessSettingsView(props: {
  upstreamSyncSettings: UpstreamSyncSettings | null;
  upstreamSyncDraft: UpstreamSyncSettingsUpdate;
  upstreamSyncBusy?: boolean;
  rows: IntegrationApiKeyRecord[];
  loading?: boolean;
  mutatingId?: number | "create" | null;
  revealedSecret: RevealedIntegrationApiSecret | null;
  onUpstreamSyncDraftChange: (patch: Partial<UpstreamSyncSettingsUpdate>) => void;
  onSaveUpstreamSyncSettings: () => void | Promise<void>;
  onCreate: (input: { label: string; notes: string | null }) => boolean | void | Promise<boolean | void>;
  onRotate: (
    record: IntegrationApiKeyRecord,
    input: { label: string; notes: string | null },
  ) => boolean | void | Promise<boolean | void>;
  onRevoke: (record: IntegrationApiKeyRecord) => void | Promise<void>;
  onRevealedSecretOpenChange: (open: boolean) => void;
}) {
  const [editor, setEditor] = useState<EditorMode | null>(null);
  const [label, setLabel] = useState("");
  const [notes, setNotes] = useState("");
  const [copyStatus, setCopyStatus] = useState<CopyButtonStatus>("idle");

  useEffect(() => {
    if (!editor) return;
    if (editor.kind === "create") {
      setLabel("");
      setNotes("");
      return;
    }
    setLabel(editor.record.label);
    setNotes(editor.record.notes || "");
  }, [editor]);

  useEffect(() => {
    setCopyStatus("idle");
  }, [props.revealedSecret?.plainTextKey]);

  const activeCount = useMemo(() => props.rows.filter((row) => row.status === "active").length, [props.rows]);

  const submitBusy = props.mutatingId === "create" || (editor?.kind === "rotate" && props.mutatingId === editor.record.id);

  const handleSubmit = async () => {
    const trimmedLabel = label.trim();
    if (!trimmedLabel || !editor) return;
    const nextNotes = notes.trim() || null;
    const shouldClose =
      editor.kind === "create"
        ? await props.onCreate({ label: trimmedLabel, notes: nextNotes })
        : await props.onRotate(editor.record, { label: trimmedLabel, notes: nextNotes });
    if (shouldClose === false) {
      return;
    }
    setEditor(null);
  };

  const handleCopySecret = async (anchor: HTMLElement) => {
    if (!props.revealedSecret?.plainTextKey) return;
    try {
      await navigator.clipboard.writeText(props.revealedSecret.plainTextKey);
      setCopyStatus("copied");
    } catch {
      anchor.focus();
      setCopyStatus("failed");
    }
  };

  return (
    <>
      <Card data-testid="upstream-sync-settings-card" aria-label="线上数据同步设置">
        <CardHeader className="gap-4 md:flex-row md:items-start md:justify-between">
          <div className="space-y-2">
            <CardTitle className="flex items-center gap-2">
              <CloudDownload className="size-5 text-cyan-200" aria-hidden="true" />
              线上数据同步
            </CardTitle>
            <CardDescription>本地账号页使用这组 integration API 设置拉取线上账号池；关闭后不会访问线上。</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge variant={props.upstreamSyncDraft.enabled ? "success" : "neutral"}>
              {props.upstreamSyncDraft.enabled ? "同步已开启" : "同步已关闭"}
            </Badge>
            <Badge variant={props.upstreamSyncSettings?.hasApiKey ? "success" : "warning"}>
              {props.upstreamSyncSettings?.hasApiKey ? "key 已保存" : "缺少 key"}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Production base URL</span>
              <Input
                value={props.upstreamSyncDraft.baseUrl}
                disabled={props.upstreamSyncBusy}
                onChange={(event) => props.onUpstreamSyncDraftChange({ baseUrl: event.target.value })}
                placeholder="https://tavreg-hikari.ivanli.cc"
              />
            </label>
            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Integration API Key</span>
              <Input
                type="password"
                value={props.upstreamSyncDraft.apiKey}
                disabled={props.upstreamSyncBusy}
                onChange={(event) => props.onUpstreamSyncDraftChange({ apiKey: event.target.value })}
                placeholder={
                  props.upstreamSyncSettings?.hasApiKey
                    ? `当前生效：${props.upstreamSyncSettings.apiKeyMasked}`
                    : "粘贴线上 API Access key"
                }
              />
            </label>
          </div>

          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <div className="flex items-start gap-3 rounded-[24px] border border-white/8 bg-[#08111d]/88 p-4">
              <Switch
                checked={props.upstreamSyncDraft.enabled}
                disabled={props.upstreamSyncBusy}
                aria-label="启用线上同步"
                onCheckedChange={(checked) => props.onUpstreamSyncDraftChange({ enabled: checked === true })}
              />
              <span className="space-y-1 text-sm">
                <span className="block font-medium text-slate-100">启用线上同步</span>
                <span className="block text-xs leading-5 text-slate-400">
                  控制账号页手动同步和 Tavily 成功回写是否调用线上实例。
                </span>
              </span>
            </div>

            <label className="flex items-start gap-3 rounded-[24px] border border-white/8 bg-[#08111d]/88 p-4">
              <Checkbox
                checked={props.upstreamSyncDraft.writeback === "success_only"}
                disabled={props.upstreamSyncBusy}
                onCheckedChange={(checked) =>
                  props.onUpstreamSyncDraftChange({ writeback: checked === true ? "success_only" : "off" })
                }
              />
              <span className="space-y-1 text-sm">
                <span className="block font-medium text-slate-100">仅回写 Tavily 成功结果</span>
                <span className="block text-xs leading-5 text-slate-400">失败、禁用、分组或密码编辑都不会回写线上。</span>
              </span>
            </label>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 rounded-[24px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,31,0.95),rgba(8,15,27,0.92))] px-4 py-3 text-sm text-slate-300">
            <div className="min-w-0">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Saved upstream</div>
              <div className="mt-1 break-all font-mono text-cyan-100">{props.upstreamSyncSettings?.baseUrl || "未设置"}</div>
            </div>
            <Button
              type="button"
              disabled={props.upstreamSyncBusy || !props.upstreamSyncDraft.baseUrl.trim()}
              onClick={() => void props.onSaveUpstreamSyncSettings()}
            >
              <Save className="size-4" aria-hidden="true" />
              {props.upstreamSyncBusy ? "保存中…" : "保存同步设置"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="gap-4 md:flex-row md:items-start md:justify-between">
          <div className="space-y-2">
            <CardTitle>API Access</CardTitle>
            <CardDescription>
              为外部 `/api/integration/v1/*` 管理多把接入密钥。明文只在创建或轮换完成后展示一次，刷新后不可再次取回。
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge variant="success">active · {activeCount}</Badge>
            <Badge variant="neutral">total · {props.rows.length}</Badge>
            <Button type="button" onClick={() => setEditor({ kind: "create" })}>
              <KeyRound className="size-4" aria-hidden="true" />
              创建 API Key
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-[24px] border border-white/8 bg-[#08111d]/88 p-4 text-sm text-slate-300">
            <div className="grid gap-3 lg:grid-cols-[minmax(0,1.1fr)_minmax(8rem,0.65fr)_minmax(9rem,0.7fr)_minmax(10rem,0.8fr)_minmax(10rem,0.8fr)_auto]">
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Label / Notes</div>
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Prefix</div>
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Status</div>
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Created</div>
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Last used</div>
              <div className="text-xs uppercase tracking-[0.22em] text-slate-500 lg:text-right">Actions</div>
            </div>
          </div>

          {props.loading ? (
            <div className="rounded-[24px] border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-500">
              API Access 加载中…
            </div>
          ) : props.rows.length === 0 ? (
            <div className="rounded-[24px] border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-500">
              还没有外部接入 Key。先创建一把给另一实例用吧，才、才不是我在催你。
            </div>
          ) : (
            <div className="space-y-3">
              {props.rows.map((row) => {
                const rowBusy = props.mutatingId === row.id;
                return (
                  <article
                    key={row.id}
                    className="grid gap-4 rounded-[24px] border border-white/8 bg-[linear-gradient(180deg,rgba(11,18,31,0.95),rgba(8,15,27,0.92))] p-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(8rem,0.65fr)_minmax(9rem,0.7fr)_minmax(10rem,0.8fr)_minmax(10rem,0.8fr)_auto]"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium text-white">{row.label}</div>
                      <div className="mt-1 text-xs text-slate-400">{row.notes || "无备注"}</div>
                    </div>
                    <div className="font-mono text-sm text-cyan-100">{row.keyPrefix}</div>
                    <div className="flex items-center gap-2">
                      <Badge variant={statusBadgeVariant(row.status)}>{row.status}</Badge>
                    </div>
                    <div className="text-sm text-slate-300">{formatDateTime(row.createdAt)}</div>
                    <div className="text-sm text-slate-300">
                      <div>{formatDateTime(row.lastUsedAt)}</div>
                      <div className="mt-1 text-xs text-slate-500">{row.lastUsedIp || "—"}</div>
                    </div>
                    <div className="flex flex-wrap gap-2 lg:justify-end">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={rowBusy || row.status !== "active"}
                        onClick={() => setEditor({ kind: "rotate", record: row })}
                      >
                        <RefreshCcw className="size-3.5" aria-hidden="true" />
                        轮换
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        disabled={rowBusy || row.status !== "active"}
                        onClick={() => void props.onRevoke(row)}
                      >
                        <ShieldOff className="size-3.5" aria-hidden="true" />
                        {row.status === "active" ? "禁用" : "已禁用"}
                      </Button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={editor != null} onOpenChange={(open) => !open && setEditor(null)}>
        <DialogContent className="w-[min(92vw,38rem)]">
          <DialogHeader>
            <DialogTitle>{editor?.kind === "rotate" ? "轮换 API Key" : "创建 API Key"}</DialogTitle>
            <DialogDescription>
              {editor?.kind === "rotate"
                ? "轮换后旧明文 Key 会立刻失效，新的明文只会展示一次。"
                : "为外部 integration v1 创建一把新密钥；创建成功后会立即给出一次性明文。"}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 px-6 py-2">
            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Label</span>
              <Input
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="例如：worker-east / staging relay"
              />
            </label>
            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Notes</span>
              <Textarea
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                placeholder="补充用途、实例归属或轮换备注（可选）"
                rows={4}
              />
            </label>
          </div>
          <DialogFooter>
            <Button type="button" variant="secondary" onClick={() => setEditor(null)}>
              取消
            </Button>
            <Button type="button" disabled={!label.trim() || submitBusy} onClick={() => void handleSubmit()}>
              {submitBusy ? "提交中…" : editor?.kind === "rotate" ? "确认轮换" : "创建并展示明文"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={props.revealedSecret != null} onOpenChange={props.onRevealedSecretOpenChange}>
        <DialogContent className="w-[min(92vw,42rem)]">
          <DialogHeader>
            <DialogTitle>{props.revealedSecret?.mode === "rotate" ? "新的 API Key 已生成" : "API Key 已创建"}</DialogTitle>
            <DialogDescription>
              这串明文只会展示这一次，请立即复制到接入方实例。关闭后我也拿不回来了，记住喔。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 px-6 py-2">
            <div className="rounded-[24px] border border-amber-300/18 bg-amber-400/8 px-4 py-3 text-sm text-amber-100">
              <div className="font-medium">一次性明文展示</div>
              <div className="mt-1 text-xs leading-5 text-amber-50/90">
                Key 只以 hash 形式落库；刷新页面或关闭弹层后，只能通过再次轮换来获取新的明文。
              </div>
            </div>
            <div className="rounded-[24px] border border-white/8 bg-[#08111d]/88 p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-white">{props.revealedSecret?.record.label}</div>
                  <div className="mt-1 text-xs text-slate-400">{props.revealedSecret?.record.keyPrefix}</div>
                </div>
                <CopyIconButton
                  label="API key"
                  copyStatus={copyStatus}
                  onCopy={handleCopySecret}
                  feedbackSide="left"
                  feedbackAlign="start"
                  feedbackValue={props.revealedSecret?.plainTextKey}
                />
              </div>
              <div className="mt-4 rounded-2xl border border-white/10 bg-[#0b1423]/90 px-4 py-3 font-mono text-sm text-cyan-100 break-all">
                {props.revealedSecret?.plainTextKey}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button type="button" onClick={() => props.onRevealedSecretOpenChange(false)}>
              我已保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
