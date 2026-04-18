import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { ChatGptUpstreamSettings } from "@/lib/app-types";

export type ChatGptUpstreamSettingsDialogDraft = {
  baseUrl: string;
  apiKey: string;
  clearBaseUrl: boolean;
  clearApiKey: boolean;
};

function sourceLabel(source: ChatGptUpstreamSettings["baseUrlSource"]): string {
  if (source === "db") return "Web 设置";
  if (source === "env") return "环境变量";
  return "未配置";
}

export function ChatGptUpstreamSettingsDialog({
  open,
  onOpenChange,
  settings,
  draft,
  saveBusy,
  error,
  onDraftChange,
  onSave,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  settings: ChatGptUpstreamSettings | null;
  draft: ChatGptUpstreamSettingsDialogDraft;
  saveBusy: boolean;
  error?: string | null;
  onDraftChange: (patch: Partial<ChatGptUpstreamSettingsDialogDraft>) => void;
  onSave: () => void | Promise<void>;
}) {
  const baseUrlSource = settings?.baseUrlSource || "unset";
  const apiKeySource = settings?.apiKeySource || "unset";
  const effectiveBaseUrl = settings?.baseUrl || "";
  const baseUrlInputId = "chatgpt-upstream-base-url";
  const apiKeyInputId = "chatgpt-upstream-api-key";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl" data-testid="chatgpt-upstream-settings-dialog">
        <DialogHeader>
          <DialogTitle>ChatGPT 补号设置</DialogTitle>
          <DialogDescription>
            这些配置只保存在当前机器的 Web SQLite 中；若清除 Web 覆盖，则会回退到环境变量默认值。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5 px-6 py-5 md:space-y-6">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex flex-col gap-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-5 text-sm text-slate-300">
              <div className="space-y-1">
                <div className="text-xs uppercase tracking-[0.22em] text-slate-500">baseUrl</div>
                <div className="break-all text-slate-100">{effectiveBaseUrl || "未配置"}</div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={settings?.configured ? "success" : "warning"}>{settings?.configured ? "已就绪" : "待配置"}</Badge>
                <Badge variant="neutral">来源：{sourceLabel(baseUrlSource)}</Badge>
              </div>
            </div>
            <div className="flex flex-col gap-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-5 text-sm text-slate-300">
              <div className="space-y-1">
                <div className="text-xs uppercase tracking-[0.22em] text-slate-500">external api key</div>
                <div className="break-all text-slate-100">{settings?.apiKeyMasked || "未配置"}</div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={settings?.hasApiKey ? "success" : "warning"}>{settings?.hasApiKey ? "已配置" : "未配置"}</Badge>
                <Badge variant="neutral">来源：{sourceLabel(apiKeySource)}</Badge>
              </div>
            </div>
          </div>

          <section className="space-y-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-5">
            <label htmlFor={baseUrlInputId} className="block text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">
              Base URL 覆盖
            </label>
            <Input
              id={baseUrlInputId}
              value={draft.baseUrl}
              onChange={(event) => onDraftChange({ baseUrl: event.target.value, clearBaseUrl: false })}
              placeholder={baseUrlSource === "db" ? effectiveBaseUrl : "https://codex-vibe-monitor.example"}
            />
            <div className="flex flex-wrap items-center gap-3 text-sm text-slate-400">
              <span>当前生效：{effectiveBaseUrl || "未配置"}</span>
              {baseUrlSource === "db" ? (
                <Button type="button" variant="outline" size="sm" onClick={() => onDraftChange({ baseUrl: "", clearBaseUrl: true })}>
                  改回环境默认
                </Button>
              ) : null}
            </div>
            {draft.clearBaseUrl ? (
              <div className="rounded-2xl border border-amber-300/18 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
                保存后会移除当前 Web Base URL 覆盖，并回退到环境变量默认值。
              </div>
            ) : null}
          </section>

          <section className="space-y-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-5">
            <label htmlFor={apiKeyInputId} className="block text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">
              External API Key 覆盖
            </label>
            <Input
              id={apiKeyInputId}
              type="password"
              value={draft.apiKey}
              onChange={(event) => onDraftChange({ apiKey: event.target.value, clearApiKey: false })}
              placeholder={settings?.hasApiKey ? "留空表示保持当前值；输入新值会替换覆盖" : "请输入 external API key"}
            />
            <div className="flex flex-wrap items-center gap-3 text-sm text-slate-400">
              <span>{settings?.hasApiKey ? `当前生效：${settings.apiKeyMasked}` : "当前没有生效中的 external API key"}</span>
              {apiKeySource === "db" ? (
                <Button type="button" variant="outline" size="sm" onClick={() => onDraftChange({ apiKey: "", clearApiKey: true })}>
                  改回环境默认
                </Button>
              ) : null}
            </div>
            {draft.clearApiKey ? (
              <div className="rounded-2xl border border-amber-300/18 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
                保存后会移除当前 Web API key 覆盖，并回退到环境变量默认值。
              </div>
            ) : null}
          </section>

          <div className="rounded-[24px] border border-white/8 bg-[#08111d]/88 p-5 text-sm text-slate-300">
            <div className="text-xs uppercase tracking-[0.22em] text-slate-500">分组历史</div>
            <div className="mt-4 flex flex-wrap gap-2">
              {settings?.groupHistory.length ? (
                settings.groupHistory.map((group) => (
                  <Badge key={group} variant="neutral">{group}</Badge>
                ))
              ) : (
                <span className="text-slate-500">成功补号后会自动回写最近使用的分组。</span>
              )}
            </div>
          </div>

          {error ? (
            <div className="rounded-2xl border border-rose-300/18 bg-rose-400/8 px-4 py-3 text-sm text-rose-100">{error}</div>
          ) : null}
        </div>

        <DialogFooter className="gap-3 sm:justify-between">
          <div className="text-sm text-slate-400">配置仅作用于 ChatGPT 补号链路。</div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
              取消
            </Button>
            <Button type="button" onClick={() => void onSave()} disabled={saveBusy}>
              {saveBusy ? "保存中…" : "保存设置"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
