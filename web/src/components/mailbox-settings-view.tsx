import { ArrowLeft, KeyRound, Link2, Settings2, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { MicrosoftGraphSettings } from "@/lib/app-types";

export type MicrosoftGraphSettingsDraft = {
  microsoftGraphClientId: string;
  microsoftGraphClientSecret: string;
  microsoftGraphRedirectUri: string;
  microsoftGraphAuthority: string;
};

function Field(props: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <label className={props.className}>
      <div className="mb-2 text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</div>
      {props.children}
    </label>
  );
}

function GuideCard(props: {
  icon: ReactNode;
  title: string;
  description: string;
  badge?: string;
}) {
  return (
    <div className="rounded-[28px] border border-white/10 bg-slate-950/35 p-4">
      <div className="flex items-start gap-3">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] text-sky-200">
          {props.icon}
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="text-sm font-semibold text-white">{props.title}</div>
            {props.badge ? <Badge variant="neutral">{props.badge}</Badge> : null}
          </div>
          <p className="mt-1 text-sm leading-6 text-slate-400">{props.description}</p>
        </div>
      </div>
    </div>
  );
}

export function MailboxSettingsView(props: {
  settings: MicrosoftGraphSettings | null;
  settingsDraft: MicrosoftGraphSettingsDraft;
  settingsBusy: boolean;
  onSettingsDraftChange: (patch: Partial<MicrosoftGraphSettingsDraft>) => void;
  onSaveSettings: () => Promise<void>;
  onBack: () => void;
}) {
  const configured = props.settings?.configured ?? false;

  return (
    <div className="space-y-6">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_360px]">
        <Card className="border-white/10 bg-[linear-gradient(180deg,rgba(6,18,34,0.94),rgba(6,18,34,0.78))]">
          <CardContent className="space-y-6 p-6 md:p-7">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <Button variant="ghost" onClick={props.onBack}>
                <ArrowLeft className="size-4" />
                返回收件箱
              </Button>
              <div className="flex flex-wrap gap-2 text-xs">
                <Badge variant={configured ? "success" : "warning"}>{configured ? "Graph 已配置" : "Graph 待配置"}</Badge>
                <Badge variant="neutral">独立设置页</Badge>
              </div>
            </div>
            <div className="space-y-3">
              <div className="text-xs uppercase tracking-[0.26em] text-cyan-300/75">Microsoft Graph</div>
              <div>
                <h2 className="text-3xl font-semibold tracking-tight text-white">把设置从工作区里拿出来</h2>
                <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
                  这个页面只负责 OAuth 接入参数。收件箱页现在只保留切换邮箱、连接授权、刷新和读信，避免配置表单打断主流程。
                </p>
              </div>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              <GuideCard
                icon={<Settings2 className="size-4" />}
                title="Authority"
                description="默认填 common，兼容任意 Entra ID 租户和个人 Microsoft 账号。"
                badge={props.settingsDraft.microsoftGraphAuthority || "common"}
              />
              <GuideCard
                icon={<Link2 className="size-4" />}
                title="回调路径"
                description="Azure 应用注册中必须和这里完全一致，协议、域名、端口和路径都不能错。"
                badge="/api/microsoft-mail/oauth/callback"
              />
              <GuideCard
                icon={<ShieldCheck className="size-4" />}
                title="权限范围"
                description="完成保存后，用 Graph OAuth 为账号授权，收件箱只读同步依赖 Mail.Read 和 offline_access。"
              />
            </div>
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle>配置状态</CardTitle>
            <CardDescription>先保存凭据，再回到收件箱页为具体账号发起连接。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="rounded-[28px] border border-white/10 bg-slate-950/35 p-4">
              <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Client Secret</div>
              <div className="mt-2 text-sm text-slate-300">
                {props.settings?.microsoftGraphClientSecretMasked || "还没有保存 secret"}
              </div>
            </div>
            <div className="rounded-[28px] border border-white/10 bg-slate-950/35 p-4">
              <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Redirect URI</div>
              <div className="mt-2 break-all text-sm text-slate-300">
                {props.settingsDraft.microsoftGraphRedirectUri || "请填写完整 callback URL"}
              </div>
            </div>
            <div className="rounded-[28px] border border-dashed border-cyan-300/20 bg-cyan-300/[0.05] p-4 text-sm leading-6 text-slate-300">
              保存完成后，回到“微软邮箱”页，点击具体账号上的“连接邮箱”即可发起 OAuth，喵。
            </div>
          </CardContent>
        </Card>
      </section>

      <Card className="border-white/10 bg-white/[0.03]">
        <CardHeader>
          <CardTitle>Graph 凭据</CardTitle>
          <CardDescription>只维护接入参数，不在这里处理单账号授权或收件箱同步。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Client ID" className="min-w-0">
              <Input
                value={props.settingsDraft.microsoftGraphClientId}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphClientId: event.target.value })}
                placeholder="Application (client) ID"
              />
            </Field>
            <Field label="Authority" className="min-w-0">
              <Input
                value={props.settingsDraft.microsoftGraphAuthority}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphAuthority: event.target.value })}
                placeholder="common"
              />
            </Field>
            <Field label="Client Secret" className="min-w-0">
              <Input
                type="password"
                value={props.settingsDraft.microsoftGraphClientSecret}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphClientSecret: event.target.value })}
                placeholder={props.settings?.microsoftGraphClientSecretMasked || "Client secret"}
              />
            </Field>
            <Field label="Redirect URI" className="min-w-0">
              <Input
                value={props.settingsDraft.microsoftGraphRedirectUri}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphRedirectUri: event.target.value })}
                placeholder="https://example.com/api/microsoft-mail/oauth/callback"
              />
            </Field>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/8 pt-4">
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant={configured ? "success" : "warning"}>{configured ? "可直接连接账号" : "保存后才能连接账号"}</Badge>
              <Badge variant="neutral">建议: Mail.Read + offline_access</Badge>
            </div>
            <Button onClick={() => void props.onSaveSettings()} disabled={props.settingsBusy}>
              <KeyRound className="size-4" />
              {props.settingsBusy ? "保存中…" : "保存 Graph 设置"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
