import { ArrowLeft, KeyRound } from "lucide-react";
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

function Field(props: { label: string; children: ReactNode; className?: string }) {
  return (
    <label className={props.className}>
      <div className="mb-2 text-[0.68rem] uppercase tracking-[0.18em] text-slate-500">{props.label}</div>
      {props.children}
    </label>
  );
}

function InfoRow(props: { label: string; value: string; emphasize?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-white/8 py-3 last:border-b-0">
      <div className="text-sm text-slate-500">{props.label}</div>
      <div className={props.emphasize ? "max-w-[60%] text-right text-sm font-medium text-white" : "max-w-[60%] text-right text-sm text-slate-300"}>
        {props.value}
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
    <div className="space-y-4">
      <Card className="border-white/10 bg-slate-950/55 shadow-none">
        <CardContent className="flex flex-col gap-4 p-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <Button variant="ghost" size="sm" className="mb-3" onClick={props.onBack}>
              <ArrowLeft className="size-4" />
              返回微软邮箱
            </Button>
            <h1 className="text-2xl font-semibold text-white">Microsoft Graph 设置</h1>
            <p className="mt-1 text-sm text-slate-400">
              这里只维护 OAuth 接入参数。单个账号的授权和收件箱刷新，回到“微软邮箱”页面执行。
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge variant={configured ? "success" : "warning"}>{configured ? "已配置" : "待配置"}</Badge>
            <Badge variant="neutral">独立设置页</Badge>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <Card className="border-white/10 bg-slate-950/55 shadow-none">
          <CardHeader className="border-b border-white/8">
            <CardTitle>接入参数</CardTitle>
            <CardDescription>保存后，微软账号页的“Bootstrap 邮箱”会使用这里的配置发起 OAuth。</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5 p-5">
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
              <div className="flex flex-wrap gap-2">
                <Badge variant={configured ? "success" : "warning"}>{configured ? "可为账号授权" : "保存后才能授权"}</Badge>
                <Badge variant="neutral">推荐权限: Mail.Read + offline_access</Badge>
              </div>
              <Button onClick={() => void props.onSaveSettings()} disabled={props.settingsBusy}>
                <KeyRound className="size-4" />
                {props.settingsBusy ? "保存中…" : "保存设置"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card className="border-white/10 bg-slate-950/55 shadow-none">
            <CardHeader className="border-b border-white/8">
              <CardTitle>当前状态</CardTitle>
              <CardDescription>这里显示当前生效的 Graph 接入信息摘要。</CardDescription>
            </CardHeader>
            <CardContent className="p-5">
              <InfoRow label="状态" value={configured ? "已配置" : "待配置"} emphasize />
              <InfoRow label="Authority" value={props.settingsDraft.microsoftGraphAuthority || "common"} />
              <InfoRow
                label="Client Secret"
                value={props.settings?.microsoftGraphClientSecretMasked || "尚未保存"}
              />
              <InfoRow
                label="Redirect URI"
                value={props.settingsDraft.microsoftGraphRedirectUri || "请填写完整 callback URL"}
              />
            </CardContent>
          </Card>

          <Card className="border-white/10 bg-slate-950/55 shadow-none">
            <CardHeader className="border-b border-white/8">
              <CardTitle>接入要求</CardTitle>
              <CardDescription>这些值需要与 Azure 应用注册保持一致。</CardDescription>
            </CardHeader>
            <CardContent className="p-5">
              <InfoRow label="回调路径" value="/api/microsoft-mail/oauth/callback" />
              <InfoRow label="默认 authority" value="common" />
              <InfoRow label="建议委托权限" value="Mail.Read, offline_access" />
              <div className="mt-4 rounded-2xl border border-white/8 bg-white/[0.02] px-4 py-3 text-sm leading-6 text-slate-300">
                配置完成后，回到微软账号页，为具体账号点击“Bootstrap 邮箱”即可发起授权。
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
