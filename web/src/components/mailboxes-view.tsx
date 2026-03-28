import DOMPurify from "dompurify";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { StatusBadge } from "@/components/status-badge";
import type {
  MailboxMessageDetail,
  MailboxMessageSummary,
  MailboxRecord,
  MicrosoftGraphSettings,
} from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

type SettingsDraft = {
  microsoftGraphClientId: string;
  microsoftGraphClientSecret: string;
  microsoftGraphRedirectUri: string;
  microsoftGraphAuthority: string;
};

function MailboxListItem(props: {
  mailbox: MailboxRecord;
  selected: boolean;
  connecting: boolean;
  syncing: boolean;
  onSelect: () => void;
  onConnect: () => void;
  onSync: () => void;
}) {
  const label = props.mailbox.graphDisplayName || props.mailbox.microsoftEmail;
  return (
    <button
      type="button"
      onClick={props.onSelect}
      className={cn(
        "w-full rounded-3xl border px-4 py-4 text-left transition",
        props.selected
          ? "border-cyan-300/50 bg-cyan-300/[0.08] shadow-[0_14px_40px_rgba(14,165,233,0.16)]"
          : "border-white/8 bg-white/[0.03] hover:border-white/15 hover:bg-white/[0.05]",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-white">{label}</div>
          <div className="mt-1 truncate text-xs text-slate-400">{props.mailbox.microsoftEmail}</div>
        </div>
        <Badge variant={props.mailbox.unreadCount > 0 ? "info" : "neutral"}>{props.mailbox.unreadCount}</Badge>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <StatusBadge status={props.mailbox.status} />
        {props.mailbox.groupName ? <Badge variant="neutral">{props.mailbox.groupName}</Badge> : null}
      </div>
      <dl className="mt-3 space-y-2 text-xs text-slate-400">
        <div className="flex items-center justify-between gap-3">
          <dt>最近同步</dt>
          <dd className="text-right text-slate-200">{formatDate(props.mailbox.lastSyncedAt)}</dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt>授权</dt>
          <dd className="text-right text-slate-200">{props.mailbox.isAuthorized ? "已连接" : "待连接"}</dd>
        </div>
      </dl>
      {props.mailbox.lastErrorMessage ? (
        <div className="mt-3 rounded-2xl border border-rose-400/20 bg-rose-500/[0.08] px-3 py-2 text-xs text-rose-100">
          {props.mailbox.lastErrorMessage}
        </div>
      ) : null}
      <div className="mt-4 flex flex-wrap gap-2">
        <Button
          variant={props.mailbox.isAuthorized ? "secondary" : "outline"}
          className="h-8 px-3 text-xs"
          onClick={(event) => {
            event.stopPropagation();
            props.onConnect();
          }}
          disabled={props.connecting}
        >
          {props.connecting ? "跳转中…" : props.mailbox.isAuthorized ? "重新授权" : "连接邮箱"}
        </Button>
        <Button
          variant="outline"
          className="h-8 px-3 text-xs"
          onClick={(event) => {
            event.stopPropagation();
            props.onSync();
          }}
          disabled={!props.mailbox.isAuthorized || props.syncing}
        >
          {props.syncing ? "同步中…" : "刷新"}
        </Button>
      </div>
    </button>
  );
}

function MessageListItem(props: {
  message: MailboxMessageSummary;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={props.onSelect}
      className={cn(
        "w-full rounded-3xl border px-4 py-4 text-left transition",
        props.selected
          ? "border-emerald-300/40 bg-emerald-300/[0.08]"
          : "border-white/8 bg-white/[0.03] hover:border-white/15 hover:bg-white/[0.05]",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-white">{props.message.subject || "(无主题)"}</div>
          <div className="mt-1 truncate text-xs text-slate-400">
            {props.message.fromName || props.message.fromAddress || "未知发件人"}
          </div>
        </div>
        {!props.message.isRead ? <Badge variant="info">未读</Badge> : null}
      </div>
      <div className="mt-3 line-clamp-3 text-sm text-slate-300">{props.message.bodyPreview || "无预览"}</div>
      <div className="mt-3 text-xs text-slate-500">{formatDate(props.message.receivedAt)}</div>
    </button>
  );
}

export function MailboxesView(props: {
  settings: MicrosoftGraphSettings | null;
  settingsDraft: SettingsDraft;
  settingsBusy: boolean;
  mailboxes: MailboxRecord[];
  selectedMailbox: MailboxRecord | null;
  messages: MailboxMessageSummary[];
  messagesTotal: number;
  messagesHasMore: boolean;
  messagesBusy: boolean;
  selectedMessageId: number | null;
  messageDetail: MailboxMessageDetail | null;
  messageBusy: boolean;
  connectingMailboxId: number | null;
  syncingMailboxId: number | null;
  onSettingsDraftChange: (patch: Partial<SettingsDraft>) => void;
  onSaveSettings: () => Promise<void>;
  onSelectMailbox: (mailboxId: number) => void;
  onConnectMailbox: (mailboxId: number) => Promise<void>;
  onSyncMailbox: (mailboxId: number) => Promise<void>;
  onLoadMoreMessages: () => Promise<void>;
  onSelectMessage: (messageId: number) => Promise<void>;
}) {
  const sanitizedBody =
    props.messageDetail?.bodyContentType === "html"
      ? DOMPurify.sanitize(props.messageDetail.bodyContent, { USE_PROFILES: { html: true } })
      : null;

  return (
    <div className="space-y-6">
      <Card className="border-white/10 bg-[linear-gradient(180deg,rgba(7,18,36,0.92),rgba(7,18,36,0.72))]">
        <CardHeader>
          <CardTitle>Microsoft Graph 配置</CardTitle>
          <CardDescription>保存后即可对导入的微软账号发起 OAuth 连接并开始同步 Inbox。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className="space-y-2">
              <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Client ID</span>
              <Input
                value={props.settingsDraft.microsoftGraphClientId}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphClientId: event.target.value })}
                placeholder="Application (client) ID"
              />
            </label>
            <label className="space-y-2">
              <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Client Secret</span>
              <Input
                type="password"
                value={props.settingsDraft.microsoftGraphClientSecret}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphClientSecret: event.target.value })}
                placeholder={props.settings?.microsoftGraphClientSecretMasked || "Client secret"}
              />
            </label>
            <label className="space-y-2">
              <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Redirect URI</span>
              <Input
                value={props.settingsDraft.microsoftGraphRedirectUri}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphRedirectUri: event.target.value })}
                placeholder="https://example.com/api/microsoft-mail/oauth/callback"
              />
            </label>
            <label className="space-y-2">
              <span className="text-xs uppercase tracking-[0.22em] text-slate-500">Authority</span>
              <Input
                value={props.settingsDraft.microsoftGraphAuthority}
                onChange={(event) => props.onSettingsDraftChange({ microsoftGraphAuthority: event.target.value })}
                placeholder="common"
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant={props.settings?.configured ? "success" : "warning"}>
                {props.settings?.configured ? "已配置" : "待配置"}
              </Badge>
              <Badge variant="neutral">callback /api/microsoft-mail/oauth/callback</Badge>
            </div>
            <Button onClick={() => void props.onSaveSettings()} disabled={props.settingsBusy}>
              {props.settingsBusy ? "保存中…" : "保存 Graph 设置"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,380px)_minmax(0,1fr)]">
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle>邮箱账号</CardTitle>
            <CardDescription>每个导入账号都会自动纳入收信模块。</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[66vh] px-4 pb-4">
              <div className="space-y-3">
                {props.mailboxes.map((mailbox) => (
                  <MailboxListItem
                    key={mailbox.id}
                    mailbox={mailbox}
                    selected={props.selectedMailbox?.id === mailbox.id}
                    connecting={props.connectingMailboxId === mailbox.id}
                    syncing={props.syncingMailboxId === mailbox.id}
                    onSelect={() => props.onSelectMailbox(mailbox.id)}
                    onConnect={() => void props.onConnectMailbox(mailbox.id)}
                    onSync={() => void props.onSyncMailbox(mailbox.id)}
                  />
                ))}
                {props.mailboxes.length === 0 ? (
                  <div className="rounded-3xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
                    还没有导入微软账号。
                  </div>
                ) : null}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle>Inbox 邮件</CardTitle>
            <CardDescription>
              {props.selectedMailbox ? `${props.selectedMailbox.microsoftEmail} · 共 ${props.messagesTotal} 封` : "先从左侧选择一个邮箱。"}
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[66vh] px-4 pb-4">
              <div className="space-y-3">
                {props.messages.map((message) => (
                  <MessageListItem
                    key={message.id}
                    message={message}
                    selected={props.selectedMessageId === message.id}
                    onSelect={() => void props.onSelectMessage(message.id)}
                  />
                ))}
                {props.messagesBusy ? (
                  <div className="rounded-3xl border border-white/8 bg-white/[0.03] px-4 py-6 text-center text-sm text-slate-400">
                    正在读取邮件列表…
                  </div>
                ) : null}
                {!props.messagesBusy && props.selectedMailbox && props.messages.length === 0 ? (
                  <div className="rounded-3xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
                    这个邮箱还没有缓存邮件。可以先点左侧的“刷新”。
                  </div>
                ) : null}
                {props.messagesHasMore ? (
                  <Button variant="outline" className="w-full" onClick={() => void props.onLoadMoreMessages()}>
                    加载更多
                  </Button>
                ) : null}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle>邮件内容</CardTitle>
            <CardDescription>
              {props.messageDetail
                ? `${props.messageDetail.fromName || props.messageDetail.fromAddress || "未知发件人"} · ${formatDate(props.messageDetail.receivedAt)}`
                : "点中间的邮件后，会在这里显示正文。"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {props.messageBusy ? (
              <div className="rounded-3xl border border-white/8 bg-white/[0.03] px-4 py-10 text-center text-sm text-slate-400">
                正在读取邮件正文…
              </div>
            ) : props.messageDetail ? (
              <div className="space-y-5">
                <div className="rounded-3xl border border-white/8 bg-slate-950/40 px-5 py-4">
                  <div className="text-xl font-semibold text-white">{props.messageDetail.subject || "(无主题)"}</div>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-400">
                    <Badge variant={props.messageDetail.isRead ? "neutral" : "info"}>
                      {props.messageDetail.isRead ? "已读" : "未读"}
                    </Badge>
                    {props.messageDetail.hasAttachments ? <Badge variant="warning">含附件</Badge> : null}
                    {props.messageDetail.webLink ? <Badge variant="neutral">Outlook Web</Badge> : null}
                  </div>
                </div>
                {props.messageDetail.bodyContentType === "html" ? (
                  <div
                    className="prose prose-invert max-w-none rounded-3xl border border-white/8 bg-slate-950/30 px-6 py-5 prose-a:text-cyan-300 prose-p:text-slate-200 prose-strong:text-white"
                    dangerouslySetInnerHTML={{ __html: sanitizedBody || "" }}
                  />
                ) : (
                  <pre className="whitespace-pre-wrap rounded-3xl border border-white/8 bg-slate-950/30 px-6 py-5 font-sans text-sm text-slate-200">
                    {props.messageDetail.bodyContent || props.messageDetail.bodyPreview || "正文为空。"}
                  </pre>
                )}
              </div>
            ) : (
              <div className="rounded-3xl border border-dashed border-white/10 px-4 py-16 text-center text-sm text-slate-400">
                还没有选中邮件。
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
