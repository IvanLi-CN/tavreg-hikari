import DOMPurify from "dompurify";
import { MailOpen, RefreshCw, Settings2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { StatusBadge } from "@/components/status-badge";
import type { MailboxMessageDetail, MailboxMessageSummary, MailboxRecord } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

function MailboxListItem(props: {
  mailbox: MailboxRecord;
  selected: boolean;
  settingsConfigured: boolean;
  connecting: boolean;
  syncing: boolean;
  onSelect: () => void;
  onConnect: () => void;
  onSync: () => void;
}) {
  const label = props.mailbox.graphDisplayName || props.mailbox.microsoftEmail;
  const connectDisabled = !props.settingsConfigured || props.connecting;

  return (
    <button
      type="button"
      onClick={props.onSelect}
      className={cn(
        "w-full rounded-[28px] border px-4 py-4 text-left transition",
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
        <Badge variant="neutral">{props.mailbox.isAuthorized ? "已连接" : "待连接"}</Badge>
        {props.mailbox.groupName ? <Badge variant="neutral">{props.mailbox.groupName}</Badge> : null}
      </div>

      <div className="mt-4 grid gap-2 text-xs text-slate-400">
        <div className="flex items-center justify-between gap-3">
          <span>最近同步</span>
          <span className="text-right text-slate-200">{formatDate(props.mailbox.lastSyncedAt)}</span>
        </div>
        <div className="flex items-center justify-between gap-3">
          <span>授权时间</span>
          <span className="text-right text-slate-200">{formatDate(props.mailbox.oauthConnectedAt)}</span>
        </div>
      </div>

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
          disabled={connectDisabled}
        >
          {props.connecting
            ? "跳转中…"
            : !props.settingsConfigured
              ? "先配 Graph"
              : props.mailbox.isAuthorized
                ? "重新授权"
                : "连接邮箱"}
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
        "w-full rounded-[28px] border px-4 py-4 text-left transition",
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
  settingsConfigured: boolean;
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
  onOpenSettings: () => void;
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
  const totalUnread = props.mailboxes.reduce((sum, mailbox) => sum + mailbox.unreadCount, 0);
  const selectedLabel = props.selectedMailbox?.graphDisplayName || props.selectedMailbox?.microsoftEmail || null;
  const selectedMailboxSyncing = props.selectedMailbox ? props.syncingMailboxId === props.selectedMailbox.id : false;

  return (
    <div className="space-y-6">
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <Card className="border-white/10 bg-[linear-gradient(180deg,rgba(6,19,33,0.94),rgba(6,19,33,0.78))]">
          <CardContent className="space-y-5 p-6 md:p-7">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/[0.08] px-3 py-1 text-[0.68rem] uppercase tracking-[0.22em] text-cyan-100">
              <MailOpen className="size-3.5" />
              Inbox Workspace
            </div>
            <div className="space-y-3">
              <h2 className="text-3xl font-semibold tracking-tight text-white">微软邮箱工作台</h2>
              <p className="max-w-3xl text-sm leading-6 text-slate-300">
                这里现在只保留邮箱切换、授权连接、刷新和读信。Graph 凭据已经拆到独立设置页，主界面不会再被大表单打断。
              </p>
            </div>
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant={props.settingsConfigured ? "success" : "warning"}>
                {props.settingsConfigured ? "Graph 已配置" : "Graph 待配置"}
              </Badge>
              <Badge variant="neutral">{props.mailboxes.length} 个邮箱</Badge>
              <Badge variant={totalUnread > 0 ? "info" : "neutral"}>{totalUnread} 未读</Badge>
              {selectedLabel ? <Badge variant="neutral">当前 {selectedLabel}</Badge> : null}
            </div>
            {!props.settingsConfigured ? (
              <div className="rounded-[24px] border border-amber-300/20 bg-amber-300/[0.08] px-4 py-3 text-sm text-amber-50">
                还没有保存 Microsoft Graph 凭据。先去设置页完成配置，再为具体账号发起连接。
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardContent className="flex h-full flex-col justify-between gap-4 p-6">
            <div className="space-y-3">
              <div className="inline-flex size-10 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] text-sky-200">
                <Settings2 className="size-4" />
              </div>
              <div>
                <div className="text-lg font-semibold text-white">设置独立管理</div>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Client ID、Client Secret、Redirect URI 和 authority 都在单独页面里维护。
                </p>
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <Button variant="outline" onClick={props.onOpenSettings}>
                <Settings2 className="size-4" />
                打开 Graph 设置
              </Button>
              <Button
                onClick={() => {
                  if (props.selectedMailbox) {
                    void props.onSyncMailbox(props.selectedMailbox.id);
                  }
                }}
                disabled={!props.selectedMailbox?.isAuthorized || selectedMailboxSyncing}
              >
                <RefreshCw className={cn("size-4", selectedMailboxSyncing ? "animate-spin" : "")} />
                {selectedMailboxSyncing ? "刷新中…" : "刷新当前邮箱"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </section>

      <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,360px)_minmax(0,1fr)]">
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle>邮箱账号</CardTitle>
            <CardDescription>每个导入账号都会自动纳入收信模块。</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[68vh] px-4 pb-4">
              <div className="space-y-3">
                {props.mailboxes.map((mailbox) => (
                  <MailboxListItem
                    key={mailbox.id}
                    mailbox={mailbox}
                    selected={props.selectedMailbox?.id === mailbox.id}
                    settingsConfigured={props.settingsConfigured}
                    connecting={props.connectingMailboxId === mailbox.id}
                    syncing={props.syncingMailboxId === mailbox.id}
                    onSelect={() => props.onSelectMailbox(mailbox.id)}
                    onConnect={() => void props.onConnectMailbox(mailbox.id)}
                    onSync={() => void props.onSyncMailbox(mailbox.id)}
                  />
                ))}
                {props.mailboxes.length === 0 ? (
                  <div className="rounded-[28px] border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
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
            <ScrollArea className="h-[68vh] px-4 pb-4">
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
                  <div className="rounded-[28px] border border-white/8 bg-white/[0.03] px-4 py-6 text-center text-sm text-slate-400">
                    正在读取邮件列表…
                  </div>
                ) : null}
                {!props.messagesBusy && props.selectedMailbox && props.messages.length === 0 ? (
                  <div className="rounded-[28px] border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
                    这个邮箱还没有缓存邮件。可以先点左侧或右上的“刷新”。
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
              <div className="rounded-[28px] border border-white/8 bg-white/[0.03] px-4 py-10 text-center text-sm text-slate-400">
                正在读取邮件正文…
              </div>
            ) : props.messageDetail ? (
              <div className="space-y-5">
                <div className="rounded-[28px] border border-white/8 bg-slate-950/40 px-5 py-4">
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
                    className="prose prose-invert max-w-none rounded-[28px] border border-white/8 bg-slate-950/30 px-6 py-5 prose-a:text-cyan-300 prose-p:text-slate-200 prose-strong:text-white"
                    dangerouslySetInnerHTML={{ __html: sanitizedBody || "" }}
                  />
                ) : (
                  <pre className="whitespace-pre-wrap rounded-[28px] border border-white/8 bg-slate-950/30 px-6 py-5 font-sans text-sm text-slate-200">
                    {props.messageDetail.bodyContent || props.messageDetail.bodyPreview || "正文为空。"}
                  </pre>
                )}
              </div>
            ) : (
              <div className="rounded-[28px] border border-dashed border-white/10 px-4 py-16 text-center text-sm text-slate-400">
                还没有选中邮件。
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
