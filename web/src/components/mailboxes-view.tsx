import DOMPurify from "dompurify";
import { MailOpen, RefreshCw, Settings2 } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { StatusBadge } from "@/components/status-badge";
import type { MailboxMessageDetail, MailboxMessageSummary, MailboxRecord } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

function PaneHeader(props: {
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-white/8 px-4 py-4">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-white">{props.title}</h2>
        <p className="mt-1 text-xs text-slate-400">{props.description}</p>
      </div>
      {props.actions ? <div className="shrink-0">{props.actions}</div> : null}
    </div>
  );
}

function MetaRow(props: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 text-xs">
      <span className="text-slate-500">{props.label}</span>
      <span className="truncate text-right text-slate-300">{props.value}</span>
    </div>
  );
}

function MailboxListItem(props: {
  mailbox: MailboxRecord;
  selected: boolean;
  onSelect: () => void;
}) {
  const label = props.mailbox.graphDisplayName || props.mailbox.microsoftEmail;

  return (
    <button
      type="button"
      onClick={props.onSelect}
      className={cn(
        "w-full cursor-pointer rounded-xl border px-3 py-3 text-left transition-colors duration-200",
        props.selected
          ? "border-sky-400/35 bg-slate-900/95"
          : "border-white/8 bg-slate-950/40 hover:border-white/14 hover:bg-slate-900/70",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-white">{label}</div>
          <div className="mt-0.5 truncate text-xs text-slate-500">{props.mailbox.microsoftEmail}</div>
        </div>
        <div className="rounded-full border border-white/8 bg-white/[0.03] px-2 py-0.5 text-[11px] font-medium text-slate-300">
          {props.mailbox.unreadCount}
        </div>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <StatusBadge status={props.mailbox.status} />
        <Badge variant="neutral">{props.mailbox.isAuthorized ? "已授权" : "未授权"}</Badge>
        {props.mailbox.groupName ? <Badge variant="neutral">{props.mailbox.groupName}</Badge> : null}
      </div>

      <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
        <MetaRow label="同步" value={formatDate(props.mailbox.lastSyncedAt)} />
        <MetaRow label="授权" value={formatDate(props.mailbox.oauthConnectedAt)} />
      </div>

      {props.mailbox.lastErrorMessage ? (
        <div className="mt-2 truncate rounded-lg border border-rose-400/20 bg-rose-500/[0.06] px-2.5 py-1.5 text-[11px] text-rose-100">
          {props.mailbox.lastErrorMessage}
        </div>
      ) : null}
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
        "w-full cursor-pointer rounded-xl border px-3 py-3 text-left transition-colors duration-200",
        props.selected
          ? "border-sky-400/35 bg-slate-900/95"
          : "border-white/8 bg-slate-950/40 hover:border-white/14 hover:bg-slate-900/70",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-white">{props.message.subject || "(无主题)"}</div>
          <div className="mt-0.5 truncate text-xs text-slate-500">
            {props.message.fromName || props.message.fromAddress || "未知发件人"}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {!props.message.isRead ? <Badge variant="info">未读</Badge> : null}
          <span className="text-[11px] text-slate-500">{formatDate(props.message.receivedAt)}</span>
        </div>
      </div>
      <div className="mt-2 line-clamp-2 text-sm leading-5 text-slate-300">{props.message.bodyPreview || "无预览"}</div>
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
  syncingMailboxId: number | null;
  onOpenSettings: () => void;
  onSelectMailbox: (mailboxId: number) => void;
  onSyncMailbox: (mailboxId: number) => Promise<void>;
  onLoadMoreMessages: () => Promise<void>;
  onSelectMessage: (messageId: number) => Promise<void>;
}) {
  const sanitizedBody =
    props.messageDetail?.bodyContentType === "html"
      ? DOMPurify.sanitize(props.messageDetail.bodyContent, { USE_PROFILES: { html: true } })
      : null;
  const totalUnread = props.mailboxes.reduce((sum, mailbox) => sum + mailbox.unreadCount, 0);
  const selectedMailboxSyncing = props.selectedMailbox ? props.syncingMailboxId === props.selectedMailbox.id : false;
  const invalidatedCount = props.mailboxes.filter((mailbox) => mailbox.status === "invalidated").length;
  const lockedCount = props.mailboxes.filter((mailbox) => mailbox.status === "locked").length;

  return (
    <div className="space-y-4">
      <Card className="border-white/10 bg-slate-950/55 shadow-none">
        <CardContent className="space-y-3 p-4">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div className="min-w-0 space-y-1">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
                <MailOpen className="size-3.5" />
                Microsoft Mail
              </div>
              <h1 className="text-2xl font-semibold text-white">微软邮箱</h1>
              <p className="text-sm text-slate-400">
                这里只显示已经连通过的微软邮箱。Graph 接入参数单独放在设置页维护。
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={props.onOpenSettings}>
                <Settings2 className="size-4" />
                Graph 设置
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
          </div>

          <div className="flex flex-wrap items-center gap-2 border-t border-white/8 pt-3 text-xs">
            <Badge variant={props.settingsConfigured ? "success" : "warning"}>
              Graph {props.settingsConfigured ? "已配置" : "待配置"}
            </Badge>
            <Badge variant="neutral">邮箱 {props.mailboxes.length}</Badge>
            <Badge variant={totalUnread > 0 ? "info" : "neutral"}>未读 {totalUnread}</Badge>
            <Badge variant={invalidatedCount > 0 ? "warning" : "neutral"}>需重连 {invalidatedCount}</Badge>
            <Badge variant={lockedCount > 0 ? "danger" : "neutral"}>锁定 {lockedCount}</Badge>
            {props.selectedMailbox ? (
              <span className="ml-auto text-slate-500">
                当前账号 {props.selectedMailbox.graphDisplayName || props.selectedMailbox.microsoftEmail}
              </span>
            ) : null}
          </div>

          {!props.settingsConfigured ? (
            <div className="rounded-xl border border-amber-300/20 bg-amber-300/[0.06] px-3 py-2 text-sm text-amber-50">
              还没有保存 Microsoft Graph 凭据。先完成配置，再回到微软账号页发起连接。
            </div>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,380px)_minmax(0,1fr)]">
        <Card className="border-white/10 bg-slate-950/55 shadow-none">
          <PaneHeader
            title="邮箱账号"
            description="这里只展示已连通过的微软邮箱，连接入口统一放在微软账号页。"
            actions={
              props.selectedMailbox ? (
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void props.onSyncMailbox(props.selectedMailbox!.id)}
                    disabled={!props.selectedMailbox.isAuthorized || props.selectedMailbox.status === "locked" || props.syncingMailboxId === props.selectedMailbox.id}
                  >
                    {props.syncingMailboxId === props.selectedMailbox.id ? "刷新中…" : "刷新"}
                  </Button>
                </div>
              ) : null
            }
          />
          <CardContent className="p-0">
            <ScrollArea className="h-[68vh] px-3 py-3">
              <div className="space-y-2">
                {props.mailboxes.map((mailbox) => (
                  <MailboxListItem
                    key={mailbox.id}
                    mailbox={mailbox}
                    selected={props.selectedMailbox?.id === mailbox.id}
                    onSelect={() => props.onSelectMailbox(mailbox.id)}
                  />
                ))}
                {props.mailboxes.length === 0 ? (
                  <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
                    还没有已连接的微软邮箱。先回微软账号页完成连接。
                  </div>
                ) : null}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-slate-950/55 shadow-none">
          <PaneHeader
            title="Inbox"
            description={
              props.selectedMailbox ? `${props.selectedMailbox.microsoftEmail} · 共 ${props.messagesTotal} 封` : "先从左侧选择一个邮箱。"
            }
          />
          <CardContent className="p-0">
            <ScrollArea className="h-[68vh] px-3 py-3">
              <div className="space-y-2">
                {props.messages.map((message) => (
                  <MessageListItem
                    key={message.id}
                    message={message}
                    selected={props.selectedMessageId === message.id}
                    onSelect={() => void props.onSelectMessage(message.id)}
                  />
                ))}
                {props.messagesBusy ? (
                  <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-6 text-center text-sm text-slate-400">
                    正在读取邮件列表…
                  </div>
                ) : null}
                {!props.messagesBusy && props.selectedMailbox && props.messages.length === 0 ? (
                  <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-400">
                    当前邮箱还没有缓存邮件，可以先手动刷新。
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

        <Card className="border-white/10 bg-slate-950/55 shadow-none">
          <PaneHeader
            title="邮件内容"
            description={
              props.messageDetail
                ? `${props.messageDetail.fromName || props.messageDetail.fromAddress || "未知发件人"} · ${formatDate(props.messageDetail.receivedAt)}`
                : "选中邮件后，在这里查看正文。"
            }
          />
          <CardContent className="space-y-3 p-3">
            {props.messageBusy ? (
              <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-10 text-center text-sm text-slate-400">
                正在读取邮件正文…
              </div>
            ) : props.messageDetail ? (
              <div className="space-y-4">
                <div className="space-y-2 border-b border-white/8 pb-3">
                  <div className="text-lg font-semibold text-white">{props.messageDetail.subject || "(无主题)"}</div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={props.messageDetail.isRead ? "neutral" : "info"}>
                      {props.messageDetail.isRead ? "已读" : "未读"}
                    </Badge>
                    {props.messageDetail.hasAttachments ? <Badge variant="warning">含附件</Badge> : null}
                    {props.messageDetail.webLink ? <Badge variant="neutral">Outlook Web</Badge> : null}
                  </div>
                  <div className="grid gap-1 text-xs text-slate-400 md:grid-cols-2">
                    <MetaRow
                      label="发件人"
                      value={props.messageDetail.fromName || props.messageDetail.fromAddress || "未知发件人"}
                    />
                    <MetaRow label="收件时间" value={formatDate(props.messageDetail.receivedAt)} />
                  </div>
                </div>

                {props.messageDetail.bodyContentType === "html" ? (
                  <div
                    className="prose prose-invert max-w-none px-1 py-1 prose-a:text-sky-300 prose-p:text-slate-200 prose-strong:text-white"
                    dangerouslySetInnerHTML={{ __html: sanitizedBody || "" }}
                  />
                ) : (
                  <pre className="whitespace-pre-wrap px-1 py-1 font-sans text-sm leading-6 text-slate-200">
                    {props.messageDetail.bodyContent || props.messageDetail.bodyPreview || "正文为空。"}
                  </pre>
                )}
              </div>
            ) : (
              <div className="rounded-2xl border border-dashed border-white/10 px-4 py-16 text-center text-sm text-slate-400">
                还没有选中邮件。
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
