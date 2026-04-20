import DOMPurify from "dompurify";
import { Inbox, MailOpen, RefreshCw, Settings2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { StatusBadge } from "@/components/status-badge";
import type { AccountRecord, MailboxMessageDetail, MailboxMessageSummary, MailboxRecord } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

function MetaRow(props: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 text-xs">
      <span className="text-slate-500">{props.label}</span>
      <span className="truncate text-right text-slate-300">{props.value}</span>
    </div>
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

function resolveMailboxStateDescription(account: AccountRecord | null, mailbox: MailboxRecord | null): string {
  if (!mailbox) {
    return account ? "当前微软账号还没有绑定可读取的邮箱。先完成 Bootstrap，再回来查看邮件内容。" : "当前账号还没有绑定可读取的邮箱。";
  }
  if (!mailbox.isAuthorized) {
    return "当前邮箱尚未完成 Graph 授权，请先进入 Graph 设置完成接入。";
  }
  if (mailbox.status === "invalidated") {
    return mailbox.lastErrorMessage || "当前邮箱授权已失效，需要重新连接后才能继续读取邮件。";
  }
  if (mailbox.status === "locked") {
    return mailbox.lastErrorMessage || "当前邮箱处于锁定状态，暂时无法同步或读取邮件。";
  }
  if (mailbox.status === "preparing") {
    return "当前邮箱仍在准备中，首次同步完成后这里会显示邮件列表与正文。";
  }
  return "当前邮箱可用。";
}

export function MailboxDrawer(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  settingsConfigured: boolean;
  account: AccountRecord | null;
  mailbox: MailboxRecord | null;
  messages: MailboxMessageSummary[];
  messagesTotal: number;
  messagesHasMore: boolean;
  messagesBusy: boolean;
  selectedMessageId: number | null;
  messageDetail: MailboxMessageDetail | null;
  messageBusy: boolean;
  syncingMailboxId: number | null;
  onOpenSettings: () => void;
  onSyncMailbox: (mailboxId: number) => Promise<void>;
  onLoadMoreMessages: () => Promise<void>;
  onSelectMessage: (messageId: number) => Promise<void>;
}) {
  const sanitizedBody =
    props.messageDetail?.bodyContentType === "html"
      ? DOMPurify.sanitize(props.messageDetail.bodyContent, { USE_PROFILES: { html: true } })
      : null;
  const title = props.mailbox?.graphDisplayName || props.account?.microsoftEmail || props.mailbox?.microsoftEmail || "微软邮箱";
  const canRefresh = Boolean(props.mailbox?.isAuthorized && props.mailbox.status !== "locked");
  const showMailboxState = !props.mailbox || !props.mailbox.isAuthorized || props.mailbox.status !== "available";
  const stateDescription = resolveMailboxStateDescription(props.account, props.mailbox);

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="top-0 right-0 left-auto grid h-dvh w-[min(96vw,84rem)] translate-x-0 translate-y-0 gap-0 rounded-none border-y-0 border-r-0 border-l border-white/12 p-0">
        <DialogHeader className="sr-only">
          <DialogTitle>{props.mailbox ? `${props.mailbox.microsoftEmail} 收件箱` : "Microsoft 收件箱"}</DialogTitle>
        </DialogHeader>

        <div className="h-full overflow-y-auto p-4 md:p-5">
          <div className="space-y-4">
            <Card className="border-white/10 bg-slate-950/55 shadow-none">
              <CardContent className="space-y-3 p-4">
                <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
                      <MailOpen className="size-3.5" />
                      Microsoft Mail
                    </div>
                    <h1 className="text-2xl font-semibold text-white">{title}</h1>
                    <p className="text-sm text-slate-400">
                      这里直接聚焦当前微软账号的单个信箱，只显示该信箱的邮件列表与邮件正文。
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" onClick={props.onOpenSettings}>
                      <Settings2 className="size-4" />
                      Graph 设置
                    </Button>
                    <Button
                      onClick={() => {
                        if (props.mailbox) {
                          void props.onSyncMailbox(props.mailbox.id);
                        }
                      }}
                      disabled={!props.mailbox || !canRefresh || props.syncingMailboxId === props.mailbox.id}
                    >
                      <RefreshCw className={cn("size-4", props.mailbox && props.syncingMailboxId === props.mailbox.id ? "animate-spin" : "")} />
                      {props.mailbox && props.syncingMailboxId === props.mailbox.id ? "刷新中…" : "刷新当前邮箱"}
                    </Button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 border-t border-white/8 pt-3 text-xs">
                  <Badge variant={props.settingsConfigured ? "success" : "warning"}>
                    Graph {props.settingsConfigured ? "已配置" : "待配置"}
                  </Badge>
                  {props.mailbox ? <StatusBadge status={props.mailbox.status} /> : <Badge variant="neutral">未绑定邮箱</Badge>}
                  {props.mailbox ? <Badge variant={props.mailbox.isAuthorized ? "neutral" : "warning"}>{props.mailbox.isAuthorized ? "已授权" : "未授权"}</Badge> : null}
                  {props.mailbox ? <Badge variant={props.mailbox.unreadCount > 0 ? "info" : "neutral"}>未读 {props.mailbox.unreadCount}</Badge> : null}
                  <span className="ml-auto truncate text-slate-500">当前账号 {props.account?.microsoftEmail || props.mailbox?.microsoftEmail || "未匹配"}</span>
                </div>

                {!props.settingsConfigured ? (
                  <div className="rounded-xl border border-amber-300/20 bg-amber-300/[0.06] px-3 py-2 text-sm text-amber-50">
                    还没有保存 Microsoft Graph 凭据。先完成配置，再回来查看该账号的信箱内容。
                  </div>
                ) : null}
              </CardContent>
            </Card>

            <div className="grid gap-4 xl:grid-cols-[minmax(0,380px)_minmax(0,1fr)]">
              <Card className="border-white/10 bg-slate-950/55 shadow-none">
                <CardHeader className="border-b border-white/8 px-4 py-4">
                  <CardTitle className="text-sm font-semibold text-white">Inbox</CardTitle>
                  <p className="text-xs text-slate-400">
                    {props.mailbox
                      ? `${props.mailbox.microsoftEmail} · 共 ${props.messagesTotal} 封`
                      : `${props.account?.microsoftEmail || "当前账号"} · 暂无可读取邮箱`}
                  </p>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[68vh] px-3 py-3">
                    {showMailboxState ? (
                      <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-sm text-slate-300">
                        <div className="flex items-center gap-2 text-white">
                          <Inbox className="size-4" />
                          当前邮箱状态
                        </div>
                        <p className="mt-3 leading-6 text-slate-400">{stateDescription}</p>
                        {props.mailbox?.lastSyncedAt ? <p className="mt-3 text-xs text-slate-500">最近同步：{formatDate(props.mailbox.lastSyncedAt)}</p> : null}
                      </div>
                    ) : (
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
                        {!props.messagesBusy && props.mailbox && props.messages.length === 0 ? (
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
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card className="border-white/10 bg-slate-950/55 shadow-none">
                <CardHeader className="border-b border-white/8 px-4 py-4">
                  <CardTitle className="text-sm font-semibold text-white">邮件内容</CardTitle>
                  <p className="text-xs text-slate-400">
                    {props.messageDetail
                      ? `${props.messageDetail.fromName || props.messageDetail.fromAddress || "未知发件人"} · ${formatDate(props.messageDetail.receivedAt)}`
                      : showMailboxState
                        ? "当前账号暂无可展示正文。"
                        : "选中邮件后，在这里查看正文。"}
                  </p>
                </CardHeader>
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
                          <MetaRow label="发件人" value={props.messageDetail.fromName || props.messageDetail.fromAddress || "未知发件人"} />
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
                      {showMailboxState ? stateDescription : "还没有选中邮件。"}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
