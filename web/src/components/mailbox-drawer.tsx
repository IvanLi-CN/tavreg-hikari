import DOMPurify from "dompurify";
import { ChevronLeft, Inbox, KeyRound, RefreshCw } from "lucide-react";
import { useEffect, useState, type KeyboardEvent as ReactKeyboardEvent, type SyntheticEvent } from "react";
import { CopyIconButton, type CopyButtonStatus } from "@/components/ui/copy-icon-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { AccountRecord, MailboxMessageDetail, MailboxMessageSummary, MailboxRecord } from "@/lib/app-types";
import { copyTextToClipboard } from "@/lib/clipboard";
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

function handleSelectableRowKeyDown(event: ReactKeyboardEvent<HTMLElement>, onSelect: () => void) {
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  onSelect();
}

function stopSelectableRowEvent(event: SyntheticEvent<HTMLElement>) {
  event.stopPropagation();
}

function MessageListItem(props: {
  message: MailboxMessageSummary;
  selected: boolean;
  onSelect: () => void;
  verificationCopyStatus: CopyButtonStatus;
  onCopyVerificationCode: (anchorElement: HTMLElement) => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={props.onSelect}
      onKeyDown={(event) => handleSelectableRowKeyDown(event, props.onSelect)}
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
          {props.message.verificationCode ? (
            <div onClick={stopSelectableRowEvent} onKeyDown={stopSelectableRowEvent}>
              <CopyIconButton
                label={`${props.message.subject || "邮件"} 验证码`}
                copyStatus={props.verificationCopyStatus}
                onCopy={props.onCopyVerificationCode}
                size="dense"
                idleIcon={<KeyRound className="size-4" aria-hidden="true" />}
                feedbackSubject="验证码"
                feedbackValue={props.message.verificationCode.code}
                successMessage="验证码已复制"
              />
            </div>
          ) : null}
          {!props.message.isRead ? <Badge variant="info">未读</Badge> : null}
          <span className="text-[11px] text-slate-500">{formatDate(props.message.receivedAt)}</span>
        </div>
      </div>
      <div className="mt-2 line-clamp-2 text-sm leading-5 text-slate-300">{props.message.bodyPreview || "无预览"}</div>
    </div>
  );
}

function resolveMailboxStateDescription(account: AccountRecord | null, mailbox: MailboxRecord | null, settingsConfigured: boolean): string {
  if (!settingsConfigured) {
    return "Microsoft Graph 还未配置，暂时无法读取该账号的邮箱内容。";
  }
  if (!mailbox) {
    return account ? "当前微软账号还没有绑定可读取的邮箱。先完成 Bootstrap，再回来查看邮件内容。" : "当前账号还没有绑定可读取的邮箱。";
  }
  if (!mailbox.isAuthorized) {
    return "当前邮箱尚未完成授权，请先完成 Microsoft 邮箱接入。";
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
  copyFeedbackAutoDismissMs?: number | null;
  copyPreviewStatus?: Partial<Record<"displayName" | "email", CopyButtonStatus>>;
  onLoadMoreMessages: () => Promise<void>;
  onSelectMessage: (messageId: number) => Promise<void>;
}) {
  const [copyStatus, setCopyStatus] = useState<Record<"displayName" | "email", CopyButtonStatus>>({
    displayName: "idle",
    email: "idle",
  });
  const [verificationCopyStatus, setVerificationCopyStatus] = useState<Record<string, CopyButtonStatus>>({});
  const [feedbackPortalContainer, setFeedbackPortalContainer] = useState<HTMLDivElement | null>(null);
  const [isCompactLayout, setIsCompactLayout] = useState(() => (typeof window !== "undefined" ? window.matchMedia("(max-width: 1023px)").matches : false));
  const [compactPane, setCompactPane] = useState<"list" | "detail">("list");
  const sanitizedBody =
    props.messageDetail?.bodyContentType === "html"
      ? DOMPurify.sanitize(props.messageDetail.bodyContent, { USE_PROFILES: { html: true } })
      : null;
  const canRefresh = Boolean(props.mailbox?.isAuthorized && props.mailbox.status !== "locked");
  const showMailboxState = !props.mailbox || !props.mailbox.isAuthorized || props.mailbox.status !== "available" || !props.settingsConfigured;
  const stateDescription = resolveMailboxStateDescription(props.account, props.mailbox, props.settingsConfigured);
  const accountDisplayName = props.mailbox?.graphDisplayName || props.account?.microsoftEmail || "当前账号";
  const mailboxLabel = props.mailbox?.microsoftEmail || props.account?.microsoftEmail || "未绑定邮箱";
  const lastUpdatedText = props.mailbox?.lastSyncedAt ? formatDate(props.mailbox.lastSyncedAt) : "尚未同步";
  const effectiveCopyStatus = {
    displayName: props.copyPreviewStatus?.displayName ?? copyStatus.displayName,
    email: props.copyPreviewStatus?.email ?? copyStatus.email,
  } satisfies Record<"displayName" | "email", CopyButtonStatus>;
  useEffect(() => {
    if (typeof window === "undefined") return;
    const mediaQuery = window.matchMedia("(max-width: 1023px)");
    const handleChange = (event: MediaQueryListEvent | MediaQueryList) => {
      setIsCompactLayout(event.matches);
    };
    handleChange(mediaQuery);
    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handleChange);
      return () => mediaQuery.removeEventListener("change", handleChange);
    }
    mediaQuery.addListener(handleChange);
    return () => mediaQuery.removeListener(handleChange);
  }, []);

  useEffect(() => {
    if (!props.open) {
      setCompactPane("list");
      return;
    }
    if (!isCompactLayout) return;
    if (showMailboxState) {
      setCompactPane("list");
    }
  }, [isCompactLayout, props.open, showMailboxState, props.mailbox?.id]);

  const handleCopyValue = async (field: "displayName" | "email", value: string, _anchorElement: HTMLElement) => {
    if (!value.trim()) {
      setCopyStatus((current) => ({ ...current, [field]: "failed" }));
      return;
    }
    try {
      await copyTextToClipboard(value);
      setCopyStatus((current) => ({ ...current, [field]: "copied" }));
    } catch {
      setCopyStatus((current) => ({ ...current, [field]: "failed" }));
    }
    window.setTimeout(() => {
      setCopyStatus((current) => (current[field] === "idle" ? current : { ...current, [field]: "idle" }));
    }, 1800);
  };

  const handleSelectMessage = async (messageId: number) => {
    await props.onSelectMessage(messageId);
    if (isCompactLayout) {
      setCompactPane("detail");
    }
  };

  const getVerificationCopyStatus = (key: string): CopyButtonStatus => verificationCopyStatus[key] || "idle";

  const handleCopyVerificationCode = async (key: string, code: string) => {
    try {
      await copyTextToClipboard(code);
      setVerificationCopyStatus((current) => ({ ...current, [key]: "copied" }));
    } catch {
      setVerificationCopyStatus((current) => ({ ...current, [key]: "failed" }));
    }
    window.setTimeout(() => {
      setVerificationCopyStatus((current) => (current[key] ? { ...current, [key]: "idle" } : current));
    }, 1800);
  };

  const listPane = (
    <Card className="min-h-0 border-white/10 bg-slate-950/55 shadow-none">
      <CardHeader className="border-b border-white/8 px-4 py-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <div className="flex items-center gap-1">
              <CardTitle className="truncate text-sm font-semibold text-white">{accountDisplayName}</CardTitle>
              <CopyIconButton
                label={`${accountDisplayName} 用户名`}
                copyStatus={effectiveCopyStatus.displayName}
                forceFeedbackOpen={props.copyPreviewStatus?.displayName != null}
                feedbackValue={accountDisplayName}
                feedbackSubject="用户名"
                autoDismissMs={props.copyFeedbackAutoDismissMs}
                size="dense"
                feedbackPortalContainer={feedbackPortalContainer}
                onCopy={(anchorElement) => void handleCopyValue("displayName", accountDisplayName, anchorElement)}
              />
            </div>
            <div className="flex items-center gap-1">
              <p className="truncate text-xs text-slate-400">{mailboxLabel}</p>
              <CopyIconButton
                label={`${mailboxLabel} 邮箱`}
                copyStatus={effectiveCopyStatus.email}
                forceFeedbackOpen={props.copyPreviewStatus?.email != null}
                feedbackValue={mailboxLabel}
                feedbackSubject="邮箱地址"
                autoDismissMs={props.copyFeedbackAutoDismissMs}
                size="dense"
                feedbackPortalContainer={feedbackPortalContainer}
                onCopy={(anchorElement) => void handleCopyValue("email", mailboxLabel, anchorElement)}
              />
              {props.mailbox?.latestVerificationCode ? (
                <CopyIconButton
                  label={`${mailboxLabel} 最新验证码`}
                  copyStatus={getVerificationCopyStatus(`mailbox:${props.mailbox.id}`)}
                  feedbackSubject="验证码"
                  feedbackValue={props.mailbox.latestVerificationCode.code}
                  successMessage="验证码已复制"
                  size="dense"
                  idleIcon={<KeyRound className="size-4" aria-hidden="true" />}
                  feedbackPortalContainer={feedbackPortalContainer}
                  onCopy={() => void handleCopyVerificationCode(`mailbox:${props.mailbox!.id}`, props.mailbox!.latestVerificationCode!.code)}
                />
              ) : null}
            </div>
            <p className="text-[11px] text-slate-500">{props.mailbox ? `共 ${props.messagesTotal} 封 · ` : ""}最后更新：{lastUpdatedText}</p>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              if (props.mailbox) {
                void props.onSyncMailbox(props.mailbox.id);
              }
            }}
            disabled={!props.mailbox || !canRefresh || props.syncingMailboxId === props.mailbox.id}
          >
            <RefreshCw className={cn("size-4", props.mailbox && props.syncingMailboxId === props.mailbox.id ? "animate-spin" : "")} />
            {props.mailbox && props.syncingMailboxId === props.mailbox.id ? "刷新中" : "刷新"}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="min-h-0 flex-1 p-0">
        <ScrollArea className="h-full px-3 py-3">
          {showMailboxState ? (
            <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-sm text-slate-300">
              <div className="flex items-center gap-2 text-white">
                <Inbox className="size-4" />
                当前邮箱状态
              </div>
              <p className="mt-3 leading-6 text-slate-400">{stateDescription}</p>
            </div>
          ) : (
            <div className="space-y-2">
              {props.messages.map((message) => (
                <MessageListItem
                  key={message.id}
                  message={message}
                  selected={props.selectedMessageId === message.id}
                  onSelect={() => void handleSelectMessage(message.id)}
                  verificationCopyStatus={getVerificationCopyStatus(`message:${message.id}`)}
                  onCopyVerificationCode={() => {
                    if (message.verificationCode) {
                      void handleCopyVerificationCode(`message:${message.id}`, message.verificationCode.code);
                    }
                  }}
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
  );

  const detailPane = (
    <Card className="min-h-0 border-white/10 bg-slate-950/55 shadow-none">
      <CardHeader className="border-b border-white/8 px-4 py-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="text-sm font-semibold text-white">邮件内容</CardTitle>
            <p className="mt-1 text-xs text-slate-400">
              {props.messageDetail
                ? `${props.messageDetail.fromName || props.messageDetail.fromAddress || "未知发件人"} · ${formatDate(props.messageDetail.receivedAt)}`
                : showMailboxState
                  ? "当前账号暂无可展示正文。"
                  : "选中邮件后，在这里查看正文。"}
            </p>
          </div>
          {isCompactLayout && !showMailboxState ? (
            <Button size="sm" variant="ghost" onClick={() => setCompactPane("list")}>
              <ChevronLeft className="size-4" />
              返回列表
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="min-h-0 space-y-3 overflow-y-auto p-3">
        {props.messageBusy ? (
          <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-10 text-center text-sm text-slate-400">
            正在读取邮件正文…
          </div>
        ) : props.messageDetail ? (
          <div className="space-y-4">
              <div className="space-y-2 border-b border-white/8 pb-3">
              <div className="flex items-start justify-between gap-3">
                <div className="text-lg font-semibold text-white">{props.messageDetail.subject || "(无主题)"}</div>
                {props.messageDetail.verificationCode ? (
                  <CopyIconButton
                    label={`${props.messageDetail.subject || "邮件"} 验证码`}
                    copyStatus={getVerificationCopyStatus(`detail:${props.messageDetail.id}`)}
                    feedbackSubject="验证码"
                    feedbackValue={props.messageDetail.verificationCode.code}
                    successMessage="验证码已复制"
                    size="dense"
                    idleIcon={<KeyRound className="size-4" aria-hidden="true" />}
                    feedbackPortalContainer={feedbackPortalContainer}
                    onCopy={() => void handleCopyVerificationCode(`detail:${props.messageDetail!.id}`, props.messageDetail!.verificationCode!.code)}
                  />
                ) : null}
              </div>
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
  );

  return (
    <Sheet open={props.open} onOpenChange={props.onOpenChange}>
      <SheetContent side="right" className="p-0">
        <SheetHeader className="sr-only">
          <SheetTitle>{props.mailbox ? `${props.mailbox.microsoftEmail} 收件箱` : "Microsoft 收件箱"}</SheetTitle>
        </SheetHeader>

        <div ref={setFeedbackPortalContainer} className="flex h-full min-h-0 flex-col p-4 md:p-5">
          {isCompactLayout && !showMailboxState ? (
            <div className="mb-4 flex items-center gap-2 lg:hidden">
              <Button
                size="sm"
                variant={compactPane === "list" ? "default" : "outline"}
                onClick={() => setCompactPane("list")}
              >
                邮件列表
              </Button>
              <Button
                size="sm"
                variant={compactPane === "detail" ? "default" : "outline"}
                onClick={() => setCompactPane("detail")}
                disabled={!props.selectedMessageId && !props.messageDetail}
              >
                邮件内容
              </Button>
            </div>
          ) : null}

          {isCompactLayout ? (
            <div className="min-h-0 flex-1">
              {compactPane === "detail" && !showMailboxState ? detailPane : listPane}
            </div>
          ) : (
            <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
              {listPane}
              {detailPane}
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
