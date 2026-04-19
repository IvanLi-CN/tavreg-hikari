import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { MailboxesView } from "@/components/mailboxes-view";
import type { MailboxMessageDetail, MailboxMessageSummary, MailboxRecord } from "@/lib/app-types";

export function MailboxDrawer(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
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
  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent
        className="top-0 right-0 left-auto grid h-dvh w-[min(96vw,96rem)] translate-x-0 translate-y-0 gap-0 rounded-none border-y-0 border-r-0 border-l border-white/12 p-0"
      >
        <DialogHeader className="sr-only">
          <DialogTitle>
            {props.selectedMailbox ? `${props.selectedMailbox.microsoftEmail} 收件箱` : "Microsoft 收件箱"}
          </DialogTitle>
        </DialogHeader>

        <div className="h-full overflow-y-auto p-4 md:p-5">
          <MailboxesView
            settingsConfigured={props.settingsConfigured}
            mailboxes={props.mailboxes}
            selectedMailbox={props.selectedMailbox}
            messages={props.messages}
            messagesTotal={props.messagesTotal}
            messagesHasMore={props.messagesHasMore}
            messagesBusy={props.messagesBusy}
            selectedMessageId={props.selectedMessageId}
            messageDetail={props.messageDetail}
            messageBusy={props.messageBusy}
            syncingMailboxId={props.syncingMailboxId}
            onOpenSettings={props.onOpenSettings}
            onSelectMailbox={props.onSelectMailbox}
            onSyncMailbox={props.onSyncMailbox}
            onLoadMoreMessages={props.onLoadMoreMessages}
            onSelectMessage={props.onSelectMessage}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
