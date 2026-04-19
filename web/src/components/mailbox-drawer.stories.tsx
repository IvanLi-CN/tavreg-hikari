import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, within } from "storybook/test";
import { MailboxDrawer } from "@/components/mailbox-drawer";
import type { MailboxRecord } from "@/lib/app-types";
import { sampleMailboxMessageDetail, sampleMailboxMessages, sampleMailboxes } from "@/stories/fixtures";

function MailboxDrawerStorySurface(props?: {
  mailboxes?: MailboxRecord[];
  initialMailboxId?: number | null;
  settingsConfigured?: boolean;
}) {
  const mailboxes = props?.mailboxes || sampleMailboxes;
  const [selectedMailboxId, setSelectedMailboxId] = useState<number | null>(props?.initialMailboxId ?? mailboxes[0]?.id ?? null);
  const selectedMailbox = useMemo(
    () => mailboxes.find((mailbox) => mailbox.id === selectedMailboxId) || null,
    [mailboxes, selectedMailboxId],
  );

  return (
    <MailboxDrawer
      open
      onOpenChange={() => undefined}
      settingsConfigured={props?.settingsConfigured ?? true}
      mailboxes={mailboxes}
      selectedMailbox={selectedMailbox}
      messages={selectedMailbox?.status === "available" ? sampleMailboxMessages : []}
      messagesTotal={selectedMailbox?.status === "available" ? sampleMailboxMessages.length : 0}
      messagesHasMore={false}
      messagesBusy={false}
      selectedMessageId={selectedMailbox?.status === "available" ? sampleMailboxMessages[0]?.id ?? null : null}
      messageDetail={selectedMailbox?.status === "available" ? sampleMailboxMessageDetail : null}
      messageBusy={false}
      syncingMailboxId={null}
      onOpenSettings={() => undefined}
      onSelectMailbox={setSelectedMailboxId}
      onSyncMailbox={async () => undefined}
      onLoadMoreMessages={async () => undefined}
      onSelectMessage={async () => undefined}
    />
  );
}

const meta = {
  title: "Views/MailboxDrawer",
  component: MailboxDrawer,
  tags: ["autodocs"],
  args: {
    open: true,
    onOpenChange: () => undefined,
    settingsConfigured: true,
    mailboxes: sampleMailboxes,
    selectedMailbox: sampleMailboxes[0] ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    messagesHasMore: false,
    messagesBusy: false,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
    messageBusy: false,
    syncingMailboxId: null,
    onOpenSettings: () => undefined,
    onSelectMailbox: () => undefined,
    onSyncMailbox: async () => undefined,
    onLoadMoreMessages: async () => undefined,
    onSelectMessage: async () => undefined,
  },
  parameters: {
    docs: {
      description: {
        component: "Microsoft 模块内的信箱抽屉，复用现有 mailbox 工作区并绑定到当前账号上下文。",
      },
    },
  },
} satisfies Meta<typeof MailboxDrawer>;

export default meta;
type Story = StoryObj<typeof meta>;

export const AvailableMailbox: Story = {
  render: () => <MailboxDrawerStorySurface initialMailboxId={sampleMailboxes.find((mailbox) => mailbox.status === "available")?.id || null} />,
};

export const InvalidatedMailbox: Story = {
  render: () => <MailboxDrawerStorySurface initialMailboxId={sampleMailboxes.find((mailbox) => mailbox.status === "invalidated")?.id || null} />,
};

export const EmptyState: Story = {
  render: () => <MailboxDrawerStorySurface mailboxes={[]} initialMailboxId={null} settingsConfigured={false} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("还没有已完成 Bootstrap 的微软邮箱。先回微软账号页完成 Bootstrap。")).toBeInTheDocument();
  },
};
