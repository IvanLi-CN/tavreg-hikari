import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { MailboxesView } from "@/components/mailboxes-view";
import type { MailboxMessageDetail, MailboxRecord } from "@/lib/app-types";
import { sampleMailboxMessageDetail, sampleMailboxMessages, sampleMailboxes } from "@/stories/fixtures";

function MailboxesStorySurface(props?: {
  selectedMailboxId?: number;
  selectedMessageId?: number;
  messageDetail?: MailboxMessageDetail | null;
  mailboxes?: MailboxRecord[];
  settingsConfigured?: boolean;
}) {
  const [selectedMailboxId, setSelectedMailboxId] = useState(props?.selectedMailboxId || sampleMailboxes[1]!.id);
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(props?.selectedMessageId || sampleMailboxMessages[0]!.id);
  const activeMailbox = (props?.mailboxes || sampleMailboxes).find((mailbox) => mailbox.id === selectedMailboxId) || null;

  return (
    <MailboxesView
      settingsConfigured={props?.settingsConfigured ?? true}
      mailboxes={props?.mailboxes || sampleMailboxes}
      selectedMailbox={activeMailbox}
      messages={sampleMailboxMessages}
      messagesTotal={sampleMailboxMessages.length}
      messagesHasMore={false}
      messagesBusy={false}
      selectedMessageId={selectedMessageId}
      messageDetail={props?.messageDetail === undefined ? sampleMailboxMessageDetail : props.messageDetail}
      messageBusy={false}
      connectingMailboxId={null}
      syncingMailboxId={null}
      onOpenSettings={fn()}
      onSelectMailbox={(mailboxId) => setSelectedMailboxId(mailboxId)}
      onConnectMailbox={fn(async () => undefined)}
      onSyncMailbox={fn(async () => undefined)}
      onLoadMoreMessages={fn(async () => undefined)}
      onSelectMessage={async (messageId) => {
        setSelectedMessageId(messageId);
      }}
    />
  );
}

const meta = {
  title: "Views/MailboxesView",
  component: MailboxesView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "微软邮箱工作台，保留左侧 mailbox 列表、中间 Inbox 列表、右侧邮件正文，并将 Graph 设置拆到独立页面。",
      },
    },
  },
} satisfies Meta<typeof MailboxesView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {} as Story["args"],
  render: () => <MailboxesStorySurface />,
};

export const NeedsSetup: Story = {
  args: {} as Story["args"],
  render: () => <MailboxesStorySurface settingsConfigured={false} selectedMailboxId={sampleMailboxes[0]!.id} messageDetail={null} />,
};

export const OpenSettingsPlay: Story = {
  args: {} as Story["args"],
  render: () => <MailboxesStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("微软邮箱工作台")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "打开 Graph 设置" }));
  },
};
