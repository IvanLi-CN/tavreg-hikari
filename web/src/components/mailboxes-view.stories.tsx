import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { MailboxesView } from "@/components/mailboxes-view";
import type { MailboxMessageDetail, MailboxRecord } from "@/lib/app-types";
import {
  sampleMailboxMessageDetail,
  sampleMailboxMessages,
  sampleMailboxes,
  sampleMicrosoftGraphSettings,
} from "@/stories/fixtures";

function MailboxesStorySurface(props?: {
  selectedMailboxId?: number;
  selectedMessageId?: number;
  messageDetail?: MailboxMessageDetail | null;
  mailboxes?: MailboxRecord[];
}) {
  const [selectedMailboxId, setSelectedMailboxId] = useState(props?.selectedMailboxId || sampleMailboxes[1]!.id);
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(props?.selectedMessageId || sampleMailboxMessages[0]!.id);
  const activeMailbox = (props?.mailboxes || sampleMailboxes).find((mailbox) => mailbox.id === selectedMailboxId) || null;

  return (
    <MailboxesView
      settings={sampleMicrosoftGraphSettings}
      settingsDraft={{
        microsoftGraphClientId: sampleMicrosoftGraphSettings.microsoftGraphClientId,
        microsoftGraphClientSecret: "",
        microsoftGraphRedirectUri: sampleMicrosoftGraphSettings.microsoftGraphRedirectUri,
        microsoftGraphAuthority: sampleMicrosoftGraphSettings.microsoftGraphAuthority,
      }}
      settingsBusy={false}
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
      onSettingsDraftChange={fn()}
      onSaveSettings={fn(async () => undefined)}
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
        component: "微软邮箱收件箱页，包含 Graph 设置、左侧 mailbox 列表、中间 Inbox 列表以及右侧净化后的邮件正文。",
      },
    },
  },
} satisfies Meta<typeof MailboxesView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  render: () => <MailboxesStorySurface />,
};

export const PreparingAndInvalidated: Story = {
  render: () => <MailboxesStorySurface selectedMailboxId={sampleMailboxes[0]!.id} messageDetail={null} />,
};

export const ConnectActionPlay: Story = {
  render: () => <MailboxesStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("Microsoft Graph 配置")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "重新授权" }));
  },
};
