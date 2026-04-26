import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { MailboxesView } from "@/components/mailboxes-view";
import type { MailboxMessageDetail, MailboxRecord } from "@/lib/app-types";
import { sampleMailboxMessageDetail, sampleMailboxMessages, sampleMailboxes } from "@/stories/fixtures";

function MailboxesStorySurface(props?: {
  selectedMailboxId?: number | null;
  selectedMessageId?: number | null;
  messageDetail?: MailboxMessageDetail | null;
  mailboxes?: MailboxRecord[];
  settingsConfigured?: boolean;
}) {
  const [selectedMailboxId, setSelectedMailboxId] = useState<number | null>(props?.selectedMailboxId ?? sampleMailboxes[1]!.id);
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(props?.selectedMessageId ?? sampleMailboxMessages[0]!.id);
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
      syncingMailboxId={null}
      onOpenSettings={fn()}
      onSelectMailbox={(mailboxId) => setSelectedMailboxId(mailboxId)}
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
        component: "微软邮箱工具页，使用紧凑的顶部工具栏和三栏工作区承载 mailbox 列表、Inbox 列表与邮件正文，Graph 设置独立到单独页面。",
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

export const NoConnectedMailboxes: Story = {
  args: {} as Story["args"],
  render: () => <MailboxesStorySurface mailboxes={[]} selectedMailboxId={null} selectedMessageId={null} messageDetail={null} />,
};

export const OpenSettingsPlay: Story = {
  args: {} as Story["args"],
  render: () => <MailboxesStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("微软邮箱")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "Graph 设置" }));
  },
};

export const VerificationCodeQuickCopyPlay: Story = {
  args: {} as Story["args"],
  render: () => <MailboxesStorySurface />,
  parameters: {
    docs: {
      description: {
        story: "验证邮箱卡片与 Inbox 消息项在存在验证码时都会显示钥匙复制按钮。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("button", { name: /复制 beta@example\\.test 最新验证码/ })).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: /复制 Your verification code 验证码/ })).toBeInTheDocument();
  },
};
