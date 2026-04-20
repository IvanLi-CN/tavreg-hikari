import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, within } from "storybook/test";
import { MailboxDrawer } from "@/components/mailbox-drawer";
import { sampleAccounts, sampleMailboxMessageDetail, sampleMailboxMessages, sampleMailboxes } from "@/stories/fixtures";

function findAccount(accountId: number | null) {
  return accountId == null ? null : sampleAccounts.rows.find((row) => row.id === accountId) || null;
}

const meta = {
  title: "Views/MailboxDrawer",
  component: MailboxDrawer,
  tags: ["autodocs"],
  args: {
    open: true,
    onOpenChange: () => undefined,
    settingsConfigured: true,
    account: findAccount(sampleMailboxes[1]?.accountId ?? null),
    mailbox: sampleMailboxes[1] ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    messagesHasMore: false,
    messagesBusy: false,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
    messageBusy: false,
    syncingMailboxId: null,
    onOpenSettings: () => undefined,
    onSyncMailbox: async () => undefined,
    onLoadMoreMessages: async () => undefined,
    onSelectMessage: async () => undefined,
  },
  parameters: {
    docs: {
      description: {
        component: "Microsoft 账号页内的单邮箱抽屉：只显示当前账号对应信箱的邮件列表与邮件正文，不再显示邮箱账号列表。",
      },
    },
  },
} satisfies Meta<typeof MailboxDrawer>;

export default meta;
type Story = StoryObj<typeof meta>;

export const AvailableMailbox: Story = {
  args: {
    account: findAccount(2),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("Inbox")).toBeInTheDocument();
    await expect(canvas.queryByText("邮箱账号")).not.toBeInTheDocument();
  },
};

export const NoMailboxBound: Story = {
  args: {
    account: findAccount(4),
    mailbox: null,
    messages: [],
    messagesTotal: 0,
    selectedMessageId: null,
    messageDetail: null,
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("当前邮箱状态")).toBeInTheDocument();
    await expect(canvas.getByText(/还没有绑定可读取的邮箱/)).toBeInTheDocument();
  },
};

export const LockedMailbox: Story = {
  args: {
    account: findAccount(3),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 3) ?? null,
    messages: [],
    messagesTotal: 0,
    selectedMessageId: null,
    messageDetail: null,
  },
};

export const NeedsGraphSetup: Story = {
  args: {
    settingsConfigured: false,
    account: findAccount(1),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 1) ?? null,
    messages: [],
    messagesTotal: 0,
    selectedMessageId: null,
    messageDetail: null,
  },
};
