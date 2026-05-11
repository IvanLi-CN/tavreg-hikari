import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, userEvent, within } from "storybook/test";
import { MailboxDrawer, type MailboxDrawerSyncFeedback } from "@/components/mailbox-drawer";
import { sampleAccounts, sampleMailboxMessageDetail, sampleMailboxMessages, sampleMailboxes } from "@/stories/fixtures";

function findAccount(accountId: number | null) {
  return accountId == null ? null : sampleAccounts.rows.find((row) => row.id === accountId) || null;
}

function MailboxDrawerSyncFeedbackHarness(props: { initialFeedback?: MailboxDrawerSyncFeedback | null; failOnRefresh?: boolean }) {
  const [syncFeedback, setSyncFeedback] = useState<MailboxDrawerSyncFeedback | null>(props.initialFeedback || null);
  const mailbox = sampleMailboxes.find((item) => item.accountId === 2) ?? null;

  return (
    <MailboxDrawer
      open
      onOpenChange={() => undefined}
      settingsConfigured
      account={findAccount(2)}
      mailbox={mailbox}
      messages={sampleMailboxMessages}
      messagesTotal={sampleMailboxMessages.length}
      messagesHasMore={false}
      messagesBusy={false}
      selectedMessageId={sampleMailboxMessages[0]?.id ?? null}
      messageDetail={sampleMailboxMessageDetail}
      messageBusy={false}
      syncingMailboxId={syncFeedback?.status === "syncing" ? mailbox?.id ?? null : null}
      syncFeedback={syncFeedback}
      onDismissSyncFeedback={() => setSyncFeedback(null)}
      onOpenSettings={() => undefined}
      onSyncMailbox={async () => {
        setSyncFeedback({ status: "syncing" });
        if (props.failOnRefresh) {
          setSyncFeedback({ status: "error", message: "Graph token expired" });
          return;
        }
        setSyncFeedback({ status: "success", message: "已刷新" });
      }}
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
    syncFeedback: null,
    onOpenSettings: () => undefined,
    onSyncMailbox: async () => undefined,
    onDismissSyncFeedback: () => undefined,
    copyFeedbackAutoDismissMs: 2200,
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
    copyFeedbackAutoDismissMs: null,
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("Beta")).toBeInTheDocument();
    await expect(canvas.getByText("beta@example.test")).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "复制Beta 用户名" })).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "复制beta@example.test 邮箱" })).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "复制beta@example.test 最新验证码" })).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: /复制 Your verification code 验证码/ })).toBeInTheDocument();
    await expect(canvas.queryByText("Inbox")).not.toBeInTheDocument();
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

export const RefreshingFeedback: Story = {
  args: {
    account: findAccount(2),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
    syncingMailboxId: sampleMailboxes.find((mailbox) => mailbox.accountId === 2)?.id ?? null,
    syncFeedback: { status: "syncing" },
  },
  play: async () => {
    await expect(within(document.body).getByRole("status")).toHaveTextContent("正在刷新邮箱");
  },
};

export const RefreshSuccessFeedback: Story = {
  args: {
    account: findAccount(2),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
    syncFeedback: { status: "success", message: "已刷新" },
  },
  play: async () => {
    await expect(within(document.body).getByRole("status")).toHaveTextContent("已刷新");
  },
};

export const RefreshFailureFeedback: Story = {
  render: () => (
    <div className="min-h-dvh bg-slate-950 p-8 text-white">
      <div className="mx-auto max-w-[1480px] space-y-6">
        <div className="rounded-[28px] border border-white/10 bg-slate-950/80 p-8">
          <div className="h-8 w-56 rounded-full bg-white/10" />
          <div className="mt-4 h-5 w-[32rem] rounded-full bg-white/5" />
        </div>
      </div>
      <MailboxDrawerSyncFeedbackHarness initialFeedback={{ status: "error", message: "Graph token expired" }} />
    </div>
  ),
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        story: "验证抽屉刷新失败时错误只出现在抽屉内部，不在背后的主界面渲染全局错误条。",
      },
    },
  },
  play: async () => {
    const body = within(document.body);
    await expect(body.getByRole("alert")).toHaveTextContent("Graph token expired");
    await expect(body.getAllByRole("alert")).toHaveLength(1);
  },
};

export const RefreshFailurePlay: Story = {
  render: () => <MailboxDrawerSyncFeedbackHarness failOnRefresh />,
  parameters: {
    docs: {
      description: {
        story: "点击抽屉刷新按钮后，在抽屉内显示失败反馈，避免把错误泄露到 overlay 背后的 AppShell。",
      },
    },
  },
  play: async () => {
    const body = within(document.body);
    await userEvent.click(body.getByRole("button", { name: "刷新" }));
    await expect(body.getByRole("alert")).toHaveTextContent("Graph token expired");
    await expect(body.getAllByRole("alert")).toHaveLength(1);
  },
};


export const OverlayPreview: Story = {
  render: () => (
    <div className="min-h-dvh bg-[radial-gradient(circle_at_top,_rgba(56,189,248,0.18),_transparent_42%),linear-gradient(180deg,rgba(15,23,42,0.95),rgba(2,6,23,0.98))] p-8 text-white">
      <div className="mx-auto max-w-[1480px] space-y-6">
        <div className="rounded-[28px] border border-white/10 bg-slate-950/80 p-8">
          <div className="h-8 w-56 rounded-full bg-white/10" />
          <div className="mt-4 h-5 w-[32rem] rounded-full bg-white/5" />
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <div className="h-28 rounded-[24px] border border-white/8 bg-white/[0.03]" />
            <div className="h-28 rounded-[24px] border border-white/8 bg-white/[0.03]" />
            <div className="h-28 rounded-[24px] border border-white/8 bg-white/[0.03]" />
          </div>
        </div>
        <div className="rounded-[28px] border border-white/10 bg-slate-950/80 p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="h-6 w-32 rounded-full bg-white/10" />
            <div className="h-10 w-48 rounded-full bg-white/8" />
          </div>
          <div className="space-y-3">
            <div className="h-16 rounded-2xl border border-white/8 bg-white/[0.03]" />
            <div className="h-16 rounded-2xl border border-white/8 bg-white/[0.03]" />
            <div className="h-16 rounded-2xl border border-white/8 bg-white/[0.03]" />
            <div className="h-16 rounded-2xl border border-white/8 bg-white/[0.03]" />
          </div>
        </div>
      </div>
      <MailboxDrawer
        open
        onOpenChange={() => undefined}
        settingsConfigured
        account={findAccount(2)}
        mailbox={sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null}
        messages={sampleMailboxMessages}
        messagesTotal={sampleMailboxMessages.length}
        messagesHasMore={false}
        messagesBusy={false}
        selectedMessageId={sampleMailboxMessages[0]?.id ?? null}
        messageDetail={sampleMailboxMessageDetail}
        messageBusy={false}
        syncingMailboxId={null}
        onOpenSettings={() => undefined}
        onSyncMailbox={async () => undefined}
        onLoadMoreMessages={async () => undefined}
        onSelectMessage={async () => undefined}
      />
    </div>
  ),
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        story: "展示 UI 库右侧抽屉的真实 overlay / viewport 高度形态。",
      },
    },
  },
};


export const CopySuccessFeedback: Story = {
  args: {
    account: findAccount(2),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
    copyFeedbackAutoDismissMs: null,
    copyPreviewStatus: { email: "copied" },
  },
  parameters: {
    docs: {
      description: {
        story: "在真实抽屉内验证邮箱复制成功时的轻提示效果：只显示“已复制”，不出现关闭按钮与失败兜底输入框。",
      },
    },
  },
  play: async () => {
    await expect(within(document.body).getByText("已复制")).toBeInTheDocument();
    await expect(within(document.body).queryByRole("textbox", { name: "完整内容（点击全选）" })).not.toBeInTheDocument();
  },
};

export const CopyFailureFeedback: Story = {
  args: {
    account: findAccount(2),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
    copyFeedbackAutoDismissMs: null,
    copyPreviewStatus: { email: "failed" },
  },
  parameters: {
    docs: {
      description: {
        story: "在真实抽屉内验证邮箱复制失败时的完整兜底反馈：显示失败说明与手动复制内容。",
      },
    },
  },
  play: async () => {
    await expect(within(document.body).getByText("复制失败")).toBeInTheDocument();
    await expect(within(document.body).getByRole("textbox", { name: "完整内容（点击全选）" })).toHaveTextContent("beta@example.test");
  },
};

export const VerificationCodeCopyFeedbackPlay: Story = {
  args: {
    account: findAccount(2),
    mailbox: sampleMailboxes.find((mailbox) => mailbox.accountId === 2) ?? null,
    messages: sampleMailboxMessages,
    messagesTotal: sampleMailboxMessages.length,
    selectedMessageId: sampleMailboxMessages[0]?.id ?? null,
    messageDetail: sampleMailboxMessageDetail,
  },
  parameters: {
    docs: {
      description: {
        story: "点击钥匙按钮后展示验证码复制成功反馈，供抽屉视觉验收使用。",
      },
    },
  },
  play: async () => {
    const originalClipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async () => undefined,
      },
    });
    try {
      const body = within(document.body);
      await userEvent.click(body.getByRole("button", { name: "复制beta@example.test 最新验证码" }));
      await expect(body.getByText("已复制")).toBeInTheDocument();
    } finally {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: originalClipboard,
      });
    }
  },
};
