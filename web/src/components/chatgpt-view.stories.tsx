import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptView } from "@/components/chatgpt-view";
import { sampleChatGptDraft, sampleChatGptJob } from "@/stories/fixtures";

const meta = {
  title: "Views/ChatGptView",
  component: ChatGptView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "ChatGPT 单账号有头浏览器流页面，聚焦默认草稿、启动/停止与当前任务态；凭据展示已迁移到 Keys 页。",
      },
    },
  },
} satisfies Meta<typeof ChatGptView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Running: Story = {
  args: {
    draft: sampleChatGptDraft,
    job: sampleChatGptJob,
    draftBusy: false,
    jobBusy: false,
    onDraftChange: fn(),
    onRegenerateDraft: fn(),
    onStart: fn(),
    onStop: fn(),
    onForceStop: fn(),
  },
};

export const Empty: Story = {
  args: {
    ...Running.args,
    job: {
      site: "chatgpt",
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
    },
  },
};

export const Cooldown: Story = {
  args: {
    ...Running.args,
    job: {
      ...sampleChatGptJob,
      cooldown: {
        active: true,
        until: "2026-04-05T09:55:00.000Z",
        sourceAttemptId: 104,
        sourceJobId: 41,
        sourceErrorCode: "challenge_cooldown",
        reason: "challenge detected",
      },
    },
  },
};

export const InteractiveDraft: Story = {
  args: {
    ...Running.args,
  },
  render: () => {
    const [draft, setDraft] = useState(sampleChatGptDraft);
    return (
      <ChatGptView
        draft={draft}
        job={{ ...sampleChatGptJob, job: null, activeAttempts: [], recentAttempts: [] }}
        draftBusy={false}
        jobBusy={false}
        onDraftChange={(patch) => setDraft((current) => ({ ...current, ...patch }))}
        onRegenerateDraft={() => undefined}
        onStart={() => undefined}
        onStop={() => undefined}
        onForceStop={() => undefined}
      />
    );
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.type(canvas.getByLabelText("昵称"), "A");
    await expect(canvas.getByDisplayValue("Nova318A")).toBeTruthy();
    await expect(canvas.queryByText("ChatGPT 最近凭据")).not.toBeInTheDocument();
  },
};

