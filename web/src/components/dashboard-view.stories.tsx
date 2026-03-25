import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { DashboardView } from "@/components/dashboard-view";
import type { JobDraft } from "@/lib/app-types";
import { sampleEvents, sampleJob } from "@/stories/fixtures";

const meta = {
  title: "Views/DashboardView",
  component: DashboardView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "主流程页，包含指标卡、运行中 attempts、最近 attempts 与实时事件流。",
      },
    },
  },
} satisfies Meta<typeof DashboardView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Running: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: { runMode: "headed", need: 5, parallel: 2, maxAttempts: 9, targets: ["tavily", "chatgpt"] },
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  render: () => {
    const [draft, setDraft] = useState<JobDraft>({ runMode: "headed", need: 5, parallel: 2, maxAttempts: 9, targets: ["tavily", "chatgpt"] });
    return (
      <DashboardView
        job={sampleJob}
        events={sampleEvents}
        jobDraft={draft}
        onJobDraftChange={(patch) => setDraft((current) => ({ ...current, ...patch }))}
        onJobAction={() => undefined}
      />
    );
  },
};

export const Empty: Story = {
  args: {
    job: { job: null, activeAttempts: [], recentAttempts: [], eligibleCount: 0, completedTargetSteps: 0, totalTargetSteps: 0 },
    events: [],
    jobDraft: { runMode: "headless", need: 1, parallel: 1, maxAttempts: 3, targets: ["tavily"] },
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
};

export const ControlPlay: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: { runMode: "headed", need: 5, parallel: 2, maxAttempts: 9, targets: ["tavily", "chatgpt"] },
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "启动" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("start");
    await userEvent.click(canvas.getByRole("button", { name: "应用调参" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("update_limits");
  },
};
