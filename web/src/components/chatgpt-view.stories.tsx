import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptView } from "@/components/chatgpt-view";
import type { ChatGptJobDraft, JobSnapshot, RunModeAvailability } from "@/lib/app-types";

const sampleJobDraft: ChatGptJobDraft = {
  runMode: "headed",
  need: 3,
  parallel: 2,
  maxAttempts: 5,
};

const sampleJob: JobSnapshot = {
  site: "chatgpt",
  job: {
    id: 41,
    status: "running",
    runMode: "headed",
    need: 3,
    parallel: 2,
    maxAttempts: 5,
    successCount: 1,
    failureCount: 1,
    skipCount: 0,
    launchedCount: 3,
    autoExtractSources: [],
    autoExtractQuantity: 0,
    autoExtractMaxWaitSec: 0,
    autoExtractAccountType: "outlook",
    startedAt: "2026-04-05T09:32:00.000Z",
    pausedAt: null,
    completedAt: null,
    lastError: "chatgpt_auth_challenge_detected",
  },
  activeAttempts: [
    {
      id: 104,
      accountId: null,
      accountEmail: "nova-demo318@alpha.example.test",
      status: "running",
      stage: "otp_verify",
      proxyNode: "Tokyo-01",
      proxyIp: "203.0.113.24",
      errorCode: null,
      errorMessage: null,
      startedAt: "2026-04-05T09:32:10.000Z",
      completedAt: null,
    },
    {
      id: 105,
      accountId: null,
      accountEmail: "echo-demo204@bravo.example.test",
      status: "running",
      stage: "consent_submit",
      proxyNode: "Singapore-03",
      proxyIp: "203.0.113.25",
      errorCode: null,
      errorMessage: null,
      startedAt: "2026-04-05T09:32:18.000Z",
      completedAt: null,
    },
  ],
  recentAttempts: [
    {
      id: 103,
      accountId: null,
      accountEmail: "rio-demo77@charlie.example.test",
      status: "failed",
      stage: "failed",
      proxyNode: "Tokyo-02",
      proxyIp: "203.0.113.26",
      errorCode: "chatgpt_auth_challenge_detected",
      errorMessage: "recent auth challenge detected",
      startedAt: "2026-04-05T09:31:04.000Z",
      completedAt: "2026-04-05T09:31:48.000Z",
    },
  ],
  eligibleCount: 0,
  autoExtractState: null,
  runModeAvailability: {
    headed: true,
    headless: true,
    headedReason: null,
  },
};

const headlessOnlyAvailability: RunModeAvailability = {
  headed: false,
  headless: true,
  headedReason: "当前环境缺少 DISPLAY / WAYLAND_DISPLAY，无法启动有头浏览器。",
};

const meta = {
  title: "Views/ChatGptView",
  component: ChatGptView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "ChatGPT 批量有头浏览器流页面，仅负责批量任务控制与运行态；生成结果统一在 Keys > ChatGPT 查看与导出。",
      },
    },
  },
} satisfies Meta<typeof ChatGptView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const BatchRunning: Story = {
  args: {
    jobDraft: sampleJobDraft,
    job: sampleJob,
    runModeAvailability: sampleJob.runModeAvailability,
    jobBusy: false,
    onJobDraftChange: fn(),
    onStart: fn(),
    onStop: fn(),
    onForceStop: fn(),
  },
};

export const BatchReady: Story = {
  args: {
    ...BatchRunning.args,
    job: {
      site: "chatgpt",
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
      runModeAvailability: sampleJob.runModeAvailability,
      cooldown: null,
    },
  },
};

export const BatchReadyHeadless: Story = {
  args: {
    ...BatchReady.args,
    jobDraft: {
      ...sampleJobDraft,
      runMode: "headless",
    },
  },
};

export const BatchReadyHeadlessOnly: Story = {
  args: {
    ...BatchReady.args,
    jobDraft: {
      ...sampleJobDraft,
      runMode: "headless",
    },
    runModeAvailability: headlessOnlyAvailability,
  },
};

export const InteractiveBatchControls: Story = {
  args: {
    ...BatchRunning.args,
  },
  render: () => {
    const [batchDraft, setBatchDraft] = useState(sampleJobDraft);
    return (
      <>
        <ChatGptView
          jobDraft={batchDraft}
          job={{ ...sampleJob, job: null, activeAttempts: [], recentAttempts: [], runModeAvailability: sampleJob.runModeAvailability }}
          runModeAvailability={sampleJob.runModeAvailability}
          jobBusy={false}
          onJobDraftChange={(patch) => setBatchDraft((current) => ({ ...current, ...patch }))}
          onStart={() => undefined}
          onStop={() => undefined}
          onForceStop={() => undefined}
        />
        <pre data-testid="chatgpt-job-draft-debug" className="sr-only">
          {JSON.stringify(batchDraft)}
        </pre>
      </>
    );
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("mode: headed")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("combobox", { name: /run mode/i }));
    await userEvent.click(within(document.body).getByRole("option", { name: "headless" }));
    await expect(canvas.getByText("mode: headless")).toBeInTheDocument();
    await userEvent.clear(canvas.getByLabelText("Need"));
    await userEvent.type(canvas.getByLabelText("Need"), "4");
    await userEvent.tab();
    await expect(canvas.getByTestId("chatgpt-job-draft-debug")).toHaveTextContent('"runMode":"headless"');
    await expect(canvas.getByTestId("chatgpt-job-draft-debug")).toHaveTextContent('"need":4');
    await expect(canvas.queryByText("最近凭据")).toBeNull();
    await expect(canvas.getByText(/Keys > ChatGPT/)).toBeInTheDocument();
  },
};

export const InteractiveHeadlessOnly: Story = {
  args: {
    ...BatchReady.args,
    jobDraft: {
      ...sampleJobDraft,
      runMode: "headless",
    },
    runModeAvailability: headlessOnlyAvailability,
  },
  render: () => {
    const [batchDraft, setBatchDraft] = useState<ChatGptJobDraft>({ ...sampleJobDraft, runMode: "headless" });
    return (
      <>
        <ChatGptView
          jobDraft={batchDraft}
          job={{ ...sampleJob, job: null, activeAttempts: [], recentAttempts: [], runModeAvailability: headlessOnlyAvailability }}
          runModeAvailability={headlessOnlyAvailability}
          jobBusy={false}
          onJobDraftChange={(patch) => setBatchDraft((current) => ({ ...current, ...patch }))}
          onStart={() => undefined}
          onStop={() => undefined}
          onForceStop={() => undefined}
        />
        <pre data-testid="chatgpt-job-draft-debug" className="sr-only">
          {JSON.stringify(batchDraft)}
        </pre>
      </>
    );
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("mode: headless")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("combobox", { name: /run mode/i }));
    await expect(within(document.body).queryByRole("option", { name: "headed" })).toBeNull();
    await expect(within(document.body).getByRole("option", { name: "headless" })).toBeInTheDocument();
    await expect(canvas.getByText(/当前环境仅支持/)).toBeInTheDocument();
    await expect(canvas.getByTestId("chatgpt-job-draft-debug")).toHaveTextContent('"runMode":"headless"');
  },
};
