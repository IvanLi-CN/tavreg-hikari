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
  upstreamGroupName: "",
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
    upstreamGroupName: "sync-ready",
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

function buildJob(status: NonNullable<typeof sampleJob.job>["status"]): JobSnapshot {
  return {
    ...sampleJob,
    activeAttempts: status === "paused" || status === "running" ? sampleJob.activeAttempts : [],
    job: sampleJob.job
      ? {
          ...sampleJob.job,
          status,
          pausedAt: status === "paused" ? "2026-04-05T09:33:02.000Z" : null,
          completedAt: ["completed", "failed", "stopped"].includes(status) ? "2026-04-05T09:40:00.000Z" : null,
        }
      : null,
  };
}

const meta = {
  title: "Views/ChatGptView",
  component: ChatGptView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "ChatGPT 批量控制页，支持上下文主按钮、更新限制、停止/强制停止与运行态 attempts 展示。",
      },
    },
  },
} satisfies Meta<typeof ChatGptView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Running: Story = {
  args: {
    jobDraft: sampleJobDraft,
    job: sampleJob,
    runModeAvailability: sampleJob.runModeAvailability,
    jobBusy: false,
    draftTouched: false,
    groupOptions: ["sync-ready", "warm-pool", "hold"],
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
};

export const Paused: Story = {
  args: {
    ...Running.args,
    job: buildJob("paused"),
  },
};

export const Stopping: Story = {
  args: {
    ...Running.args,
    job: buildJob("stopping"),
  },
};

export const Stopped: Story = {
  args: {
    ...Running.args,
    job: buildJob("stopped"),
  },
};

export const BatchReady: Story = {
  args: {
    ...Running.args,
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

export const MailboxCooldown: Story = {
  args: {
    ...BatchReady.args,
    job: {
      site: "chatgpt",
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
      runModeAvailability: sampleJob.runModeAvailability,
      cooldown: {
        active: true,
        until: "2026-04-14T07:41:28.000Z",
        sourceAttemptId: null,
        sourceJobId: null,
        sourceErrorCode: "mailbox_rate_limited",
        reason: "recent mailbox provider rate limit detected",
      },
    },
  },
};

export const RunningStagedDisableSupplement: Story = {
  args: {
    ...Running.args,
    draftTouched: true,
    jobDraft: {
      ...sampleJobDraft,
      upstreamGroupName: "",
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("supplement: 不补号")).toBeInTheDocument();
    await expect(canvas.getByText("当前不会执行自动补号。")).toBeInTheDocument();
  },
};

export const InteractiveBatchControls: Story = {
  args: {
    ...BatchReady.args,
  },
  render: () => {
    const [batchDraft, setBatchDraft] = useState(sampleJobDraft);
    const [draftTouched, setDraftTouched] = useState(false);
    return (
      <>
        <ChatGptView
          jobDraft={batchDraft}
          job={{ ...sampleJob, job: null, activeAttempts: [], recentAttempts: [], runModeAvailability: sampleJob.runModeAvailability }}
          runModeAvailability={sampleJob.runModeAvailability}
          jobBusy={false}
          draftTouched={draftTouched}
          groupOptions={["sync-ready", "warm-pool", "hold"]}
          onJobDraftChange={(patch) => {
            setDraftTouched(true);
            setBatchDraft((current) => ({ ...current, ...patch }));
          }}
          onJobAction={() => undefined}
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
    await userEvent.click(canvas.getByRole("button", { name: "不补号" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "warm-pool" }));
    await expect(canvas.getByTestId("chatgpt-job-draft-debug")).toHaveTextContent('"runMode":"headless"');
    await expect(canvas.getByTestId("chatgpt-job-draft-debug")).toHaveTextContent('"need":4');
    await expect(canvas.getByText(/supplement:/)).toBeInTheDocument();
    await expect(canvas.getByText("开始")).toBeInTheDocument();
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
    const [draftTouched, setDraftTouched] = useState(false);
    return (
      <>
        <ChatGptView
          jobDraft={batchDraft}
          job={{ ...sampleJob, job: null, activeAttempts: [], recentAttempts: [], runModeAvailability: headlessOnlyAvailability }}
          runModeAvailability={headlessOnlyAvailability}
          jobBusy={false}
          draftTouched={draftTouched}
          groupOptions={["sync-ready", "warm-pool", "hold"]}
          onJobDraftChange={(patch) => {
            setDraftTouched(true);
            setBatchDraft((current) => ({ ...current, ...patch }));
          }}
          onJobAction={() => undefined}
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

export const ControlPlay: Story = {
  args: {
    ...Running.args,
    onJobAction: fn(),
  },
  render: (args) => {
    const [draft, setDraft] = useState(sampleJobDraft);
    const [draftTouched, setDraftTouched] = useState(false);
    return (
      <>
        <ChatGptView
          jobDraft={draft}
          job={sampleJob}
          runModeAvailability={sampleJob.runModeAvailability}
          jobBusy={false}
          draftTouched={draftTouched}
          groupOptions={["sync-ready", "warm-pool", "hold"]}
          onJobDraftChange={(patch) => {
            setDraftTouched(true);
            setDraft((current) => ({ ...current, ...patch }));
          }}
          onJobAction={args.onJobAction}
        />
        <pre data-testid="chatgpt-job-draft-debug" className="sr-only">
          {JSON.stringify(draft)}
        </pre>
      </>
    );
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    const draftDebug = canvas.getByTestId("chatgpt-job-draft-debug");

    await userEvent.click(canvas.getByRole("button", { name: "暂停" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("pause", undefined);

    await userEvent.clear(canvas.getByLabelText("Need"));
    await userEvent.type(canvas.getByLabelText("Need"), "4");
    await userEvent.click(canvas.getByRole("button", { name: /sync-ready/ }));
    await userEvent.click(within(document.body).getByRole("button", { name: "warm-pool" }));
    await userEvent.click(canvas.getByRole("button", { name: "更新限制" }));
    await expect(draftDebug).toHaveTextContent('"need":4');
    await expect(args.onJobAction).toHaveBeenCalledWith(
      "update_limits",
      expect.objectContaining({
        draft: expect.objectContaining({ need: 4, parallel: 2, maxAttempts: 5, runMode: "headed", upstreamGroupName: "warm-pool" }),
      }),
    );


    await userEvent.click(canvas.getByRole("button", { name: "停止" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("stop", undefined);

    await userEvent.click(canvas.getByRole("button", { name: "强制停止" }));
    await expect(within(document.body).getByRole("dialog", { name: "强制停止 ChatGPT 任务？" })).toBeInTheDocument();
    await userEvent.click(within(document.body).getByRole("button", { name: "取消" }));
    await expect(args.onJobAction).not.toHaveBeenCalledWith("force_stop", expect.anything());

    await userEvent.click(canvas.getByRole("button", { name: "强制停止" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "确认强停" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("force_stop", { confirmForceStop: true });
  },
};
