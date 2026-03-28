import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { DashboardView } from "@/components/dashboard-view";
import type { JobDraft } from "@/lib/app-types";
import { normalizeJobDraft } from "@/lib/job-draft";
import { sampleEvents, sampleExtractorSettings, sampleJob } from "@/stories/fixtures";

const meta = {
  title: "Views/DashboardView",
  component: DashboardView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "主流程页，包含指标卡、四源自动补号控制、运行中 attempts、最近 attempts 与实时事件流。",
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
    jobDraft: {
      runMode: "headed",
      need: 5,
      parallel: 2,
      maxAttempts: 9,
      autoExtractSources: ["zhanghaoya", "hotmail666"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 60,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: sampleExtractorSettings.availability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  render: () => {
    const [draft, setDraft] = useState<JobDraft>({
      runMode: "headed",
      need: 5,
      parallel: 2,
      maxAttempts: 9,
      autoExtractSources: ["zhanghaoya", "hotmail666"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 60,
      autoExtractAccountType: "outlook",
    });
    return (
      <>
        <DashboardView
          job={sampleJob}
          events={sampleEvents}
          jobDraft={draft}
          extractorAvailability={sampleExtractorSettings.availability}
          onJobDraftChange={(patch) => setDraft((current) => normalizeJobDraft({ ...current, ...patch }))}
          onJobAction={() => undefined}
        />
        <pre data-testid="job-draft-debug" className="sr-only">
          {JSON.stringify(draft)}
        </pre>
      </>
    );
  },
};

export const Empty: Story = {
  args: {
    job: { job: null, activeAttempts: [], recentAttempts: [], eligibleCount: 0, autoExtractState: null },
    events: [],
    jobDraft: {
      runMode: "headless",
      need: 1,
      parallel: 1,
      maxAttempts: 3,
      autoExtractSources: [],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 60,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: { zhanghaoya: false, shanyouxiang: true, shankeyun: true, hotmail666: false },
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
};

export const OverflowGuard: Story = {
  args: {
    job: {
      ...sampleJob,
      recentAttempts: Array.from({ length: 3 }, (_, index) => ({
        id: 300 + index,
        accountId: 50 + index,
        accountEmail: `very-long-account-${index}-with-an-extremely-wide-identifier-to-force-wrap-and-overflow-checks@subdomain.example-outlook-account.test`,
        status: index === 0 ? "running" : "failed",
        stage: "spawned",
        proxyNode: "Tokyo-01-long-node-name-for-overflow-guard",
        proxyIp: "203.0.113.24",
        errorCode: index === 0 ? null : "proxy-check-timeout-with-verbose-diagnostic-code",
        errorMessage: null,
        startedAt: "2026-03-18T07:18:00.000Z",
        completedAt: index === 0 ? null : "2026-03-18T07:19:00.000Z",
      })),
    },
    events: [
      {
        type: "job.updated.with-extra-debug-context.for-layout-guard",
        timestamp: "2026-03-18T07:24:20.000Z",
        payload: {
          detail:
            "This payload intentionally contains a very long line to verify the dashboard keeps overflow inside the card instead of pushing the whole page wider than the shell container.",
          nested: {
            accountEmail:
              "overflow-check-account-with-a-very-very-long-address@subdomain.example-outlook-account.test",
            diagnosticCode: "proxy-node-timeout-after-retrying-connection-through-multiple-fallback-routes",
          },
        },
      },
      ...sampleEvents,
    ],
    jobDraft: {
      runMode: "headed",
      need: 5,
      parallel: 2,
      maxAttempts: 9,
      autoExtractSources: ["zhanghaoya", "shankeyun", "hotmail666"],
      autoExtractQuantity: 2,
      autoExtractMaxWaitSec: 45,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: sampleExtractorSettings.availability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  decorators: [
    (Story) => (
      <div className="mx-auto w-full max-w-[1080px] overflow-hidden">
        <Story />
      </div>
    ),
  ],
};

export const FourSourceCompact: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: {
      runMode: "headed",
      need: 6,
      parallel: 2,
      maxAttempts: 12,
      autoExtractSources: ["zhanghaoya", "shanyouxiang", "shankeyun", "hotmail666"],
      autoExtractQuantity: 2,
      autoExtractMaxWaitSec: 45,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: {
      zhanghaoya: true,
      shanyouxiang: true,
      shankeyun: true,
      hotmail666: true,
    },
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  decorators: [
    (Story) => (
      <div className="mx-auto w-full max-w-[980px] overflow-hidden">
        <Story />
      </div>
    ),
  ],
};

export const ControlPlay: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: {
      runMode: "headed",
      need: 5,
      parallel: 2,
      maxAttempts: 9,
      autoExtractSources: ["zhanghaoya", "hotmail666"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 60,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: sampleExtractorSettings.availability,
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

export const BufferedNumberFlowPlay: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: {
      runMode: "headed",
      need: 5,
      parallel: 2,
      maxAttempts: 9,
      autoExtractSources: ["zhanghaoya", "hotmail666"],
      autoExtractQuantity: 1,
      autoExtractMaxWaitSec: 60,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: sampleExtractorSettings.availability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  render: (args) => {
    const [draft, setDraft] = useState<JobDraft>(args.jobDraft);
    const [lastAction, setLastAction] = useState<string>("");
    return (
      <>
        <DashboardView
          job={sampleJob}
          events={sampleEvents}
          jobDraft={draft}
          extractorAvailability={sampleExtractorSettings.availability}
          onJobDraftChange={(patch) => {
            setDraft((current) => normalizeJobDraft({ ...current, ...patch }));
            args.onJobDraftChange(patch);
          }}
          onJobAction={(action) => {
            setLastAction(action);
            args.onJobAction(action);
          }}
        />
        <pre data-testid="job-draft-debug" className="sr-only">
          {JSON.stringify({ draft, lastAction })}
        </pre>
      </>
    );
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const draftDebug = canvas.getByTestId("job-draft-debug");
    const maxAttemptsInput = canvas.getByLabelText("Max Attempts");
    const needInput = canvas.getByLabelText("Need");
    const autoQuantityInput = canvas.getByLabelText("Auto Quantity");

    await userEvent.clear(maxAttemptsInput);
    await userEvent.type(maxAttemptsInput, "10");
    await expect(maxAttemptsInput).toHaveValue("10");

    await userEvent.clear(needInput);
    await userEvent.type(needInput, "12");
    await userEvent.click(canvas.getByRole("button", { name: "应用调参" }));
    await expect(needInput).toHaveValue("12");
    await expect(draftDebug.textContent).toContain("\"need\":12");
    await expect(draftDebug.textContent).toContain("\"lastAction\":\"update_limits\"");

    await userEvent.clear(autoQuantityInput);
    await userEvent.type(autoQuantityInput, "0");
    await userEvent.tab();
    await expect(autoQuantityInput).toHaveValue("1");

    await userEvent.clear(maxAttemptsInput);
    await userEvent.type(maxAttemptsInput, "1");
    await userEvent.tab();
    await expect(maxAttemptsInput).toHaveValue("18");
  },
};
