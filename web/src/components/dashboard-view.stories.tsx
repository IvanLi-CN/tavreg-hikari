import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { DashboardView } from "@/components/dashboard-view";
import type { JobDraft, RunModeAvailability } from "@/lib/app-types";
import { normalizeJobDraft } from "@/lib/job-draft";
import { sampleEvents, sampleExtractorSettings, sampleJob } from "@/stories/fixtures";

const defaultDraft: JobDraft = {
  runMode: "headed",
  need: 5,
  parallel: 2,
  maxAttempts: 9,
  autoExtractSources: ["zhanghaoya", "hotmail666"],
  autoExtractQuantity: 1,
  autoExtractMaxWaitSec: 60,
  autoExtractAccountType: "outlook",
};

const defaultRunModeAvailability: RunModeAvailability = {
  headed: true,
  headless: true,
  headedReason: null,
};

const headlessOnlyAvailability: RunModeAvailability = {
  headed: false,
  headless: true,
  headedReason: "当前环境缺少 DISPLAY / WAYLAND_DISPLAY，无法启动有头浏览器。",
};

function buildJob(status: NonNullable<typeof sampleJob.job>["status"]) {
  return {
    ...sampleJob,
    activeAttempts: status === "stopped" ? [] : sampleJob.activeAttempts,
    job: sampleJob.job
      ? {
          ...sampleJob.job,
          status,
          pausedAt: status === "paused" ? "2026-03-18T07:25:00.000Z" : null,
          completedAt: status === "stopped" ? "2026-03-18T07:28:00.000Z" : null,
          lastError: null,
        }
      : null,
  };
}

const meta = {
  title: "Views/DashboardView",
  component: DashboardView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "Tavily 页，包含指标卡、四源自动补号控制、运行中 attempts、最近 attempts 与实时事件流。",
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
    jobDraft: defaultDraft,
    runModeAvailability: defaultRunModeAvailability,
    extractorAvailability: sampleExtractorSettings.availability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  render: () => {
    const [draft, setDraft] = useState<JobDraft>(defaultDraft);
    return (
      <>
        <DashboardView
          job={sampleJob}
          events={sampleEvents}
          jobDraft={draft}
          runModeAvailability={defaultRunModeAvailability}
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
    job: { site: "tavily", job: null, activeAttempts: [], recentAttempts: [], eligibleCount: 0, autoExtractState: null, runModeAvailability: defaultRunModeAvailability },
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
    runModeAvailability: defaultRunModeAvailability,
    extractorAvailability: { zhanghaoya: false, shanyouxiang: true, shankeyun: true, hotmail666: false },
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
};

export const EmptyHeadlessOnly: Story = {
  args: {
    ...Empty.args,
    job: { ...(Empty.args?.job as any), runModeAvailability: headlessOnlyAvailability },
    runModeAvailability: headlessOnlyAvailability,
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

export const ForceStopping: Story = {
  args: {
    ...Running.args,
    job: buildJob("force_stopping"),
  },
};

export const Stopped: Story = {
  args: {
    ...Running.args,
    job: buildJob("stopped"),
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
    runModeAvailability: defaultRunModeAvailability,
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

export const ActiveAttemptsNoWrap: Story = {
  args: {
    job: {
      ...sampleJob,
      activeAttempts: [
        {
          id: 307,
          accountId: 91,
          accountEmail: "jmunyxy196@example.test",
          status: "failed",
          stage: "login_home",
          proxyNode: "美国03 | 合适下载使用-0.01倍率",
          proxyIp: "208.87.242.97",
          errorCode: null,
          errorMessage: null,
          startedAt: "2026-03-28T15:57:20.000Z",
          completedAt: null,
        },
        {
          id: 309,
          accountId: 93,
          accountEmail: "myarjzor2958@example.test",
          status: "running",
          stage: "login_home",
          proxyNode: "美国圣何塞07 | 三网推荐",
          proxyIp: "2602:feda:dd0:7705:add5:6893:e933:3196",
          errorCode: null,
          errorMessage: null,
          startedAt: "2026-03-28T15:57:20.000Z",
          completedAt: null,
        },
        {
          id: 310,
          accountId: 94,
          accountEmail: "lbajazwav629@example.test",
          status: "running",
          stage: "proxy_select",
          proxyNode: "香港04 | 移动联通推荐",
          proxyIp: "—",
          errorCode: null,
          errorMessage: null,
          startedAt: "2026-03-28T15:58:14.000Z",
          completedAt: null,
        },
      ],
    },
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
    runModeAvailability: defaultRunModeAvailability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  parameters: {
    docs: {
      description: {
        story: "长邮箱、长代理节点与 IPv6 出口 IP 在同一行内截断显示，表格改为固定列宽，不再把整行撑成多行。",
      },
    },
  },
  decorators: [
    (Story) => (
      <div className="mx-auto w-full max-w-[1180px] overflow-hidden">
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
      autoExtractAccountType: "unlimited",
    },
    extractorAvailability: {
      zhanghaoya: true,
      shanyouxiang: true,
      shankeyun: true,
      hotmail666: true,
    },
    runModeAvailability: defaultRunModeAvailability,
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

export const AccountTypeSelectorPlay: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: {
      ...defaultDraft,
      autoExtractAccountType: "outlook",
    },
    extractorAvailability: {
      zhanghaoya: true,
      shanyouxiang: true,
      shankeyun: true,
      hotmail666: true,
    },
    runModeAvailability: defaultRunModeAvailability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  render: (args) => {
    const [draft, setDraft] = useState<JobDraft>(args.jobDraft);
    return (
      <>
        <DashboardView
          job={{
            ...sampleJob,
            autoExtractState: {
              ...sampleJob.autoExtractState!,
              accountType: draft.autoExtractAccountType,
            },
          }}
          events={sampleEvents}
          jobDraft={draft}
          runModeAvailability={defaultRunModeAvailability}
          extractorAvailability={args.extractorAvailability}
          onJobDraftChange={(patch) => {
            setDraft((current) => normalizeJobDraft({ ...current, ...patch }));
            args.onJobDraftChange(patch);
          }}
          onJobAction={args.onJobAction}
        />
        <pre data-testid="job-account-type-debug" className="sr-only">
          {draft.autoExtractAccountType}
        </pre>
      </>
    );
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("类型 Outlook")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("combobox", { name: /account type/i }));
    await userEvent.click(within(document.body).getByRole("option", { name: "不限" }));
    await expect(canvas.getByText("类型 不限")).toBeInTheDocument();
    await expect(canvas.getByTestId("job-account-type-debug")).toHaveTextContent("unlimited");
    await expect(args.onJobDraftChange).toHaveBeenCalledWith({ autoExtractAccountType: "unlimited" });
  },
};

export const ControlPlay: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: defaultDraft,
    runModeAvailability: defaultRunModeAvailability,
    extractorAvailability: sampleExtractorSettings.availability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "暂停" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("pause", undefined);

    await userEvent.click(canvas.getByRole("button", { name: "更新限制" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("update_limits", expect.anything());

    await userEvent.click(canvas.getByRole("button", { name: "停止" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("stop", undefined);

    await userEvent.click(canvas.getByRole("button", { name: "强制停止" }));
    await expect(within(document.body).getByRole("dialog", { name: "确认强制停止" })).toBeInTheDocument();
    await userEvent.click(within(document.body).getByRole("button", { name: "取消" }));
    await expect(args.onJobAction).not.toHaveBeenCalledWith("force_stop", expect.anything());

    await userEvent.click(canvas.getByRole("button", { name: "强制停止" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "确认强停" }));
    await expect(args.onJobAction).toHaveBeenCalledWith("force_stop", { confirmForceStop: true });
  },
};

export const BufferedNumberFlowPlay: Story = {
  args: {
    job: sampleJob,
    events: sampleEvents,
    jobDraft: defaultDraft,
    runModeAvailability: defaultRunModeAvailability,
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
          runModeAvailability={defaultRunModeAvailability}
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
    await userEvent.click(canvas.getByRole("button", { name: "更新限制" }));
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

export const HeadlessOnlyRunModePlay: Story = {
  args: {
    job: { ...sampleJob, runModeAvailability: headlessOnlyAvailability },
    events: sampleEvents,
    jobDraft: { ...defaultDraft, runMode: "headless" },
    runModeAvailability: headlessOnlyAvailability,
    extractorAvailability: sampleExtractorSettings.availability,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText(/当前环境仅支持/)).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("combobox", { name: /run mode/i }));
    await expect(within(document.body).queryByRole("option", { name: "headed" })).toBeNull();
    await expect(within(document.body).getByRole("option", { name: "headless" })).toBeInTheDocument();
  },
};
