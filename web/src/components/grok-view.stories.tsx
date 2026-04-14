import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
import { GrokView } from "@/components/grok-view";
import type { JobDraft } from "@/lib/app-types";
import { normalizeJobDraft } from "@/lib/job-draft";
import { sampleGrokJob } from "@/stories/fixtures";

const defaultDraft: JobDraft = {
  runMode: "headed",
  need: 3,
  parallel: 2,
  maxAttempts: 5,
  autoExtractSources: [],
  autoExtractQuantity: 1,
  autoExtractMaxWaitSec: 60,
  autoExtractAccountType: "outlook",
};

function buildJob(status: NonNullable<typeof sampleGrokJob.job>["status"]) {
  return {
    ...sampleGrokJob,
    activeAttempts: status === "paused" || status === "running" ? sampleGrokJob.activeAttempts : [],
    job: sampleGrokJob.job
      ? {
          ...sampleGrokJob.job,
          status,
          pausedAt: status === "paused" ? "2026-04-10T03:16:00.000Z" : null,
          completedAt: ["completed", "failed", "stopped"].includes(status) ? "2026-04-10T03:20:00.000Z" : null,
        }
      : null,
  };
}

const meta = {
  title: "Views/GrokView",
  component: GrokView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "Grok 批量任务页，包含 runMode / need / parallel / maxAttempts 控制、attempt 历史与强停确认。",
      },
    },
  },
} satisfies Meta<typeof GrokView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Running: Story = {
  args: {
    job: sampleGrokJob,
    jobDraft: defaultDraft,
    jobBusy: false,
    onJobDraftChange: fn(),
    onJobAction: fn(),
  },
  render: () => {
    const [draft, setDraft] = useState<JobDraft>(defaultDraft);
    return (
      <GrokView
        job={sampleGrokJob}
        jobDraft={draft}
        jobBusy={false}
        onJobDraftChange={(patch) => setDraft((current) => normalizeJobDraft({ ...current, ...patch, autoExtractSources: [] }))}
        onJobAction={() => undefined}
      />
    );
  },
};

export const Idle: Story = {
  args: {
    job: {
      site: "grok",
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
      runModeAvailability: {
        headed: true,
        headless: true,
        headedReason: null,
      },
      cooldown: null,
    },
    jobDraft: { ...defaultDraft, runMode: "headless", need: 1, parallel: 1, maxAttempts: 3 },
    jobBusy: false,
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

export const Failed: Story = {
  args: {
    ...Running.args,
    job: buildJob("failed"),
  },
};

export const MailboxCooldown: Story = {
  args: {
    ...Idle.args,
    job: {
      site: "grok",
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
      runModeAvailability: {
        headed: true,
        headless: true,
        headedReason: null,
      },
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
