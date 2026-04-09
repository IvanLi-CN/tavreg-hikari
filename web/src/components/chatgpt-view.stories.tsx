import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptView } from "@/components/chatgpt-view";
import type { ChatGptCredentialRecord, ChatGptJobDraft, JobSnapshot } from "@/lib/app-types";

const sampleJobDraft: ChatGptJobDraft = {
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
      accountEmail: "mail-a72f3d18@box-3189a6b1.ivanli.asia",
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
      accountEmail: "mail-c4917e0b@box-4df1be91.ivanli.asia",
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
      accountEmail: "mail-0cb2f761@box-90ce7a14.ivanli.asia",
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
};

const sampleCredentials: ChatGptCredentialRecord[] = [
  {
    id: 17,
    jobId: 39,
    attemptId: 99,
    email: "mail-43c9fc87@box-79818a03.ivanli.asia",
    accountId: "acc-demo-17",
    accessTokenMasked: "*********************9NjG2Q",
    refreshTokenMasked: "*********************Zp4mLK",
    idTokenMasked: "*********************2Vh9sd",
    expiresAt: "2026-04-05T16:10:00.000Z",
    createdAt: "2026-04-05T09:10:00.000Z",
    hasSecrets: true,
  },
];

const revealedCredential: ChatGptCredentialRecord = {
  ...sampleCredentials[0]!,
  accessToken: "access-token-demo",
  refreshToken: "refresh-token-demo",
  idToken: "id-token-demo",
  credentialJson: JSON.stringify(
    {
      type: "codex",
      email: "mail-43c9fc87@box-79818a03.ivanli.asia",
      account_id: "acc-demo-17",
      expired: "2026-04-05T16:10:00.000Z",
      access_token: "access-token-demo",
      refresh_token: "refresh-token-demo",
      id_token: "id-token-demo",
      last_refresh: "2026-04-05T09:10:00.000Z",
      token_type: "Bearer",
    },
    null,
    2,
  ),
};

const meta = {
  title: "Views/ChatGptView",
  component: ChatGptView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "ChatGPT 批量有头浏览器流，聚焦自动生成 attempt 资料、批量任务控制、运行中的多 attempt 与完整凭据 reveal/export。",
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
    credentials: sampleCredentials,
    revealedCredential,
    jobBusy: false,
    credentialBusy: false,
    onJobDraftChange: fn(),
    onStart: fn(),
    onStop: fn(),
    onForceStop: fn(),
    onRevealCredential: fn(),
    onCopyCredential: fn(),
    onExportCredential: fn(),
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
      cooldown: null,
    },
    credentials: [],
    revealedCredential: null,
  },
};

export const InteractiveBatchControls: Story = {
  args: {
    ...BatchRunning.args,
  },
  render: () => {
    const [batchDraft, setBatchDraft] = useState(sampleJobDraft);
    const [revealed, setRevealed] = useState<ChatGptCredentialRecord | null>(null);
    return (
      <ChatGptView
        jobDraft={batchDraft}
        job={{ ...sampleJob, job: null, activeAttempts: [], recentAttempts: [] }}
        credentials={sampleCredentials}
        revealedCredential={revealed}
        jobBusy={false}
        credentialBusy={false}
        onJobDraftChange={(patch) => setBatchDraft((current) => ({ ...current, ...patch }))}
        onStart={() => undefined}
        onStop={() => undefined}
        onForceStop={() => undefined}
        onRevealCredential={() => setRevealed(revealedCredential)}
        onCopyCredential={() => undefined}
        onExportCredential={() => undefined}
      />
    );
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.clear(canvas.getByLabelText("Need"));
    await userEvent.type(canvas.getByLabelText("Need"), "4");
    await userEvent.tab();
    await expect(canvas.getByDisplayValue("4")).toBeTruthy();
    await userEvent.click(canvas.getByRole("button", { name: "显示凭据" }));
    await expect(canvas.getByDisplayValue(/access-token-demo/)).toBeTruthy();
  },
};
