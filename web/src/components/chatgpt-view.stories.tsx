import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptView } from "@/components/chatgpt-view";
import type { ChatGptCredentialRecord, ChatGptDraft, JobSnapshot } from "@/lib/app-types";

const sampleDraft: ChatGptDraft = {
  email: "nova123@mail.707979.xyz",
  password: "Pw8$hikariDemo19",
  nickname: "Nova318",
  birthDate: "1998-07-14",
  mailboxId: "mailbox-demo-318",
  generatedAt: "2026-04-05T09:30:00.000Z",
};

const sampleJob: JobSnapshot = {
  site: "chatgpt",
  job: {
    id: 41,
    status: "running",
    runMode: "headed",
    need: 1,
    parallel: 1,
    maxAttempts: 1,
    successCount: 0,
    failureCount: 0,
    skipCount: 0,
    launchedCount: 1,
    autoExtractSources: [],
    autoExtractQuantity: 0,
    autoExtractMaxWaitSec: 0,
    autoExtractAccountType: "outlook",
    startedAt: "2026-04-05T09:32:00.000Z",
    pausedAt: null,
    completedAt: null,
    lastError: null,
  },
  activeAttempts: [
    {
      id: 104,
      accountId: null,
      accountEmail: sampleDraft.email,
      status: "running",
      stage: "otp_verify",
      proxyNode: "Tokyo-01",
      proxyIp: "203.0.113.24",
      errorCode: null,
      errorMessage: null,
      startedAt: "2026-04-05T09:32:10.000Z",
      completedAt: null,
    },
  ],
  recentAttempts: [],
  eligibleCount: 0,
  autoExtractState: null,
};

const sampleCredentials: ChatGptCredentialRecord[] = [
  {
    id: 17,
    jobId: 39,
    attemptId: 99,
    email: "sample@mail.707979.xyz",
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
      email: "sample@mail.707979.xyz",
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
        component: "ChatGPT 单账号有头浏览器流，聚焦默认草稿、任务状态和完整凭据 reveal/export。",
      },
    },
  },
} satisfies Meta<typeof ChatGptView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Running: Story = {
  args: {
    draft: sampleDraft,
    job: sampleJob,
    credentials: sampleCredentials,
    revealedCredential: revealedCredential,
    draftBusy: false,
    jobBusy: false,
    credentialBusy: false,
    onDraftChange: fn(),
    onRegenerateDraft: fn(),
    onStart: fn(),
    onStop: fn(),
    onForceStop: fn(),
    onRevealCredential: fn(),
    onCopyCredential: fn(),
    onExportCredential: fn(),
  },
};

export const Empty: Story = {
  args: {
    ...Running.args,
    draft: sampleDraft,
    job: {
      site: "chatgpt",
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
    },
    credentials: [],
    revealedCredential: null,
  },
};

export const InteractiveDraft: Story = {
  args: {
    ...Running.args,
  },
  render: () => {
    const [draft, setDraft] = useState(sampleDraft);
    const [revealed, setRevealed] = useState<ChatGptCredentialRecord | null>(null);
    return (
      <ChatGptView
        draft={draft}
        job={{ ...sampleJob, job: null, activeAttempts: [], recentAttempts: [] }}
        credentials={sampleCredentials}
        revealedCredential={revealed}
        draftBusy={false}
        jobBusy={false}
        credentialBusy={false}
        onDraftChange={(patch) => setDraft((current) => ({ ...current, ...patch }))}
        onRegenerateDraft={() => undefined}
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
    await userEvent.type(canvas.getByLabelText("昵称"), "A");
    await expect(canvas.getByDisplayValue("Nova318A")).toBeTruthy();
    await userEvent.click(canvas.getByRole("button", { name: "显示凭据" }));
    await expect(canvas.getByDisplayValue(/access-token-demo/)).toBeTruthy();
  },
};
