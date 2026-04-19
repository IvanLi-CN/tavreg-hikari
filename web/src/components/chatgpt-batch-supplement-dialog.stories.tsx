import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptBatchSupplementDialog } from "@/components/chatgpt-batch-supplement-dialog";
import type { ChatGptCredentialSupplementPayload } from "@/lib/app-types";

const defaultResult: ChatGptCredentialSupplementPayload = {
  ok: true,
  groupName: "sync-ready",
  requested: 2,
  succeeded: 1,
  failed: 1,
  results: [
    {
      credentialId: 17,
      email: "nova.alpha@mail.example.test",
      accountId: "acc-demo-17",
      groupName: "sync-ready",
      success: false,
      message: "missing accountId",
    },
    {
      credentialId: 18,
      email: "nova.beta@mail.example.test",
      accountId: "acc-demo-18",
      groupName: "sync-ready",
      success: true,
      message: "ok",
    },
  ],
};

const meta = {
  title: "Dialogs/ChatGptBatchSupplementDialog",
  component: ChatGptBatchSupplementDialog,
  tags: ["autodocs"],
} satisfies Meta<typeof ChatGptBatchSupplementDialog>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    open: true,
    selectedCount: 2,
    groupOptions: ["sync-ready", "warm-pool", "hold"],
    groupName: "sync-ready",
    busy: false,
    configured: true,
    result: defaultResult,
    onOpenChange: fn(),
    onGroupNameChange: fn(),
    onSubmit: fn(),
  },
};

export const NeedsConfiguration: Story = {
  args: {
    ...Default.args,
    configured: false,
    result: null,
    groupName: "",
  },
};

export const InteractivePlay: Story = {
  args: {
    ...Default.args,
    result: null,
    groupName: "",
  },
  render: () => {
    const [groupName, setGroupName] = useState("");
    const [result, setResult] = useState<ChatGptCredentialSupplementPayload | null>(null);
    return (
      <ChatGptBatchSupplementDialog
        open
        selectedCount={2}
        groupOptions={["sync-ready", "warm-pool", "hold"]}
        groupName={groupName}
        busy={false}
        configured
        result={result}
        onOpenChange={() => undefined}
        onGroupNameChange={setGroupName}
        onSubmit={() =>
          setResult({
            ok: true,
            groupName: groupName || "sync-ready",
            requested: 2,
            succeeded: 2,
            failed: 0,
            results: [],
          })
        }
      />
    );
  },
  play: async () => {
    const dialog = within(document.body).getByRole("dialog", { name: "批量补号" });
    await userEvent.click(within(dialog).getByRole("button", { name: "不补号" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "warm-pool" }));
    await userEvent.click(within(dialog).getByRole("button", { name: /补号 2 条/ }));
    await expect(within(dialog).getByText(/当前批次全部补号成功/)).toBeInTheDocument();
  },
};
