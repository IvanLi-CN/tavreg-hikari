import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import {
  ChatGptUpstreamSettingsDialog,
  type ChatGptUpstreamSettingsDialogDraft,
} from "@/components/chatgpt-upstream-settings-dialog";
import type { ChatGptUpstreamSettings } from "@/lib/app-types";

const sampleSettings: ChatGptUpstreamSettings = {
  baseUrl: "https://cvm.example.test",
  apiKeyMasked: "************abcd",
  hasApiKey: true,
  configured: true,
  groupHistory: ["sync-ready", "warm-pool", "hold"],
  baseUrlSource: "db",
  apiKeySource: "env",
};

const sampleDraft: ChatGptUpstreamSettingsDialogDraft = {
  baseUrl: sampleSettings.baseUrl,
  apiKey: "",
  clearBaseUrl: false,
  clearApiKey: false,
};

const meta = {
  title: "Dialogs/ChatGptUpstreamSettingsDialog",
  component: ChatGptUpstreamSettingsDialog,
  tags: ["autodocs"],
} satisfies Meta<typeof ChatGptUpstreamSettingsDialog>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    open: true,
    settings: sampleSettings,
    draft: sampleDraft,
    saveBusy: false,
    error: null,
    onOpenChange: fn(),
    onDraftChange: fn(),
    onSave: fn(),
  },
};

export const InteractivePlay: Story = {
  args: {
    ...Default.args,
  },
  render: () => {
    const [draft, setDraft] = useState(sampleDraft);
    return (
      <ChatGptUpstreamSettingsDialog
        open
        settings={sampleSettings}
        draft={draft}
        saveBusy={false}
        error={null}
        onOpenChange={() => undefined}
        onDraftChange={(patch) => setDraft((current) => ({ ...current, ...patch }))}
        onSave={() => undefined}
      />
    );
  },
  play: async () => {
    const dialog = within(document.body).getByTestId("chatgpt-upstream-settings-dialog");
    await userEvent.clear(within(dialog).getByRole("textbox", { name: /Base URL 覆盖/i }));
    await userEvent.type(within(dialog).getByRole("textbox", { name: /Base URL 覆盖/i }), "https://override.example.test");
    await expect(within(dialog).getByDisplayValue("https://override.example.test")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "改回环境默认" }));
    await expect(within(dialog).getByText(/保存后会移除当前 Web Base URL 覆盖/)).toBeInTheDocument();
  },
};
