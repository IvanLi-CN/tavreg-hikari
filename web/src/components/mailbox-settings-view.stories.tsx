import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { MailboxSettingsView } from "@/components/mailbox-settings-view";
import { sampleMicrosoftGraphSettings } from "@/stories/fixtures";

const meta = {
  title: "Views/MailboxSettingsView",
  component: MailboxSettingsView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "微软邮箱的独立 Graph 设置页，用于维护 Client ID、Client Secret、Redirect URI 和 authority。",
      },
    },
  },
} satisfies Meta<typeof MailboxSettingsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Configured: Story = {
  args: {
    settings: sampleMicrosoftGraphSettings,
    settingsDraft: {
      microsoftGraphClientId: sampleMicrosoftGraphSettings.microsoftGraphClientId,
      microsoftGraphClientSecret: "",
      microsoftGraphRedirectUri: sampleMicrosoftGraphSettings.microsoftGraphRedirectUri,
      microsoftGraphAuthority: sampleMicrosoftGraphSettings.microsoftGraphAuthority,
    },
    settingsBusy: false,
    onSettingsDraftChange: fn(),
    onSaveSettings: fn(async () => undefined),
    onBack: fn(),
  },
};

export const PendingSetup: Story = {
  args: {
    settings: {
      ...sampleMicrosoftGraphSettings,
      configured: false,
      microsoftGraphClientSecretMasked: "",
    },
    settingsDraft: {
      microsoftGraphClientId: "",
      microsoftGraphClientSecret: "",
      microsoftGraphRedirectUri: "",
      microsoftGraphAuthority: "common",
    },
    settingsBusy: false,
    onSettingsDraftChange: fn(),
    onSaveSettings: fn(async () => undefined),
    onBack: fn(),
  },
};

export const SavePlay: Story = {
  args: {
    settings: sampleMicrosoftGraphSettings,
    settingsDraft: {
      microsoftGraphClientId: sampleMicrosoftGraphSettings.microsoftGraphClientId,
      microsoftGraphClientSecret: "",
      microsoftGraphRedirectUri: sampleMicrosoftGraphSettings.microsoftGraphRedirectUri,
      microsoftGraphAuthority: sampleMicrosoftGraphSettings.microsoftGraphAuthority,
    },
    settingsBusy: false,
    onSettingsDraftChange: fn(),
    onSaveSettings: fn(async () => undefined),
    onBack: fn(),
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("独立设置页")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "保存 Graph 设置" }));
  },
};
