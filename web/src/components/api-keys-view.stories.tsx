import type { Meta, StoryObj } from "@storybook/react-vite";
import { ApiKeysView } from "@/components/api-keys-view";
import { sampleApiKeys } from "@/stories/fixtures";
import { fn } from "storybook/test";

const meta = {
  title: "Views/ApiKeysView",
  component: ApiKeysView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "Artifacts 查询页，同时展示 Tavily API key 与 ChatGPT access token 的脱敏预览。",
      },
    },
  },
} satisfies Meta<typeof ApiKeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    apiKeys: sampleApiKeys,
    query: { q: "", status: "", target: "", artifactType: "", page: 1, pageSize: 20 },
    onQueryChange: fn(),
  },
};

export const Empty: Story = {
  args: {
    apiKeys: { rows: [], total: 0, page: 1, pageSize: 20, summary: { active: 0, revoked: 0 } },
    query: { q: "", status: "", target: "", artifactType: "", page: 1, pageSize: 20 },
    onQueryChange: fn(),
  },
};
