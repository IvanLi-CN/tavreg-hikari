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
        component: "API key 查询页，只展示 key 视角的数据和状态。",
      },
    },
  },
} satisfies Meta<typeof ApiKeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    apiKeys: sampleApiKeys,
    query: { q: "", status: "", page: 1, pageSize: 20 },
    onQueryChange: fn(),
  },
};

export const Empty: Story = {
  args: {
    apiKeys: { rows: [], total: 0, page: 1, pageSize: 20 },
    query: { q: "", status: "", page: 1, pageSize: 20 },
    onQueryChange: fn(),
  },
};
