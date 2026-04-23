import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, within } from "storybook/test";
import { SiteKeysView } from "@/components/site-keys-view";
import { TavilyKeysPane } from "@/components/keys-view";
import { sampleApiKeys } from "@/stories/fixtures";

const meta = {
  title: "Views/SiteKeysView",
  component: SiteKeysView,
  tags: ["autodocs"],
  args: {
    siteLabel: "Tavily",
    onBack: fn(),
  },
} satisfies Meta<typeof SiteKeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const CompactHeader: Story = {
  args: {
    siteLabel: "Tavily",
    onBack: fn(),
    children: null,
  },
  render: (args) => (
    <SiteKeysView {...args}>
      <TavilyKeysPane
        apiKeys={sampleApiKeys}
        query={{ q: "", status: "", groupName: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 }}
        selectedIds={[]}
        exportOpen={false}
        exportContent=""
        exportBusy={false}
        onQueryChange={fn()}
        onToggleSelection={fn()}
        onTogglePageSelection={fn()}
        onClearSelection={fn()}
        onOpenExport={fn()}
        onExportOpenChange={fn()}
        onCopyExport={fn()}
        onSaveExport={fn()}
      />
    </SiteKeysView>
  ),
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("button", { name: "返回任务控制" })).toBeInTheDocument();
    await expect(canvas.getByText("查看 Tavily Keys")).toBeInTheDocument();
    await expect(canvas.queryByText(/站内|子视图/)).toBeNull();
  },
};
