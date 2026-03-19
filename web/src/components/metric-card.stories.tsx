import type { Meta, StoryObj } from "@storybook/react-vite";
import { MetricCard } from "@/components/metric-card";

const meta = {
  title: "UI/MetricCard",
  component: MetricCard,
  tags: ["autodocs"],
} satisfies Meta<typeof MetricCard>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Gallery: Story = {
  args: {
    label: "成功 / 目标",
    value: "2 / 5",
  },
  render: () => (
    <div className="grid gap-4 p-6 md:grid-cols-4">
      <MetricCard label="成功 / 目标" value="2 / 5" tone="good" />
      <MetricCard label="并行 / 已发起" value="2 / 4" tone="warn" />
      <MetricCard label="状态" value="running" />
      <MetricCard label="异常" value="1" tone="bad" />
    </div>
  ),
};
