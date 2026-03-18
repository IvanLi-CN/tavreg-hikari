import type { Meta, StoryObj } from "@storybook/react-vite";
import { StatusBadge } from "@/components/status-badge";

const meta = {
  title: "UI/StatusBadge",
  component: StatusBadge,
  tags: ["autodocs"],
} satisfies Meta<typeof StatusBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Gallery: Story = {
  args: {
    status: "ready",
  },
  render: () => (
    <div className="flex flex-wrap gap-3 p-6">
      <StatusBadge status="ready" />
      <StatusBadge status="running" />
      <StatusBadge status="paused" />
      <StatusBadge status="failed" />
      <StatusBadge status="active" />
    </div>
  ),
};
