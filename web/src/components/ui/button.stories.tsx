import type { Meta, StoryObj } from "@storybook/react-vite";
import { Download, RefreshCcw } from "lucide-react";
import { Button } from "@/components/ui/button";

const meta = {
  title: "UI/Button",
  component: Button,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "主控制台的主按钮、次按钮与轮廓按钮。",
      },
    },
  },
  args: {
    children: "执行操作",
  },
} satisfies Meta<typeof Button>;

export default meta;

type Story = StoryObj<typeof meta>;

export const Default: Story = {};

export const Variants: Story = {
  render: () => (
    <div className="flex flex-wrap gap-3 p-6">
      <Button>启动流程</Button>
      <Button variant="secondary">暂停流程</Button>
      <Button variant="outline">检查节点</Button>
      <Button variant="ghost">查看详情</Button>
    </div>
  ),
};

export const WithIcons: Story = {
  render: () => (
    <div className="flex flex-wrap gap-3 p-6">
      <Button><RefreshCcw className="size-4" />同步节点</Button>
      <Button variant="outline"><Download className="size-4" />导出快照</Button>
    </div>
  ),
};
