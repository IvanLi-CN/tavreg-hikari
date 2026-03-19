import type { Meta, StoryObj } from "@storybook/react-vite";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const meta = {
  title: "UI/Card",
  component: Card,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "控制台所有大模块统一使用的面板容器。",
      },
    },
  },
} satisfies Meta<typeof Card>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  render: () => (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle>节点列表</CardTitle>
        <CardDescription>查看节点延迟、出口 IP 与近 24 小时成功提 key 数量。</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="rounded-3xl border border-white/8 bg-white/[0.03] p-4 text-sm text-slate-300">
          面板内容示意
        </div>
      </CardContent>
    </Card>
  ),
};
