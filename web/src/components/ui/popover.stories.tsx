import type { Meta, StoryObj } from "@storybook/react-vite";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

const meta = {
  title: "UI/Popover",
  component: Popover,
  tags: ["autodocs"],
} satisfies Meta<typeof Popover>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  render: () => (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="secondary">打开浮层</Button>
      </PopoverTrigger>
      <PopoverContent>
        <div className="space-y-1 p-1">
          <div className="text-sm font-medium text-slate-100">分组面板</div>
          <div className="text-sm text-slate-400">这里可以搜索已有分组，或者直接创建新分组。</div>
        </div>
      </PopoverContent>
    </Popover>
  ),
};
