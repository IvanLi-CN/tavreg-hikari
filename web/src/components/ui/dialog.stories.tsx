import type { Meta, StoryObj } from "@storybook/react-vite";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

const meta = {
  title: "UI/Dialog",
  component: Dialog,
  tags: ["autodocs"],
} satisfies Meta<typeof Dialog>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  render: () => (
    <Dialog>
      <DialogTrigger asChild>
        <Button>打开弹窗</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>导入预览</DialogTitle>
          <DialogDescription>这里展示解析后的账号、重复判断和导入决策。</DialogDescription>
        </DialogHeader>
        <div className="px-6 py-2 text-sm text-slate-300">new@outlook.com 将被新增到 default 分组。</div>
        <DialogFooter>
          <Button variant="secondary">取消</Button>
          <Button>确认导入</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  ),
};
