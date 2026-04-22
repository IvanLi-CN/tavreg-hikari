import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ForceStopDialog } from "@/components/force-stop-dialog";
import { Button } from "@/components/ui/button";

const meta = {
  title: "Components/ForceStopDialog",
  component: ForceStopDialog,
  tags: ["autodocs"],
  args: {
    open: true,
    taskLabel: "ChatGPT",
    scopeLabel: "当前任务",
    onOpenChange: fn(),
    onConfirm: fn(),
  },
  parameters: {
    docs: {
      description: {
        component: "统一的强制停止危险确认弹窗，用于主流程、ChatGPT 与 Grok 控制区。",
      },
    },
  },
} satisfies Meta<typeof ForceStopDialog>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {};

export const GenericScope: Story = {
  args: {
    taskLabel: undefined,
    scopeLabel: "当前任务和补号请求",
  },
};

export const Interactive: Story = {
  args: {
    open: false,
    onOpenChange: fn(),
    onConfirm: fn(),
  },
  render: (args) => {
    const [open, setOpen] = useState(false);
    return (
      <div className="min-h-[18rem] bg-[#07111f] p-6">
        <Button onClick={() => setOpen(true)}>打开强停确认</Button>
        <ForceStopDialog
          {...args}
          open={open}
          onOpenChange={(nextOpen) => {
            setOpen(nextOpen);
            args.onOpenChange(nextOpen);
          }}
          onConfirm={() => {
            args.onConfirm();
          }}
        />
      </div>
    );
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);

    await userEvent.click(canvas.getByRole("button", { name: "打开强停确认" }));
    await expect(within(document.body).getByRole("dialog", { name: "立即强制停止 ChatGPT 任务？" })).toBeInTheDocument();

    await userEvent.click(within(document.body).getByRole("button", { name: "返回" }));
    await expect(args.onOpenChange).toHaveBeenCalledWith(false);

    await userEvent.click(canvas.getByRole("button", { name: "打开强停确认" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "强制停止" }));
    await expect(args.onConfirm).toHaveBeenCalled();
  },
};
