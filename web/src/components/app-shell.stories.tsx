import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { AppShell } from "@/components/app-shell";
import type { PageKey } from "@/lib/app-types";

const meta = {
  title: "Shell/AppShell",
  component: AppShell,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "管理台顶层壳层，负责品牌头部、分段导航和全局错误条。",
      },
    },
  },
} satisfies Meta<typeof AppShell>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    activePage: "tavily",
    error: null,
    onNavigate: fn(),
    children: null,
  },
  render: (args) => {
    const [page, setPage] = useState<PageKey>(args.activePage);
    return (
      <AppShell {...args} activePage={page} onNavigate={setPage}>
        <div className="rounded-[32px] border border-white/10 bg-[#09111f]/80 p-8 text-sm text-slate-300">
          {page} content
        </div>
      </AppShell>
    );
  },
};

export const KeysActive: Story = {
  args: {
    activePage: "keys",
    error: null,
    onNavigate: fn(),
    children: null,
  },
  render: (args) => {
    const [page, setPage] = useState<PageKey>(args.activePage);
    return (
      <AppShell {...args} activePage={page} onNavigate={setPage}>
        <div className="rounded-[32px] border border-white/10 bg-[#09111f]/80 p-8 text-sm text-slate-300">
          {page} content
        </div>
      </AppShell>
    );
  },
};

export const NavigationPlay: Story = {
  args: {
    activePage: "tavily",
    error: null,
    onNavigate: fn(),
    children: null,
  },
  render: (args) => {
    return (
      <AppShell {...args}>
        <div className="rounded-[32px] border border-white/10 bg-[#09111f]/80 p-8 text-sm text-slate-300">
          tavily content
        </div>
      </AppShell>
    );
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("tab", { name: "Keys" })).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("tab", { name: "Keys" }));
    await expect(args.onNavigate).toHaveBeenCalledWith("keys");
  },
};
