import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, within } from "storybook/test";
import { CopyIconButton, type CopyButtonStatus } from "@/components/ui/copy-icon-button";
import { cn } from "@/lib/utils";

type BubbleCase = {
  id: string;
  title: string;
  subject: string;
  status: Exclude<CopyButtonStatus, "idle">;
  size?: "default" | "compact" | "dense";
  feedbackValue: string;
  previewValue?: string;
  successMessage?: string;
  failureMessage?: string;
};

type TailCase = {
  id: string;
  title: string;
  side: "top" | "right" | "bottom" | "left";
  status: Exclude<CopyButtonStatus, "idle">;
  feedbackValue: string;
  previewValue?: string;
  subject: string;
  successMessage?: string;
  failureMessage?: string;
};

const bubbleCases: BubbleCase[] = [
  {
    id: "success-default",
    title: "成功 / Default",
    subject: "用户名",
    status: "copied",
    size: "default",
    feedbackValue: "Beta",
    successMessage: "用户名已复制到剪贴板。",
  },
  {
    id: "failure-default",
    title: "失败 / Default",
    subject: "邮箱地址",
    status: "failed",
    size: "default",
    feedbackValue: "beta@example.test",
    previewValue: "beta@example…",
    failureMessage: "请手动复制邮箱地址。",
  },
  {
    id: "success-compact",
    title: "成功 / Compact",
    subject: "密码",
    status: "copied",
    size: "compact",
    feedbackValue: "pass-456",
    successMessage: "密码已复制。",
  },
  {
    id: "failure-compact",
    title: "失败 / Compact",
    subject: "辅助邮箱",
    status: "failed",
    size: "compact",
    feedbackValue: "backup@example.test",
    previewValue: "backup@example…",
    failureMessage: "请手动复制辅助邮箱。",
  },
  {
    id: "success-dense",
    title: "成功 / Dense",
    subject: "微软用户名",
    status: "copied",
    size: "dense",
    feedbackValue: "Archimedes Wilma",
    previewValue: "Archimedes…",
    successMessage: "微软用户名已复制到剪贴板。",
  },
  {
    id: "failure-dense",
    title: "失败 / Dense",
    subject: "邀请码",
    status: "failed",
    size: "dense",
    feedbackValue: "INV-2026-0419",
    previewValue: "INV-2026…",
    failureMessage: "请手动复制邀请码。",
  },
];

const tailCases: TailCase[] = [
  {
    id: "tail-top",
    title: "尾巴方向 / Top",
    side: "top",
    status: "copied",
    subject: "用户名",
    feedbackValue: "Beta",
    successMessage: "用户名已复制。",
  },
  {
    id: "tail-right",
    title: "尾巴方向 / Right",
    side: "right",
    status: "failed",
    subject: "邮箱地址",
    feedbackValue: "beta@x.io",
    previewValue: "beta@x…",
    failureMessage: "请手动复制邮箱。",
  },
  {
    id: "tail-bottom",
    title: "尾巴方向 / Bottom",
    side: "bottom",
    status: "copied",
    subject: "密码",
    feedbackValue: "pass-456",
    successMessage: "密码已复制。",
  },
  {
    id: "tail-left",
    title: "尾巴方向 / Left",
    side: "left",
    status: "failed",
    subject: "邀请码",
    feedbackValue: "INV-20419",
    previewValue: "INV-20419",
    failureMessage: "请手动复制邀请码。",
  },
];

function LiveTrigger({
  item,
  container,
  side,
  mode = "card",
}: {
  item: BubbleCase | TailCase;
  container: HTMLElement | null;
  side: "top" | "right" | "bottom" | "left";
  mode?: "card" | "icon";
}) {
  if (mode === "icon") {
    return (
      <div className="inline-flex items-center gap-3 rounded-2xl border border-white/10 bg-slate-950/55 px-3 py-2 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
        <div className="text-sm text-slate-400">{item.subject}</div>
        <CopyIconButton
          label={item.subject}
          feedbackSubject={item.subject}
          copyStatus={item.status}
          feedbackValue={item.feedbackValue}
          successMessage={item.successMessage}
          failureMessage={item.failureMessage}
          size={"size" in item ? item.size : undefined}
          onCopy={() => undefined}
          forceFeedbackOpen
          feedbackSide={side}
          feedbackAlign="center"
          feedbackAvoidCollisions={false}
          feedbackPortalContainer={container}
        />
      </div>
    );
  }

  return (
    <div className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-slate-950/55 px-3 py-2 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <div className="min-w-0">
        <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">{item.subject}</div>
        <div className="truncate text-lg font-semibold text-white">{item.previewValue || item.feedbackValue}</div>
      </div>
      <CopyIconButton
        label={item.subject}
        feedbackSubject={item.subject}
        copyStatus={item.status}
        feedbackValue={item.feedbackValue}
        successMessage={item.successMessage}
        failureMessage={item.failureMessage}
        size={"size" in item ? item.size : undefined}
        onCopy={() => undefined}
        forceFeedbackOpen
        feedbackSide={side}
        feedbackAlign="center"
        feedbackAvoidCollisions={false}
        feedbackPortalContainer={container}
      />
    </div>
  );
}

function LiveBubbleSpecimen({
  item,
  side,
  mode = "card",
}: {
  item: BubbleCase | TailCase;
  side: "top" | "right" | "bottom" | "left";
  mode?: "card" | "icon";
}) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null);

  return (
    <div ref={setContainer} className="relative min-h-[13rem] overflow-hidden rounded-[20px] border border-dashed border-white/10 bg-slate-950/35 p-4">
      <div
        className={cn(
          "absolute",
          mode === "card" && side === "bottom" && "left-6 top-5",
          mode === "card" && side === "top" && "bottom-6 right-12",
          mode === "card" && side === "right" && "left-10 top-1/2 -translate-y-1/2",
          mode === "card" && side === "left" && "right-10 top-1/2 -translate-y-1/2",
          mode === "icon" && side === "bottom" && "left-1/2 top-12 -translate-x-1/2",
          mode === "icon" && side === "top" && "left-1/2 bottom-12 -translate-x-1/2",
          mode === "icon" && side === "right" && "left-14 top-1/2 -translate-y-1/2",
          mode === "icon" && side === "left" && "right-14 top-1/2 -translate-y-1/2",
        )}
      >
        <LiveTrigger item={item} container={container} side={side} mode={mode} />
      </div>
    </div>
  );
}

function BubbleMatrixSurface() {
  return (
    <div className="min-h-dvh overflow-x-hidden bg-[radial-gradient(circle_at_top,_rgba(56,189,248,0.14),_transparent_35%),linear-gradient(180deg,#0f172a,#020617)] p-6 text-white sm:p-8">
      <div className="mx-auto max-w-6xl rounded-[28px] border border-white/10 bg-slate-950/70 p-5 shadow-[0_24px_60px_rgba(2,6,23,0.46)] sm:p-6">
        <div className="mb-8 space-y-2">
          <div className="text-xs uppercase tracking-[0.24em] text-cyan-300/80">Copy Feedback</div>
          <h1 className="text-2xl font-semibold">复制气泡形态总览</h1>
          <p className="max-w-3xl text-sm leading-6 text-slate-400">
            这里直接渲染真实组件实例，尾巴与定位全部由第三方库负责，不再使用伪造的静态气泡示意图。
          </p>
        </div>

        <section className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-white">状态矩阵</h2>
            <p className="mt-1 text-sm text-slate-400">统一使用向下展开，集中验证 success / failure / 密度变化。</p>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            {bubbleCases.map((item) => (
              <div key={item.id} className="rounded-[24px] border border-white/8 bg-white/[0.03] p-5">
                <div className="mb-4 text-sm font-medium text-slate-200">{item.title}</div>
                <LiveBubbleSpecimen item={item} side="bottom" />
              </div>
            ))}
          </div>
        </section>

        <section className="mt-10 space-y-4">
          <div>
            <h2 className="text-lg font-semibold text-white">尾巴方向验证</h2>
            <p className="mt-1 text-sm text-slate-400">使用真实组件分别验证 top / right / bottom / left 四个方向。</p>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            {tailCases.map((item) => (
              <div key={item.id} className="rounded-[24px] border border-white/8 bg-white/[0.03] p-5">
                <div className="mb-4 text-sm font-medium text-slate-200">{item.title}</div>
                <LiveBubbleSpecimen item={item} side={item.side} mode="icon" />
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

const meta = {
  title: "UI/CopyIconButton",
  component: CopyIconButton,
  tags: ["autodocs"],
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        component: "复制图标按钮的独立 Story：直接渲染真实 CopyIconButton + Popover 组合，集中验证气泡定位、箭头和反馈内容。",
      },
    },
  },
  args: {
    label: "邮箱地址",
    feedbackSubject: "邮箱地址",
    copyStatus: "idle",
    feedbackValue: "alpha@example.test",
    onCopy: () => undefined,
  },
} satisfies Meta<typeof CopyIconButton>;

export default meta;

type Story = StoryObj<typeof meta>;

export const StatesMatrix: Story = {
  render: () => <BubbleMatrixSurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("复制气泡形态总览")).toBeInTheDocument();
    await expect(canvas.getByText("状态矩阵")).toBeInTheDocument();
    await expect(canvas.getByText("尾巴方向验证")).toBeInTheDocument();
    await expect(canvas.getByText("成功 / Default")).toBeInTheDocument();
    await expect(canvas.getByText("尾巴方向 / Left")).toBeInTheDocument();
  },
};
