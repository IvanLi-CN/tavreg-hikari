import type { Meta, StoryObj } from "@storybook/react-vite";
import { Input } from "@/components/ui/input";

const meta = {
  title: "UI/Input",
  component: Input,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "用于搜索、配置项编辑和数值输入的标准输入框。",
      },
    },
  },
} satisfies Meta<typeof Input>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    placeholder: "输入邮箱或前缀",
  },
};

export const Disabled: Story = {
  args: {
    value: "https://example.com/subscription.yaml",
    disabled: true,
  },
};
