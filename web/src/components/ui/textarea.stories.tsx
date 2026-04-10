import type { Meta, StoryObj } from "@storybook/react-vite";
import { Textarea } from "@/components/ui/textarea";

const meta = {
  title: "UI/Textarea",
  component: Textarea,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "批量导入微软账号时使用的多行输入框。",
      },
    },
  },
} satisfies Meta<typeof Textarea>;

export default meta;
type Story = StoryObj<typeof meta>;

export const ImportFormat: Story = {
  args: {
    value: "alpha@example.test,password123\nbeta@example.test,password456",
    className: "min-h-56",
  },
};
