import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, userEvent, within } from "storybook/test";
import { GroupCombobox } from "@/components/group-combobox";

const meta = {
  title: "Components/GroupCombobox",
  component: GroupCombobox,
  tags: ["autodocs"],
  args: {
    groups: ["default", "linked", "failed-pool"],
    value: "",
    placeholder: "导入分组（可直接新建）",
    emptyLabel: "不设置分组",
    allowEmpty: true,
  },
} satisfies Meta<typeof GroupCombobox>;

export default meta;
type Story = StoryObj<typeof meta>;

const baseArgs = {
  groups: ["default", "linked", "failed-pool"],
  value: "",
  onChange: () => undefined,
  placeholder: "导入分组（可直接新建）",
  emptyLabel: "不设置分组",
  allowEmpty: true,
};

export const Default: Story = {
  args: baseArgs,
  render: (args) => {
    const [value, setValue] = useState("");
    return <GroupCombobox {...args} value={value} onChange={setValue} />;
  },
};

export const CreateNewGroupPlay: Story = {
  args: baseArgs,
  render: (args) => {
    const [value, setValue] = useState("");
    return <GroupCombobox {...args} value={value} onChange={setValue} />;
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "导入分组（可直接新建）" }));
    const textbox = within(document.body).getByPlaceholderText("搜索或输入新分组");
    await userEvent.type(textbox, "new-batch");
    await userEvent.click(within(document.body).getByRole("button", { name: /新建分组/ }));
    await expect(canvas.getByRole("button", { name: /new-batch/ })).toBeInTheDocument();
  },
};
