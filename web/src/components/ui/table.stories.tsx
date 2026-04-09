import type { Meta, StoryObj } from "@storybook/react-vite";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const meta = {
  title: "UI/Table",
  component: Table,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "标准表格语义组件，替代原先逐格圆角卡片式布局。",
      },
    },
  },
} satisfies Meta<typeof Table>;

export default meta;
type Story = StoryObj<typeof meta>;

export const AccountGrid: Story = {
  render: () => (
    <div className="p-6">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>邮箱</TableHead>
            <TableHead>状态</TableHead>
            <TableHead>导入时间</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell className="break-all">alpha@example.test</TableCell>
            <TableCell>ready</TableCell>
            <TableCell>2026/3/18 15:38:08</TableCell>
          </TableRow>
          <TableRow>
            <TableCell className="break-all">beta@example.test</TableCell>
            <TableCell>succeeded</TableCell>
            <TableCell>2026/3/18 15:39:12</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>
  ),
};
