import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { AccountsView } from "@/components/accounts-view";
import type { AccountImportPreviewPayload, AccountQuery, AccountsPayload } from "@/lib/app-types";
import { sampleAccounts } from "@/stories/fixtures";

function createDefaultQuery(): AccountQuery {
  return { q: "", status: "", hasApiKey: "", groupName: "", page: 1, pageSize: 20 };
}

const previewFixture: AccountImportPreviewPayload = {
  summary: {
    parsed: 4,
    invalid: 1,
    create: 1,
    updatePassword: 1,
    keepExisting: 1,
    inputDuplicate: 1,
  },
  effectiveEntries: [
    { email: "new@outlook.com", password: "password321" },
    { email: "beta@outlook.com", password: "password789" },
  ],
  items: [
    {
      lineNumber: 1,
      rawLine: "new@outlook.com----password321",
      email: "new@outlook.com",
      normalizedEmail: "new@outlook.com",
      password: "password321",
      decision: "create",
      note: "新增账号",
    },
    {
      lineNumber: 2,
      rawLine: "beta@outlook.com password789",
      email: "beta@outlook.com",
      normalizedEmail: "beta@outlook.com",
      password: "password789",
      decision: "update_password",
      note: "已有账号，密码会更新；该账号已有 API key，后续调度仍会跳过",
      existingAccountId: 2,
      existingHasApiKey: true,
      groupName: "linked",
    },
    {
      lineNumber: 3,
      rawLine: "beta@outlook.com password000",
      email: "beta@outlook.com",
      normalizedEmail: "beta@outlook.com",
      password: "password000",
      decision: "input_duplicate",
      note: "同一批导入中邮箱重复，已以后出现的记录为准",
      duplicateOfLine: 2,
    },
    {
      lineNumber: 4,
      rawLine: "gamma@outlook.com pass-111",
      email: "gamma@outlook.com",
      normalizedEmail: "gamma@outlook.com",
      password: "pass-111",
      decision: "keep_existing",
      note: "已有账号且密码未变",
      existingAccountId: 3,
      existingHasApiKey: false,
      groupName: "failed-pool",
    },
    {
      lineNumber: 5,
      rawLine: "bad-line",
      email: "",
      normalizedEmail: "",
      password: "",
      decision: "invalid",
      note: "未识别到邮箱",
    },
  ],
};

const baseArgs = {
  accounts: sampleAccounts,
  importContent: "",
  importGroupName: "",
  batchGroupName: "",
  preview: null,
  previewOpen: false,
  query: createDefaultQuery(),
  selectedIds: [],
  importBusy: false,
  previewBusy: false,
  batchBusy: false,
  allCurrentPageSelected: false,
  onImportContentChange: fn(),
  onImportGroupChange: fn(),
  onBatchGroupNameChange: fn(),
  onOpenPreview: fn(),
  onPreviewOpenChange: fn(),
  onConfirmImport: fn(),
  onQueryChange: fn(),
  onToggleSelection: fn(),
  onTogglePageSelection: fn(),
  onApplyBatchGroup: fn(),
  onDeleteSelected: fn(),
  onClearSelection: fn(),
};

function AccountsStorySurface(props: {
  accounts?: AccountsPayload;
  preview?: AccountImportPreviewPayload | null;
  previewOpen?: boolean;
  importBusy?: boolean;
  previewBusy?: boolean;
  batchBusy?: boolean;
}) {
  const [content, setContent] = useState("");
  const [importGroupName, setImportGroupName] = useState("");
  const [batchGroupName, setBatchGroupName] = useState("");
  const [query, setQuery] = useState<AccountQuery>(createDefaultQuery());
  const [selectedIds, setSelectedIds] = useState<number[]>([2]);
  const [previewOpen, setPreviewOpen] = useState(Boolean(props.previewOpen));

  return (
    <AccountsView
      accounts={props.accounts || sampleAccounts}
      importContent={content}
      importGroupName={importGroupName}
      batchGroupName={batchGroupName}
      preview={props.preview || null}
      previewOpen={previewOpen}
      query={query}
      selectedIds={selectedIds}
      importBusy={Boolean(props.importBusy)}
      previewBusy={Boolean(props.previewBusy)}
      batchBusy={Boolean(props.batchBusy)}
      allCurrentPageSelected={selectedIds.length > 0 && selectedIds.length === (props.accounts || sampleAccounts).rows.length}
      onImportContentChange={setContent}
      onImportGroupChange={setImportGroupName}
      onBatchGroupNameChange={setBatchGroupName}
      onOpenPreview={() => setPreviewOpen(true)}
      onPreviewOpenChange={setPreviewOpen}
      onConfirmImport={() => undefined}
      onQueryChange={setQuery}
      onToggleSelection={(id, checked) => setSelectedIds((current) => (checked ? Array.from(new Set([...current, id])) : current.filter((item) => item !== id)))}
      onTogglePageSelection={(checked) => setSelectedIds(checked ? (props.accounts || sampleAccounts).rows.map((row) => row.id) : [])}
      onApplyBatchGroup={() => undefined}
      onDeleteSelected={() => undefined}
      onClearSelection={() => setSelectedIds([])}
    />
  );
}

const meta = {
  title: "Views/AccountsView",
  component: AccountsView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component:
          "微软账号导入与查询页，包含前端预解析弹窗、分组组合框、跨分页勾选、批量分组和批量删除的交互面。",
      },
    },
  },
} satisfies Meta<typeof AccountsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
};

export const Empty: Story = {
  args: baseArgs,
  render: () => (
    <AccountsStorySurface
      accounts={{
        rows: [],
        total: 0,
        page: 1,
        pageSize: 20,
        groups: [],
      }}
    />
  ),
};

export const PreviewDialog: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface preview={previewFixture} previewOpen />,
};

export const ImportPreviewPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface preview={previewFixture} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const trigger = canvas.getByRole("button", { name: "导入预览" });
    await expect(trigger).toBeDisabled();
    await userEvent.type(canvas.getByRole("textbox", { name: "account-import" }), "new@outlook.com----password321");
    await expect(trigger).toBeEnabled();
    await userEvent.click(trigger);
    await expect(within(document.body).getByRole("dialog", { name: "导入预览" })).toBeInTheDocument();
  },
};
