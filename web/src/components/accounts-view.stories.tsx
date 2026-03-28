import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, waitFor, within } from "storybook/test";
import { AccountsView } from "@/components/accounts-view";
import { buildImportCommitEntries } from "@/lib/account-import";
import type {
  AccountExtractorHistoryPayload,
  AccountExtractorHistoryQuery,
  AccountExtractorSettings,
  AccountImportPreviewPayload,
  AccountQuery,
  AccountsPayload,
} from "@/lib/app-types";
import {
  sampleAccounts,
  sampleExtractorHistory,
  sampleExtractorHistoryDense,
  sampleExtractorHistoryEmpty,
  sampleExtractorHistoryFailureMatrix,
  sampleExtractorSettings,
} from "@/stories/fixtures";

function createDefaultQuery(): AccountQuery {
  return { q: "", status: "", hasApiKey: "", groupName: "", page: 1, pageSize: 20 };
}

function createDefaultExtractorHistoryQuery(): AccountExtractorHistoryQuery {
  return { provider: "", status: "", q: "", page: 1, pageSize: 10 };
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
  previewCommitCount: 0,
  previewOpen: false,
  query: createDefaultQuery(),
  selectedIds: [],
  revealedPasswordsById: {},
  importBusy: false,
  previewBusy: false,
  batchBusy: false,
  extractorSettings: sampleExtractorSettings,
  extractorSettingsBusy: false,
  extractorHistory: sampleExtractorHistory,
  extractorHistoryQuery: createDefaultExtractorHistoryQuery(),
  extractorHistoryBusy: false,
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
  onSaveProofMailbox: fn(async () => undefined),
  onSaveAvailability: fn(async () => undefined),
  onSaveExtractorSettings: fn(async () => undefined),
  onExtractorHistoryQueryChange: fn(),
  onRefreshExtractorHistory: fn(async () => undefined),
  onOpenMailbox: fn(),
};

type AccountsStorySurfaceProps = {
  accounts?: AccountsPayload;
  preview?: AccountImportPreviewPayload | null;
  previewOpen?: boolean;
  importBusy?: boolean;
  previewBusy?: boolean;
  batchBusy?: boolean;
  extractorSettings?: AccountExtractorSettings | null;
  extractorHistory?: AccountExtractorHistoryPayload;
  extractorHistoryQuery?: AccountExtractorHistoryQuery;
  extractorHistoryBusy?: boolean;
  frameClassName?: string;
};

function AccountsStorySurface(props: AccountsStorySurfaceProps) {
  const accounts = props.accounts || sampleAccounts;
  const extractorSettings = props.extractorSettings ?? sampleExtractorSettings;
  const extractorHistory = props.extractorHistory || sampleExtractorHistory;
  const [content, setContent] = useState("");
  const [importGroupName, setImportGroupName] = useState("");
  const [batchGroupName, setBatchGroupName] = useState("");
  const [query, setQuery] = useState<AccountQuery>(createDefaultQuery());
  const [selectedIds, setSelectedIds] = useState<number[]>([2]);
  const [previewOpen, setPreviewOpen] = useState(Boolean(props.previewOpen));
  const [extractorHistoryQuery, setExtractorHistoryQuery] = useState<AccountExtractorHistoryQuery>(
    props.extractorHistoryQuery ?? createDefaultExtractorHistoryQuery(),
  );

  return (
    <div className={props.frameClassName}>
      <AccountsView
        accounts={accounts}
        importContent={content}
        importGroupName={importGroupName}
        batchGroupName={batchGroupName}
        preview={props.preview || null}
        previewCommitCount={props.preview ? buildImportCommitEntries(props.preview, importGroupName).length : 0}
        previewOpen={previewOpen}
        query={query}
        selectedIds={selectedIds}
        revealedPasswordsById={{ 2: "password789" }}
        importBusy={Boolean(props.importBusy)}
        previewBusy={Boolean(props.previewBusy)}
        batchBusy={Boolean(props.batchBusy)}
        extractorSettings={extractorSettings}
        extractorSettingsBusy={false}
        extractorHistory={extractorHistory}
        extractorHistoryQuery={extractorHistoryQuery}
        extractorHistoryBusy={Boolean(props.extractorHistoryBusy)}
        allCurrentPageSelected={selectedIds.length > 0 && selectedIds.length === accounts.rows.length}
        onImportContentChange={setContent}
        onImportGroupChange={setImportGroupName}
        onBatchGroupNameChange={setBatchGroupName}
        onOpenPreview={() => setPreviewOpen(true)}
        onPreviewOpenChange={setPreviewOpen}
        onConfirmImport={() => undefined}
        onQueryChange={setQuery}
        onToggleSelection={(id, checked) => setSelectedIds((current) => (checked ? Array.from(new Set([...current, id])) : current.filter((item) => item !== id)))}
        onTogglePageSelection={(checked) => setSelectedIds(checked ? accounts.rows.map((row) => row.id) : [])}
        onApplyBatchGroup={() => undefined}
        onDeleteSelected={() => undefined}
        onClearSelection={() => setSelectedIds([])}
        onSaveProofMailbox={async () => undefined}
        onSaveAvailability={async () => undefined}
        onSaveExtractorSettings={async () => undefined}
        onExtractorHistoryQueryChange={setExtractorHistoryQuery}
        onRefreshExtractorHistory={async () => undefined}
        onOpenMailbox={() => undefined}
      />
    </div>
  );
}

async function openExtractorSettingsDialog(canvasElement: HTMLElement): Promise<HTMLElement> {
  const canvas = within(canvasElement);
  await userEvent.click(canvas.getByRole("button", { name: "打开提取器设置" }));
  await waitFor(() => {
    expect(within(document.body).getByRole("dialog", { name: "微软账号提取器设置" })).toBeInTheDocument();
  });
  return within(document.body).getByTestId("extractor-settings-dialog");
}

async function getExtractorHistoryViewport(): Promise<HTMLElement> {
  const scrollRoot = within(document.body).getByTestId("extractor-history-scroll-area");
  await waitFor(() => {
    const viewport = scrollRoot.querySelector<HTMLElement>("[data-radix-scroll-area-viewport]");
    expect(viewport).not.toBeNull();
  });
  return scrollRoot.querySelector<HTMLElement>("[data-radix-scroll-area-viewport]")!;
}

async function expectNoHorizontalOverflow(element: HTMLElement, tolerance = 12): Promise<void> {
  await waitFor(() => {
    expect(element.scrollWidth).toBeLessThanOrEqual(element.clientWidth + tolerance);
  });
}

async function expectHistoryViewportToScroll(viewport: HTMLElement): Promise<void> {
  await waitFor(() => {
    expect(viewport.scrollHeight).toBeGreaterThan(viewport.clientHeight);
  });
  viewport.scrollTop = viewport.scrollHeight;
  viewport.dispatchEvent(new Event("scroll"));
  await waitFor(() => {
    expect(viewport.scrollTop).toBeGreaterThan(0);
  });
}

const meta = {
  title: "Views/AccountsView",
  component: AccountsView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component:
          "微软账号导入与查询页，包含前端预解析弹窗、四个自动提取号源的 KEY 配置、本地提取历史筛选，以及跨分页勾选、批量分组和批量删除的交互面。提取器设置弹窗补充了高密度历史、失败矩阵、空态和紧凑视口四类可复现场景。",
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
        summary: {
          ready: 0,
          linked: 0,
          failed: 0,
          disabled: 0,
        },
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

export const ExtractorSettingsEntry: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  parameters: {
    docs: {
      description: {
        story: "基础交互入口，验证主页面能够打开提取器设置弹窗。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    await openExtractorSettingsDialog(canvasElement);
  },
};

export const ExtractorSettingsDenseHistory: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface extractorHistory={sampleExtractorHistoryDense} extractorHistoryQuery={createDefaultExtractorHistoryQuery()} />,
  parameters: {
    docs: {
      description: {
        story: "高密度历史列表，覆盖 6862 条总记录、超长 masked key、长 raw response 和多批次明细布局。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const dialog = await openExtractorSettingsDialog(canvasElement);
    const viewport = await getExtractorHistoryViewport();
    await expectHistoryViewportToScroll(viewport);
    await expect(within(dialog).getByRole("button", { name: "下一页" })).toBeVisible();
    await expectNoHorizontalOverflow(dialog);
    await expectNoHorizontalOverflow(within(document.body).getByTestId("extractor-history-panel"));
  },
};

export const ExtractorSettingsFailureMatrix: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface extractorHistory={sampleExtractorHistoryFailureMatrix} extractorHistoryQuery={createDefaultExtractorHistoryQuery()} />,
  parameters: {
    docs: {
      description: {
        story: "失败矩阵场景，集中覆盖 rejected、invalid_key、parse_failed、error 与 insufficient_stock 等状态组合。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const dialog = await openExtractorSettingsDialog(canvasElement);
    await expect(within(dialog).getAllByText("rejected").length).toBeGreaterThan(0);
    await expect(within(dialog).getAllByText("invalid_key").length).toBeGreaterThan(0);
    await expect(within(dialog).getAllByText("parse_failed").length).toBeGreaterThan(0);
    await expectNoHorizontalOverflow(dialog);
  },
};

export const ExtractorSettingsCompactViewport: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface extractorHistory={sampleExtractorHistoryDense} extractorHistoryQuery={createDefaultExtractorHistoryQuery()} />,
  parameters: {
    docs: {
      description: {
        story: "375px 窄视口场景，用于验证弹窗在移动宽度下仍然内部滚动、分页可见且没有横向炸开。",
      },
    },
  },
  globals: {
    viewport: { value: "extractorCompact375", isRotated: false },
  },
  play: async ({ canvasElement }) => {
    const dialog = await openExtractorSettingsDialog(canvasElement);
    const viewport = await getExtractorHistoryViewport();
    await expectHistoryViewportToScroll(viewport);
    await expect(within(dialog).getByRole("button", { name: "下一页" })).toBeVisible();
    await expectNoHorizontalOverflow(dialog, 16);
  },
};

export const ExtractorSettingsEmptyHistory: Story = {
  args: baseArgs,
  render: () => (
    <AccountsStorySurface
      extractorHistory={sampleExtractorHistoryEmpty}
      extractorHistoryQuery={{ provider: "zhanghaoya", status: "accepted", q: "no-match", page: 1, pageSize: 10 }}
    />
  ),
  parameters: {
    docs: {
      description: {
        story: "空历史场景，验证筛选条件下无数据时的空态与分页按钮禁用状态。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const dialog = await openExtractorSettingsDialog(canvasElement);
    await expect(within(dialog).getByText("当前筛选下还没有本地提取记录。")).toBeInTheDocument();
    await expect(within(dialog).getByRole("button", { name: "上一页" })).toBeDisabled();
    await expect(within(dialog).getByRole("button", { name: "下一页" })).toBeDisabled();
  },
};

export const ExtractorSettingsCompact: Story = {
  args: baseArgs,
  decorators: [
    (Story) => (
      <div className="mx-auto w-full max-w-[980px] overflow-hidden">
        <Story />
      </div>
    ),
  ],
  render: () => <AccountsStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "打开提取器设置" }));
    const dialog = within(document.body).getByRole("dialog", { name: "微软账号提取器设置" });
    await expect(dialog).toBeInTheDocument();
    await expect(within(dialog).getByText("闪客云 KEY")).toBeInTheDocument();
    await expect(within(dialog).getByText("Hotmail666 KEY")).toBeInTheDocument();
  },
};

export const PasswordCopyPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  play: async ({ canvasElement }) => {
    const writeText = fn(async () => undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const canvas = within(canvasElement);
    const trigger = canvas.getByRole("button", { name: "复制 alpha@outlook.com 密码" });
    await userEvent.click(trigger);
    await expect(writeText).toHaveBeenCalledWith("pass-456");
    await expect(within(trigger).getByText("已复制")).toBeInTheDocument();
  },
};
