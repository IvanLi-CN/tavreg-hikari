import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ApiKeysView } from "@/components/api-keys-view";
import type { ApiKeyQuery, ApiKeysPayload } from "@/lib/app-types";
import { sampleApiKeys } from "@/stories/fixtures";

function createDefaultQuery(): ApiKeyQuery {
  return { q: "", status: "", groupName: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 };
}

const exportFixtureById: Record<number, { apiKey: string; extractedIp: string | null }> = {
  1: { apiKey: "tvly-real-key-a", extractedIp: "1.2.3.4" },
  2: { apiKey: "tvly-real-key-b", extractedIp: null },
};

function buildExportContent(selectedIds: number[]): string {
  return selectedIds
    .map((id) => exportFixtureById[id])
    .filter((item): item is { apiKey: string; extractedIp: string | null } => Boolean(item))
    .map((item) => `${item.apiKey} | ${item.extractedIp || ""}`)
    .join("\n");
}

const sortingDemoApiKeys: ApiKeysPayload = {
  ...sampleApiKeys,
  rows: [
    {
      id: 101,
      accountId: 301,
      microsoftEmail: "sort.alpha@example.test",
      groupName: "linked",
      apiKeyMasked: "tvly-****-alpha",
      apiKeyPrefix: "tvly-alpha",
      status: "active",
      extractedAt: "2026-03-18T09:00:00.000Z",
      lastVerifiedAt: "2026-03-18T09:10:00.000Z",
    },
    {
      id: 102,
      accountId: 302,
      microsoftEmail: "sort.beta@example.test",
      groupName: "ops",
      apiKeyMasked: "tvly-****-beta",
      apiKeyPrefix: "tvly-beta",
      status: "active",
      extractedAt: "2026-03-18T12:00:00.000Z",
      lastVerifiedAt: "2026-03-18T07:00:00.000Z",
    },
    {
      id: 103,
      accountId: 303,
      microsoftEmail: "sort.gamma@example.test",
      groupName: "ops",
      apiKeyMasked: "tvly-****-gamma",
      apiKeyPrefix: "tvly-gamma",
      status: "revoked",
      extractedAt: "2026-03-18T08:00:00.000Z",
      lastVerifiedAt: null,
    },
  ],
};

function parseTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function compareNullableTime(left: string | null | undefined, right: string | null | undefined, sortDir: "desc" | "asc"): number {
  const leftValue = parseTime(left);
  const rightValue = parseTime(right);
  if (leftValue == null && rightValue == null) return 0;
  if (leftValue == null) return 1;
  if (rightValue == null) return -1;
  return sortDir === "asc" ? leftValue - rightValue : rightValue - leftValue;
}

function applyQuery(source: ApiKeysPayload, query: ApiKeyQuery): ApiKeysPayload {
  const pattern = query.q.trim().toLowerCase();
  const filteredRows = source.rows.filter((row) => {
    if (query.status && row.status !== query.status) return false;
    if (query.groupName && (row.groupName || "") !== query.groupName) return false;
    if (!pattern) return true;
    return [row.microsoftEmail, row.apiKeyPrefix, row.groupName || ""].some((value) => value.toLowerCase().includes(pattern));
  });
  const sortedRows = [...filteredRows].sort((left, right) => {
    const primary =
      query.sortBy === "lastVerifiedAt"
        ? compareNullableTime(left.lastVerifiedAt, right.lastVerifiedAt, query.sortDir)
        : compareNullableTime(left.extractedAt, right.extractedAt, query.sortDir);
    if (primary !== 0) return primary;
    return query.sortDir === "asc" ? left.id - right.id : right.id - left.id;
  });
  const start = (query.page - 1) * query.pageSize;
  const pagedRows = sortedRows.slice(start, start + query.pageSize);
  return {
    ...source,
    rows: pagedRows,
    total: sortedRows.length,
    page: query.page,
    pageSize: query.pageSize,
    summary: {
      active: filteredRows.filter((row) => row.status === "active").length,
      revoked: filteredRows.filter((row) => row.status === "revoked").length,
    },
  };
}

function ApiKeysStorySurface(props: {
  apiKeys?: ApiKeysPayload;
  initialSelectedIds?: number[];
  initialExportOpen?: boolean;
  initialQuery?: ApiKeyQuery;
}) {
  const sourceApiKeys = props.apiKeys || sampleApiKeys;
  const [query, setQuery] = useState<ApiKeyQuery>(props.initialQuery || createDefaultQuery());
  const [selectedIds, setSelectedIds] = useState<number[]>(props.initialSelectedIds || []);
  const [exportOpen, setExportOpen] = useState(Boolean(props.initialExportOpen));
  const apiKeys = useMemo(() => applyQuery(sourceApiKeys, query), [query, sourceApiKeys]);
  const exportContent = useMemo(() => buildExportContent(selectedIds), [selectedIds]);

  return (
    <ApiKeysView
      apiKeys={apiKeys}
      query={query}
      selectedIds={selectedIds}
      exportOpen={exportOpen}
      exportContent={exportContent}
      exportBusy={false}
      onQueryChange={setQuery}
      onToggleSelection={(apiKeyId, checked) =>
        setSelectedIds((current) => (checked ? Array.from(new Set([...current, apiKeyId])) : current.filter((id) => id !== apiKeyId)))
      }
      onTogglePageSelection={(checked) => setSelectedIds(checked ? apiKeys.rows.map((row) => row.id) : [])}
      onClearSelection={() => setSelectedIds([])}
      onOpenExport={() => setExportOpen(true)}
      onExportOpenChange={setExportOpen}
      onCopyExport={() => undefined}
      onSaveExport={() => undefined}
    />
  );
}

const meta = {
  title: "Views/ApiKeysView",
  component: ApiKeysView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "API key 查询与导出页，包含账号分组继承、分组筛选、跨分页勾选、导出弹窗与复制/保存动作的交互面。",
      },
    },
  },
} satisfies Meta<typeof ApiKeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

const baseArgs = {
  apiKeys: sampleApiKeys,
  query: createDefaultQuery(),
  selectedIds: [],
  exportOpen: false,
  exportContent: "",
  exportBusy: false,
  onQueryChange: fn(),
  onToggleSelection: fn(),
  onTogglePageSelection: fn(),
  onClearSelection: fn(),
  onOpenExport: fn(),
  onExportOpenChange: fn(),
  onCopyExport: fn(),
  onSaveExport: fn(),
};

export const Default: Story = {
  args: baseArgs,
  render: () => <ApiKeysStorySurface />,
};

export const Empty: Story = {
  args: baseArgs,
  render: () => (
    <ApiKeysStorySurface
      apiKeys={{
        rows: [],
        total: 0,
        page: 1,
        pageSize: 20,
        summary: {
          active: 0,
          revoked: 0,
        },
        groups: [],
      }}
    />
  ),
};

export const LinkedGroup: Story = {
  args: baseArgs,
  render: () => <ApiKeysStorySurface initialQuery={{ ...createDefaultQuery(), groupName: "linked" }} />,
};

export const ExportDialog: Story = {
  args: baseArgs,
  render: () => <ApiKeysStorySurface initialSelectedIds={[1, 2]} initialExportOpen />,
};

export const BatchExportPlay: Story = {
  args: baseArgs,
  render: () => <ApiKeysStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const exportButton = canvas.getByRole("button", { name: "导出" });

    await expect(exportButton).toBeDisabled();
    await userEvent.click(canvas.getByRole("checkbox", { name: "select-current-page" }));
    await expect(exportButton).toBeEnabled();
    await expect(canvas.getByText("总已选 2 / 2")).toBeInTheDocument();

    await userEvent.click(exportButton);
    const dialog = within(document.body).getByRole("dialog", { name: "导出 API Keys" });
    await expect(dialog).toBeInTheDocument();
    await expect(within(dialog).getByRole("textbox", { name: "api-key-export-content" })).toHaveValue(
      "tvly-real-key-a | 1.2.3.4\ntvly-real-key-b | ",
    );
  },
};

export const ActionsOnly: Story = {
  args: {
    apiKeys: sampleApiKeys,
    query: createDefaultQuery(),
    selectedIds: [1],
    exportOpen: false,
    exportContent: buildExportContent([1]),
    exportBusy: false,
    onQueryChange: fn(),
    onToggleSelection: fn(),
    onTogglePageSelection: fn(),
    onClearSelection: fn(),
    onOpenExport: fn(),
    onExportOpenChange: fn(),
    onCopyExport: fn(),
    onSaveExport: fn(),
  },
};

export const SortingTimeColumnsPlay: Story = {
  args: baseArgs,
  render: () => <ApiKeysStorySurface apiKeys={sortingDemoApiKeys} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const extractedAtButton = canvas.getByRole("button", { name: /提取时间排序/ });
    const lastVerifiedButton = canvas.getByRole("button", { name: /最近验证排序/ });
    const rowCells = () => canvas.getAllByRole("cell").filter((cell) => cell.textContent?.includes("sort."));

    await expect(rowCells()[0]).toHaveTextContent("sort.beta@example.test");
    await userEvent.click(extractedAtButton);
    await expect(rowCells()[0]).toHaveTextContent("sort.gamma@example.test");
    await userEvent.click(lastVerifiedButton);
    await expect(rowCells()[0]).toHaveTextContent("sort.alpha@example.test");
    await userEvent.click(lastVerifiedButton);
    await expect(rowCells()[0]).toHaveTextContent("sort.beta@example.test");
  },
};
