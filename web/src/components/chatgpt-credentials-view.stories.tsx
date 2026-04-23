import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptCredentialsView } from "@/components/chatgpt-credentials-view";
import { KEYS_PAGE_SIZE_OPTIONS } from "@/lib/keys-page";
import type {
  ChatGptCredentialQuery,
  ChatGptCredentialRecord,
  ChatGptCredentialSort,
  ChatGptCredentialSupplementPayload,
} from "@/lib/app-types";
import { createSampleChatGptCredentialsPayload, sampleChatGptCredentials } from "@/stories/fixtures";

const defaultSort: ChatGptCredentialSort = {
  sortBy: "createdAt",
  sortDir: "desc",
};

const fixedNowMs = Date.parse("2026-04-10T03:00:00.000Z");

const defaultQuery: ChatGptCredentialQuery = {
  q: "",
  expiryStatus: "",
  page: 1,
  pageSize: 20,
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

function sortCredentials(rows: ChatGptCredentialRecord[], sort: ChatGptCredentialSort): ChatGptCredentialRecord[] {
  return [...rows].sort((left, right) => {
    const primary =
      sort.sortBy === "expiresAt"
        ? compareNullableTime(left.expiresAt, right.expiresAt, sort.sortDir)
        : compareNullableTime(left.createdAt, right.createdAt, sort.sortDir);
    if (primary !== 0) return primary;
    return sort.sortDir === "asc" ? left.id - right.id : right.id - left.id;
  });
}

function applyCredentialQuery(rows: ChatGptCredentialRecord[], query: ChatGptCredentialQuery): ChatGptCredentialRecord[] {
  const pattern = query.q.trim().toLowerCase();
  return rows.filter((row) => {
    if (query.expiryStatus === "valid") {
      const expiresAt = row.expiresAt ? Date.parse(row.expiresAt) : Number.NaN;
      if (!Number.isFinite(expiresAt) || expiresAt <= fixedNowMs) return false;
    }
    if (query.expiryStatus === "expired") {
      const expiresAt = row.expiresAt ? Date.parse(row.expiresAt) : Number.NaN;
      if (!Number.isFinite(expiresAt) || expiresAt > fixedNowMs) return false;
    }
    if (query.expiryStatus === "noExpiry" && row.expiresAt) return false;
    if (!pattern) return true;
    return [row.email, row.accountId || ""].some((value) => value.toLowerCase().includes(pattern));
  });
}

function createLargeCredentialRows(count: number): ChatGptCredentialRecord[] {
  return Array.from({ length: count }, (_, index) => {
    const template = sampleChatGptCredentials[index % sampleChatGptCredentials.length]!;
    const id = index + 1;
    return {
      ...template,
      id,
      jobId: 500 + Math.floor(index / 25),
      attemptId: 900 + id,
      email: `virtual-${String(id).padStart(4, "0")}@mail.example.test`,
      accountId: `acc-virtual-${id}`,
      createdAt: new Date(Date.parse("2026-04-01T00:00:00.000Z") + index * 60_000).toISOString(),
      expiresAt: index % 3 === 0 ? null : new Date(Date.parse("2026-04-12T00:00:00.000Z") - index * 45_000).toISOString(),
    };
  });
}

function mergeIds(current: number[], incoming: number[]): number[] {
  return Array.from(new Set([...current, ...incoming]));
}

function ChatGptCredentialsStorySurface(props?: {
  credentials?: ChatGptCredentialRecord[];
  initialQuery?: ChatGptCredentialQuery;
  initialSelectedIds?: number[];
  initialExportOpen?: boolean;
}) {
  const sourceCredentials = props?.credentials || sampleChatGptCredentials;
  const [selectedIds, setSelectedIds] = useState<number[]>(props?.initialSelectedIds || []);
  const [exportOpen, setExportOpen] = useState(Boolean(props?.initialExportOpen));
  const [batchSupplementOpen, setBatchSupplementOpen] = useState(false);
  const [batchSupplementGroupName, setBatchSupplementGroupName] = useState("");
  const [batchSupplementResult, setBatchSupplementResult] = useState<ChatGptCredentialSupplementPayload | null>(null);
  const [query, setQuery] = useState<ChatGptCredentialQuery>(props?.initialQuery || defaultQuery);
  const [sort, setSort] = useState<ChatGptCredentialSort>(defaultSort);
  const filteredCredentials = useMemo(() => applyCredentialQuery(sourceCredentials, query), [query, sourceCredentials]);
  const sortedCredentials = useMemo(() => sortCredentials(filteredCredentials, sort), [filteredCredentials, sort]);
  const pagedCredentials = useMemo(() => {
    const start = (query.page - 1) * query.pageSize;
    return sortedCredentials.slice(start, start + query.pageSize);
  }, [query.page, query.pageSize, sortedCredentials]);
  const payload = useMemo(
    () =>
      createSampleChatGptCredentialsPayload(pagedCredentials, {
        total: sortedCredentials.length,
        page: query.page,
        pageSize: query.pageSize,
        nowMs: fixedNowMs,
      }),
    [pagedCredentials, query.page, query.pageSize, sortedCredentials.length],
  );
  const exportContent = useMemo(
    () =>
      JSON.stringify(
        selectedIds
          .map((id) => sourceCredentials.find((row) => row.id === id))
          .filter((row): row is ChatGptCredentialRecord => Boolean(row))
          .map((row) => ({ id: row.id, email: row.email })),
        null,
        2,
      ),
    [selectedIds, sourceCredentials],
  );

  return (
    <ChatGptCredentialsView
      credentials={payload}
      query={query}
      sort={sort}
      credentialBusy={false}
      selectedIds={selectedIds}
      exportOpen={exportOpen}
      exportContent={exportContent}
      exportBusy={false}
      groupOptions={["sync-ready", "warm-pool", "hold"]}
      upstreamSettingsConfigured
      batchSupplementOpen={batchSupplementOpen}
      batchSupplementBusy={false}
      batchSupplementGroupName={batchSupplementGroupName}
      batchSupplementResult={batchSupplementResult}
      onQueryChange={setQuery}
      onSortChange={setSort}
      onToggleSelection={(credentialId, checked) =>
        setSelectedIds((current) => (checked ? mergeIds(current, [credentialId]) : current.filter((id) => id !== credentialId)))
      }
      onTogglePageSelection={(checked) =>
        setSelectedIds((current) =>
          checked ? mergeIds(current, payload.rows.map((row) => row.id)) : current.filter((id) => !payload.rows.some((row) => row.id === id)),
        )
      }
      onClearSelection={() => setSelectedIds([])}
      onOpenExport={() => setExportOpen(true)}
      onExportOpenChange={setExportOpen}
      onCopyExport={() => undefined}
      onSaveExport={() => undefined}
      onCopyCredential={() => undefined}
      onExportCredential={() => undefined}
      onBatchSupplementOpenChange={(open) => {
        setBatchSupplementOpen(open);
        if (!open) setBatchSupplementResult(null);
      }}
      onBatchSupplementGroupNameChange={setBatchSupplementGroupName}
      onOpenBatchSupplement={() => {
        setBatchSupplementOpen(true);
        setBatchSupplementResult(null);
      }}
      onSubmitBatchSupplement={() => {
        setBatchSupplementResult({
          ok: true,
          groupName: batchSupplementGroupName || "sync-ready",
          requested: selectedIds.length,
          succeeded: Math.max(0, selectedIds.length - 1),
          failed: selectedIds.length > 0 ? 1 : 0,
          results: selectedIds.map((id, index) => {
            const row = sourceCredentials.find((item) => item.id === id) || null;
            return {
              credentialId: id,
              email: row?.email || null,
              accountId: row?.accountId || null,
              groupName: batchSupplementGroupName || "sync-ready",
              success: index !== 0,
              message: index === 0 ? "missing accountId" : "ok",
            };
          }),
        });
      }}
    />
  );
}

const meta = {
  title: "Views/ChatGptCredentialsView",
  component: ChatGptCredentialsView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "ChatGPT keys 列表片段，支持服务端分页、跨页勾选、底部浮动批量条与整页虚拟列表。",
      },
    },
  },
} satisfies Meta<typeof ChatGptCredentialsView>;

export default meta;
type Story = StoryObj<typeof meta>;

const baseArgs = {
  credentials: createSampleChatGptCredentialsPayload(),
  query: defaultQuery,
  sort: defaultSort,
  credentialBusy: false,
  selectedIds: [],
  exportOpen: false,
  exportContent: "",
  exportBusy: false,
  groupOptions: ["sync-ready", "warm-pool", "hold"],
  upstreamSettingsConfigured: true,
  batchSupplementOpen: false,
  batchSupplementBusy: false,
  batchSupplementGroupName: "",
  batchSupplementResult: null,
  onQueryChange: fn(),
  onSortChange: fn(),
  onToggleSelection: fn(),
  onTogglePageSelection: fn(),
  onClearSelection: fn(),
  onOpenExport: fn(),
  onExportOpenChange: fn(),
  onCopyExport: fn(),
  onSaveExport: fn(),
  onCopyCredential: fn(),
  onExportCredential: fn(),
  onBatchSupplementOpenChange: fn(),
  onBatchSupplementGroupNameChange: fn(),
  onOpenBatchSupplement: fn(),
  onSubmitBatchSupplement: fn(),
};

export const Default: Story = {
  args: baseArgs,
  render: () => <ChatGptCredentialsStorySurface />,
};

export const Empty: Story = {
  args: baseArgs,
  render: () => <ChatGptCredentialsStorySurface credentials={[]} />,
};

export const FloatingDockAndPaginationPlay: Story = {
  args: baseArgs,
  render: () => <ChatGptCredentialsStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.queryByRole("button", { name: "导出" })).toBeInTheDocument();
    await userEvent.click(canvas.getAllByRole("checkbox", { name: /select-credential-/ })[0]!);
    await expect(canvas.getByText(/总已选 · 1/)).toBeInTheDocument();

    await userEvent.click(canvas.getByRole("combobox", { name: "每页条数" }));
    const popup = within(document.body);
    for (const pageSize of KEYS_PAGE_SIZE_OPTIONS) {
      await expect(popup.getByRole("option", { name: `${pageSize} / 页` })).toBeInTheDocument();
    }
  },
};

export const CrossPageSelectionPlay: Story = {
  args: baseArgs,
  render: () => <ChatGptCredentialsStorySurface credentials={createLargeCredentialRows(36)} initialQuery={{ ...defaultQuery, pageSize: 10 }} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const firstPageCheckboxes = canvas.getAllByRole("checkbox", { name: /select-credential-/ });
    await userEvent.click(firstPageCheckboxes[0]!);
    await userEvent.click(canvas.getByRole("button", { name: "下一页" }));
    const secondPageCheckboxes = within(canvasElement).getAllByRole("checkbox", { name: /select-credential-/ });
    await userEvent.click(secondPageCheckboxes[1]!);
    await expect(within(canvasElement).getByText(/总已选 · 2/)).toBeInTheDocument();
    await userEvent.click(within(canvasElement).getByRole("button", { name: "导出" }));
    const dialog = within(document.body).getByRole("dialog", { name: "导出 ChatGPT Keys" });
    await expect(dialog).toBeInTheDocument();
    const content = within(dialog).getByRole("textbox", { name: "chatgpt-key-export-content" });
    await expect(content).toHaveValue(expect.stringContaining("virtual-0001@mail.example.test"));
    await expect(content).toHaveValue(expect.stringContaining("virtual-0012@mail.example.test"));
  },
};

export const BatchSupplementPlay: Story = {
  args: baseArgs,
  render: () => <ChatGptCredentialsStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getAllByRole("checkbox", { name: /select-credential-/ })[0]!);
    await userEvent.click(canvas.getByRole("button", { name: "批量补号" }));
    const dialog = within(document.body).getByRole("dialog", { name: "批量补号" });
    await userEvent.click(within(dialog).getByRole("button", { name: "不补号" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "sync-ready" }));
    await userEvent.click(within(dialog).getByRole("button", { name: /补号 1 条/ }));
    await expect(within(dialog).getByText(/missing accountId|当前批次全部补号成功/)).toBeInTheDocument();
  },
};

export const Virtualized5000Rows: Story = {
  args: baseArgs,
  render: () => <ChatGptCredentialsStorySurface credentials={createLargeCredentialRows(5000)} initialQuery={{ ...defaultQuery, pageSize: 5000 }} />,
};
