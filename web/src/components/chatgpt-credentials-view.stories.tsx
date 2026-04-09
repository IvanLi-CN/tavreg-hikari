import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ChatGptCredentialsView } from "@/components/chatgpt-credentials-view";
import { sampleChatGptCredentials } from "@/stories/fixtures";
import type { ChatGptCredentialQuery, ChatGptCredentialRecord, ChatGptCredentialSort } from "@/lib/app-types";

const defaultSort: ChatGptCredentialSort = {
  sortBy: "createdAt",
  sortDir: "desc",
};

const fixedNowMs = Date.parse("2026-04-10T03:00:00.000Z");

const defaultQuery: ChatGptCredentialQuery = {
  q: "",
  expiryStatus: "",
};

const sortingDemoCredentials: ChatGptCredentialRecord[] = [
  {
    ...sampleChatGptCredentials[0]!,
    id: 201,
    email: "sort.alpha@mail.example.test",
    accountId: "acc-sort-alpha",
    expiresAt: "2026-04-06T12:00:00.000Z",
    createdAt: "2026-04-05T08:00:00.000Z",
  },
  {
    ...sampleChatGptCredentials[1]!,
    id: 202,
    email: "sort.beta@mail.example.test",
    accountId: "acc-sort-beta",
    expiresAt: "2026-04-06T09:30:00.000Z",
    createdAt: "2026-04-05T12:00:00.000Z",
  },
  {
    ...sampleChatGptCredentials[2]!,
    id: 203,
    email: "sort.gamma@mail.example.test",
    accountId: "acc-sort-gamma",
    expiresAt: null,
    createdAt: "2026-04-05T10:00:00.000Z",
  },
];

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

function ChatGptCredentialsStorySurface(props?: { credentials?: ChatGptCredentialRecord[] }) {
  const sourceCredentials = props?.credentials || sampleChatGptCredentials;
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [exportOpen, setExportOpen] = useState(false);
  const [query, setQuery] = useState<ChatGptCredentialQuery>(defaultQuery);
  const [sort, setSort] = useState<ChatGptCredentialSort>(defaultSort);
  const filteredCredentials = useMemo(() => applyCredentialQuery(sourceCredentials, query), [query, sourceCredentials]);
  const credentials = useMemo(() => sortCredentials(filteredCredentials, sort), [filteredCredentials, sort]);
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
      credentials={credentials}
      query={query}
      sort={sort}
      credentialBusy={false}
      selectedIds={selectedIds}
      exportOpen={exportOpen}
      exportContent={exportContent}
      exportBusy={false}
      onQueryChange={setQuery}
      onSortChange={setSort}
      onToggleSelection={(credentialId, checked) =>
        setSelectedIds((current) => (checked ? Array.from(new Set([...current, credentialId])) : current.filter((id) => id !== credentialId)))
      }
      onTogglePageSelection={(checked) => setSelectedIds(checked ? credentials.map((row) => row.id) : [])}
      onClearSelection={() => setSelectedIds([])}
      onOpenExport={() => setExportOpen(true)}
      onExportOpenChange={setExportOpen}
      onCopyExport={() => undefined}
      onSaveExport={() => undefined}
      onCopyCredential={() => undefined}
      onExportCredential={() => undefined}
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
        component: "ChatGPT keys 列表片段，使用与 Keys 页一致的列表骨架展示最近记录；行内只提供复制与下载动作，但不会在页面展示明文详情。",
      },
    },
  },
} satisfies Meta<typeof ChatGptCredentialsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    credentials: sortCredentials(sampleChatGptCredentials, defaultSort),
    query: defaultQuery,
    sort: defaultSort,
    credentialBusy: false,
    selectedIds: [],
    exportOpen: false,
    exportContent: "",
    exportBusy: false,
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
  },
  render: () => <ChatGptCredentialsStorySurface />,
};

export const Empty: Story = {
  args: {
    ...Default.args,
    credentials: [],
  },
  render: () => <ChatGptCredentialsStorySurface credentials={[]} />,
};

export const ExportPlay: Story = {
  args: {
    ...Default.args,
  },
  render: () => <ChatGptCredentialsStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("checkbox", { name: "select-current-page" }));
    await expect(canvas.getByText(`总已选 ${sampleChatGptCredentials.length} / ${sampleChatGptCredentials.length}`)).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "导出" }));
    const dialog = within(document.body).getByRole("dialog", { name: "导出 ChatGPT Keys" });
    await expect(dialog).toBeInTheDocument();
    await expect(within(dialog).getByRole("textbox", { name: "chatgpt-key-export-content" })).toHaveValue(
      JSON.stringify(
        sortCredentials(sampleChatGptCredentials, defaultSort).map((row) => ({ id: row.id, email: row.email })),
        null,
        2,
      ),
    );
  },
};

export const SortingTimeColumnsPlay: Story = {
  args: {
    ...Default.args,
  },
  render: () => <ChatGptCredentialsStorySurface credentials={sortingDemoCredentials} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const createdAtButton = canvas.getByRole("button", { name: /创建时间排序/ });
    const expiresAtButton = canvas.getByRole("button", { name: /过期时间排序/ });
    const rowCells = () => canvas.getAllByRole("cell").filter((cell) => cell.textContent?.includes("sort."));

    await expect(rowCells()[0]).toHaveTextContent("sort.beta@mail.example.test");
    await userEvent.click(createdAtButton);
    await expect(rowCells()[0]).toHaveTextContent("sort.alpha@mail.example.test");
    await userEvent.click(expiresAtButton);
    await expect(rowCells()[0]).toHaveTextContent("sort.alpha@mail.example.test");
    await userEvent.click(expiresAtButton);
    await expect(rowCells()[0]).toHaveTextContent("sort.beta@mail.example.test");
  },
};

export const FilteringPlay: Story = {
  args: {
    ...Default.args,
  },
  render: () => <ChatGptCredentialsStorySurface credentials={sortingDemoCredentials} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    await userEvent.type(canvas.getByRole("textbox", { name: "搜索" }), "gamma");
    await expect(canvas.getByText("sort.gamma@mail.example.test")).toBeInTheDocument();
    await expect(canvas.queryByText("sort.alpha@mail.example.test")).not.toBeInTheDocument();

    await userEvent.clear(canvas.getByRole("textbox", { name: "搜索" }));
    await userEvent.click(canvas.getByRole("combobox", { name: "有效期" }));
    await userEvent.click(within(document.body).getByRole("option", { name: "无过期时间" }));
    await expect(canvas.getByText("sort.gamma@mail.example.test")).toBeInTheDocument();
    await expect(canvas.queryByText("sort.beta@mail.example.test")).not.toBeInTheDocument();
  },
};
