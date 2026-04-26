import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { KeysView } from "@/components/keys-view";
import type {
  ApiKeyQuery,
  ChatGptCredentialQuery,
  ChatGptCredentialRecord,
  ChatGptCredentialSort,
  ChatGptCredentialSupplementPayload,
  GrokApiKeyQuery,
} from "@/lib/app-types";
import { createSampleChatGptCredentialsPayload, sampleApiKeys, sampleChatGptCredentials, sampleGrokApiKeys } from "@/stories/fixtures";

function mergeIds(current: number[], incoming: number[]): number[] {
  return Array.from(new Set([...current, ...incoming]));
}

function defaultApiKeyQuery(): ApiKeyQuery {
  return { q: "", status: "", groupName: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 };
}

function defaultGrokQuery(): GrokApiKeyQuery {
  return { q: "", status: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 };
}

function defaultCredentialQuery(): ChatGptCredentialQuery {
  return { q: "", expiryStatus: "", page: 1, pageSize: 20 };
}

function defaultCredentialSort(): ChatGptCredentialSort {
  return { sortBy: "createdAt", sortDir: "desc" };
}

function sortCredentials(rows: ChatGptCredentialRecord[], sort: ChatGptCredentialSort): ChatGptCredentialRecord[] {
  return [...rows].sort((left, right) => {
    const leftValue = Date.parse(sort.sortBy === "expiresAt" ? left.expiresAt || "" : left.createdAt);
    const rightValue = Date.parse(sort.sortBy === "expiresAt" ? right.expiresAt || "" : right.createdAt);
    const safeLeft = Number.isFinite(leftValue) ? leftValue : Number.NEGATIVE_INFINITY;
    const safeRight = Number.isFinite(rightValue) ? rightValue : Number.NEGATIVE_INFINITY;
    return sort.sortDir === "asc" ? safeLeft - safeRight : safeRight - safeLeft;
  });
}

function KeysViewStorySurface() {
  const [tavilySelectedIds, setTavilySelectedIds] = useState<number[]>([]);
  const [grokSelectedIds, setGrokSelectedIds] = useState<number[]>([]);
  const [chatGptSelectedIds, setChatGptSelectedIds] = useState<number[]>([]);
  const [chatGptQuery, setChatGptQuery] = useState(defaultCredentialQuery());
  const [chatGptSort, setChatGptSort] = useState(defaultCredentialSort());
  const [chatGptExportOpen, setChatGptExportOpen] = useState(false);
  const [batchSupplementOpen, setBatchSupplementOpen] = useState(false);
  const [batchSupplementGroupName, setBatchSupplementGroupName] = useState("");
  const [batchSupplementResult, setBatchSupplementResult] = useState<ChatGptCredentialSupplementPayload | null>(null);
  const sortedChatGptRows = useMemo(() => sortCredentials(sampleChatGptCredentials, chatGptSort), [chatGptSort]);
  const pagedChatGptRows = useMemo(() => {
    const start = (chatGptQuery.page - 1) * chatGptQuery.pageSize;
    return sortedChatGptRows.slice(start, start + chatGptQuery.pageSize);
  }, [chatGptQuery.page, chatGptQuery.pageSize, sortedChatGptRows]);
  const chatGptPayload = useMemo(
    () => createSampleChatGptCredentialsPayload(pagedChatGptRows, { total: sortedChatGptRows.length, page: chatGptQuery.page, pageSize: chatGptQuery.pageSize }),
    [chatGptQuery.page, chatGptQuery.pageSize, pagedChatGptRows, sortedChatGptRows.length],
  );

  return (
    <KeysView
      defaultTab="tavily"
      tavily={{
        apiKeys: sampleApiKeys,
        query: defaultApiKeyQuery(),
        selectedIds: tavilySelectedIds,
        exportOpen: false,
        exportContent: "",
        exportBusy: false,
        onQueryChange: fn(),
        onToggleSelection: (id, checked) =>
          setTavilySelectedIds((current) => (checked ? mergeIds(current, [id]) : current.filter((item) => item !== id))),
        onTogglePageSelection: (checked) =>
          setTavilySelectedIds((current) =>
            checked ? mergeIds(current, sampleApiKeys.rows.map((row) => row.id)) : current.filter((id) => !sampleApiKeys.rows.some((row) => row.id === id)),
          ),
        onClearSelection: () => setTavilySelectedIds([]),
        onOpenExport: fn(),
        onExportOpenChange: fn(),
        onCopyExport: fn(),
        onSaveExport: fn(),
      }}
      grok={{
        apiKeys: sampleGrokApiKeys,
        query: defaultGrokQuery(),
        selectedIds: grokSelectedIds,
        exportOpen: false,
        exportContent: "",
        exportBusy: false,
        onQueryChange: fn(),
        onToggleSelection: (id, checked) =>
          setGrokSelectedIds((current) => (checked ? mergeIds(current, [id]) : current.filter((item) => item !== id))),
        onTogglePageSelection: (checked) =>
          setGrokSelectedIds((current) =>
            checked ? mergeIds(current, sampleGrokApiKeys.rows.map((row) => row.id)) : current.filter((id) => !sampleGrokApiKeys.rows.some((row) => row.id === id)),
          ),
        onClearSelection: () => setGrokSelectedIds([]),
        onOpenExport: fn(),
        onExportOpenChange: fn(),
        onCopyExport: fn(),
        onSaveExport: fn(),
        onResolveCopyField: async () => "demo-copy-value",
      }}
      chatgpt={{
        credentials: chatGptPayload,
        query: chatGptQuery,
        sort: chatGptSort,
        credentialBusy: false,
        selectedIds: chatGptSelectedIds,
        exportOpen: chatGptExportOpen,
        exportContent: JSON.stringify(chatGptSelectedIds, null, 2),
        exportBusy: false,
        groupOptions: ["sync-ready", "warm-pool"],
        upstreamSettingsConfigured: true,
        batchSupplementOpen,
        batchSupplementBusy: false,
        batchSupplementGroupName,
        batchSupplementResult,
        onQueryChange: setChatGptQuery,
        onSortChange: setChatGptSort,
        onToggleSelection: (id, checked) =>
          setChatGptSelectedIds((current) => (checked ? mergeIds(current, [id]) : current.filter((item) => item !== id))),
        onTogglePageSelection: (checked) =>
          setChatGptSelectedIds((current) =>
            checked ? mergeIds(current, chatGptPayload.rows.map((row) => row.id)) : current.filter((id) => !chatGptPayload.rows.some((row) => row.id === id)),
          ),
        onClearSelection: () => setChatGptSelectedIds([]),
        onOpenExport: () => setChatGptExportOpen(true),
        onExportOpenChange: setChatGptExportOpen,
        onCopyExport: fn(),
        onSaveExport: fn(),
        onCopyCredential: fn(),
        onExportCredential: fn(),
        onBatchSupplementOpenChange: (open) => {
          setBatchSupplementOpen(open);
          if (!open) setBatchSupplementResult(null);
        },
        onBatchSupplementGroupNameChange: setBatchSupplementGroupName,
        onOpenBatchSupplement: () => setBatchSupplementOpen(true),
        onSubmitBatchSupplement: () =>
          setBatchSupplementResult({ ok: true, groupName: batchSupplementGroupName || "sync-ready", requested: chatGptSelectedIds.length, succeeded: chatGptSelectedIds.length, failed: 0, results: [] }),
        onOpenUpstreamSettings: fn(),
      }}
    />
  );
}

const meta = {
  title: "Views/KeysView",
  component: KeysView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "统一 Keys 视图，包含 Tavily / Grok / ChatGPT tabs、分页、跨页勾选与底部浮动批量条。",
      },
    },
  },
} satisfies Meta<typeof KeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

const baseArgs = {
  tavily: {
    apiKeys: sampleApiKeys,
    query: defaultApiKeyQuery(),
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
  },
  grok: {
    apiKeys: sampleGrokApiKeys,
    query: defaultGrokQuery(),
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
    onResolveCopyField: async () => "demo-copy-value",
  },
  chatgpt: {
    credentials: createSampleChatGptCredentialsPayload(),
    query: defaultCredentialQuery(),
    sort: defaultCredentialSort(),
    credentialBusy: false,
    selectedIds: [],
    exportOpen: false,
    exportContent: "",
    exportBusy: false,
    groupOptions: ["sync-ready", "warm-pool"],
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
    onOpenUpstreamSettings: fn(),
  },
  defaultTab: "tavily" as const,
};

export const Default: Story = {
  args: baseArgs,
  render: () => <KeysViewStorySurface />,
};

export const TabsAndCopyPlay: Story = {
  args: baseArgs,
  render: () => <KeysViewStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.queryByText(/站内|子视图/)).toBeNull();
    await userEvent.click(canvas.getByRole("tab", { name: "ChatGPT" }));
    await expect(within(canvasElement).getByText(/valid ·/)).toBeInTheDocument();
    await userEvent.click(within(canvasElement).getAllByRole("checkbox", { name: /select-credential-/ })[0]!);
    await expect(within(canvasElement).getByText(/总已选 · 1/)).toBeInTheDocument();
  },
};
