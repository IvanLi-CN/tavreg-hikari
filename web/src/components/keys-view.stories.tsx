import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { AppShell } from "@/components/app-shell";
import { KeysView } from "@/components/keys-view";
import type {
  ApiKeyQuery,
  ApiKeysPayload,
  ChatGptCredentialQuery,
  ChatGptCredentialRecord,
  ChatGptCredentialSort,
  ChatGptCredentialSupplementPayload,
  GrokApiKeyQuery,
  GrokApiKeysPayload,
} from "@/lib/app-types";
import {
  sampleApiKeys,
  sampleChatGptCredentials,
  sampleGrokApiKeys,
} from "@/stories/fixtures";

const fixedNowMs = Date.parse("2026-04-10T03:00:00.000Z");

function createDefaultQuery(): ApiKeyQuery {
  return { q: "", status: "", groupName: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 };
}

function createGrokDefaultQuery(): GrokApiKeyQuery {
  return { q: "", status: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 };
}

const defaultCredentialSort: ChatGptCredentialSort = {
  sortBy: "createdAt",
  sortDir: "desc",
};

const defaultCredentialQuery: ChatGptCredentialQuery = {
  q: "",
  expiryStatus: "",
};

const exportFixtureById: Record<number, { apiKey: string; extractedIp: string | null }> = {
  1: { apiKey: sampleApiKeys.rows[0]!.apiKey, extractedIp: "1.2.3.4" },
  2: { apiKey: sampleApiKeys.rows[1]!.apiKey, extractedIp: null },
};

const grokExportFixtureById: Record<number, { email: string; password: string; sso: string }> = {
  11: { email: "grok-1697@mail.example.test", password: "Pw-demo-1697", sso: "sso_live_demo_a" },
  12: { email: "grok-1601@mail.example.test", password: "Pw-demo-1601", sso: "sso_live_demo_b" },
};

function buildExportContent(selectedIds: number[]): string {
  return selectedIds
    .map((id) => exportFixtureById[id])
    .filter((item): item is { apiKey: string; extractedIp: string | null } => Boolean(item))
    .map((item) => `${item.apiKey} | ${item.extractedIp || ""}`)
    .join("\n");
}

function buildGrokExportContent(selectedIds: number[]): string {
  return selectedIds
    .map((id) => grokExportFixtureById[id])
    .filter((item): item is { email: string; password: string; sso: string } => Boolean(item))
    .map((item) => item.sso)
    .join("\n");
}

function buildChatGptExportContent(selectedIds: number[]) {
  return JSON.stringify(
    selectedIds
      .map((id) => sampleChatGptCredentials.find((row) => row.id === id))
      .filter((row): row is (typeof sampleChatGptCredentials)[number] => Boolean(row))
      .map((row) => ({ id: row.id, email: row.email })),
    null,
    2,
  );
}

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
    return [row.microsoftEmail, row.apiKey, row.groupName || ""].some((value) => value.toLowerCase().includes(pattern));
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

function applyGrokQuery(source: GrokApiKeysPayload, query: GrokApiKeyQuery): GrokApiKeysPayload {
  const pattern = query.q.trim().toLowerCase();
  const filteredRows = source.rows.filter((row) => {
    if (query.status && row.status !== query.status) return false;
    if (!pattern) return true;
    return [row.email, row.sso, row.extractedIp || ""].some((value) => value.toLowerCase().includes(pattern));
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
  return {
    ...source,
    rows: sortedRows.slice(start, start + query.pageSize),
    total: sortedRows.length,
    page: query.page,
    pageSize: query.pageSize,
    summary: {
      active: filteredRows.filter((row) => row.status === "active").length,
      revoked: filteredRows.filter((row) => row.status !== "active").length,
    },
  };
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

function KeysStorySurface(props: {
  apiKeys?: ApiKeysPayload;
  grokApiKeys?: GrokApiKeysPayload;
  credentials?: ChatGptCredentialRecord[];
  defaultTab?: "tavily" | "grok" | "chatgpt";
  onOpenChatGptUpstreamSettings?: () => void;
}) {
  const sourceApiKeys = props.apiKeys || sampleApiKeys;
  const sourceGrokApiKeys = props.grokApiKeys || sampleGrokApiKeys;
  const sourceCredentials = props.credentials || sampleChatGptCredentials;
  const [query, setQuery] = useState<ApiKeyQuery>(createDefaultQuery());
  const [grokQuery, setGrokQuery] = useState<GrokApiKeyQuery>(createGrokDefaultQuery());
  const [credentialQuery, setCredentialQuery] = useState<ChatGptCredentialQuery>(defaultCredentialQuery);
  const [credentialSort, setCredentialSort] = useState<ChatGptCredentialSort>(defaultCredentialSort);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [selectedGrokIds, setSelectedGrokIds] = useState<number[]>([]);
  const [selectedChatGptIds, setSelectedChatGptIds] = useState<number[]>([]);
  const [exportOpen, setExportOpen] = useState(false);
  const [grokExportOpen, setGrokExportOpen] = useState(false);
  const [chatGptExportOpen, setChatGptExportOpen] = useState(false);
  const [chatGptBatchSupplementOpen, setChatGptBatchSupplementOpen] = useState(false);
  const [chatGptBatchSupplementGroupName, setChatGptBatchSupplementGroupName] = useState("");
  const [chatGptBatchSupplementResult, setChatGptBatchSupplementResult] = useState<ChatGptCredentialSupplementPayload | null>(null);
  const apiKeys = useMemo(() => applyQuery(sourceApiKeys, query), [query, sourceApiKeys]);
  const grokApiKeys = useMemo(() => applyGrokQuery(sourceGrokApiKeys, grokQuery), [grokQuery, sourceGrokApiKeys]);
  const filteredCredentials = useMemo(() => applyCredentialQuery(sourceCredentials, credentialQuery), [credentialQuery, sourceCredentials]);
  const credentials = useMemo(() => sortCredentials(filteredCredentials, credentialSort), [credentialSort, filteredCredentials]);
  const exportContent = useMemo(() => buildExportContent(selectedIds), [selectedIds]);
  const grokExportContent = useMemo(() => buildGrokExportContent(selectedGrokIds), [selectedGrokIds]);
  const chatGptExportContent = useMemo(() => buildChatGptExportContent(selectedChatGptIds), [selectedChatGptIds]);

  return (
    <KeysView
      defaultTab={props.defaultTab}
      nowMs={fixedNowMs}
      tavily={{
        apiKeys,
        query,
        selectedIds,
        exportOpen,
        exportContent,
        exportBusy: false,
        onQueryChange: setQuery,
        onToggleSelection: (apiKeyId, checked) =>
          setSelectedIds((current) => (checked ? Array.from(new Set([...current, apiKeyId])) : current.filter((id) => id !== apiKeyId))),
        onTogglePageSelection: (checked) => setSelectedIds(checked ? apiKeys.rows.map((row) => row.id) : []),
        onClearSelection: () => setSelectedIds([]),
        onOpenExport: () => setExportOpen(true),
        onExportOpenChange: setExportOpen,
        onCopyExport: () => undefined,
        onSaveExport: () => undefined,
      }}
      grok={{
        apiKeys: grokApiKeys,
        query: grokQuery,
        selectedIds: selectedGrokIds,
        exportOpen: grokExportOpen,
        exportContent: grokExportContent,
        exportBusy: false,
        onQueryChange: setGrokQuery,
        onToggleSelection: (apiKeyId, checked) =>
          setSelectedGrokIds((current) => (checked ? Array.from(new Set([...current, apiKeyId])) : current.filter((id) => id !== apiKeyId))),
        onTogglePageSelection: (checked) => setSelectedGrokIds(checked ? grokApiKeys.rows.map((row) => row.id) : []),
        onClearSelection: () => setSelectedGrokIds([]),
        onOpenExport: () => setGrokExportOpen(true),
        onExportOpenChange: setGrokExportOpen,
        onCopyExport: () => undefined,
        onSaveExport: () => undefined,
        onResolveCopyField: async (apiKeyId, field) => {
          const item = grokExportFixtureById[apiKeyId];
          if (!item) return "";
          return field === "email" ? item.email : field === "password" ? item.password : item.sso;
        },
      }}
      chatgpt={{
        credentials,
        query: credentialQuery,
        sort: credentialSort,
        credentialBusy: false,
        selectedIds: selectedChatGptIds,
        exportOpen: chatGptExportOpen,
        exportContent: chatGptExportContent,
        exportBusy: false,
        groupOptions: ["sync-ready", "warm-pool", "hold"],
        upstreamSettingsConfigured: true,
        batchSupplementOpen: chatGptBatchSupplementOpen,
        batchSupplementBusy: false,
        batchSupplementGroupName: chatGptBatchSupplementGroupName,
        batchSupplementResult: chatGptBatchSupplementResult,
        onQueryChange: setCredentialQuery,
        onSortChange: setCredentialSort,
        onToggleSelection: (credentialId, checked) =>
          setSelectedChatGptIds((current) => (checked ? Array.from(new Set([...current, credentialId])) : current.filter((id) => id !== credentialId))),
        onTogglePageSelection: (checked) => setSelectedChatGptIds(checked ? credentials.map((row) => row.id) : []),
        onClearSelection: () => setSelectedChatGptIds([]),
        onOpenExport: () => setChatGptExportOpen(true),
        onExportOpenChange: setChatGptExportOpen,
        onCopyExport: () => undefined,
        onSaveExport: () => undefined,
        onCopyCredential: () => undefined,
        onExportCredential: () => undefined,
        onBatchSupplementOpenChange: (open) => {
          setChatGptBatchSupplementOpen(open);
          if (!open) setChatGptBatchSupplementResult(null);
        },
        onBatchSupplementGroupNameChange: setChatGptBatchSupplementGroupName,
        onOpenBatchSupplement: () => {
          setChatGptBatchSupplementOpen(true);
          setChatGptBatchSupplementResult(null);
        },
        onSubmitBatchSupplement: () => {
          setChatGptBatchSupplementResult({
            ok: true,
            groupName: chatGptBatchSupplementGroupName || "sync-ready",
            requested: selectedChatGptIds.length,
            succeeded: selectedChatGptIds.length,
            failed: 0,
            results: selectedChatGptIds.map((id) => {
              const row = sourceCredentials.find((item) => item.id === id) || null;
              return {
                credentialId: id,
                email: row?.email || null,
                accountId: row?.accountId || null,
                groupName: chatGptBatchSupplementGroupName || "sync-ready",
                success: true,
                message: "ok",
              };
            }),
          });
        },
        onOpenUpstreamSettings: props.onOpenChatGptUpstreamSettings || (() => undefined),
      }}
    />
  );
}

function IntegratedKeysStorySurface(props: {
  apiKeys?: ApiKeysPayload;
  grokApiKeys?: GrokApiKeysPayload;
  credentials?: ChatGptCredentialRecord[];
  defaultTab?: "tavily" | "grok" | "chatgpt";
}) {
  return (
    <AppShell activePage="keys" error={null} onNavigate={() => undefined}>
      <KeysStorySurface {...props} />
    </AppShell>
  );
}

const meta = {
  title: "Views/KeysView",
  component: KeysView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "统一的 Keys 页，内含 Tavily、Grok 与 ChatGPT 三个数据源 tabs。Tavily tab 直接显示完整 KEY 并提供行内复制；ChatGPT tab 仍只提供复制与下载动作，不在页面展示明文详情。",
      },
    },
  },
} satisfies Meta<typeof KeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    tavily: {
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
    },
    grok: {
      apiKeys: sampleGrokApiKeys,
      query: createGrokDefaultQuery(),
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
      onResolveCopyField: fn(async () => ""),
    },
    chatgpt: {
      credentials: sortCredentials(sampleChatGptCredentials, defaultCredentialSort),
      query: defaultCredentialQuery,
      sort: defaultCredentialSort,
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
      onOpenUpstreamSettings: fn(),
    },
  },
  render: () => <KeysStorySurface />,
};

export const ChatGptTab: Story = {
  args: Default.args,
  render: () => <KeysStorySurface defaultTab="chatgpt" />,
};

export const GrokTab: Story = {
  args: Default.args,
  render: () => <KeysStorySurface defaultTab="grok" />,
};

export const IntegratedTavily: Story = {
  args: Default.args,
  render: () => <IntegratedKeysStorySurface />,
};

export const IntegratedChatGpt: Story = {
  args: Default.args,
  render: () => <IntegratedKeysStorySurface defaultTab="chatgpt" />,
};

export const IntegratedGrok: Story = {
  args: Default.args,
  render: () => <IntegratedKeysStorySurface defaultTab="grok" />,
};

export const EmptyChatGpt: Story = {
  args: Default.args,
  render: () => <KeysStorySurface defaultTab="chatgpt" credentials={[]} />,
};

export const ExportPlay: Story = {
  args: Default.args,
  render: () => <KeysStorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("tab", { name: "ChatGPT" }));
    await expect(canvas.getByText(`总已选 0 / ${sampleChatGptCredentials.length}`)).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("checkbox", { name: "select-current-page" }));
    await expect(canvas.getByText(`总已选 ${sampleChatGptCredentials.length} / ${sampleChatGptCredentials.length}`)).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "导出" }));
    const dialog = within(document.body).getByRole("dialog", { name: "导出 ChatGPT Keys" });
    await expect(dialog).toBeInTheDocument();
  },
};

export const BatchSupplementPlay: Story = {
  args: Default.args,
  render: () => <KeysStorySurface defaultTab="chatgpt" />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getAllByRole("checkbox", { name: /select-credential-/ })[0]!);
    await userEvent.click(canvas.getByRole("button", { name: "批量补号" }));
    const dialog = within(document.body).getByRole("dialog", { name: "批量补号" });
    await userEvent.click(within(dialog).getByRole("button", { name: "不补号" }));
    await userEvent.click(within(document.body).getByRole("button", { name: "sync-ready" }));
    await userEvent.click(within(dialog).getByRole("button", { name: /补号 1 条/ }));
    await expect(within(dialog).getByText(/success · 1/i)).toBeInTheDocument();
    await expect(within(dialog).getByText(/当前批次全部补号成功/)).toBeInTheDocument();
  },
};

export const SettingsEntryPlay: Story = {
  args: Default.args,
  render: (args) => (
    <KeysStorySurface
      defaultTab="chatgpt"
      onOpenChatGptUpstreamSettings={args.chatgpt.onOpenUpstreamSettings as () => void}
    />
  ),
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "补号设置" }));
    await expect(args.chatgpt.onOpenUpstreamSettings).toHaveBeenCalled();
  },
};
