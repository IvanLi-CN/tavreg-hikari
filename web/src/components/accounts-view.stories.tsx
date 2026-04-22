import { useEffect, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, waitFor, within } from "storybook/test";
import { AccountsView } from "@/components/accounts-view";
import { buildImportCommitEntries } from "@/lib/account-import";
import { createDefaultAccountQuery } from "@/lib/account-query";
import type {
  AccountBatchBootstrapMode,
  AccountBatchBootstrapPreviewPayload,
  AccountExtractorHistoryPayload,
  AccountExtractorHistoryQuery,
  AccountExtractorRunDraft,
  AccountExtractorRuntime,
  AccountExtractorSettings,
  AccountImportPreviewPayload,
  AccountQuery,
  AccountsPayload,
  ExtractorSseState,
  ProxyPayload,
} from "@/lib/app-types";
import {
  sampleAccounts,
  sampleExtractorHistory,
  sampleExtractorHistoryDense,
  sampleExtractorHistoryEmpty,
  sampleExtractorHistoryFailureMatrix,
  sampleExtractorRuntimeFailed,
  sampleExtractorRuntimeIdle,
  sampleExtractorRuntimeRunning,
  sampleExtractorRuntimeSucceeded,
  sampleExtractorSettings,
  sampleProxies,
} from "@/stories/fixtures";

function createDefaultQuery(): AccountQuery {
  return createDefaultAccountQuery();
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
    { email: "new@example.test", password: "password321" },
    { email: "beta@example.test", password: "password789" },
  ],
  items: [
    {
      lineNumber: 1,
      rawLine: "new@example.test----password321",
      email: "new@example.test",
      normalizedEmail: "new@example.test",
      password: "password321",
      decision: "create",
      note: "新增账号",
    },
    {
      lineNumber: 2,
      rawLine: "beta@example.test password789",
      email: "beta@example.test",
      normalizedEmail: "beta@example.test",
      password: "password789",
      decision: "update_password",
      note: "已有账号，密码会更新；该账号已有 API key，后续调度仍会跳过",
      existingAccountId: 2,
      existingHasApiKey: true,
      groupName: "linked",
    },
    {
      lineNumber: 3,
      rawLine: "beta@example.test password000",
      email: "beta@example.test",
      normalizedEmail: "beta@example.test",
      password: "password000",
      decision: "input_duplicate",
      note: "同一批导入中邮箱重复，已以后出现的记录为准",
      duplicateOfLine: 2,
    },
    {
      lineNumber: 4,
      rawLine: "gamma@example.test pass-111",
      email: "gamma@example.test",
      normalizedEmail: "gamma@example.test",
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
  connectBusy: false,
  connectProgress: null,
  batchBootstrapPreview: null,
  batchBootstrapPreviewBusy: false,
  activeBatchBootstrapMode: null,
  extractorSettings: sampleExtractorSettings,
  extractorSettingsBusy: false,
  extractorRuntime: sampleExtractorRuntimeIdle,
  extractorRunDraft: {
    sources: ["zhanghaoya"],
    quantity: 1,
    maxWaitSec: 60,
    accountType: "outlook",
  } satisfies AccountExtractorRunDraft,
  extractorRunBusy: false,
  extractorSseState: "open" as ExtractorSseState,
  extractorHistory: sampleExtractorHistory,
  extractorHistoryQuery: createDefaultExtractorHistoryQuery(),
  extractorHistoryBusy: false,
  allCurrentPageSelected: false,
  graphSettingsConfigured: true,
  connectingAccountIds: [],
  proxyNodes: sampleProxies.nodes,
  proxyCheckState: sampleProxies.checkState,
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
  onConnectAccount: fn(async () => undefined),
  onConnectSelectedAccounts: fn(async () => undefined),
  onCheckProxyNode: fn(async () => undefined),
  onSwitchSessionProxy: fn(async () => undefined),
  onSaveProofMailbox: fn(async () => undefined),
  onSaveAvailability: fn(async () => undefined),
  onSaveExtractorSettings: fn(async () => undefined),
  onExtractorRunDraftChange: fn(),
  onRunExtractor: fn(async () => undefined),
  onStopExtractor: fn(async () => undefined),
  onExtractorHistoryQueryChange: fn(),
  onRefreshExtractorHistory: fn(async () => undefined),
  onOpenMailbox: fn(),
  onOpenMailboxSettings: fn(),
  onOpenStandaloneMailboxWorkspace: fn(),
};
const restoreAvailabilitySpy = fn(async () => undefined);

function buildStoryBatchBootstrapPreview(
  accounts: AccountsPayload,
  selectedIds: number[],
  mode: AccountBatchBootstrapMode = "pending_only",
): AccountBatchBootstrapPreviewPayload {
  const items = Array.from(new Set(selectedIds)).map((accountId) => {
    const account = accounts.rows.find((row) => row.id === accountId) || null;
    if (!account) {
      return { accountId, microsoftEmail: null, decision: "missing" as const, reason: "账号不存在" };
    }
    if (account.disabledAt || account.skipReason === "microsoft_account_locked" || /^microsoft_account_locked/i.test(account.lastErrorCode || "")) {
      return { accountId, microsoftEmail: account.microsoftEmail, decision: "blocked" as const, reason: "账号当前不可 Bootstrap" };
    }
    if (account.browserSession?.status === "bootstrapping") {
      return { accountId, microsoftEmail: account.microsoftEmail, decision: "bootstrapping" as const, reason: "账号当前正在 Bootstrap" };
    }
    if (mode === "pending_only" && account.browserSession?.status === "ready" && account.mailboxStatus === "available") {
      return { accountId, microsoftEmail: account.microsoftEmail, decision: "already_bootstrapped" as const, reason: "账号已经 Bootstrap 成功" };
    }
    return { accountId, microsoftEmail: account.microsoftEmail, decision: "queue" as const, reason: null };
  });
  const queueIds = items.filter((item) => item.decision === "queue").map((item) => item.accountId);
  return {
    ok: true,
    mode,
    requestedCount: selectedIds.length,
    queueIds,
    items,
    summary: {
      queueableCount: queueIds.length,
      blockedCount: items.filter((item) => item.decision === "blocked").length,
      alreadyBootstrappedCount: items.filter((item) => item.decision === "already_bootstrapped").length,
      bootstrappingCount: items.filter((item) => item.decision === "bootstrapping").length,
      missingCount: items.filter((item) => item.decision === "missing").length,
    },
  };
}

function applyStoryAccountQuery(accounts: AccountsPayload, query: AccountQuery): AccountsPayload {
  const pattern = query.q.trim().toLowerCase();
  const filteredRows = accounts.rows.filter((row) => {
    if (query.status && row.lastResultStatus !== query.status) return false;
    if (query.hasApiKey === "true" && !row.hasApiKey) return false;
    if (query.hasApiKey === "false" && row.hasApiKey) return false;
    if (query.sessionStatus && (row.browserSession?.status || "pending") !== query.sessionStatus) return false;
    if (query.mailboxStatus && (row.mailboxStatus || "preparing") !== query.mailboxStatus) return false;
    if (query.groupName && (row.groupName || "") !== query.groupName) return false;
    if (!pattern) return true;
    return [
      row.microsoftEmail,
      row.passwordPlaintext || "",
      row.groupName || "",
      row.proofMailboxAddress || "",
    ].some((value) => value.toLowerCase().includes(pattern));
  });
  const sortedRows = [...filteredRows].sort((left, right) => {
    const importedDelta = right.importedAt.localeCompare(left.importedAt);
    if (importedDelta !== 0) return importedDelta;
    return right.id - left.id;
  });
  if (query.sortBy === "importedAt") {
    sortedRows.sort((left, right) => {
      const delta = query.sortDir === "asc"
        ? left.importedAt.localeCompare(right.importedAt)
        : right.importedAt.localeCompare(left.importedAt);
      if (delta !== 0) return delta;
      const importedDelta = right.importedAt.localeCompare(left.importedAt);
      if (importedDelta !== 0) return importedDelta;
      return right.id - left.id;
    });
  } else if (query.sortBy === "lastUsedAt") {
    sortedRows.sort((left, right) => {
      const leftValue = left.lastUsedAt;
      const rightValue = right.lastUsedAt;
      if (query.sortDir === "asc") {
        if (leftValue == null && rightValue != null) return -1;
        if (leftValue != null && rightValue == null) return 1;
        if (leftValue != null && rightValue != null) {
          const delta = leftValue.localeCompare(rightValue);
          if (delta !== 0) return delta;
        }
      } else {
        if (leftValue == null && rightValue != null) return 1;
        if (leftValue != null && rightValue == null) return -1;
        if (leftValue != null && rightValue != null) {
          const delta = rightValue.localeCompare(leftValue);
          if (delta !== 0) return delta;
        }
      }
      const importedDelta = right.importedAt.localeCompare(left.importedAt);
      if (importedDelta !== 0) return importedDelta;
      return right.id - left.id;
    });
  }
  const start = (query.page - 1) * query.pageSize;
  const pagedRows = sortedRows.slice(start, start + query.pageSize);
  return {
    ...accounts,
    rows: pagedRows,
    total: filteredRows.length,
    page: query.page,
    pageSize: query.pageSize,
  };
}

type AccountsStorySurfaceProps = {
  accounts?: AccountsPayload;
  preview?: AccountImportPreviewPayload | null;
  previewOpen?: boolean;
  importBusy?: boolean;
  previewBusy?: boolean;
  batchBusy?: boolean;
  connectBusy?: boolean;
  extractorSettings?: AccountExtractorSettings | null;
  extractorRuntime?: AccountExtractorRuntime;
  extractorRunDraft?: AccountExtractorRunDraft;
  extractorRunBusy?: boolean;
  extractorSseState?: ExtractorSseState;
  extractorHistory?: AccountExtractorHistoryPayload;
  extractorHistoryQuery?: AccountExtractorHistoryQuery;
  extractorHistoryBusy?: boolean;
  proxies?: ProxyPayload;
  frameClassName?: string;
  initialSelectedIds?: number[];
  graphSettingsConfigured?: boolean;
  connectingAccountIds?: number[];
  initialDesktopToolsCollapsed?: boolean;
  onConnectAccount?: (accountId: number) => Promise<void>;
  onConnectSelectedAccounts?: (mode?: AccountBatchBootstrapMode) => Promise<void>;
  onCheckProxyNode?: (nodeName: string) => Promise<void>;
  onSwitchSessionProxy?: (accountId: number, proxyNode: string) => Promise<void>;
  onSaveProofMailbox?: (accountId: number, proofMailboxAddress: string | null, proofMailboxId?: string | null) => Promise<void>;
  onSaveAvailability?: (accountId: number, disabled: boolean, disabledReason: string | null) => Promise<void>;
  onSaveExtractorSettings?: (patch: Partial<AccountExtractorSettings>) => Promise<void>;
  onRunExtractor?: () => Promise<void>;
  onStopExtractor?: () => Promise<void>;
};

function AccountsStorySurface(props: AccountsStorySurfaceProps) {
  const accounts = props.accounts || sampleAccounts;
  const [extractorSettings, setExtractorSettings] = useState<AccountExtractorSettings>(props.extractorSettings ?? sampleExtractorSettings);
  const [accountsState, setAccountsState] = useState<AccountsPayload>(accounts);
  const [proxyState, setProxyState] = useState<ProxyPayload>(props.proxies ?? sampleProxies);
  const extractorHistory = props.extractorHistory || sampleExtractorHistory;
  const [content, setContent] = useState("");
  const [importGroupName, setImportGroupName] = useState("");
  const [batchGroupName, setBatchGroupName] = useState("");
  const [query, setQuery] = useState<AccountQuery>(createDefaultQuery());
  const [selectedIds, setSelectedIds] = useState<number[]>(props.initialSelectedIds ?? [2]);
  const [previewOpen, setPreviewOpen] = useState(Boolean(props.previewOpen));
  const [extractorRunDraft, setExtractorRunDraft] = useState<AccountExtractorRunDraft>(
    props.extractorRunDraft ?? {
      sources: ["zhanghaoya"],
      quantity: 1,
      maxWaitSec: 60,
      accountType: "outlook" as const,
    },
  );
  const [extractorHistoryQuery, setExtractorHistoryQuery] = useState<AccountExtractorHistoryQuery>(
    props.extractorHistoryQuery ?? createDefaultExtractorHistoryQuery(),
  );
  const visibleAccounts = applyStoryAccountQuery(accountsState, query);
  const batchBootstrapPreview = buildStoryBatchBootstrapPreview(accountsState, selectedIds);

  useEffect(() => {
    if (!props.extractorRunDraft) return;
    setExtractorRunDraft(props.extractorRunDraft);
  }, [props.extractorRunDraft]);

  useEffect(() => {
    if (!props.extractorSettings) return;
    setExtractorSettings(props.extractorSettings);
  }, [props.extractorSettings]);

  useEffect(() => {
    setAccountsState(accounts);
  }, [accounts]);

  useEffect(() => {
    if (!props.proxies) return;
    setProxyState(props.proxies);
  }, [props.proxies]);

  const handleStoryCheckProxyNode = props.onCheckProxyNode
    ?? (async (nodeName: string) => {
      setProxyState((current) => ({
        ...current,
        checkState: {
          ...current.checkState,
          status: "running",
          scope: "node",
          concurrency: 1,
          total: 1,
          completed: 0,
          succeeded: 0,
          failed: 0,
          activeWorkers: 1,
          currentNodeNames: [nodeName],
          startedAt: "2026-04-15T12:00:00.000Z",
          finishedAt: null,
          error: null,
        },
      }));
      await Promise.resolve();
      setProxyState((current) => ({
        ...current,
        checkState: {
          ...current.checkState,
          status: "completed",
          completed: 1,
          succeeded: 1,
          failed: 0,
          activeWorkers: 0,
          currentNodeNames: [],
          finishedAt: "2026-04-15T12:00:03.000Z",
          error: null,
        },
        nodes: current.nodes.map((node) =>
          node.nodeName === nodeName
            ? {
                ...node,
                lastLatencyMs: 208,
                lastEgressIp: node.lastEgressIp || "52.11.12.44",
                lastCheckedAt: "2026-04-15T12:00:03.000Z",
                lastStatus: "ok",
              }
            : node,
        ),
      }));
    });

  const handleStorySwitchSessionProxy = props.onSwitchSessionProxy
    ?? (async (accountId: number, proxyNode: string) => {
      setAccountsState((current) => ({
        ...current,
        rows: current.rows.map((row) =>
          row.id === accountId
            ? {
                ...row,
                mailboxStatus: "preparing",
                browserSession: row.browserSession
                  ? {
                      ...row.browserSession,
                      status: "pending",
                      proxyNode,
                      proxyIp: null,
                      proxyCountry: null,
                      proxyRegion: null,
                      proxyCity: null,
                      proxyTimezone: null,
                      lastErrorCode: null,
                      lastErrorMessage: null,
                      updatedAt: "2026-04-15T12:01:00.000Z",
                    }
                  : {
                      id: 9990 + accountId,
                      status: "pending",
                      profilePath: `/workspace/output/browser-profiles/accounts/${accountId}/chrome`,
                      browserEngine: "chrome",
                      proxyNode,
                      proxyIp: null,
                      proxyCountry: null,
                      proxyRegion: null,
                      proxyCity: null,
                      proxyTimezone: null,
                      lastBootstrappedAt: null,
                      lastUsedAt: null,
                      lastErrorCode: null,
                      lastErrorMessage: null,
                      createdAt: "2026-04-15T12:01:00.000Z",
                      updatedAt: "2026-04-15T12:01:00.000Z",
                    },
              }
            : row,
        ),
      }));
    });

  return (
    <div className={props.frameClassName}>
      <AccountsView
        accounts={visibleAccounts}
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
        connectBusy={Boolean(props.connectBusy)}
        connectProgress={props.connectBusy ? { current: 1, total: Math.max(1, batchBootstrapPreview.summary.queueableCount || selectedIds.length) } : null}
        batchBootstrapPreview={batchBootstrapPreview}
        batchBootstrapPreviewBusy={false}
        activeBatchBootstrapMode={null}
        initialDesktopToolsCollapsed={props.initialDesktopToolsCollapsed}
        extractorSettings={extractorSettings}
        extractorSettingsBusy={false}
        extractorRuntime={props.extractorRuntime ?? sampleExtractorRuntimeIdle}
        extractorRunDraft={extractorRunDraft}
        extractorRunBusy={Boolean(props.extractorRunBusy)}
        extractorSseState={props.extractorSseState ?? "open"}
        extractorHistory={extractorHistory}
        extractorHistoryQuery={extractorHistoryQuery}
        extractorHistoryBusy={Boolean(props.extractorHistoryBusy)}
        allCurrentPageSelected={selectedIds.length > 0 && selectedIds.length === visibleAccounts.rows.length}
        graphSettingsConfigured={props.graphSettingsConfigured ?? true}
        connectingAccountIds={props.connectingAccountIds ?? []}
        proxyNodes={proxyState.nodes}
        proxyCheckState={proxyState.checkState}
        onImportContentChange={setContent}
        onImportGroupChange={setImportGroupName}
        onBatchGroupNameChange={setBatchGroupName}
        onOpenPreview={() => setPreviewOpen(true)}
        onPreviewOpenChange={setPreviewOpen}
        onConfirmImport={() => undefined}
        onQueryChange={setQuery}
        onToggleSelection={(id, checked) => setSelectedIds((current) => (checked ? Array.from(new Set([...current, id])) : current.filter((item) => item !== id)))}
        onTogglePageSelection={(checked) => setSelectedIds(checked ? visibleAccounts.rows.map((row) => row.id) : [])}
        onApplyBatchGroup={() => undefined}
        onDeleteSelected={() => undefined}
        onClearSelection={() => setSelectedIds([])}
        onConnectAccount={props.onConnectAccount ?? (async () => undefined)}
        onConnectSelectedAccounts={props.onConnectSelectedAccounts ?? (async () => undefined)}
        onCheckProxyNode={handleStoryCheckProxyNode}
        onSwitchSessionProxy={handleStorySwitchSessionProxy}
        onSaveProofMailbox={props.onSaveProofMailbox ?? (async () => undefined)}
        onSaveAvailability={props.onSaveAvailability ?? (async () => undefined)}
        onSaveExtractorSettings={
          props.onSaveExtractorSettings
            ?? (async (patch) => {
              setExtractorSettings((current) => ({ ...current, ...patch }));
            })
        }
        onExtractorRunDraftChange={(patch) => setExtractorRunDraft((current) => ({ ...current, ...patch }))}
        onRunExtractor={props.onRunExtractor ?? (async () => undefined)}
        onStopExtractor={props.onStopExtractor ?? (async () => undefined)}
        onExtractorHistoryQueryChange={setExtractorHistoryQuery}
        onRefreshExtractorHistory={async () => undefined}
        onOpenMailbox={() => undefined}
        onOpenMailboxSettings={() => undefined}
        onOpenStandaloneMailboxWorkspace={() => undefined}
      />
    </div>
  );
}

const failureReuseAccounts: AccountsPayload = {
  total: 4,
  page: 1,
  pageSize: 20,
  summary: {
    ready: 0,
    linked: 0,
    failed: 1,
    disabled: 3,
  },
  groups: ["failed-pool", "manual-hold", "retry-pool"],
  rows: sampleAccounts.rows.filter((row) => ["gamma@example.test", "delta@example.test", "omega@example.test", "manual-hold@example.test"].includes(row.microsoftEmail)),
};

const sessionBootstrapAccounts: AccountsPayload = {
  total: 3,
  page: 1,
  pageSize: 20,
  summary: {
    ready: 1,
    linked: 1,
    failed: 0,
    disabled: 1,
  },
  groups: ["default", "linked", "failed-pool"],
  rows: sampleAccounts.rows.filter((row) => ["alpha@example.test", "beta@example.test", "gamma@example.test"].includes(row.microsoftEmail)),
};

const sessionProxyDenseProxies: ProxyPayload = {
  ...sampleProxies,
  nodes: [
    sampleProxies.nodes[0]!,
    sampleProxies.nodes[1]!,
    { ...sampleProxies.nodes[1]!, id: 3, nodeName: "Sydney-03", lastLatencyMs: 707, lastEgressIp: "207.211.147.108" },
    { ...sampleProxies.nodes[1]!, id: 4, nodeName: "Melbourne-04", lastLatencyMs: 701, lastEgressIp: "168.138.12.140" },
    { ...sampleProxies.nodes[1]!, id: 5, nodeName: "Zurich-05", lastLatencyMs: 1323, lastEgressIp: "152.67.70.103" },
    { ...sampleProxies.nodes[0]!, id: 6, nodeName: "Hong Kong-06", lastLatencyMs: 650, lastEgressIp: "103.197.71.112" },
    { ...sampleProxies.nodes[1]!, id: 7, nodeName: "Hong Kong-07", lastLatencyMs: 7714, lastEgressIp: "103.197.71.115" },
    { ...sampleProxies.nodes[0]!, id: 8, nodeName: "Hong Kong-08", lastLatencyMs: 644, lastEgressIp: "103.197.71.113" },
    { ...sampleProxies.nodes[1]!, id: 9, nodeName: "Hong Kong-09", lastLatencyMs: null, lastEgressIp: null },
    { ...sampleProxies.nodes[0]!, id: 10, nodeName: "Hong Kong-10", lastLatencyMs: 648, lastEgressIp: "103.197.71.114" },
    { ...sampleProxies.nodes[1]!, id: 11, nodeName: "Hong Kong-11", lastLatencyMs: null, lastEgressIp: null },
    { ...sampleProxies.nodes[1]!, id: 12, nodeName: "Hong Kong-12", lastLatencyMs: null, lastEgressIp: null },
    { ...sampleProxies.nodes[1]!, id: 13, nodeName: "Hong Kong-13", lastLatencyMs: null, lastEgressIp: null },
    { ...sampleProxies.nodes[1]!, id: 14, nodeName: "Hong Kong-14", lastLatencyMs: 2549, lastEgressIp: "103.197.71.236" },
    { ...sampleProxies.nodes[1]!, id: 15, nodeName: "Hong Kong-15", lastLatencyMs: null, lastEgressIp: null },
  ],
};

const sortingDemoAccounts: AccountsPayload = {
  ...sampleAccounts,
  rows: sampleAccounts.rows.map((row) => {
    if (row.id === 1) {
      return {
        ...row,
        importedAt: "2026-03-18T07:20:00.000Z",
      };
    }
    if (row.id === 2) {
      return {
        ...row,
        importedAt: "2026-03-18T07:25:00.000Z",
      };
    }
    return row;
  }),
};

async function openExtractorSettingsDialog(canvasElement: HTMLElement): Promise<HTMLElement> {
  const canvas = within(canvasElement);
  await userEvent.click(canvas.getByTestId("open-extractor-settings"));
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

async function getSessionProxyViewport(): Promise<HTMLElement> {
  const scrollRoot = within(document.body).getByTestId("session-proxy-scroll-area");
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
          "微软账号导入与查询页，包含提号器实时面板、四个自动提取号源的 KEY 配置、本地提取历史筛选，以及跨分页勾选、批量分组、批量 Bootstrap 和批量删除的交互面。桌面表格额外支持导入时间与最近使用两列的三态排序，并补齐 Session / 收信状态筛选与左侧工具列收起。",
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

export const DefaultCompactCards: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  globals: {
    viewport: { value: "extractorCompact375", isRotated: false },
  },
  parameters: {
    docs: {
      description: {
        story: "默认账号池在 375px 视口下切换为卡片布局，验证双字段分组和图标操作在移动宽度下仍可直接使用。",
      },
    },
  },
};

export const ProofMailboxDialogPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface frameClassName="mx-auto max-w-[1400px]" />,
  parameters: {
    docs: {
      description: {
        story: "打开账号页辅助邮箱弹窗，确认当前展示与保存链路都围绕 `cfmail` provider。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getAllByRole("button", { name: /设置 .* 的辅助邮箱/ })[0]!);
    const dialog = await waitFor(() => within(document.body).getByRole("dialog", { name: "设置辅助邮箱" }));
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText(/cfmail/i)).toBeInTheDocument();
    expect(within(dialog).getByDisplayValue("alpha-proof@mail.example.test")).toBeInTheDocument();
  },
};

export const DesktopActionButtonsNoWrap: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface frameClassName="mx-auto max-w-[1400px]" />,
  parameters: {
    docs: {
      description: {
        story: "桌面表格回归场景，固定较窄工作区宽度，验证操作列收敛为图标按钮组并通过表格横向滚动消化宽度压力。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const table = canvas.getByRole("table");
    const tableScroller = table.parentElement as HTMLDivElement | null;
    const connectButton = canvas.getAllByRole("button", { name: /alpha@example\.test .*Bootstrap/ })[0]!;
    const proofButton = canvas.getAllByRole("button", { name: /设置 alpha@example\.test 的辅助邮箱/ })[0]!;
    const availabilityButton = canvas.getAllByRole("button", { name: /标记 alpha@example\.test 不可用/ })[0]!;
    const mailboxButton = canvas.getAllByRole("button", { name: /打开 alpha@example\.test 的收件箱/ })[0]!;

    expect(connectButton).toBeTruthy();
    expect(proofButton).toBeTruthy();
    expect(availabilityButton).toBeTruthy();
    expect(mailboxButton).toBeTruthy();
    expect(connectButton.textContent?.trim()).toBe("");
    expect(proofButton.textContent?.trim()).toBe("");
    expect(availabilityButton.textContent?.trim()).toBe("");
    expect(mailboxButton.textContent?.trim()).toBe("");
    expect(tableScroller).toBeTruthy();
    expect(tableScroller!.scrollWidth).toBeGreaterThan(tableScroller!.clientWidth);
  },
};

export const ActionIconTooltipsPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface frameClassName="mx-auto max-w-[1400px]" />,
  parameters: {
    docs: {
      description: {
        story: "验证账号列表的图标按钮统一通过第三方 tooltip 延迟展示用途说明，而不是依赖原生 title。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const proofButton = canvas.getAllByRole("button", { name: /设置 alpha@example\.test 的辅助邮箱/ })[0]!;
    await userEvent.hover(proofButton);
    await waitFor(() => {
      expect(within(document.body).getByText("设置 alpha@example.test 的辅助邮箱")).toBeInTheDocument();
    });
  },
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
    await userEvent.type(canvas.getByRole("textbox", { name: "account-import" }), "new@example.test----password321");
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
    await userEvent.click(canvas.getByTestId("open-extractor-settings"));
    const dialog = within(document.body).getByRole("dialog", { name: "微软账号提取器设置" });
    await expect(dialog).toBeInTheDocument();
    await expect(within(dialog).getByText("闪客云 KEY")).toBeInTheDocument();
    await expect(within(dialog).getByText("Hotmail666 KEY")).toBeInTheDocument();
  },
};

export const ExtractorRuntimeRunning: Story = {
  args: baseArgs,
  render: () => (
    <AccountsStorySurface
      extractorRuntime={{ ...sampleExtractorRuntimeRunning, accountType: "hotmail" }}
      extractorRunDraft={{ sources: ["zhanghaoya", "shanyouxiang"], quantity: 2, maxWaitSec: 45, accountType: "hotmail" }}
      extractorSseState="open"
    />
  ),
  parameters: {
    docs: {
      description: {
        story: "提号器运行中场景，展示实时 accepted/raw/in-flight/remaining wait 指标、当前邮箱类型，以及 SSE 已连接状态。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("SSE 已连接")).toBeInTheDocument();
    await expect(canvas.getByText("目标接受：1 / 2")).toBeInTheDocument();
    await expect(canvas.getByText("原始请求：3")).toBeInTheDocument();
    await expect(canvas.getByText("剩余等待：27s / 45s")).toBeInTheDocument();
    await expect(canvas.getByText("邮箱类型：Hotmail")).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "取消提号" })).toBeInTheDocument();
  },
};

export const ExtractorAccountTypePlay: Story = {
  args: baseArgs,
  render: () => {
    return (
      <AccountsStorySurface
        extractorRuntime={{ ...sampleExtractorRuntimeIdle, accountType: "outlook" }}
        extractorRunDraft={{
          sources: ["zhanghaoya", "hotmail666"],
          quantity: 2,
          maxWaitSec: 45,
          accountType: "outlook",
        }}
      />
    );
  },
  parameters: {
    docs: {
      description: {
        story: "验证账号页手动提号器可以切换到“不限”，并保持摘要状态同步。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("邮箱类型：Outlook")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("combobox", { name: "邮箱类型" }));
    await userEvent.click(within(document.body).getByRole("option", { name: "不限" }));
    await expect(canvas.getByText("邮箱类型：不限")).toBeInTheDocument();
  },
};

export const ExtractorSettingsDefaultAccountTypePlay: Story = {
  args: {
    ...baseArgs,
    onSaveExtractorSettings: fn(async () => undefined),
  },
  render: (args) => <AccountsStorySurface onSaveExtractorSettings={args.onSaveExtractorSettings} />,
  parameters: {
    docs: {
      description: {
        story: "验证提号器设置弹窗允许保存默认账号类型为“不限”，并把选择值连同 KEY 一起提交。",
      },
    },
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByTestId("open-extractor-settings"));
    const dialog = within(document.body).getByRole("dialog", { name: "微软账号提取器设置" });
    await userEvent.click(within(dialog).getByRole("combobox", { name: "默认邮箱类型" }));
    await userEvent.click(within(document.body).getByRole("option", { name: "不限" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "保存" }));
    await expect(args.onSaveExtractorSettings).toHaveBeenCalledWith(
      expect.objectContaining({ defaultAutoExtractAccountType: "unlimited" }),
    );
  },
};

export const ExtractorStartCancelCooldownPlay: Story = {
  args: baseArgs,
  render: () => {
    function InteractiveSurface() {
      const [runtime, setRuntime] = useState<AccountExtractorRuntime>(sampleExtractorRuntimeIdle);
      const [busy, setBusy] = useState(false);
      const draft: AccountExtractorRunDraft = {
        sources: ["zhanghaoya", "hotmail666"],
        quantity: 2,
        maxWaitSec: 60,
        accountType: "outlook",
      };
      return (
        <AccountsStorySurface
          extractorRuntime={runtime}
          extractorRunDraft={draft}
          extractorRunBusy={busy}
          onRunExtractor={async () => {
            setBusy(true);
            await new Promise((resolve) => window.setTimeout(resolve, 80));
            setRuntime({
              ...sampleExtractorRuntimeRunning,
              enabledSources: draft.sources,
              requestedUsableCount: draft.quantity,
              maxWaitSec: draft.maxWaitSec,
              remainingWaitSec: 58,
            });
            setBusy(false);
          }}
          onStopExtractor={async () => {
            setBusy(true);
            setRuntime((current) => ({
              ...current,
              status: "stopping",
              lastMessage: "提号取消中，等待 2 个在途请求收尾",
            }));
            await new Promise((resolve) => window.setTimeout(resolve, 80));
            setRuntime({
              ...sampleExtractorRuntimeIdle,
              status: "stopped",
              enabledSources: draft.sources,
              requestedUsableCount: draft.quantity,
              lastMessage: "提号已取消",
              updatedAt: "2026-04-03T03:20:00.000Z",
            });
            setBusy(false);
          }}
        />
      );
    }
    return <InteractiveSurface />;
  },
  parameters: {
    docs: {
      description: {
        story: "验证开始提号后按钮先禁用 1 秒，再切到红色取消按钮；取消后同样禁用 1 秒再恢复开始态。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const startButton = canvas.getByRole("button", { name: "开始提号 + 自动 Bootstrap" });
    await userEvent.click(startButton);
    await expect(canvas.getByRole("button", { name: "提号中…" })).toBeDisabled();
    await new Promise((resolve) => window.setTimeout(resolve, 1100));
    const cancelButton = canvas.getByRole("button", { name: "取消提号" });
    await expect(cancelButton).toBeEnabled();
    await userEvent.click(cancelButton);
    await expect(canvas.getByRole("button", { name: "取消中…" })).toBeDisabled();
    await new Promise((resolve) => window.setTimeout(resolve, 1100));
    await expect(canvas.getByRole("button", { name: "开始提号 + 自动 Bootstrap" })).toBeEnabled();
  },
};

export const ExtractorRunInputsBlurCorrectionPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  parameters: {
    docs: {
      description: {
        story: "验证提号数量与最长等待输入框允许先清空再重输，只在失焦后做数值订正，避免边删边被立即改写。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const quantityInput = canvas.getByRole("spinbutton", { name: "提号数量" }) as HTMLInputElement;
    const maxWaitInput = canvas.getByRole("spinbutton", { name: "最长等待（秒）" }) as HTMLInputElement;

    await userEvent.clear(quantityInput);
    expect(quantityInput.value).toBe("");
    await userEvent.type(quantityInput, "12");
    expect(quantityInput.value).toBe("12");
    await userEvent.tab();
    await expect(quantityInput).toHaveValue(12);

    await userEvent.clear(maxWaitInput);
    expect(maxWaitInput.value).toBe("");
    await userEvent.type(maxWaitInput, "300");
    expect(maxWaitInput.value).toBe("300");
    await userEvent.tab();
    await expect(maxWaitInput).toHaveValue(300);
  },
};

export const ExtractorRuntimeOutcomeStates: Story = {
  args: baseArgs,
  render: () => (
    <div className="space-y-6">
      <AccountsStorySurface extractorRuntime={sampleExtractorRuntimeSucceeded} extractorRunDraft={{ sources: ["zhanghaoya", "shankeyun"], quantity: 2, maxWaitSec: 45, accountType: "outlook" }} />
      <AccountsStorySurface extractorRuntime={sampleExtractorRuntimeFailed} extractorRunDraft={{ sources: ["zhanghaoya"], quantity: 1, maxWaitSec: 30, accountType: "outlook" }} extractorSseState="error" />
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: "提号器收敛态矩阵，覆盖成功与失败两类结果，便于核对重试前的最终摘要和错误文案。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("已接受 2 / 2 个账号")).toBeInTheDocument();
    await expect(canvas.getByText("提号等待超时（30 秒）")).toBeInTheDocument();
    await expect(canvas.getByText("SSE 异常")).toBeInTheDocument();
  },
};

export const PasswordCopyPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  parameters: {
    docs: {
      description: {
        story: "复制成功后会弹出可见气泡，明确提示已复制，同时保留可点击全选的完整内容文本块供手动校验或再次复制。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const writeText = fn(async () => undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const canvas = within(canvasElement);
    const trigger = canvas.getByRole("button", { name: "复制alpha@example.test 密码" });
    await userEvent.click(trigger);
    await expect(writeText).toHaveBeenCalledWith("pass-456");
    await waitFor(() => {
      expect(canvas.getByRole("button", { name: "alpha@example.test 密码已复制" })).toBeInTheDocument();
    });
    await expect(within(document.body).getByText("已复制")).toBeInTheDocument();
    await expect(within(document.body).getByRole("textbox", { name: "完整内容（点击全选）" })).toHaveTextContent("pass-456");
  },
};

export const CopyFailureFallbackPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  parameters: {
    docs: {
      description: {
        story: "当浏览器拒绝自动复制时，复制图标会弹出气泡说明失败原因，并提供可点击全选的完整内容文本块供手动复制。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const writeText = fn(async () => {
      throw new Error("clipboard blocked by browser");
    });
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const canvas = within(canvasElement);
    const trigger = canvas.getByRole("button", { name: "复制beta@example.test 邮箱" });
    await userEvent.click(trigger);
    await waitFor(() => {
      expect(within(document.body).getByText("自动复制失败")).toBeInTheDocument();
    });
    await expect(within(document.body).getByRole("textbox", { name: "完整内容（点击全选）" })).toHaveTextContent("beta@example.test");
  },
};

export const FailureReuseMatrix: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface />,
  parameters: {
    docs: {
      description: {
        story: "状态矩阵场景，集中展示瞬时失败可复用、密码错误阻断、未知辅助邮箱阻断与人工停用四类差异。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("Microsoft 密码错误")).toBeInTheDocument();
    await expect(canvas.getByText("未知辅助邮箱：de*****@genq.top")).toBeInTheDocument();
    await expect(canvas.getByText("人工复核中")).toBeInTheDocument();
    await expect(canvas.getAllByRole("button", { name: /恢复 .* 可用/ }).length).toBeGreaterThanOrEqual(3);
  },
};

export const FailureReuseCompactCards: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface accounts={failureReuseAccounts} initialSelectedIds={[]} />,
  parameters: {
    docs: {
      description: {
        story: "窄视口卡片态，只保留密码错误阻断、未知辅助邮箱阻断、瞬时失败可复用与人工停用四个目标账号，便于直接核对恢复入口和阻断文案。",
      },
    },
  },
  globals: {
    viewport: { value: "extractorCompact375", isRotated: false },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("Microsoft 密码错误")).toBeInTheDocument();
    await expect(canvas.getByText("未知辅助邮箱：de*****@genq.top")).toBeInTheDocument();
    await expect(canvas.getByText("人工复核中")).toBeInTheDocument();
    await expect(canvas.getAllByRole("button", { name: /恢复 .* 可用/ }).length).toBeGreaterThanOrEqual(3);
  },
};

export const RestoreBlockedAccountPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface onSaveAvailability={restoreAvailabilitySpy} />,
  parameters: {
    docs: {
      description: {
        story: "验证硬账号阻断与人工停用都会暴露恢复入口，并复用同一 PATCH 语义解除阻断。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const restoreButtons = canvas.getAllByRole("button", { name: /恢复 .* 可用/ });
    await expect(restoreButtons.length).toBeGreaterThan(0);
    await userEvent.click(restoreButtons[0]!);
    await expect(restoreAvailabilitySpy).toHaveBeenCalledWith(expect.any(Number), false, null);
  },
};

export const SessionBootstrapStates: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface accounts={sessionBootstrapAccounts} initialSelectedIds={[]} />,
  parameters: {
    docs: {
      description: {
        story: "账号级持久浏览器会话状态矩阵，固定展示 bootstrap 中、ready 复用、blocked 重试三态，以及对应代理/IP 与 profile 路径摘要。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("BOOTSTRAPPING")).toBeInTheDocument();
    await expect(canvas.getAllByText("READY").length).toBeGreaterThan(0);
    await expect(canvas.getByText("BLOCKED")).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: /alpha@example\.test Bootstrap 中/ })).toBeDisabled();
    await expect(canvas.getAllByRole("button", { name: /重试 Bootstrap/ }).length).toBeGreaterThanOrEqual(2);
    await expect(canvas.getByText("34.91.22.10 · Tokyo-01")).toBeInTheDocument();
    await expect(canvas.getByText("52.11.12.44 · Seoul-02")).toBeInTheDocument();
    await expect(canvas.getByText("…/browser-profiles/accounts/1/chrome")).toBeInTheDocument();
    await expect(canvas.getByText("…/browser-profiles/accounts/2/chrome")).toBeInTheDocument();
    await expect(canvas.getByText("…/browser-profiles/accounts/3/chrome")).toBeInTheDocument();
  },
};

export const SessionBootstrapCompactCards: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface accounts={sessionBootstrapAccounts} initialSelectedIds={[]} />,
  parameters: {
    docs: {
      description: {
        story: "375px 卡片态回归，确保最小账号页在移动宽度下仍能直接看到 session、proxy 与 profile 摘要。",
      },
    },
  },
  globals: {
    viewport: { value: "extractorCompact375", isRotated: false },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getAllByText("Session").length).toBeGreaterThan(0);
    await expect(canvas.getByText("Session Proxy")).toBeInTheDocument();
    await expect(canvas.getByText("Profile")).toBeInTheDocument();
    await expect(canvas.getByText("…/browser-profiles/accounts/1/chrome")).toBeInTheDocument();
    await expect(canvas.getByText("…/browser-profiles/accounts/3/chrome")).toBeInTheDocument();
  },
};

export const SessionProxySwitchDialogPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface accounts={sessionBootstrapAccounts} proxies={sessionProxyDenseProxies} initialSelectedIds={[]} frameClassName="mx-auto max-w-[1440px]" />,
  parameters: {
    docs: {
      description: {
        story: "账号页 Session Proxy 单元格支持行内编辑，弹窗内展示名称、IP、延迟与测速/选择操作，并可立即切换到新节点。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "更换 beta@example.test 的 Session Proxy" }));
    const dialog = within(document.body).getByRole("dialog", { name: "更换 Session Proxy" });
    await expect(within(dialog).getByText("当前节点信息")).toBeInTheDocument();
    await expect(within(dialog).getByText("候选代理节点")).toBeInTheDocument();
    await expect(within(dialog).getByText("名称")).toBeInTheDocument();
    await expect(within(dialog).getByText("IP")).toBeInTheDocument();
    await expect(within(dialog).getByText("延迟")).toBeInTheDocument();
    await expect(within(dialog).getByText("操作")).toBeInTheDocument();
    await expect(within(dialog).getByText("Tokyo-01")).toBeInTheDocument();
    await expect(within(dialog).getByText("Seoul-02")).toBeInTheDocument();
    const nameHeader = within(dialog).getByText("名称");
    expect(window.getComputedStyle(nameHeader).position).toBe("sticky");
    const proxyViewport = await getSessionProxyViewport();
    await expectNoHorizontalOverflow(proxyViewport, 2);
    await waitFor(() => {
      expect(proxyViewport.scrollHeight).toBeGreaterThan(proxyViewport.clientHeight);
    });
    proxyViewport.scrollTop = 220;
    proxyViewport.dispatchEvent(new Event("scroll"));
    const stickyTop = Math.round(nameHeader.getBoundingClientRect().top);
    proxyViewport.scrollTop = proxyViewport.scrollHeight;
    proxyViewport.dispatchEvent(new Event("scroll"));
    await waitFor(() => {
      expect(proxyViewport.scrollTop).toBeGreaterThan(0);
    });
    await waitFor(() => {
      expect(Math.abs(Math.round(nameHeader.getBoundingClientRect().top) - stickyTop)).toBeLessThanOrEqual(2);
    });
    await userEvent.click(within(dialog).getAllByRole("button", { name: "测速" })[1]!);
    await expect(within(dialog).getByText("208 ms")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "选择" }));
    await waitFor(() => {
      expect(within(document.body).queryByRole("dialog", { name: "更换 Session Proxy" })).not.toBeInTheDocument();
    });
    await expect(canvas.getByText("Seoul-02")).toBeInTheDocument();
    await expect(canvas.queryByText("52.11.12.44 · Seoul-02")).not.toBeInTheDocument();

    await userEvent.click(canvas.getByRole("button", { name: "更换 beta@example.test 的 Session Proxy" }));
    const reopenedDialog = within(document.body).getByRole("dialog", { name: "更换 Session Proxy" });
    await expect(within(reopenedDialog).getByText("当前节点信息")).toBeInTheDocument();
    await expect(within(reopenedDialog).getByText("Seoul-02")).toBeInTheDocument();
    await expect(within(reopenedDialog).getByText("当前代理")).toBeInTheDocument();
    const seoulRow = within(reopenedDialog).getAllByText("Seoul-02").find((element) => element.closest("tr"))?.closest("tr");
    expect(seoulRow).not.toBeNull();
    await expect(within(seoulRow as HTMLElement).getByText("当前")).toBeInTheDocument();
  },
};

export const SessionProxySwitchCompactCards: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface accounts={sessionBootstrapAccounts} initialSelectedIds={[]} />,
  parameters: {
    docs: {
      description: {
        story: "375px 卡片态下仍可从 Session Proxy 字段直接打开更换弹窗，不会把卡片布局挤坏。",
      },
    },
  },
  globals: {
    viewport: { value: "extractorCompact375", isRotated: false },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "更换 beta@example.test 的 Session Proxy" }));
    const dialog = within(document.body).getByRole("dialog", { name: "更换 Session Proxy" });
    await expect(within(dialog).getByText("Tokyo-01")).toBeInTheDocument();
    await expect(within(dialog).getByText("Seoul-02")).toBeInTheDocument();
  },
};

const batchBootstrapSpy = fn(async () => undefined);
const forceBootstrapSpy = fn(async () => undefined);

export const BatchBootstrapSelectionPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface initialSelectedIds={[2, 3, 4]} onConnectSelectedAccounts={batchBootstrapSpy} />,
  parameters: {
    docs: {
      description: {
        story: "批量 Bootstrap 入口固定在微软账号页；默认只处理未成功 Bootstrap 的账号，并把锁定/禁用/进行中账号排除在外。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("可 Bootstrap 1 条")).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "已锁定" })).toBeDisabled();
    await userEvent.click(canvas.getByRole("button", { name: "批量 Bootstrap" }));
    await expect(batchBootstrapSpy).toHaveBeenCalledTimes(1);
  },
};

export const DesktopToolsCollapsed: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface initialDesktopToolsCollapsed frameClassName="mx-auto max-w-[1600px]" />,
  parameters: {
    docs: {
      description: {
        story: "桌面态左侧工具列收起后的账号页，验证右侧账号池拿到完整宽度且仍保留稳定的“展开工具列”入口。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.queryByText("提号器")).not.toBeInTheDocument();
    await expect(canvas.queryByText("导入微软账号")).not.toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "展开工具列" })).toBeInTheDocument();
  },
};

export const ForceBootstrapSelectionPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface initialSelectedIds={[2, 4]} onConnectSelectedAccounts={forceBootstrapSpy} />,
  parameters: {
    docs: {
      description: {
        story: "验证工具栏同时暴露“批量 Bootstrap”和“强制 Bootstrap”两个入口，便于直接对已成功账号重新发起 Bootstrap。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("button", { name: "强制 Bootstrap" })).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "强制 Bootstrap" }));
    await expect(forceBootstrapSpy).toHaveBeenCalledWith("force");
  },
};

export const StatusFiltersPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface initialSelectedIds={[]} />,
  parameters: {
    docs: {
      description: {
        story: "验证账号池新增 Session 与收信状态筛选，并且能与现有条件组合筛掉不匹配记录。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const rowCells = () => canvas.getAllByRole("cell").filter((cell) => cell.textContent?.includes("@example.test"));

    await expect(rowCells().length).toBeGreaterThan(3);

    await userEvent.click(canvas.getByRole("combobox", { name: "Session" }));
    await userEvent.click(within(document.body).getByRole("option", { name: "failed" }));
    await expect(rowCells()).toHaveLength(1);
    await expect(rowCells()[0]).toHaveTextContent("delta@example.test");

    await userEvent.click(canvas.getByRole("combobox", { name: "收信状态" }));
    await userEvent.click(within(document.body).getByRole("option", { name: "invalidated" }));
    await expect(rowCells()).toHaveLength(1);
    await expect(rowCells()[0]).toHaveTextContent("delta@example.test");
  },
};

export const SortingTimeColumnsPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface accounts={sortingDemoAccounts} initialSelectedIds={[2]} />,
  parameters: {
    docs: {
      description: {
        story: "验证账号页默认按导入时间降序展示，并在时间列排序切换后恢复到默认的导入时间降序。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const importedAtButton = canvas.getByRole("button", { name: /导入时间排序/ });
    const lastUsedButton = canvas.getByRole("button", { name: /最近使用排序/ });
    const rowCells = () => canvas.getAllByRole("cell").filter((cell) => cell.textContent?.includes("@example.test"));

    await expect(rowCells()[0]).toHaveTextContent("beta@example.test");
    await userEvent.click(importedAtButton);
    await expect(rowCells()[0]).toHaveTextContent("gamma@example.test");
    await userEvent.click(importedAtButton);
    await expect(rowCells()[0]).toHaveTextContent("beta@example.test");

    await userEvent.click(lastUsedButton);
    await expect(rowCells()[0]).toHaveTextContent("beta@example.test");
    await userEvent.click(lastUsedButton);
    await expect(rowCells()[0]).toHaveTextContent("alpha@example.test");
    await userEvent.click(lastUsedButton);
    await expect(rowCells()[0]).toHaveTextContent("beta@example.test");
    await expect(importedAtButton).toHaveAttribute("aria-label", expect.stringContaining("当前默认降序"));
  },
};

export const MailWorkspaceEntryPlay: Story = {
  args: baseArgs,
  render: () => <AccountsStorySurface initialSelectedIds={[]} />,
  parameters: {
    docs: {
      description: {
        story: "验证 Microsoft 账号页头部同时暴露独立“微软邮箱”入口与 Graph 设置入口。",
      },
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("button", { name: "微软邮箱" })).toBeInTheDocument();
    await expect(canvas.getByRole("button", { name: "Graph 设置" })).toBeInTheDocument();
  },
};
