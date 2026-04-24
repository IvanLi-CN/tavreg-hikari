import { useMemo, useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { GrokApiKeysView } from "@/components/grok-api-keys-view";
import type { GrokApiKeyQuery, GrokApiKeysPayload } from "@/lib/app-types";
import { sampleGrokApiKeys } from "@/stories/fixtures";

function createDefaultQuery(): GrokApiKeyQuery {
  return { q: "", status: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 };
}

const exportFixtureById: Record<
  number,
  { email: string; password: string; sso: string; ssoRw: string; cfClearance: string; checkoutUrl: string; birthDate: string }
> = {
  11: {
    email: "grok-1697@mail.example.test",
    password: "Pw-demo-1697",
    sso: "eyJhbGciOiJIUzI1NiJ9.demo_long_sso_token_alpha_abcdefghijklmnopqrstuvwxyz_1234567890",
    ssoRw: "sso_rw_demo_a",
    cfClearance: "cf_clearance_demo_a",
    checkoutUrl: "https://checkout.stripe.example/a",
    birthDate: "1996-03-18T16:00:00.000Z",
  },
  12: {
    email: "grok-1601@mail.example.test",
    password: "Pw-demo-1601",
    sso: "eyJhbGciOiJIUzI1NiJ9.demo_long_sso_token_beta_abcdefghijklmnopqrstuvwxyz_1234567890",
    ssoRw: "sso_rw_demo_b",
    cfClearance: "cf_clearance_demo_b",
    checkoutUrl: "https://checkout.stripe.example/b",
    birthDate: "1998-11-07T16:00:00.000Z",
  },
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

function applyQuery(source: GrokApiKeysPayload, query: GrokApiKeyQuery): GrokApiKeysPayload {
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

function buildExportContent(selectedIds: number[]): string {
  return selectedIds
    .map((id) => exportFixtureById[id])
    .filter(
      (
        item,
      ): item is { email: string; password: string; sso: string; ssoRw: string; cfClearance: string; checkoutUrl: string; birthDate: string } =>
        Boolean(item),
    )
    .map((item) => item.sso)
    .join("\n");
}

function buildStorySource(): GrokApiKeysPayload {
  return sampleGrokApiKeys;
}

function StorySurface(props: { source?: GrokApiKeysPayload; initialQuery?: GrokApiKeyQuery; initialSelectedIds?: number[]; initialExportOpen?: boolean }) {
  const source = props.source || buildStorySource();
  const [query, setQuery] = useState<GrokApiKeyQuery>(props.initialQuery || createDefaultQuery());
  const [selectedIds, setSelectedIds] = useState<number[]>(props.initialSelectedIds || []);
  const [exportOpen, setExportOpen] = useState(Boolean(props.initialExportOpen));
  const apiKeys = useMemo(() => applyQuery(source, query), [query, source]);
  const exportContent = useMemo(() => buildExportContent(selectedIds), [selectedIds]);

  return (
    <GrokApiKeysView
      apiKeys={apiKeys}
      query={query}
      selectedIds={selectedIds}
      exportOpen={exportOpen}
      exportContent={exportContent}
      exportBusy={false}
      onQueryChange={setQuery}
      onToggleSelection={(id, checked) => setSelectedIds((current) => (checked ? Array.from(new Set([...current, id])) : current.filter((item) => item !== id)))}
      onTogglePageSelection={(checked) => setSelectedIds(checked ? apiKeys.rows.map((row) => row.id) : [])}
      onClearSelection={() => setSelectedIds([])}
      onOpenExport={() => setExportOpen(true)}
      onExportOpenChange={setExportOpen}
      onCopyExport={() => undefined}
      onSaveExport={() => undefined}
      onResolveCopyField={async (apiKeyId, field) => {
        const item = exportFixtureById[apiKeyId];
        if (!item) return "";
        return field === "email" ? item.email : field === "password" ? item.password : item.sso;
      }}
    />
  );
}

const meta = {
  title: "Views/GrokApiKeysView",
  component: GrokApiKeysView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component:
          "Grok SSO 列表页直接显示邮箱、密码与 SSO 原文，长值在固定宽度列内省略，邮箱/密码/SSO 都提供纯 icon 复制按钮；批量导出时每行只输出一个 SSO token。",
      },
    },
  },
} satisfies Meta<typeof GrokApiKeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

const baseArgs = {
  apiKeys: buildStorySource(),
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
  onResolveCopyField: fn(async () => ""),
};

export const Default: Story = {
  args: baseArgs,
  render: () => <StorySurface />,
};

export const ExportDialog: Story = {
  args: baseArgs,
  render: () => <StorySurface initialSelectedIds={[11, 12]} initialExportOpen />,
};

export const ActionsOnly: Story = {
  args: baseArgs,
  render: () => <StorySurface initialSelectedIds={[11]} />,
};

export const CompactBelowMd: Story = {
  args: baseArgs,
  parameters: {
    viewport: { value: "keysCompact700", isRotated: false },
  },
  render: () => <StorySurface initialSelectedIds={[11]} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("checkbox", { name: "select-current-page-mobile" })).toBeInTheDocument();
    await expect(canvas.queryByRole("checkbox", { name: "select-current-page" })).toBeNull();
    await expect(canvas.queryByText("出口 IP")).toBeNull();
    await expect(canvas.getAllByText("SSO").length).toBeGreaterThan(0);
  },
};

export const MediumTableLayout: Story = {
  args: baseArgs,
  parameters: {
    viewport: { value: "keysMedium820", isRotated: false },
  },
  render: () => <StorySurface initialSelectedIds={[11]} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("checkbox", { name: "select-current-page" })).toBeInTheDocument();
    await expect(canvas.queryByRole("checkbox", { name: "select-current-page-mobile" })).toBeNull();
    await expect(canvas.getByText("邮箱")).toBeInTheDocument();
    await expect(canvas.getByText("SSO")).toBeInTheDocument();
    await expect(canvas.queryByText("出口 IP")).toBeNull();
  },
};

export const WideTableLayout: Story = {
  args: baseArgs,
  parameters: {
    viewport: { value: "keysWide1120", isRotated: false },
  },
  render: () => <StorySurface initialSelectedIds={[11]} />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByRole("checkbox", { name: "select-current-page" })).toBeInTheDocument();
    await expect(canvas.queryByRole("checkbox", { name: "select-current-page-mobile" })).toBeNull();
    await expect(canvas.getByText("出口 IP")).toBeInTheDocument();
    await expect(canvas.getByText("提取时间")).toBeInTheDocument();
    await expect(canvas.getByText("最近验证")).toBeInTheDocument();
  },
};

export const CopyActionPlay: Story = {
  args: baseArgs,
  render: () => <StorySurface />,
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const button = canvas.getByRole("button", { name: /复制 grok-1697@mail.example.test 的密码/i });
    await userEvent.click(button);
    await expect(button).toHaveClass("text-emerald-300");
  },
};
