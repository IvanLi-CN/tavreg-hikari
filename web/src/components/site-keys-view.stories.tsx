import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { AppShell } from "@/components/app-shell";
import { ChatGptKeysPane, GrokKeysPane, TavilyKeysPane } from "@/components/keys-view";
import { SiteKeysView } from "@/components/site-keys-view";
import { sampleApiKeys, sampleChatGptCredentials, sampleGrokApiKeys } from "@/stories/fixtures";

const chatGptSort = {
  sortBy: "createdAt",
  sortDir: "desc",
} as const;

const meta = {
  title: "Views/SiteKeysView",
  component: SiteKeysView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "站点内嵌的 Keys 子视图，用于替代顶层 Keys 导航并保留返回主控页入口。",
      },
    },
  },
} satisfies Meta<typeof SiteKeysView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const TavilyKeys: Story = {
  args: {
    siteLabel: "Tavily",
    description: "这里收纳 Tavily 提取结果；返回后继续处理 Tavily 主流程与自动补号。",
    onBack: () => undefined,
    children: null,
  },
  render: () => (
    <AppShell activePage="tavily" error={null} onNavigate={() => undefined}>
      <SiteKeysView
        siteLabel="Tavily"
        description="这里收纳 Tavily 提取结果；返回后继续处理 Tavily 主流程与自动补号。"
        badgeText={`总计 ${sampleApiKeys.total}`}
        onBack={() => undefined}
      >
        <TavilyKeysPane
          apiKeys={sampleApiKeys}
          query={{ q: "", status: "", groupName: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 }}
          selectedIds={[]}
          exportOpen={false}
          exportContent=""
          exportBusy={false}
          onQueryChange={() => undefined}
          onToggleSelection={() => undefined}
          onTogglePageSelection={() => undefined}
          onClearSelection={() => undefined}
          onOpenExport={() => undefined}
          onExportOpenChange={() => undefined}
          onCopyExport={() => undefined}
          onSaveExport={() => undefined}
        />
      </SiteKeysView>
    </AppShell>
  ),
};

export const GrokKeys: Story = {
  args: {
    siteLabel: "Grok",
    description: "这里集中查看 Grok 站点的 SSO 与导出结果；返回后继续 Grok 批量任务。",
    onBack: () => undefined,
    children: null,
  },
  render: () => (
    <AppShell activePage="grok" error={null} onNavigate={() => undefined}>
      <SiteKeysView
        siteLabel="Grok"
        description="这里集中查看 Grok 站点的 SSO 与导出结果；返回后继续 Grok 批量任务。"
        badgeText={`总计 ${sampleGrokApiKeys.total}`}
        onBack={() => undefined}
      >
        <GrokKeysPane
          apiKeys={sampleGrokApiKeys}
          query={{ q: "", status: "", sortBy: "extractedAt", sortDir: "desc", page: 1, pageSize: 20 }}
          selectedIds={[]}
          exportOpen={false}
          exportContent=""
          exportBusy={false}
          onQueryChange={() => undefined}
          onToggleSelection={() => undefined}
          onTogglePageSelection={() => undefined}
          onClearSelection={() => undefined}
          onOpenExport={() => undefined}
          onExportOpenChange={() => undefined}
          onCopyExport={() => undefined}
          onSaveExport={() => undefined}
          onResolveCopyField={async () => ""}
        />
      </SiteKeysView>
    </AppShell>
  ),
};

const openSettingsSpy = fn();
const backSpy = fn();

export const ChatGptKeys: Story = {
  args: {
    siteLabel: "ChatGPT",
    description: "这里集中查看 ChatGPT keys，并保留站内补号设置入口；返回后继续 ChatGPT 任务控制。",
    onBack: () => undefined,
    children: null,
  },
  render: () => (
    <AppShell activePage="chatgpt" error={null} onNavigate={() => undefined}>
      <SiteKeysView
        siteLabel="ChatGPT"
        description="这里集中查看 ChatGPT keys，并保留站内补号设置入口；返回后继续 ChatGPT 任务控制。"
        badgeText={`总计 ${sampleChatGptCredentials.length}`}
        onBack={backSpy}
      >
        <ChatGptKeysPane
          credentials={sampleChatGptCredentials}
          query={{ q: "", expiryStatus: "" }}
          sort={chatGptSort}
          credentialBusy={false}
          selectedIds={[]}
          exportOpen={false}
          exportContent=""
          exportBusy={false}
          groupOptions={["team-a", "team-b"]}
          upstreamSettingsConfigured={true}
          batchSupplementOpen={false}
          batchSupplementBusy={false}
          batchSupplementGroupName=""
          batchSupplementResult={null}
          onQueryChange={() => undefined}
          onSortChange={() => undefined}
          onToggleSelection={() => undefined}
          onTogglePageSelection={() => undefined}
          onClearSelection={() => undefined}
          onOpenExport={() => undefined}
          onExportOpenChange={() => undefined}
          onCopyExport={() => undefined}
          onSaveExport={() => undefined}
          onCopyCredential={() => undefined}
          onExportCredential={() => undefined}
          onBatchSupplementOpenChange={() => undefined}
          onBatchSupplementGroupNameChange={() => undefined}
          onOpenBatchSupplement={() => undefined}
          onSubmitBatchSupplement={() => undefined}
          onOpenUpstreamSettings={openSettingsSpy}
        />
      </SiteKeysView>
    </AppShell>
  ),
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "返回任务控制" }));
    await expect(backSpy).toHaveBeenCalledTimes(1);
    await userEvent.click(canvas.getByRole("button", { name: "补号设置" }));
    await expect(openSettingsSpy).toHaveBeenCalledTimes(1);
    if (document.activeElement instanceof HTMLElement) {
      document.activeElement.blur();
    }
  },
};
