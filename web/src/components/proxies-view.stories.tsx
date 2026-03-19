import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ProxiesView } from "@/components/proxies-view";
import type { ProxyCheckScope, ProxyPayload } from "@/lib/app-types";
import { sampleProxies } from "@/stories/fixtures";

const meta = {
  title: "Views/ProxiesView",
  component: ProxiesView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "代理页，包含订阅设置、当前状态和节点列表。",
      },
    },
  },
} satisfies Meta<typeof ProxiesView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    proxies: sampleProxies,
    selectedProxy: sampleProxies.nodes[0] || null,
    proxyCheckScope: "current",
    onProxyCheckScopeChange: fn(),
    onProxySettingsChange: fn(),
    onSaveProxySettings: fn(),
    onCheckScope: fn(),
    onSelectNode: fn(),
    onCheckNode: fn(),
  },
  render: () => {
    const [payload, setPayload] = useState<ProxyPayload>(sampleProxies);
    const [scope, setScope] = useState<ProxyCheckScope>("current");
    return (
      <ProxiesView
        proxies={payload}
        selectedProxy={payload.nodes.find((node) => node.isSelected) || null}
        proxyCheckScope={scope}
        onProxyCheckScopeChange={setScope}
        onProxySettingsChange={(key, value) => setPayload((current) => ({ ...current, settings: { ...current.settings, [key]: value } }))}
        onSaveProxySettings={() => undefined}
        onCheckScope={() => undefined}
        onSelectNode={() => undefined}
        onCheckNode={() => undefined}
      />
    );
  },
};

export const ActionsPlay: Story = {
  args: {
    proxies: sampleProxies,
    selectedProxy: sampleProxies.nodes[0] || null,
    proxyCheckScope: "current",
    onProxyCheckScopeChange: fn(),
    onProxySettingsChange: fn(),
    onSaveProxySettings: fn(),
    onCheckScope: fn(),
    onSelectNode: fn(),
    onCheckNode: fn(),
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "执行检查" }));
    await expect(args.onCheckScope).toHaveBeenCalled();
    await userEvent.click(canvas.getByRole("button", { name: "切换" }));
    await expect(args.onSelectNode).toHaveBeenCalled();
  },
};
