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

export const BufferedSettingsPlay: Story = {
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
  render: (args) => {
    const [payload, setPayload] = useState<ProxyPayload>(sampleProxies);
    const [scope, setScope] = useState<ProxyCheckScope>("current");
    const [saved, setSaved] = useState(false);
    return (
      <>
        <ProxiesView
          proxies={payload}
          selectedProxy={payload.nodes.find((node) => node.isSelected) || null}
          proxyCheckScope={scope}
          onProxyCheckScopeChange={(nextScope) => {
            setScope(nextScope);
            args.onProxyCheckScopeChange(nextScope);
          }}
          onProxySettingsChange={(key, value) => {
            setPayload((current) => ({ ...current, settings: { ...current.settings, [key]: value } }));
            args.onProxySettingsChange(key, value);
          }}
          onSaveProxySettings={() => {
            setSaved(true);
            args.onSaveProxySettings();
          }}
          onCheckScope={args.onCheckScope}
          onSelectNode={args.onSelectNode}
          onCheckNode={args.onCheckNode}
        />
        <pre data-testid="proxy-settings-debug" className="sr-only">
          {JSON.stringify({ settings: payload.settings, saved })}
        </pre>
      </>
    );
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    const debug = canvas.getByTestId("proxy-settings-debug");
    const timeoutInput = canvas.getByLabelText("Timeout (ms)");
    const apiPortInput = canvas.getByLabelText("API Port");
    const maxLatencyInput = canvas.getByLabelText("Max Latency (ms)");

    await userEvent.clear(timeoutInput);
    await userEvent.type(timeoutInput, "1");
    await expect(timeoutInput).toHaveValue("1");
    await userEvent.tab();
    await expect(timeoutInput).toHaveValue("1000");

    await userEvent.clear(maxLatencyInput);
    await userEvent.type(maxLatencyInput, "1");
    await userEvent.tab();
    await expect(maxLatencyInput).toHaveValue("100");

    await userEvent.clear(apiPortInput);
    await userEvent.type(apiPortInput, "0");
    await userEvent.click(canvas.getByRole("button", { name: "保存并同步" }));
    await expect(apiPortInput).toHaveValue("1");
    await expect(debug.textContent).toContain("\"apiPort\":1");
    await expect(debug.textContent).toContain("\"saved\":true");
  },
};
