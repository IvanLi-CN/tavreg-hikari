import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ProxiesView } from "@/components/proxies-view";
import { pickProxySettingsUpdate, type ProxyCheckScope, type ProxyPayload, type ProxySettingsUpdate } from "@/lib/app-types";
import { sampleProxies } from "@/stories/fixtures";

const meta = {
  title: "Views/ProxiesView",
  component: ProxiesView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "代理页，包含订阅设置、库存摘要与节点诊断列表；业务任务默认自动轮换代理节点。",
      },
    },
  },
} satisfies Meta<typeof ProxiesView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    proxies: sampleProxies,
    proxyCheckScope: "all",
    onProxyCheckScopeChange: fn(),
    onProxySettingsChange: fn(),
    onSaveProxySettings: fn(),
    onCheckScope: fn(),
    onCheckNode: fn(),
  },
  render: () => {
    const [payload, setPayload] = useState<ProxyPayload>(sampleProxies);
    const [scope, setScope] = useState<ProxyCheckScope>("all");
    return (
      <ProxiesView
        proxies={payload}
        proxyCheckScope={scope}
        onProxyCheckScopeChange={setScope}
        onProxySettingsChange={(key, value) => setPayload((current) => ({ ...current, settings: { ...current.settings, [key]: value } }))}
        onSaveProxySettings={() => undefined}
        onCheckScope={() => undefined}
        onCheckNode={() => undefined}
      />
    );
  },
};

export const ActionsPlay: Story = {
  args: {
    proxies: sampleProxies,
    proxyCheckScope: "all",
    onProxyCheckScopeChange: fn(),
    onProxySettingsChange: fn(),
    onSaveProxySettings: fn(),
    onCheckScope: fn(),
    onCheckNode: fn(),
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: "执行检查" }));
    await expect(args.onCheckScope).toHaveBeenCalled();
    await userEvent.click(canvas.getAllByRole("button", { name: "检查" })[0]!);
    await expect(args.onCheckNode).toHaveBeenCalled();
  },
};

export const BufferedSettingsPlay: Story = {
  args: {
    proxies: sampleProxies,
    proxyCheckScope: "all",
    onProxyCheckScopeChange: fn(),
    onProxySettingsChange: fn(),
    onSaveProxySettings: fn(),
    onCheckScope: fn(),
    onCheckNode: fn(),
  },
  render: (args) => {
    const [payload, setPayload] = useState<ProxyPayload>(sampleProxies);
    const [scope, setScope] = useState<ProxyCheckScope>("all");
    const [savedPayload, setSavedPayload] = useState<ProxySettingsUpdate | null>(null);
    return (
      <>
        <ProxiesView
          proxies={payload}
          proxyCheckScope={scope}
          onProxyCheckScopeChange={(nextScope) => {
            setScope(nextScope);
            args.onProxyCheckScopeChange(nextScope);
          }}
          onProxySettingsChange={(key, value) => {
            setPayload((current) => ({ ...current, settings: { ...current.settings, [key]: value } }));
            args.onProxySettingsChange(key, value);
          }}
          onSaveProxySettings={(settings) => {
            const nextPayload = settings || pickProxySettingsUpdate(payload.settings);
            setSavedPayload(nextPayload);
            args.onSaveProxySettings(nextPayload);
          }}
          onCheckScope={args.onCheckScope}
          onCheckNode={args.onCheckNode}
        />
        <pre data-testid="proxy-settings-debug" className="sr-only">
          {JSON.stringify({ settings: payload.settings, savedPayload })}
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
    await expect(debug.textContent).toContain("\"savedPayload\"");
    await expect(debug.textContent).not.toContain("\"defaultRunMode\"");
    await expect(debug.textContent).not.toContain("\"defaultNeed\"");
    await expect(debug.textContent).not.toContain("\"defaultParallel\"");
    await expect(debug.textContent).not.toContain("\"defaultMaxAttempts\"");
  },
};
