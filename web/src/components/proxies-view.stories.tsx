import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { ProxiesView } from "@/components/proxies-view";
import { pickProxySettingsUpdate, type ProxyPayload, type ProxySettingsUpdate } from "@/lib/app-types";
import { sampleProxies } from "@/stories/fixtures";

function withPayload(extra: Partial<ProxyPayload>): ProxyPayload {
  return {
    ...sampleProxies,
    ...extra,
    broker: {
      ...sampleProxies.broker,
      ...(extra.broker || {}),
    },
  };
}

const meta = {
  title: "Views/ProxiesView",
  component: ProxiesView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "Proxy Broker 管理页，展示 Broker 配置、profile catalog、活动 listener sessions 与历史诊断快照。",
      },
    },
  },
} satisfies Meta<typeof ProxiesView>;

export default meta;
type Story = StoryObj<typeof meta>;

const defaultArgs = {
  proxies: sampleProxies,
  onProxySettingsChange: fn(),
  onSaveProxySettings: fn(),
  onCheckScope: fn(),
};

export const Default: Story = {
  args: defaultArgs,
  render: () => {
    const [payload, setPayload] = useState<ProxyPayload>(sampleProxies);
    return (
      <ProxiesView
        {...defaultArgs}
        proxies={payload}
        onProxySettingsChange={(key, value) => setPayload((current) => ({ ...current, settings: { ...current.settings, [key]: value } }))}
        onSaveProxySettings={() => undefined}
        onCheckScope={() => undefined}
      />
    );
  },
};
export const EmptyBroker: Story = {
  args: {
    ...defaultArgs,
    proxies: withPayload({
      nodes: [],
      broker: {
        ...sampleProxies.broker,
        apiKeyConfigured: false,
        configured: false,
        catalogGroups: [],
        sessions: [],
      },
    }),
  },
};

export const BrokerAuthError: Story = {
  args: {
    ...defaultArgs,
    proxies: withPayload({
      syncError: "authentication_required: authentication required",
      broker: {
        ...sampleProxies.broker,
        apiKeyConfigured: false,
        configured: false,
        catalogGroups: [],
        sessions: [],
      },
    }),
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText(/Broker 同步失败/)).toBeInTheDocument();
    await expect(canvas.getByText("未配置")).toBeInTheDocument();
  },
};

export const ActionsPlay: Story = {
  args: defaultArgs,
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: /刷新 Catalog/ }));
    await expect(args.onCheckScope).toHaveBeenCalled();
  },
};

export const BufferedSettingsPlay: Story = {
  args: defaultArgs,
  render: (args) => {
    const [payload, setPayload] = useState<ProxyPayload>(sampleProxies);
    const [savedPayload, setSavedPayload] = useState<ProxySettingsUpdate | null>(null);
    return (
      <>
        <ProxiesView
          {...args}
          proxies={payload}
          onProxySettingsChange={(key, value) => {
            setPayload((current) => ({ ...current, settings: { ...current.settings, [key]: value } }));
            args.onProxySettingsChange(key, value);
          }}
          onSaveProxySettings={(settings) => {
            const nextPayload = settings || pickProxySettingsUpdate(payload.settings);
            setSavedPayload(nextPayload);
            args.onSaveProxySettings(nextPayload);
          }}
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

    await userEvent.clear(timeoutInput);
    await userEvent.type(timeoutInput, "1");
    await userEvent.tab();
    await expect(timeoutInput).toHaveValue("1000");

    await userEvent.clear(canvas.getByLabelText("Profile ID"));
    await userEvent.type(canvas.getByLabelText("Profile ID"), "tavreg");
    await userEvent.click(canvas.getByRole("button", { name: "保存 Broker 设置" }));
    await expect(debug.textContent).toContain("\"proxyBrokerProfileId\":\"tavreg\"");
    await expect(debug.textContent).not.toContain("\"defaultRunMode\"");
    await expect(debug.textContent).not.toContain("\"apiPort\"");
    await expect(debug.textContent).not.toContain("\"mixedPort\"");
  },
};
