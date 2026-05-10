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

export const ProbeStates: Story = {
  args: {
    ...defaultArgs,
    proxies: withPayload({
      broker: {
        ...sampleProxies.broker,
        catalogGroups: [
          {
            import: {
              import_id: "imp-probe-states",
              name: "Probe states",
              proxy_count: 4,
              distinct_ip_count: 4,
            },
            nodes: [
              {
                import_id: "imp-probe-states",
                node_id: "node-healthy",
                proxy_name: "Tokyo Healthy",
                proxy_type: "hysteria2",
                server: "tokyo.example.test",
                resolved_ips: ["203.0.113.24"],
                primary_ip: "203.0.113.24",
                can_open_session: true,
                ip_metadata: [{ ip: "203.0.113.24", last_probe_ok: true, median_latency_ms: 280, last_latency_ms: 320, probe_updated_at: new Date(Date.now() - 5 * 60 * 1000).toISOString() }],
              },
              {
                import_id: "imp-probe-states",
                node_id: "node-slow",
                proxy_name: "Sydney Slow",
                proxy_type: "vless",
                server: "sydney.example.test",
                resolved_ips: ["203.0.113.108"],
                primary_ip: "203.0.113.108",
                can_open_session: true,
                ip_metadata: [{ ip: "203.0.113.108", last_probe_ok: true, median_latency_ms: 2887, last_latency_ms: 2335, probe_updated_at: new Date(Date.now() - 5 * 60 * 1000).toISOString() }],
              },
              {
                import_id: "imp-probe-states",
                node_id: "node-failed",
                proxy_name: "Seoul Failed",
                proxy_type: "vless",
                server: "seoul.example.test",
                resolved_ips: ["198.51.100.18"],
                primary_ip: "198.51.100.18",
                can_open_session: true,
                ip_metadata: [{ ip: "198.51.100.18", last_probe_ok: false, median_latency_ms: 1510, last_latency_ms: 1640, probe_updated_at: new Date(Date.now() - 6 * 60 * 1000).toISOString() }],
              },
              {
                import_id: "imp-probe-states",
                node_id: "node-unprobed",
                proxy_name: "Zurich Unprobed",
                proxy_type: "hysteria2",
                server: "zurich.example.test",
                resolved_ips: ["192.0.2.183"],
                primary_ip: "192.0.2.183",
                can_open_session: false,
                ip_metadata: [],
              },
            ],
          },
        ],
      },
    }),
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await expect(canvas.getByText("健康低延迟")).toBeInTheDocument();
    await expect(canvas.getByText("Tokyo Healthy")).toBeInTheDocument();
    await expect(canvas.getByText("Sydney Slow")).toBeInTheDocument();
    await expect(canvas.getByText("Seoul Failed")).toBeInTheDocument();
    await expect(canvas.getByText("Zurich Unprobed")).toBeInTheDocument();
  },
};

export const ActionsPlay: Story = {
  args: defaultArgs,
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole("button", { name: /刷新探测/ }));
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
