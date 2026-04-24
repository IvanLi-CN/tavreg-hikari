import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, userEvent, within } from "storybook/test";
import { ApiAccessSettingsView, type RevealedIntegrationApiSecret } from "@/components/api-access-settings-view";
import type { IntegrationApiKeyRecord } from "@/lib/app-types";

function createRecord(partial: Partial<IntegrationApiKeyRecord> & Pick<IntegrationApiKeyRecord, "id" | "label" | "keyPrefix">): IntegrationApiKeyRecord {
  return {
    id: partial.id,
    label: partial.label,
    notes: partial.notes ?? null,
    keyPrefix: partial.keyPrefix,
    status: partial.status ?? "active",
    createdAt: partial.createdAt ?? "2026-04-24T08:30:00.000Z",
    updatedAt: partial.updatedAt ?? "2026-04-24T08:30:00.000Z",
    rotatedAt: partial.rotatedAt ?? null,
    revokedAt: partial.revokedAt ?? null,
    lastUsedAt: partial.lastUsedAt ?? "2026-04-24T09:45:00.000Z",
    lastUsedIp: partial.lastUsedIp ?? "10.0.0.8",
  };
}

const sampleRows = [
  createRecord({
    id: 1,
    label: "relay-east",
    notes: "供 east relay 消费 integration v1。",
    keyPrefix: "thki_demo_east",
    status: "active",
  }),
  createRecord({
    id: 2,
    label: "legacy-worker",
    notes: "待下线，先保留审计。",
    keyPrefix: "thki_demo_legacy",
    status: "revoked",
    revokedAt: "2026-04-24T07:10:00.000Z",
    lastUsedAt: null,
    lastUsedIp: null,
  }),
];

function InteractivePreview() {
  const [rows, setRows] = useState<IntegrationApiKeyRecord[]>(sampleRows);
  const [mutatingId, setMutatingId] = useState<number | "create" | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<RevealedIntegrationApiSecret | null>(null);

  return (
    <ApiAccessSettingsView
      rows={rows}
      mutatingId={mutatingId}
      revealedSecret={revealedSecret}
      onCreate={async ({ label, notes }) => {
        setMutatingId("create");
        const record = createRecord({
          id: rows.length + 10,
          label,
          notes,
          keyPrefix: "thki_new_secret",
          lastUsedAt: null,
          lastUsedIp: null,
        });
        setRows((current) => [record, ...current]);
        setRevealedSecret({
          mode: "create",
          record,
          plainTextKey: "thki_new_secret_plaintext_demo",
        });
        setMutatingId(null);
      }}
      onRotate={async (record, { label, notes }) => {
        setMutatingId(record.id);
        const nextRecord = {
          ...record,
          label,
          notes,
          keyPrefix: `${record.keyPrefix}_r2`,
          rotatedAt: "2026-04-24T10:10:00.000Z",
          updatedAt: "2026-04-24T10:10:00.000Z",
        };
        setRows((current) => current.map((item) => (item.id === record.id ? nextRecord : item)));
        setRevealedSecret({
          mode: "rotate",
          record: nextRecord,
          plainTextKey: "thki_rotated_secret_plaintext_demo",
        });
        setMutatingId(null);
      }}
      onRevoke={async (record) => {
        setMutatingId(record.id);
        setRows((current) =>
          current.map((item) =>
            item.id === record.id
              ? {
                  ...item,
                  status: "revoked",
                  revokedAt: "2026-04-24T10:20:00.000Z",
                  updatedAt: "2026-04-24T10:20:00.000Z",
                }
              : item,
          ),
        );
        setMutatingId(null);
      }}
      onRevealedSecretOpenChange={(open) => {
        if (!open) setRevealedSecret(null);
      }}
    />
  );
}

const meta = {
  title: "Views/ApiAccessSettingsView",
  component: ApiAccessSettingsView,
  tags: ["autodocs"],
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        component: "Settings → API Access 专页，管理 integration v1 的外部接入 API key、一次性明文展示和审计元数据。",
      },
    },
  },
} satisfies Meta<typeof ApiAccessSettingsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    rows: sampleRows,
    revealedSecret: null,
    onCreate: async () => {},
    onRotate: async () => {},
    onRevoke: async () => {},
    onRevealedSecretOpenChange: () => {},
  },
  render: () => (
    <div className="p-6">
      <ApiAccessSettingsView
        rows={sampleRows}
        revealedSecret={null}
        onCreate={async () => {}}
        onRotate={async () => {}}
        onRevoke={async () => {}}
        onRevealedSecretOpenChange={() => {}}
      />
    </div>
  ),
};

export const RevealDialogVisible: Story = {
  args: {
    rows: sampleRows,
    revealedSecret: {
      mode: "create",
      record: sampleRows[0]!,
      plainTextKey: "thki_demo_secret_plaintext_once",
    },
    onCreate: async () => {},
    onRotate: async () => {},
    onRevoke: async () => {},
    onRevealedSecretOpenChange: () => {},
  },
  render: () => (
    <div className="p-6">
      <ApiAccessSettingsView
        rows={sampleRows}
        revealedSecret={{
          mode: "create",
          record: sampleRows[0]!,
          plainTextKey: "thki_demo_secret_plaintext_once",
        }}
        onCreate={async () => {}}
        onRotate={async () => {}}
        onRevoke={async () => {}}
        onRevealedSecretOpenChange={() => {}}
      />
    </div>
  ),
};

export const InteractiveLifecyclePlay: Story = {
  args: {
    rows: sampleRows,
    revealedSecret: null,
    onCreate: async () => {},
    onRotate: async () => {},
    onRevoke: async () => {},
    onRevealedSecretOpenChange: () => {},
  },
  render: () => (
    <div className="p-6">
      <InteractivePreview />
    </div>
  ),
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    await userEvent.click(canvas.getByRole("button", { name: "创建 API Key" }));
    await userEvent.type(canvas.getByPlaceholderText("例如：worker-east / staging relay"), "worker-west");
    await userEvent.type(canvas.getByPlaceholderText("补充用途、实例归属或轮换备注（可选）"), "给 west relay 使用");
    await userEvent.click(canvas.getByRole("button", { name: "创建并展示明文" }));
    await expect(canvas.getByText("API Key 已创建")).toBeInTheDocument();
    await expect(canvas.getByText("thki_new_secret_plaintext_demo")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "我已保存" }));

    await userEvent.click(canvas.getAllByRole("button", { name: "轮换" })[0]!);
    await expect(canvas.getByText("轮换 API Key")).toBeInTheDocument();
    await userEvent.clear(canvas.getByPlaceholderText("例如：worker-east / staging relay"));
    await userEvent.type(canvas.getByPlaceholderText("例如：worker-east / staging relay"), "relay-east-rotated");
    await userEvent.click(canvas.getByRole("button", { name: "确认轮换" }));
    await expect(canvas.getByText("新的 API Key 已生成")).toBeInTheDocument();
    await expect(canvas.getByText("thki_rotated_secret_plaintext_demo")).toBeInTheDocument();
    await userEvent.click(canvas.getByRole("button", { name: "我已保存" }));

    await userEvent.click(canvas.getAllByRole("button", { name: "禁用" })[0]!);
    await expect(canvas.getAllByText("revoked")[0]).toBeInTheDocument();
  },
};
