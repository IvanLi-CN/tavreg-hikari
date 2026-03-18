import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn, userEvent, within } from "storybook/test";
import { AccountsView } from "@/components/accounts-view";
import type { AccountQuery } from "@/lib/app-types";
import { sampleAccounts } from "@/stories/fixtures";

const meta = {
  title: "Views/AccountsView",
  component: AccountsView,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "微软账号导入与查询页，必须支持导入文本、状态筛选和去重后的台账列表。",
      },
    },
  },
} satisfies Meta<typeof AccountsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    accounts: sampleAccounts,
    importContent: "",
    query: { q: "", status: "", hasApiKey: "" },
    onImportContentChange: fn(),
    onImport: fn(),
    onQueryChange: fn(),
  },
  render: () => {
    const [content, setContent] = useState("");
    const [query, setQuery] = useState<AccountQuery>({ q: "", status: "", hasApiKey: "" });
    return (
      <AccountsView
        accounts={sampleAccounts}
        importContent={content}
        query={query}
        onImportContentChange={setContent}
        onImport={() => undefined}
        onQueryChange={setQuery}
      />
    );
  },
};

export const Empty: Story = {
  args: {
    accounts: { rows: [], total: 0 },
    importContent: "",
    query: { q: "", status: "", hasApiKey: "" },
    onImportContentChange: fn(),
    onImport: fn(),
    onQueryChange: fn(),
  },
};

export const ImportPlay: Story = {
  args: {
    accounts: sampleAccounts,
    importContent: "",
    query: { q: "", status: "", hasApiKey: "" },
    onImportContentChange: fn(),
    onImport: fn(),
    onQueryChange: fn(),
  },
  render: (args) => {
    const [content, setContent] = useState("");
    const [query, setQuery] = useState<AccountQuery>({ q: "", status: "", hasApiKey: "" });
    return (
      <AccountsView
        accounts={sampleAccounts}
        importContent={content}
        query={query}
        onImportContentChange={setContent}
        onImport={args.onImport}
        onQueryChange={setQuery}
      />
    );
  },
  play: async ({ canvasElement, args }) => {
    const canvas = within(canvasElement);
    const submit = canvas.getByRole("button", { name: "导入并去重" });
    await expect(submit).toBeDisabled();
    await userEvent.type(canvas.getByRole("textbox", { name: "account-import" }), "new@outlook.com,password321");
    await expect(submit).toBeEnabled();
    await userEvent.click(submit);
    await expect(args.onImport).toHaveBeenCalled();
  },
};
