import { useState } from "react";
import type { Meta, StoryObj } from "@storybook/react-vite";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const meta = {
  title: "UI/Tabs",
  component: Tabs,
  tags: ["autodocs"],
  parameters: {
    docs: {
      description: {
        component: "头部导航和场景切换使用的分段标签组件。",
      },
    },
  },
} satisfies Meta<typeof Tabs>;

export default meta;
type Story = StoryObj<typeof meta>;

export const NavigationTabs: Story = {
  render: () => {
    const [value, setValue] = useState("tavily");
    return (
      <div className="p-6">
        <Tabs value={value} onValueChange={setValue}>
          <TabsList>
            <TabsTrigger value="tavily">Tavily</TabsTrigger>
            <TabsTrigger value="chatgpt">ChatGPT</TabsTrigger>
            <TabsTrigger value="accounts">微软账号</TabsTrigger>
            <TabsTrigger value="apiKeys">API Keys</TabsTrigger>
          </TabsList>
          <TabsContent value="tavily" className="pt-4 text-sm text-slate-300">当前在 Tavily 面板。</TabsContent>
          <TabsContent value="chatgpt" className="pt-4 text-sm text-slate-300">当前在 ChatGPT 面板。</TabsContent>
          <TabsContent value="accounts" className="pt-4 text-sm text-slate-300">当前在账号池面板。</TabsContent>
          <TabsContent value="apiKeys" className="pt-4 text-sm text-slate-300">当前在 API keys 面板。</TabsContent>
        </Tabs>
      </div>
    );
  },
};
