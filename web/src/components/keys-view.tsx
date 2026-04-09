import { useState, type ComponentProps } from "react";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ChatGptCredentialsView } from "@/components/chatgpt-credentials-view";
import { ApiKeysView } from "@/components/api-keys-view";

type KeysTabKey = "tavily" | "chatgpt";

type TavilyKeysPaneProps = ComponentProps<typeof ApiKeysView>;
type ChatGptKeysPaneProps = ComponentProps<typeof ChatGptCredentialsView>;

export function KeysView({
  tavily,
  chatgpt,
  defaultTab = "tavily",
  nowMs = Date.now(),
}: {
  tavily: TavilyKeysPaneProps;
  chatgpt: ChatGptKeysPaneProps;
  defaultTab?: KeysTabKey;
  nowMs?: number;
}) {
  const [tab, setTab] = useState<KeysTabKey>(defaultTab);
  const chatGptValidCount = chatgpt.credentials.filter((row) => {
    if (!row.expiresAt) return false;
    const expiresAt = Date.parse(row.expiresAt);
    return Number.isFinite(expiresAt) && expiresAt > nowMs;
  }).length;
  const chatGptExpiredCount = chatgpt.credentials.filter((row) => {
    if (!row.expiresAt) return false;
    const expiresAt = Date.parse(row.expiresAt);
    return Number.isFinite(expiresAt) && expiresAt <= nowMs;
  }).length;
  const chatGptNoExpiryCount = chatgpt.credentials.filter((row) => !row.expiresAt).length;
  const headerSlot = (
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <TabsList className="w-full justify-start overflow-x-auto md:w-fit">
        <TabsTrigger value="tavily">Tavily</TabsTrigger>
        <TabsTrigger value="chatgpt">ChatGPT</TabsTrigger>
      </TabsList>

      <div className="flex flex-wrap items-center gap-2 md:justify-end">
        {tab === "tavily" ? (
          <>
            <Badge variant="success">active · {tavily.apiKeys.summary.active}</Badge>
            <Badge variant="warning">revoked · {tavily.apiKeys.summary.revoked}</Badge>
            <Badge variant="info">total · {tavily.apiKeys.total}</Badge>
          </>
        ) : (
          <>
            <Badge variant="success">valid · {chatGptValidCount}</Badge>
            <Badge variant="warning">expired · {chatGptExpiredCount}</Badge>
            <Badge variant="neutral">no expiry · {chatGptNoExpiryCount}</Badge>
            <Badge variant="info">total · {chatgpt.credentials.length}</Badge>
          </>
        )}
      </div>
    </div>
  );

  return (
    <Tabs value={tab} onValueChange={(value) => setTab(value as KeysTabKey)}>
      <TabsContent value="tavily" className="pt-0">
        <ApiKeysView {...tavily} headerSlot={headerSlot} />
      </TabsContent>

      <TabsContent value="chatgpt" className="pt-0">
        <ChatGptCredentialsView {...chatgpt} headerSlot={headerSlot} />
      </TabsContent>
    </Tabs>
  );
}
