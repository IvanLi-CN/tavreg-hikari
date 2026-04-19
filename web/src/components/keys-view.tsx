import { useEffect, useState, type ComponentProps, type ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ChatGptCredentialsView } from "@/components/chatgpt-credentials-view";
import { ApiKeysView } from "@/components/api-keys-view";
import { GrokApiKeysView } from "@/components/grok-api-keys-view";

type KeysTabKey = "tavily" | "grok" | "chatgpt";

type TavilyKeysPaneProps = ComponentProps<typeof ApiKeysView> & {
  headerSlot?: ReactNode;
};
type GrokKeysPaneProps = ComponentProps<typeof GrokApiKeysView> & {
  headerSlot?: ReactNode;
};
type ChatGptKeysPaneProps = ComponentProps<typeof ChatGptCredentialsView> & {
  onOpenUpstreamSettings: () => void;
  headerSlot?: ReactNode;
  nowMs?: number;
};

function resolveChatGptCounts(credentials: ChatGptKeysPaneProps["credentials"], nowMs: number) {
  const valid = credentials.filter((row) => {
    if (!row.expiresAt) return false;
    const expiresAt = Date.parse(row.expiresAt);
    return Number.isFinite(expiresAt) && expiresAt > nowMs;
  }).length;
  const expired = credentials.filter((row) => {
    if (!row.expiresAt) return false;
    const expiresAt = Date.parse(row.expiresAt);
    return Number.isFinite(expiresAt) && expiresAt <= nowMs;
  }).length;
  const noExpiry = credentials.filter((row) => !row.expiresAt).length;
  return { valid, expired, noExpiry };
}

function buildChatGptHeaderSlot(props: {
  credentials: ChatGptKeysPaneProps["credentials"];
  onOpenUpstreamSettings: () => void;
  nowMs: number;
}) {
  const counts = resolveChatGptCounts(props.credentials, props.nowMs);
  return (
    <div className="flex max-w-full flex-wrap items-center gap-2 md:justify-end md:pr-1">
      <Badge variant="success">valid · {counts.valid}</Badge>
      <Badge variant="warning">expired · {counts.expired}</Badge>
      <Badge variant="neutral">no expiry · {counts.noExpiry}</Badge>
      <Badge variant="info">total · {props.credentials.length}</Badge>
      <Button type="button" variant="outline" size="sm" onClick={props.onOpenUpstreamSettings}>
        补号设置
      </Button>
    </div>
  );
}

export function TavilyKeysPane({ headerSlot, ...props }: TavilyKeysPaneProps) {
  return <ApiKeysView {...props} headerSlot={headerSlot} />;
}

export function GrokKeysPane({ headerSlot, ...props }: GrokKeysPaneProps) {
  return <GrokApiKeysView {...props} headerSlot={headerSlot} />;
}

export function ChatGptKeysPane({
  onOpenUpstreamSettings,
  headerSlot,
  nowMs = Date.now(),
  ...props
}: ChatGptKeysPaneProps) {
  return (
    <ChatGptCredentialsView
      {...props}
      headerSlot={headerSlot || buildChatGptHeaderSlot({ credentials: props.credentials, onOpenUpstreamSettings, nowMs })}
    />
  );
}

export function KeysView({
  tavily,
  grok,
  chatgpt,
  defaultTab = "tavily",
  nowMs = Date.now(),
}: {
  tavily: Omit<TavilyKeysPaneProps, "headerSlot">;
  grok: Omit<GrokKeysPaneProps, "headerSlot">;
  chatgpt: Omit<ChatGptKeysPaneProps, "headerSlot" | "nowMs">;
  defaultTab?: KeysTabKey;
  nowMs?: number;
}) {
  const [tab, setTab] = useState<KeysTabKey>(defaultTab);
  useEffect(() => {
    setTab(defaultTab);
  }, [defaultTab]);
  const headerSlot = (
    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <TabsList className="w-full justify-start overflow-x-auto md:w-fit">
        <TabsTrigger value="tavily">Tavily</TabsTrigger>
        <TabsTrigger value="grok">Grok</TabsTrigger>
        <TabsTrigger value="chatgpt">ChatGPT</TabsTrigger>
      </TabsList>

      <div className="flex flex-wrap items-center gap-2 md:justify-end">
        {tab === "tavily" ? (
          <>
            <Badge variant="success">active · {tavily.apiKeys.summary.active}</Badge>
            <Badge variant="warning">revoked · {tavily.apiKeys.summary.revoked}</Badge>
            <Badge variant="info">total · {tavily.apiKeys.total}</Badge>
          </>
        ) : tab === "grok" ? (
          <>
            <Badge variant="success">active · {grok.apiKeys.summary.active}</Badge>
            <Badge variant="warning">other · {grok.apiKeys.summary.revoked}</Badge>
            <Badge variant="info">total · {grok.apiKeys.total}</Badge>
          </>
        ) : (
          buildChatGptHeaderSlot({
            credentials: chatgpt.credentials,
            onOpenUpstreamSettings: chatgpt.onOpenUpstreamSettings,
            nowMs,
          })
        )}
      </div>
    </div>
  );

  return (
    <Tabs value={tab} onValueChange={(value) => setTab(value as KeysTabKey)}>
      <TabsContent value="tavily" className="pt-0">
        <TavilyKeysPane {...tavily} headerSlot={headerSlot} />
      </TabsContent>

      <TabsContent value="grok" className="pt-0">
        <GrokKeysPane {...grok} headerSlot={headerSlot} />
      </TabsContent>

      <TabsContent value="chatgpt" className="pt-0">
        <ChatGptKeysPane {...chatgpt} nowMs={nowMs} headerSlot={headerSlot} />
      </TabsContent>
    </Tabs>
  );
}
