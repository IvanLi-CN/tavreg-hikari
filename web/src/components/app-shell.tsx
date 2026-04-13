import { AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { PageKey } from "@/lib/app-types";

const pageItems: Array<{ key: PageKey; label: string }> = [
  { key: "tavily", label: "Tavily" },
  { key: "grok", label: "Grok" },
  { key: "chatgpt", label: "ChatGPT" },
  { key: "accounts", label: "微软账号" },
  { key: "mailboxes", label: "微软邮箱" },
  { key: "keys", label: "Keys" },
  { key: "proxies", label: "代理节点" },
];

export function AppShell({
  activePage,
  error,
  onNavigate,
  children,
}: {
  activePage: PageKey;
  error: string | null;
  onNavigate: (page: PageKey) => void;
  children: ReactNode;
}) {
  return (
    <div className="min-h-dvh text-slate-100">
      <a
        href="#app-main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-full focus:bg-slate-50 focus:px-4 focus:py-2 focus:text-slate-950"
      >
        跳到主内容
      </a>
      <div className="mx-auto flex min-h-dvh w-full max-w-screen-2xl flex-col px-4 py-6 sm:px-6 lg:px-8">
        <header className="mb-6 rounded-[32px] border border-white/10 bg-[linear-gradient(180deg,rgba(8,17,32,0.92),rgba(8,17,32,0.78))] px-5 py-5 shadow-[0_18px_60px_rgba(0,0,0,0.32)] backdrop-blur md:px-7">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-2xl">
              <div className="text-xs uppercase tracking-[0.3em] text-cyan-300/80">Tavreg Hikari</div>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Web 管理台</h1>
              <p className="mt-2 text-sm text-slate-400">
                Tavily、Grok 与 ChatGPT 的浏览器流程、账号池和代理状态统一在一个本机控制面里。
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Badge variant="success">localhost only</Badge>
                <Badge variant="info">realtime socket</Badge>
                <Badge variant="neutral">sqlite ledger</Badge>
              </div>
            </div>
            <Tabs value={activePage} onValueChange={(value) => onNavigate(value as PageKey)}>
              <TabsList className="w-full justify-start overflow-x-auto md:w-auto">
                {pageItems.map((item) => (
                  <TabsTrigger key={item.key} value={item.key}>
                    {item.label}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>
        </header>

        {error ? (
          <div role="alert" className="mb-4 flex items-start gap-3 rounded-3xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        <main id="app-main" className="flex-1">{children}</main>
      </div>
    </div>
  );
}
