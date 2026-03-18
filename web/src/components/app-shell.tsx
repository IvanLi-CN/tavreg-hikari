import { AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { PageKey } from "@/lib/app-types";

const pageItems: Array<{ key: PageKey; label: string }> = [
  { key: "dashboard", label: "主流程" },
  { key: "accounts", label: "微软账号" },
  { key: "apiKeys", label: "API Keys" },
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
      <div className="mx-auto flex min-h-dvh w-full max-w-screen-2xl flex-col px-4 py-6 sm:px-6 lg:px-8">
        <header className="mb-6 rounded-[32px] border border-white/10 bg-[#081120]/80 px-5 py-5 shadow-[0_18px_60px_rgba(0,0,0,0.32)] backdrop-blur md:px-7">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-2xl">
              <div className="text-xs uppercase tracking-[0.3em] text-cyan-300/80">Tavreg Hikari</div>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Web 管理台</h1>
              <p className="mt-2 text-sm text-slate-400">
                账号池、主流程、代理状态统一在一个本机控制面里。
              </p>
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
          <div className="mb-4 flex items-start gap-3 rounded-3xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        <main className="flex-1">{children}</main>
      </div>
    </div>
  );
}
