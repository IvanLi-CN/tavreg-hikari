import { ArrowLeft, KeyRound } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";

export function SiteKeysView(props: {
  siteLabel: "Tavily" | "Grok" | "ChatGPT";
  onBack: () => void;
  children: ReactNode;
}) {
  return (
    <section className="space-y-4">
      <div className="flex flex-col gap-3 rounded-[24px] border border-white/8 bg-[rgba(15,23,42,0.45)] px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] sm:flex-row sm:items-center sm:justify-between">
        <Button variant="ghost" size="sm" className="w-fit" onClick={props.onBack}>
          <ArrowLeft className="size-4" />
          返回任务控制
        </Button>
        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-400 sm:justify-end">
          <KeyRound className="size-3.5" />
          查看 {props.siteLabel} Keys
        </div>
      </div>

      {props.children}
    </section>
  );
}
