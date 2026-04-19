import { ArrowLeft, KeyRound } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export function SiteKeysView(props: {
  siteLabel: "Tavily" | "Grok" | "ChatGPT";
  description: string;
  badgeText?: string;
  onBack: () => void;
  children: ReactNode;
}) {
  return (
    <section className="space-y-4">
      <Card className="border-white/10 bg-slate-950/55 shadow-none">
        <CardContent className="flex flex-col gap-4 p-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <Button variant="ghost" size="sm" className="mb-3" onClick={props.onBack}>
              <ArrowLeft className="size-4" />
              返回任务控制
            </Button>
            <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
              <KeyRound className="size-3.5" />
              {props.siteLabel} Keys
            </div>
            <h1 className="mt-2 text-2xl font-semibold text-white">{props.siteLabel} Keys</h1>
            <p className="mt-1 text-sm text-slate-400">{props.description}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge variant="neutral">站内子视图</Badge>
            {props.badgeText ? <Badge variant="info">{props.badgeText}</Badge> : null}
          </div>
        </CardContent>
      </Card>

      {props.children}
    </section>
  );
}
