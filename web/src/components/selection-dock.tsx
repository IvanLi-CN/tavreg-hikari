import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function SelectionDock(props: {
  open: boolean;
  selectedOnPage: number;
  totalSelected: number;
  totalCount: number;
  className?: string;
  children: ReactNode;
}) {
  if (!props.open) return null;
  return (
    <div className={cn("fixed inset-x-0 bottom-4 z-40 px-4", props.className)}>
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-3 rounded-[28px] border border-white/12 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,29,0.98))] p-4 shadow-[0_24px_60px_rgba(2,6,23,0.58)] backdrop-blur md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="info">当前页已选 · {props.selectedOnPage}</Badge>
          <Badge variant="success">总已选 · {props.totalSelected}</Badge>
          <Badge variant="neutral">总记录 · {props.totalCount}</Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">{props.children}</div>
      </div>
    </div>
  );
}
