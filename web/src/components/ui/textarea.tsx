import type * as React from "react";
import { cn } from "@/lib/utils";

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      className={cn(
        "flex min-h-32 w-full rounded-3xl border border-white/12 bg-[rgba(15,23,42,0.7)] px-4 py-3 text-sm text-slate-50 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] outline-none transition duration-200 placeholder:text-slate-500 focus-visible:border-emerald-300/50 focus-visible:ring-2 focus-visible:ring-emerald-300/20",
        className,
      )}
      {...props}
    />
  );
}

export { Textarea };
