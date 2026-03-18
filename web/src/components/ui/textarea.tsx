import type * as React from "react";
import { cn } from "@/lib/utils";

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      className={cn(
        "flex min-h-32 w-full rounded-3xl border border-white/12 bg-[#0d1728] px-4 py-3 text-sm text-slate-50 outline-none transition placeholder:text-slate-500 focus-visible:border-cyan-300/60 focus-visible:ring-2 focus-visible:ring-cyan-300/30",
        className,
      )}
      {...props}
    />
  );
}

export { Textarea };
