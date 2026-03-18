import type * as React from "react";
import { cn } from "@/lib/utils";

function Input({ className, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      className={cn(
        "flex h-11 w-full min-w-0 rounded-2xl border border-white/12 bg-[#0d1728] px-4 py-2 text-sm text-slate-50 outline-none transition placeholder:text-slate-500 focus-visible:border-cyan-300/60 focus-visible:ring-2 focus-visible:ring-cyan-300/30",
        className,
      )}
      {...props}
    />
  );
}

export { Input };
