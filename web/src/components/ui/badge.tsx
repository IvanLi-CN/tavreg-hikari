import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium tracking-[0.08em] uppercase",
  {
    variants: {
      variant: {
        neutral: "border-white/12 bg-white/6 text-slate-200",
        success: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
        warning: "border-amber-400/30 bg-amber-400/10 text-amber-200",
        danger: "border-rose-400/30 bg-rose-400/10 text-rose-200",
        info: "border-cyan-400/30 bg-cyan-400/10 text-cyan-200",
      },
    },
    defaultVariants: {
      variant: "neutral",
    },
  },
);

function Badge({ className, variant, ...props }: React.ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
