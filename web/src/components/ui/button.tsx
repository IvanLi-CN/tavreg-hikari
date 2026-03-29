import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex cursor-pointer items-center justify-center gap-2 rounded-xl text-sm font-medium transition-all duration-200 outline-none disabled:pointer-events-none disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-emerald-300/70 focus-visible:ring-offset-2 focus-visible:ring-offset-[#09111f]",
  {
    variants: {
      variant: {
        default: "bg-emerald-500 text-slate-950 shadow-[0_10px_30px_rgba(34,197,94,0.28)] hover:bg-emerald-400 hover:shadow-[0_14px_36px_rgba(34,197,94,0.34)]",
        secondary: "border border-white/10 bg-white/8 text-slate-100 hover:bg-white/12",
        outline: "border border-sky-400/24 bg-sky-400/6 text-sky-100 hover:border-sky-300/36 hover:bg-sky-400/12",
        danger: "bg-rose-500 text-white shadow-[0_10px_30px_rgba(244,63,94,0.28)] hover:bg-rose-400 hover:shadow-[0_14px_36px_rgba(244,63,94,0.34)]",
        ghost: "text-slate-200 hover:bg-white/8",
      },
      size: {
        default: "h-10 px-4",
        sm: "h-8 px-3 text-xs",
        lg: "h-11 px-5",
        icon: "size-10",
        pill: "h-11 rounded-full px-5",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  }) {
  const Comp = asChild ? Slot : "button";

  return <Comp className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}

export { Button, buttonVariants };
