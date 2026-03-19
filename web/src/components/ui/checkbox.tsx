import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { Check } from "lucide-react";
import type * as React from "react";
import { cn } from "@/lib/utils";

function Checkbox({ className, ...props }: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      className={cn(
        "peer inline-flex size-5 shrink-0 cursor-pointer items-center justify-center rounded-md border border-white/14 bg-[#0b1423] text-emerald-300 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)] outline-none transition focus-visible:ring-2 focus-visible:ring-emerald-300/35 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-emerald-300/45 data-[state=checked]:bg-emerald-400/14",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator>
        <Check className="size-3.5" />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };
