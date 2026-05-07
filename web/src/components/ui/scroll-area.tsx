import * as ScrollAreaPrimitive from "@radix-ui/react-scroll-area";
import type * as React from "react";
import { cn } from "@/lib/utils";

function ScrollArea({
  className,
  children,
  scrollbars = "vertical",
  ...props
}: React.ComponentProps<typeof ScrollAreaPrimitive.Root> & { scrollbars?: "vertical" | "horizontal" | "both" }) {
  return (
    <ScrollAreaPrimitive.Root className={cn("relative overflow-hidden", className)} {...props}>
      <ScrollAreaPrimitive.Viewport className="h-full w-full rounded-[inherit]">{children}</ScrollAreaPrimitive.Viewport>
      {scrollbars === "vertical" || scrollbars === "both" ? <ScrollBar /> : null}
      {scrollbars === "horizontal" || scrollbars === "both" ? <ScrollBar orientation="horizontal" /> : null}
      <ScrollAreaPrimitive.Corner />
    </ScrollAreaPrimitive.Root>
  );
}

function ScrollBar({ className, orientation = "vertical", ...props }: React.ComponentProps<typeof ScrollAreaPrimitive.ScrollAreaScrollbar>) {
  return (
    <ScrollAreaPrimitive.ScrollAreaScrollbar
      orientation={orientation}
      className={cn(
        "flex touch-none select-none p-0.5 transition-colors",
        orientation === "vertical" ? "h-full w-2.5 border-l border-l-transparent" : "h-2.5 flex-col border-t border-t-transparent",
        className,
      )}
      {...props}
    >
      <ScrollAreaPrimitive.Thumb className="relative flex-1 rounded-full bg-white/14" />
    </ScrollAreaPrimitive.ScrollAreaScrollbar>
  );
}

export { ScrollArea, ScrollBar };
