import * as PopoverPrimitive from "@radix-ui/react-popover";
import type * as React from "react";
import { cn } from "@/lib/utils";

const Popover = PopoverPrimitive.Root;
const PopoverTrigger = PopoverPrimitive.Trigger;
const PopoverAnchor = PopoverPrimitive.Anchor;

function PopoverContent({
  className,
  sideOffset = 8,
  align = "start",
  showArrow = false,
  arrowClassName,
  arrowWidth = 16,
  arrowHeight = 8,
  portalContainer,
  children,
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Content> & {
  showArrow?: boolean;
  arrowClassName?: string;
  arrowWidth?: number;
  arrowHeight?: number;
  portalContainer?: HTMLElement | null;
}) {
  return (
    <PopoverPrimitive.Portal container={portalContainer ?? undefined}>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        className={cn(
          "z-50 w-80 rounded-[24px] border border-white/12 bg-[linear-gradient(180deg,rgba(12,22,38,0.98),rgba(7,14,27,0.98))] p-2 shadow-[0_24px_60px_rgba(2,6,23,0.62)] outline-none data-[state=open]:animate-in data-[state=closed]:animate-out",
          className,
        )}
        {...props}
      >
        {children}
        {showArrow ? (
          <PopoverPrimitive.Arrow
            width={arrowWidth}
            height={arrowHeight}
            className={cn(
              "fill-[#0d1728] stroke-white/12 stroke-[1px] drop-shadow-[0_6px_12px_rgba(2,6,23,0.18)]",
              arrowClassName,
            )}
          />
        ) : null}
      </PopoverPrimitive.Content>
    </PopoverPrimitive.Portal>
  );
}

export { Popover, PopoverTrigger, PopoverAnchor, PopoverContent };
