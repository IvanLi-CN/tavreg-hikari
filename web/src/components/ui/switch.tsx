import type * as React from "react";
import { cn } from "@/lib/utils";

export type SwitchProps = Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "onChange"> & {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
};

function Switch({ checked = false, className, disabled, onCheckedChange, onClick, ...props }: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      className={cn(
        "relative inline-flex h-8 w-14 shrink-0 items-center rounded-full border border-white/12 bg-slate-800/85 p-1 outline-none transition-[background-color,border-color,box-shadow] duration-200 ease-out motion-reduce:transition-none",
        "focus-visible:ring-2 focus-visible:ring-emerald-300/35 disabled:cursor-not-allowed disabled:opacity-50",
        "data-[state=checked]:border-emerald-300/45 data-[state=checked]:bg-emerald-400/24 data-[state=checked]:shadow-[0_0_0_1px_rgba(52,211,153,0.12),0_12px_30px_rgba(16,185,129,0.16)]",
        className,
      )}
      data-state={checked ? "checked" : "unchecked"}
      onClick={(event) => {
        onClick?.(event);
        if (!event.defaultPrevented) {
          onCheckedChange?.(!checked);
        }
      }}
      {...props}
    >
      <span
        aria-hidden="true"
        className={cn(
          "block size-6 rounded-full bg-slate-300 shadow-[0_3px_10px_rgba(0,0,0,0.35)] transition-transform duration-200 ease-out motion-reduce:transition-none",
          checked ? "translate-x-6 bg-emerald-100" : "translate-x-0",
        )}
      />
    </button>
  );
}

export { Switch };
