import * as TabsPrimitive from "@radix-ui/react-tabs";
import type * as React from "react";
import { cn } from "@/lib/utils";

function Tabs(props: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return <TabsPrimitive.Root {...props} />;
}

function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      className={cn("inline-flex flex-wrap gap-2 rounded-full border border-white/10 bg-white/6 p-1.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]", className)}
      {...props}
    />
  );
}

function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        "inline-flex h-11 cursor-pointer items-center justify-center rounded-full px-5 text-sm font-medium text-slate-300 transition duration-200 data-[state=active]:bg-sky-400 data-[state=active]:text-slate-950 data-[state=active]:shadow-[0_10px_24px_rgba(56,189,248,0.24)] data-[state=inactive]:hover:bg-white/8",
        className,
      )}
      {...props}
    />
  );
}

function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn(className)} {...props} />;
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
