import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function MetricCard({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string | number;
  tone?: "default" | "good" | "warn" | "bad";
}) {
  return (
    <Card className="border-white/8 bg-[#09111f]/90">
      <CardHeader className="pb-2">
        <div className="text-[0.7rem] uppercase tracking-[0.24em] text-slate-500">{label}</div>
      </CardHeader>
      <CardContent>
        <div
          className={cn(
            "text-3xl font-semibold tracking-tight text-slate-50",
            tone === "good" && "text-emerald-300",
            tone === "warn" && "text-amber-300",
            tone === "bad" && "text-rose-300",
          )}
        >
          {value}
        </div>
      </CardContent>
    </Card>
  );
}
