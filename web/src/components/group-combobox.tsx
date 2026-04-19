import { Check, ChevronsUpDown, FolderPlus, Search } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

export function GroupCombobox({
  groups,
  value,
  onChange,
  placeholder = "选择分组",
  emptyLabel = "不设置分组",
  allowEmpty = true,
  className,
  triggerClassName,
}: {
  groups: string[];
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  emptyLabel?: string;
  allowEmpty?: boolean;
  className?: string;
  triggerClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!open) {
      setSearch("");
    }
  }, [open]);

  const normalizedSearch = search.trim().toLowerCase();
  const filteredGroups = groups.filter((group) => group.toLowerCase().includes(normalizedSearch));
  const exactMatch = groups.some((group) => group.toLowerCase() === normalizedSearch);
  const canCreate = normalizedSearch.length > 0 && !exactMatch;

  const commit = (nextValue: string) => {
    onChange(nextValue);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="secondary"
          className={cn("w-full justify-between rounded-2xl border-white/12 bg-white/6 px-4", triggerClassName)}
        >
          <span className={cn("truncate", value ? "text-slate-100" : "text-slate-500")}>{value || placeholder}</span>
          <ChevronsUpDown className="size-4 text-slate-400" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className={cn("w-[min(22rem,calc(100vw-2rem))] p-2", className)}>
        <div className="space-y-2">
          <div className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/4 px-3">
            <Search className="size-4 text-slate-500" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索或输入新分组"
              className="h-10 border-0 bg-transparent px-0 shadow-none focus-visible:ring-0"
            />
          </div>

          <ScrollArea className="max-h-64">
            <div className="space-y-1 pr-2">
              {allowEmpty ? (
                <button
                  type="button"
                  className="flex w-full items-center justify-between rounded-2xl px-3 py-2 text-left text-sm text-slate-300 transition hover:bg-white/7 hover:text-white"
                  onClick={() => commit("")}
                >
                  <span>{emptyLabel}</span>
                  {!value ? <Check className="size-4 text-emerald-300" /> : null}
                </button>
              ) : null}

              {filteredGroups.map((group) => (
                <button
                  key={group}
                  type="button"
                  className="flex w-full items-center justify-between rounded-2xl px-3 py-2 text-left text-sm text-slate-200 transition hover:bg-white/7 hover:text-white"
                  onClick={() => commit(group)}
                >
                  <span className="truncate">{group}</span>
                  {value === group ? <Check className="size-4 text-emerald-300" /> : null}
                </button>
              ))}

              {canCreate ? (
                <button
                  type="button"
                  className="flex w-full items-center justify-between rounded-2xl border border-emerald-300/18 bg-emerald-400/8 px-3 py-2 text-left text-sm text-emerald-100 transition hover:bg-emerald-400/14"
                  onClick={() => commit(search.trim())}
                >
                  <span className="truncate">新建分组 “{search.trim()}”</span>
                  <FolderPlus className="size-4" />
                </button>
              ) : null}

              {!filteredGroups.length && !canCreate ? (
                <div className="rounded-2xl px-3 py-5 text-center text-sm text-slate-500">没有匹配的分组</div>
              ) : null}
            </div>
          </ScrollArea>
        </div>
      </PopoverContent>
    </Popover>
  );
}
