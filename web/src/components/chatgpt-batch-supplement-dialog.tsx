import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { GroupCombobox } from "@/components/group-combobox";
import type { ChatGptCredentialSupplementPayload } from "@/lib/app-types";

export function ChatGptBatchSupplementDialog({
  open,
  onOpenChange,
  selectedCount,
  groupOptions,
  groupName,
  busy,
  configured,
  result,
  onGroupNameChange,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  selectedCount: number;
  groupOptions: string[];
  groupName: string;
  busy: boolean;
  configured: boolean;
  result: ChatGptCredentialSupplementPayload | null;
  onGroupNameChange: (value: string) => void;
  onSubmit: () => void | Promise<void>;
}) {
  const failedRows = result?.results.filter((item) => !item.success) || [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl" data-testid="chatgpt-batch-supplement-dialog">
        <DialogHeader>
          <DialogTitle>批量补号</DialogTitle>
          <DialogDescription>
            只会处理当前已勾选的 ChatGPT 记录；空值语义固定为 <span className="font-medium text-slate-200">不补号</span>。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="rounded-[24px] border border-white/8 bg-white/[0.03] p-4 text-sm text-slate-300">
            当前已勾选 <span className="font-medium text-slate-100">{selectedCount}</span> 条记录。
          </div>

          <label className="flex flex-col gap-2">
            <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">目标分组</span>
            <GroupCombobox
              groups={groupOptions}
              value={groupName}
              onChange={onGroupNameChange}
              placeholder="不补号"
              emptyLabel="不补号"
            />
          </label>

          {!configured ? (
            <div className="rounded-2xl border border-amber-300/18 bg-amber-300/[0.06] px-4 py-3 text-sm text-amber-50">
              当前补号设置还没配完整；请先到 <span className="font-medium text-amber-100">Keys &gt; ChatGPT &gt; 补号设置</span> 完成配置，再执行批量补号。
            </div>
          ) : null}

          {result ? (
            <div className="space-y-3 rounded-[24px] border border-white/8 bg-[#08111d]/88 p-4">
              <div className="flex flex-wrap gap-2">
                <Badge variant="info">group · {result.groupName}</Badge>
                <Badge variant="success">success · {result.succeeded}</Badge>
                <Badge variant="warning">failed · {result.failed}</Badge>
                <Badge variant="neutral">requested · {result.requested}</Badge>
              </div>
              {failedRows.length ? (
                <div className="space-y-2 text-sm text-slate-300">
                  {failedRows.map((item) => (
                    <div key={`${item.credentialId}-${item.message}`} className="rounded-2xl border border-rose-300/12 bg-rose-400/[0.05] px-4 py-3">
                      <div className="font-medium text-slate-100">{item.email || `credential #${item.credentialId}`}</div>
                      <div className="mt-1 text-slate-400">{item.message}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm text-emerald-100">当前批次全部补号成功。</div>
              )}
            </div>
          ) : null}
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <div className="text-sm text-slate-400">提交后不会影响本地 credential 记录本身。</div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
              取消
            </Button>
            <Button type="button" onClick={() => void onSubmit()} disabled={busy || selectedCount === 0 || !groupName.trim() || !configured}>
              {busy ? "补号中…" : `补号 ${selectedCount} 条`}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
