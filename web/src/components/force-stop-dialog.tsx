import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

type ForceStopDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  taskLabel?: string;
  scopeLabel: string;
};

function resolveTitle(taskLabel?: string): string {
  return taskLabel ? `立即强制停止 ${taskLabel} 任务？` : "立即强制停止？";
}

export function ForceStopDialog({ open, onOpenChange, onConfirm, taskLabel, scopeLabel }: ForceStopDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[min(92vw,34rem)]">
        <DialogHeader>
          <DialogTitle>{resolveTitle(taskLabel)}</DialogTitle>
          <DialogDescription>
            {`此操作会立即终止${scopeLabel}。正在运行的 attempt 将被标记为“已停止”，不会继续自动完成后续流程。`}
          </DialogDescription>
        </DialogHeader>
        <div className="px-6 text-sm leading-6 text-slate-300">
          建议优先使用优雅停止；只有在任务无法及时结束时，再使用强制停止。
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            返回
          </Button>
          <Button
            variant="danger"
            onClick={() => {
              onOpenChange(false);
              onConfirm();
            }}
          >
            强制停止
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
