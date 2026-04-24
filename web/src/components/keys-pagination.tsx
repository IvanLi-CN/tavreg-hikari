import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { KEYS_PAGE_SIZE_OPTIONS } from "@/lib/keys-page";

export function KeysPagination(props: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
}) {
  const pageCount = Math.max(1, Math.ceil(Math.max(0, props.total) / Math.max(1, props.pageSize)));
  return (
    <div className="flex flex-col gap-3 border-t border-white/8 pt-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="text-sm text-slate-400">
        第 {Math.min(props.page, pageCount)} / {pageCount} 页，共 {props.total} 条，每页 {props.pageSize} 条。
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Select value={String(props.pageSize)} onValueChange={(value) => props.onPageSizeChange(Number(value))}>
          <SelectTrigger className="w-[8.75rem]">
            <SelectValue placeholder="每页条数" />
          </SelectTrigger>
          <SelectContent>
            {KEYS_PAGE_SIZE_OPTIONS.map((pageSize) => (
              <SelectItem key={pageSize} value={String(pageSize)}>
                {pageSize} / 页
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="secondary" onClick={() => props.onPageChange(Math.max(1, props.page - 1))} disabled={props.page <= 1}>
          上一页
        </Button>
        <Button variant="secondary" onClick={() => props.onPageChange(Math.min(pageCount, props.page + 1))} disabled={props.page >= pageCount}>
          下一页
        </Button>
      </div>
    </div>
  );
}
