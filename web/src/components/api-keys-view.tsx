import { useEffect, useRef, type ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import type { ApiKeyQuery, ApiKeysPayload } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

function FilterField(props: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

export function ApiKeysView({
  apiKeys,
  query,
  selectedIds,
  exportOpen,
  exportContent,
  exportBusy,
  onQueryChange,
  onToggleSelection,
  onTogglePageSelection,
  onClearSelection,
  onOpenExport,
  onExportOpenChange,
  onCopyExport,
  onSaveExport,
}: {
  apiKeys: ApiKeysPayload;
  query: ApiKeyQuery;
  selectedIds: number[];
  exportOpen: boolean;
  exportContent: string;
  exportBusy: boolean;
  onQueryChange: (value: ApiKeyQuery) => void;
  onToggleSelection: (apiKeyId: number, checked: boolean) => void;
  onTogglePageSelection: (checked: boolean) => void;
  onClearSelection: () => void;
  onOpenExport: () => void;
  onExportOpenChange: (open: boolean) => void;
  onCopyExport: () => void;
  onSaveExport: () => void;
}) {
  const exportTextareaRef = useRef<HTMLTextAreaElement>(null);
  const activeCount = apiKeys.summary.active;
  const revokedCount = apiKeys.summary.revoked;
  const pageCount = Math.max(1, Math.ceil(Math.max(1, apiKeys.total) / Math.max(1, query.pageSize)));
  const selectedOnPage = apiKeys.rows.filter((row) => selectedIds.includes(row.id)).length;
  const allCurrentPageSelected = apiKeys.rows.length > 0 && selectedOnPage === apiKeys.rows.length;

  useEffect(() => {
    if (!exportOpen || !exportContent) return;
    const textarea = exportTextareaRef.current;
    if (!textarea) return;
    const frame = window.requestAnimationFrame(() => {
      textarea.focus();
      textarea.select();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [exportContent, exportOpen]);

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>API Keys</CardTitle>
          <CardDescription>共 {apiKeys.total} 条 key 记录，默认展示前缀与遮罩值。支持跨分页勾选后批量导出。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Badge variant="success">active · {activeCount}</Badge>
            <Badge variant="warning">revoked · {revokedCount}</Badge>
            <Badge variant="info">total · {apiKeys.total}</Badge>
          </div>

          <div className="flex flex-col gap-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-slate-400">
              <span>当前页已选 {selectedOnPage} / {apiKeys.rows.length}</span>
              <span>总已选 {selectedIds.length} / {apiKeys.total}</span>
            </div>
            <label className="flex items-center gap-3 text-sm text-slate-300 md:hidden">
              <Checkbox
                checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                aria-label="select-current-page-mobile"
                disabled={apiKeys.rows.length === 0}
              />
              <span>全选当前页</span>
            </label>
            <div className="flex flex-wrap gap-2">
              <Button variant="secondary" onClick={onClearSelection} disabled={selectedIds.length === 0 || exportBusy}>
                清空勾选
              </Button>
              <Button onClick={onOpenExport} disabled={selectedIds.length === 0 || exportBusy}>
                {exportBusy ? "导出中…" : "导出"}
              </Button>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <FilterField label="搜索">
              <Input
                name="api-key-query"
                value={query.q}
                onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })}
                placeholder="邮箱或前缀"
              />
            </FilterField>
            <FilterField label="状态">
              <Select value={query.status || "__all__"} onValueChange={(value) => onQueryChange({ ...query, status: value === "__all__" ? "" : value, page: 1 })}>
                <SelectTrigger>
                  <SelectValue placeholder="全部" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">全部</SelectItem>
                  <SelectItem value="active">active</SelectItem>
                  <SelectItem value="revoked">revoked</SelectItem>
                  <SelectItem value="unknown">unknown</SelectItem>
                </SelectContent>
              </Select>
            </FilterField>
          </div>

          {apiKeys.rows.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              还没有 API key 记录。
            </div>
          ) : (
            <>
              <div className="space-y-3 md:hidden">
                {apiKeys.rows.map((row) => (
                  <article key={row.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                    <div className="flex items-start gap-3">
                      <Checkbox
                        checked={selectedIds.includes(row.id)}
                        onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                        aria-label={`select-${row.microsoftEmail}`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="break-all text-sm font-medium text-white">{row.microsoftEmail}</div>
                            <div className="mt-1 text-sm text-slate-400">{row.apiKeyPrefix}</div>
                          </div>
                          <StatusBadge status={row.status} />
                        </div>
                        <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                          <div className="flex items-center justify-between gap-3">
                            <dt className="text-slate-500">遮罩</dt>
                            <dd>{row.apiKeyMasked}</dd>
                          </div>
                          <div className="flex items-center justify-between gap-3">
                            <dt className="text-slate-500">提取时间</dt>
                            <dd>{formatDate(row.extractedAt)}</dd>
                          </div>
                          <div className="flex items-center justify-between gap-3">
                            <dt className="text-slate-500">最近验证</dt>
                            <dd>{formatDate(row.lastVerifiedAt)}</dd>
                          </div>
                        </dl>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
              <div className="hidden md:block">
                <Table className="min-w-[920px]">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-14">
                        <Checkbox
                          checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                          onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                          aria-label="select-current-page"
                        />
                      </TableHead>
                      <TableHead>账号</TableHead>
                      <TableHead>Key 前缀</TableHead>
                      <TableHead>Key 遮罩</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>提取时间</TableHead>
                      <TableHead>最近验证</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {apiKeys.rows.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell>
                          <Checkbox
                            checked={selectedIds.includes(row.id)}
                            onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                            aria-label={`select-${row.microsoftEmail}`}
                          />
                        </TableCell>
                        <TableCell className="min-w-[15rem] whitespace-nowrap">{row.microsoftEmail}</TableCell>
                        <TableCell>{row.apiKeyPrefix}</TableCell>
                        <TableCell>{row.apiKeyMasked}</TableCell>
                        <TableCell><StatusBadge status={row.status} /></TableCell>
                        <TableCell>{formatDate(row.extractedAt)}</TableCell>
                        <TableCell>{formatDate(row.lastVerifiedAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="flex flex-col gap-3 border-t border-white/8 pt-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="text-sm text-slate-400">
                  第 {query.page} / {pageCount} 页，每页 {query.pageSize} 条。
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Select value={String(query.pageSize)} onValueChange={(value) => onQueryChange({ ...query, pageSize: Number(value), page: 1 })}>
                    <SelectTrigger className="w-[7.5rem]">
                      <SelectValue placeholder="每页条数" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="10">10 / 页</SelectItem>
                      <SelectItem value="20">20 / 页</SelectItem>
                      <SelectItem value="50">50 / 页</SelectItem>
                      <SelectItem value="100">100 / 页</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button variant="secondary" onClick={() => onQueryChange({ ...query, page: Math.max(1, query.page - 1) })} disabled={query.page <= 1}>
                    上一页
                  </Button>
                  <Button variant="secondary" onClick={() => onQueryChange({ ...query, page: Math.min(pageCount, query.page + 1) })} disabled={query.page >= pageCount}>
                    下一页
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={exportOpen} onOpenChange={onExportOpenChange}>
        <DialogContent className="w-[min(96vw,62rem)]">
          <DialogHeader>
            <DialogTitle>导出 API Keys</DialogTitle>
            <DialogDescription>
              每行格式固定为 <code>key | ip</code>。文本框为只读状态，打开后会默认全选，方便直接复制或保存。
            </DialogDescription>
          </DialogHeader>

          <div className="px-6 py-2">
            <Textarea
              ref={exportTextareaRef}
              readOnly
              value={exportContent}
              className="min-h-72 resize-none rounded-[24px] bg-[#08111d]/88 font-mono text-xs leading-6 text-slate-100"
              aria-label="api-key-export-content"
            />
          </div>

          <DialogFooter>
            <Button variant="secondary" onClick={() => onExportOpenChange(false)}>
              关闭
            </Button>
            <Button variant="outline" onClick={onCopyExport} disabled={!exportContent}>
              复制
            </Button>
            <Button onClick={onSaveExport} disabled={!exportContent}>
              保存成文件
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
