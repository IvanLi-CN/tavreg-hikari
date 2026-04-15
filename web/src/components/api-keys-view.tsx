import { useEffect, useRef, useState, type ReactNode } from "react";
import { AlertCircle, ArrowDown, ArrowUp, ArrowUpDown, Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import type { ApiKeyQuery, ApiKeySortBy, ApiKeysPayload } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

function FilterField(props: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function resolveApiKeySortState(
  query: Pick<ApiKeyQuery, "sortBy" | "sortDir">,
  column: ApiKeySortBy,
): "inactive" | "desc" | "asc" {
  if (query.sortBy !== column) return "inactive";
  return query.sortDir;
}

function SortableApiKeyTimeTableHead(props: {
  label: string;
  column: ApiKeySortBy;
  query: ApiKeyQuery;
  className?: string;
  onQueryChange: (value: ApiKeyQuery) => void;
}) {
  const state = resolveApiKeySortState(props.query, props.column);
  const ariaSort = state === "asc" ? "ascending" : state === "desc" ? "descending" : "none";
  const nextQuery: ApiKeyQuery =
    state === "desc"
      ? { ...props.query, sortBy: props.column, sortDir: "asc", page: 1 }
      : { ...props.query, sortBy: props.column, sortDir: "desc", page: 1 };

  return (
    <TableHead aria-sort={ariaSort} className={props.className}>
      <button
        type="button"
        className={cn(
          "inline-flex items-center gap-2 rounded-xl px-1 py-1 text-left transition-colors",
          state === "inactive" ? "text-slate-400 hover:text-slate-100" : "text-cyan-200 hover:text-cyan-100",
        )}
        onClick={() => props.onQueryChange(nextQuery)}
        aria-label={`${props.label}排序：${state === "desc" ? "当前降序，再点升序" : state === "asc" ? "当前升序，再点降序" : "当前未排序，点击按降序排序"}`}
      >
        <span>{props.label}</span>
        {state === "desc" ? (
          <ArrowDown className="size-3.5" aria-hidden="true" />
        ) : state === "asc" ? (
          <ArrowUp className="size-3.5" aria-hidden="true" />
        ) : (
          <ArrowUpDown className="size-3.5" aria-hidden="true" />
        )}
      </button>
    </TableHead>
  );
}

async function copyTextToClipboard(value: string): Promise<void> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  if (typeof document === "undefined") {
    throw new Error("clipboard unavailable");
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  const succeeded = document.execCommand("copy");
  textarea.remove();
  if (!succeeded) {
    throw new Error("clipboard unavailable");
  }
}

function CopyValueButton(props: {
  status: "idle" | "copied" | "failed";
  ariaLabel: string;
  onClick: () => void;
}) {
  const Icon = props.status === "copied" ? Check : props.status === "failed" ? AlertCircle : Copy;
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className={cn(
        "size-8 shrink-0 rounded-lg",
        props.status === "copied"
          ? "text-emerald-300 hover:text-emerald-200"
          : props.status === "failed"
            ? "text-rose-200 hover:text-rose-100"
            : "text-cyan-200/90 hover:text-cyan-100",
      )}
      aria-label={props.ariaLabel}
      title={props.ariaLabel}
      onClick={props.onClick}
    >
      <Icon className="size-3.5" aria-hidden="true" />
    </Button>
  );
}

export function ApiKeysView({
  apiKeys,
  query,
  selectedIds,
  exportOpen,
  exportContent,
  exportBusy,
  headerSlot,
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
  headerSlot?: ReactNode;
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
  const copyResetTimerRef = useRef<number | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<{
    apiKeyId: number | null;
    status: "idle" | "copied" | "failed";
  }>({ apiKeyId: null, status: "idle" });
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

  useEffect(() => {
    return () => {
      if (copyResetTimerRef.current != null) {
        window.clearTimeout(copyResetTimerRef.current);
      }
    };
  }, []);

  function getCopyStatus(apiKeyId: number): "idle" | "copied" | "failed" {
    return copyFeedback.apiKeyId === apiKeyId ? copyFeedback.status : "idle";
  }

  async function handleCopyKey(apiKeyId: number, value: string): Promise<void> {
    if (copyResetTimerRef.current != null) {
      window.clearTimeout(copyResetTimerRef.current);
    }
    try {
      await copyTextToClipboard(value);
      setCopyFeedback({ apiKeyId, status: "copied" });
    } catch {
      setCopyFeedback({ apiKeyId, status: "failed" });
    }
    copyResetTimerRef.current = window.setTimeout(() => {
      setCopyFeedback((current) => (current.apiKeyId === apiKeyId ? { apiKeyId: null, status: "idle" } : current));
      copyResetTimerRef.current = null;
    }, 1600);
  }

  return (
    <>
      <Card>
        <CardContent className="space-y-4">
          {headerSlot ? <div>{headerSlot}</div> : null}

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

          <div className="grid gap-3 md:grid-cols-3">
            <FilterField label="搜索">
              <Input
                name="api-key-query"
                value={query.q}
                onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })}
                placeholder="邮箱 / 分组 / KEY"
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
            <FilterField label="分组">
              <Select value={query.groupName || "__all__"} onValueChange={(value) => onQueryChange({ ...query, groupName: value === "__all__" ? "" : value, page: 1 })}>
                <SelectTrigger>
                  <SelectValue placeholder="全部分组" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">全部分组</SelectItem>
                  {apiKeys.groups.map((group) => (
                    <SelectItem key={group} value={group}>
                      {group}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FilterField>
          </div>

          {apiKeys.rows.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              还没有 Tavily API key 记录。
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
                      <div className="min-w-0 flex-1 overflow-hidden">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0 flex-1">
                            <div className="break-all text-sm font-medium text-white">{row.microsoftEmail}</div>
                          </div>
                          <StatusBadge status={row.status} />
                        </div>
                        <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                          <div className="grid gap-2 rounded-2xl border border-white/6 bg-white/[0.02] p-3">
                            <div className="flex items-center justify-between gap-2">
                              <dt className="text-slate-500">KEY</dt>
                              <CopyValueButton
                                status={getCopyStatus(row.id)}
                                ariaLabel={`复制 ${row.microsoftEmail} 的 KEY`}
                                onClick={() => void handleCopyKey(row.id, row.apiKey)}
                              />
                            </div>
                            <dd className="min-w-0 break-all font-mono text-[0.92rem] text-slate-100">{row.apiKey}</dd>
                          </div>
                          <div className="flex items-center justify-between gap-3">
                            <dt className="text-slate-500">分组</dt>
                            <dd>{row.groupName || "—"}</dd>
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
                <Table className="min-w-[980px] w-full table-fixed">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-14">
                        <Checkbox
                          checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                          onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                          aria-label="select-current-page"
                        />
                      </TableHead>
                      <TableHead className="w-[20%] min-w-[15rem]">账号</TableHead>
                      <TableHead className="w-[10rem]">分组</TableHead>
                      <TableHead>KEY</TableHead>
                      <TableHead className="w-[9rem]">状态</TableHead>
                      <SortableApiKeyTimeTableHead
                        className="w-[11rem]"
                        label="提取时间"
                        column="extractedAt"
                        query={query}
                        onQueryChange={onQueryChange}
                      />
                      <SortableApiKeyTimeTableHead
                        className="w-[11rem]"
                        label="最近验证"
                        column="lastVerifiedAt"
                        query={query}
                        onQueryChange={onQueryChange}
                      />
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
                        <TableCell className="whitespace-nowrap">{row.groupName || "—"}</TableCell>
                        <TableCell className="min-w-0">
                          <div className="inline-flex max-w-full items-center gap-2 align-middle">
                            <span
                              className="min-w-0 shrink truncate font-mono text-[0.92rem] text-slate-100"
                              title={row.apiKey}
                            >
                              {row.apiKey}
                            </span>
                            <CopyValueButton
                              status={getCopyStatus(row.id)}
                              ariaLabel={`复制 ${row.microsoftEmail} 的 KEY`}
                              onClick={() => void handleCopyKey(row.id, row.apiKey)}
                            />
                          </div>
                        </TableCell>
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
