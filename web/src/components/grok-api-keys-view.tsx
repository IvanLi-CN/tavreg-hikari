import { useEffect, useRef, useState, type ReactNode } from "react";
import { AlertCircle, ArrowDown, ArrowUp, ArrowUpDown, Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import type { GrokApiKeyQuery, GrokApiKeySortBy, GrokApiKeysPayload } from "@/lib/app-types";
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

function resolveSortState(
  query: Pick<GrokApiKeyQuery, "sortBy" | "sortDir">,
  column: GrokApiKeySortBy,
): "inactive" | "desc" | "asc" {
  if (query.sortBy !== column) return "inactive";
  return query.sortDir;
}

function SortableTimeHead(props: {
  label: string;
  column: GrokApiKeySortBy;
  query: GrokApiKeyQuery;
  onQueryChange: (value: GrokApiKeyQuery) => void;
  className?: string;
}) {
  const state = resolveSortState(props.query, props.column);
  const ariaSort = state === "asc" ? "ascending" : state === "desc" ? "descending" : "none";
  const nextQuery: GrokApiKeyQuery =
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

type CopyField = "email" | "password" | "sso";

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

export function GrokApiKeysView({
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
  onResolveCopyField,
}: {
  apiKeys: GrokApiKeysPayload;
  query: GrokApiKeyQuery;
  selectedIds: number[];
  exportOpen: boolean;
  exportContent: string;
  exportBusy: boolean;
  headerSlot?: ReactNode;
  onQueryChange: (value: GrokApiKeyQuery) => void;
  onToggleSelection: (apiKeyId: number, checked: boolean) => void;
  onTogglePageSelection: (checked: boolean) => void;
  onClearSelection: () => void;
  onOpenExport: () => void;
  onExportOpenChange: (open: boolean) => void;
  onCopyExport: () => void;
  onSaveExport: () => void;
  onResolveCopyField: (apiKeyId: number, field: CopyField) => Promise<string>;
}) {
  const exportTextareaRef = useRef<HTMLTextAreaElement>(null);
  const copyResetTimerRef = useRef<number | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<{
    apiKeyId: number | null;
    field: CopyField | null;
    status: "idle" | "copied" | "failed";
  }>({ apiKeyId: null, field: null, status: "idle" });
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

  useEffect(
    () => () => {
      if (copyResetTimerRef.current != null) {
        window.clearTimeout(copyResetTimerRef.current);
      }
    },
    [],
  );

  const queueCopyFeedbackReset = () => {
    if (copyResetTimerRef.current != null) {
      window.clearTimeout(copyResetTimerRef.current);
    }
    copyResetTimerRef.current = window.setTimeout(() => {
      setCopyFeedback({ apiKeyId: null, field: null, status: "idle" });
      copyResetTimerRef.current = null;
    }, 1600);
  };

  const getCopyStatus = (apiKeyId: number, field: CopyField) =>
    copyFeedback.apiKeyId === apiKeyId && copyFeedback.field === field ? copyFeedback.status : "idle";

  const handleCopyField = async (apiKeyId: number, field: CopyField) => {
    try {
      const value = await onResolveCopyField(apiKeyId, field);
      if (!value.trim()) {
        throw new Error("empty copy value");
      }
      await copyTextToClipboard(value);
      setCopyFeedback({ apiKeyId, field, status: "copied" });
    } catch {
      setCopyFeedback({ apiKeyId, field, status: "failed" });
    }
    queueCopyFeedbackReset();
  };

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
            <label className="flex items-center gap-3 text-sm text-slate-300 xl:hidden">
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
                name="grok-api-key-query"
                value={query.q}
                onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })}
                placeholder="邮箱 / SSO / IP"
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
            <FilterField label="每页条数">
              <Select value={String(query.pageSize)} onValueChange={(value) => onQueryChange({ ...query, pageSize: Number(value), page: 1 })}>
                <SelectTrigger>
                  <SelectValue placeholder="每页条数" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10 / 页</SelectItem>
                  <SelectItem value="20">20 / 页</SelectItem>
                  <SelectItem value="50">50 / 页</SelectItem>
                  <SelectItem value="100">100 / 页</SelectItem>
                </SelectContent>
              </Select>
            </FilterField>
          </div>

          {apiKeys.rows.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              还没有 Grok SSO 记录。
            </div>
          ) : (
            <>
              <div className="space-y-3 xl:hidden">
                {apiKeys.rows.map((row) => (
                  <article key={row.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                    <div className="flex items-start gap-3">
                      <Checkbox
                        checked={selectedIds.includes(row.id)}
                        onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                        aria-label={`select-${row.email}`}
                      />
                      <div className="min-w-0 flex-1 overflow-hidden">
                        <div className="flex min-w-0 items-start justify-between gap-2">
                          <div className="min-w-0 flex-1 break-all pr-1 text-sm font-medium text-white">{row.email}</div>
                          <div className="flex shrink-0 items-center gap-2">
                            <CopyValueButton
                              status={getCopyStatus(row.id, "email")}
                              ariaLabel={`复制 ${row.email} 邮箱`}
                              onClick={() => void handleCopyField(row.id, "email")}
                            />
                            <StatusBadge status={row.status} />
                          </div>
                        </div>
                        <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                          <div className="grid gap-3 rounded-2xl border border-white/6 bg-white/[0.02] p-3">
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">出口 IP</dt>
                              <dd className="min-w-0 text-right font-mono text-[0.92rem] text-slate-100">{row.extractedIp || "—"}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">提取时间</dt>
                              <dd className="pl-4 text-right">{formatDate(row.extractedAt)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">最近验证</dt>
                              <dd className="pl-4 text-right">{formatDate(row.lastVerifiedAt)}</dd>
                            </div>
                          </div>
                          <div className="grid gap-2 rounded-2xl border border-white/6 bg-white/[0.02] p-3">
                            <div className="flex items-center justify-between gap-2">
                              <dt className="text-slate-500">密码</dt>
                              <CopyValueButton
                                status={getCopyStatus(row.id, "password")}
                                ariaLabel={`复制 ${row.email} 的密码`}
                                onClick={() => void handleCopyField(row.id, "password")}
                              />
                            </div>
                            <dd className="min-w-0 break-all font-mono text-[0.92rem] text-slate-100">{row.password}</dd>
                          </div>
                          <div className="grid gap-2 rounded-2xl border border-white/6 bg-white/[0.02] p-3">
                            <div className="flex items-center justify-between gap-2">
                              <dt className="text-slate-500">SSO</dt>
                              <CopyValueButton
                                status={getCopyStatus(row.id, "sso")}
                                ariaLabel={`复制 ${row.email} 的 SSO`}
                                onClick={() => void handleCopyField(row.id, "sso")}
                              />
                            </div>
                            <dd className="min-w-0 break-all font-mono text-[0.92rem] text-slate-100">{row.sso}</dd>
                          </div>
                        </dl>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
              <div className="hidden xl:block">
                <Table className="w-full table-fixed text-[0.8rem]">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12 px-3">
                        <Checkbox
                          checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                          onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                          aria-label="select-current-page"
                        />
                      </TableHead>
                      <TableHead className="w-[12rem] px-3">邮箱</TableHead>
                      <TableHead className="w-[9rem] px-3">密码</TableHead>
                      <TableHead className="w-[15rem] px-3">SSO</TableHead>
                      <TableHead className="w-[7rem] px-3">出口 IP</TableHead>
                      <TableHead className="w-[5.5rem] px-3">状态</TableHead>
                      <SortableTimeHead label="提取时间" column="extractedAt" query={query} onQueryChange={onQueryChange} className="w-[8rem] px-3" />
                      <SortableTimeHead label="最近验证" column="lastVerifiedAt" query={query} onQueryChange={onQueryChange} className="w-[8rem] px-3" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {apiKeys.rows.map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="px-3">
                          <Checkbox
                            checked={selectedIds.includes(row.id)}
                            onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                            aria-label={`select-${row.email}`}
                          />
                        </TableCell>
                        <TableCell className="w-[12rem] overflow-hidden px-3">
                          <div className="flex min-w-0 items-center gap-2">
                            <span className="min-w-0 flex-1 truncate whitespace-nowrap" title={row.email}>
                              {row.email}
                            </span>
                            <CopyValueButton
                              status={getCopyStatus(row.id, "email")}
                              ariaLabel={`复制 ${row.email} 邮箱`}
                              onClick={() => void handleCopyField(row.id, "email")}
                            />
                          </div>
                        </TableCell>
                        <TableCell className="w-[9rem] overflow-hidden px-3">
                          <div className="flex min-w-0 items-center gap-2">
                            <span className="min-w-0 flex-1 truncate whitespace-nowrap font-mono text-[0.92rem]" title={row.password}>
                              {row.password}
                            </span>
                            <CopyValueButton
                              status={getCopyStatus(row.id, "password")}
                              ariaLabel={`复制 ${row.email} 的密码`}
                              onClick={() => void handleCopyField(row.id, "password")}
                            />
                          </div>
                        </TableCell>
                        <TableCell className="w-[15rem] overflow-hidden px-3">
                          <div className="flex min-w-0 items-center gap-2">
                            <span className="min-w-0 flex-1 truncate whitespace-nowrap font-mono text-[0.92rem]" title={row.sso}>
                              {row.sso}
                            </span>
                            <CopyValueButton
                              status={getCopyStatus(row.id, "sso")}
                              ariaLabel={`复制 ${row.email} 的 SSO`}
                              onClick={() => void handleCopyField(row.id, "sso")}
                            />
                          </div>
                        </TableCell>
                        <TableCell className="w-[7rem] overflow-hidden px-3">
                          <span className="block truncate whitespace-nowrap font-mono text-[0.92rem]" title={row.extractedIp || "—"}>
                            {row.extractedIp || "—"}
                          </span>
                        </TableCell>
                        <TableCell className="px-3"><StatusBadge status={row.status} /></TableCell>
                        <TableCell className="w-[8rem] overflow-hidden px-3">
                          <span className="block truncate whitespace-nowrap" title={formatDate(row.extractedAt)}>
                            {formatDate(row.extractedAt)}
                          </span>
                        </TableCell>
                        <TableCell className="w-[8rem] overflow-hidden px-3">
                          <span className="block truncate whitespace-nowrap" title={formatDate(row.lastVerifiedAt)}>
                            {formatDate(row.lastVerifiedAt)}
                          </span>
                        </TableCell>
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
            <DialogTitle>导出 Grok SSO</DialogTitle>
            <DialogDescription>
              每行固定导出一个 <code>SSO token</code>。文本框为只读状态，打开后会默认全选，方便直接复制或保存。
            </DialogDescription>
          </DialogHeader>

          <div className="px-6 py-2">
            <Textarea
              ref={exportTextareaRef}
              readOnly
              value={exportContent}
              className="min-h-72 resize-none rounded-[24px] bg-[#08111d]/88 font-mono text-xs leading-6 text-slate-100"
              aria-label="grok-api-key-export-content"
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
