import { useEffect, useRef, useState, type ReactNode } from "react";
import { AlertCircle, ArrowDown, ArrowUp, ArrowUpDown, Check, Copy } from "lucide-react";
import { KeysPagination } from "@/components/keys-pagination";
import { SelectionDock } from "@/components/selection-dock";
import { StatusBadge } from "@/components/status-badge";
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
import { Textarea } from "@/components/ui/textarea";
import { WindowVirtualList } from "@/components/window-virtual-list";
import type { ApiKeyQuery, ApiKeySortBy, ApiKeysPayload } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

const desktopGridClass =
  "grid min-w-[980px] grid-cols-[3.5rem_minmax(15rem,1.2fr)_10rem_minmax(18rem,1.8fr)_9rem_11rem_11rem]";

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

function SortableApiKeyHeaderButton(props: {
  label: string;
  column: ApiKeySortBy;
  query: ApiKeyQuery;
  onQueryChange: (value: ApiKeyQuery) => void;
}) {
  const state = resolveApiKeySortState(props.query, props.column);
  const nextQuery: ApiKeyQuery =
    state === "desc"
      ? { ...props.query, sortBy: props.column, sortDir: "asc", page: 1 }
      : { ...props.query, sortBy: props.column, sortDir: "desc", page: 1 };

  return (
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
        <CardContent className={cn("space-y-4", selectedIds.length > 0 && "pb-28")}>
          {headerSlot ? <div>{headerSlot}</div> : null}

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
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

          {apiKeys.rows.length > 0 ? (
            <label className="flex items-center gap-3 text-sm text-slate-300 sm:hidden">
              <Checkbox
                checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                aria-label="select-current-page-mobile"
                disabled={apiKeys.rows.length === 0}
              />
              <span>全选当前页（{apiKeys.rows.length} 条）</span>
            </label>
          ) : null}

          {apiKeys.rows.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              还没有 Tavily API key 记录。
            </div>
          ) : (
            <>
              <div className="sm:hidden">
                <WindowVirtualList
                  items={apiKeys.rows}
                  getKey={(row) => row.id}
                  estimateSize={() => 232}
                  renderItem={(row) => (
                    <article key={row.id} className="px-0 pb-3">
                      <div className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
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
                      </div>
                    </article>
                  )}
                />
              </div>

              <div className="hidden sm:block">
                <div className="w-full overflow-x-auto rounded-[24px] border border-white/8 bg-[rgba(15,23,42,0.62)] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                  <div className={cn(desktopGridClass, "border-b border-white/8 bg-white/[0.03] text-xs font-medium uppercase tracking-[0.14em] text-slate-400")}>
                    <div className="px-4 py-3">
                      <Checkbox
                        checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                        onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                        aria-label="select-current-page"
                      />
                    </div>
                    <div className="px-4 py-3">账号</div>
                    <div className="px-4 py-3">分组</div>
                    <div className="px-4 py-3">KEY</div>
                    <div className="px-4 py-3">状态</div>
                    <div className="px-4 py-3">
                      <SortableApiKeyHeaderButton label="提取时间" column="extractedAt" query={query} onQueryChange={onQueryChange} />
                    </div>
                    <div className="px-4 py-3">
                      <SortableApiKeyHeaderButton label="最近验证" column="lastVerifiedAt" query={query} onQueryChange={onQueryChange} />
                    </div>
                  </div>
                  <WindowVirtualList
                    items={apiKeys.rows}
                    className="min-w-[980px]"
                    compactQuery="(max-width: 0px)"
                    getKey={(row) => row.id}
                    estimateSize={() => 63}
                    renderItem={(row) => (
                      <div className={cn(desktopGridClass, "border-b border-white/8 text-sm text-slate-100 transition duration-200 hover:bg-white/[0.03]")}>
                        <div className="px-4 py-3">
                          <Checkbox
                            checked={selectedIds.includes(row.id)}
                            onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                            aria-label={`select-${row.microsoftEmail}`}
                          />
                        </div>
                        <div className="px-4 py-3 whitespace-nowrap">{row.microsoftEmail}</div>
                        <div className="px-4 py-3 whitespace-nowrap">{row.groupName || "—"}</div>
                        <div className="min-w-0 px-4 py-3">
                          <div className="inline-flex max-w-full items-center gap-2 align-middle">
                            <span className="min-w-0 shrink truncate font-mono text-[0.92rem] text-slate-100" title={row.apiKey}>
                              {row.apiKey}
                            </span>
                            <CopyValueButton
                              status={getCopyStatus(row.id)}
                              ariaLabel={`复制 ${row.microsoftEmail} 的 KEY`}
                              onClick={() => void handleCopyKey(row.id, row.apiKey)}
                            />
                          </div>
                        </div>
                        <div className="px-4 py-3"><StatusBadge status={row.status} /></div>
                        <div className="px-4 py-3">{formatDate(row.extractedAt)}</div>
                        <div className="px-4 py-3">{formatDate(row.lastVerifiedAt)}</div>
                      </div>
                    )}
                  />
                </div>
              </div>

              <KeysPagination
                page={query.page}
                pageSize={query.pageSize}
                total={apiKeys.total}
                onPageChange={(page) => onQueryChange({ ...query, page })}
                onPageSizeChange={(pageSize) => onQueryChange({ ...query, pageSize, page: 1 })}
              />
            </>
          )}
        </CardContent>
      </Card>

      <SelectionDock open={selectedIds.length > 0} selectedOnPage={selectedOnPage} totalSelected={selectedIds.length} totalCount={apiKeys.total}>
        <Button variant="secondary" onClick={onClearSelection} disabled={selectedIds.length === 0 || exportBusy}>
          清空勾选
        </Button>
        <Button onClick={onOpenExport} disabled={selectedIds.length === 0 || exportBusy}>
          {exportBusy ? "导出中…" : "导出"}
        </Button>
      </SelectionDock>

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
