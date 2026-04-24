import { useEffect, useRef, useState, type ReactNode } from "react";
import { AlertCircle, ArrowDown, ArrowUp, ArrowUpDown, Check, Copy } from "lucide-react";
import { KeysPagination } from "@/components/keys-pagination";
import { SelectionDock } from "@/components/selection-dock";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { WindowVirtualList } from "@/components/window-virtual-list";
import type { GrokApiKeyQuery, GrokApiKeySortBy, GrokApiKeysPayload } from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

const desktopGridClass =
  "grid w-full min-w-[860px] grid-cols-[2.75rem_minmax(10rem,1.15fr)_minmax(6.5rem,0.78fr)_minmax(11rem,1.85fr)_minmax(5.75rem,0.72fr)_5.5rem_minmax(6.5rem,0.92fr)_minmax(6.5rem,0.92fr)] lg:min-w-[980px] lg:grid-cols-[3rem_minmax(11rem,1.08fr)_minmax(7.5rem,0.82fr)_minmax(14rem,1.7fr)_minmax(6.25rem,0.78fr)_6rem_minmax(7.5rem,0.92fr)_minmax(7.5rem,0.92fr)]";

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

function SortableTimeButton(props: {
  label: string;
  column: GrokApiKeySortBy;
  query: GrokApiKeyQuery;
  onQueryChange: (value: GrokApiKeyQuery) => void;
}) {
  const state = resolveSortState(props.query, props.column);
  const nextQuery: GrokApiKeyQuery =
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
        <CardContent className={cn("space-y-4", selectedIds.length > 0 && "pb-28")}>
          {headerSlot ? <div>{headerSlot}</div> : null}

          <div className="grid gap-3 sm:grid-cols-2">
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
          </div>

          {apiKeys.rows.length > 0 ? (
            <label className="flex items-center gap-3 text-sm text-slate-300 md:hidden">
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
              还没有 Grok SSO 记录。
            </div>
          ) : (
            <>
              <div className="md:hidden">
                <WindowVirtualList
                  items={apiKeys.rows}
                  getKey={(row) => row.id}
                  estimateSize={() => 380}
                  renderItem={(row) => (
                    <article key={row.id} className="px-0 pb-3">
                      <div className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
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
                      </div>
                    </article>
                  )}
                />
              </div>

              <div className="hidden md:block">
                <div className="w-full overflow-x-auto rounded-[24px] border border-white/8 bg-[rgba(15,23,42,0.62)] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                  <div className={cn(desktopGridClass, "border-b border-white/8 bg-white/[0.03] text-xs font-medium uppercase tracking-[0.14em] text-slate-400")}>
                    <div className="px-3 py-3">
                      <Checkbox
                        checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                        onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                        aria-label="select-current-page"
                      />
                    </div>
                    <div className="px-3 py-3">邮箱</div>
                    <div className="px-3 py-3">密码</div>
                    <div className="px-3 py-3">SSO</div>
                    <div className="px-3 py-3">出口 IP</div>
                    <div className="px-3 py-3">状态</div>
                    <div className="px-3 py-3">
                      <SortableTimeButton label="提取时间" column="extractedAt" query={query} onQueryChange={onQueryChange} />
                    </div>
                    <div className="px-3 py-3">
                      <SortableTimeButton label="最近验证" column="lastVerifiedAt" query={query} onQueryChange={onQueryChange} />
                    </div>
                  </div>
                  <WindowVirtualList
                    items={apiKeys.rows}
                    className="w-full min-w-[860px] lg:min-w-[980px]"
                    compactQuery="(max-width: 0px)"
                    getKey={(row) => row.id}
                    estimateSize={() => 63}
                    renderItem={(row) => (
                      <div className={cn(desktopGridClass, "border-b border-white/8 text-[0.8rem] text-slate-100 transition duration-200 hover:bg-white/[0.03]")}>
                        <div className="px-3 py-3">
                          <Checkbox
                            checked={selectedIds.includes(row.id)}
                            onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                            aria-label={`select-${row.email}`}
                          />
                        </div>
                        <div className="overflow-hidden px-3 py-3">
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
                        </div>
                        <div className="overflow-hidden px-3 py-3">
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
                        </div>
                        <div className="overflow-hidden px-3 py-3">
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
                        </div>
                        <div className="overflow-hidden px-3 py-3">
                          <span className="block truncate whitespace-nowrap font-mono text-[0.92rem]" title={row.extractedIp || "—"}>
                            {row.extractedIp || "—"}
                          </span>
                        </div>
                        <div className="px-3 py-3"><StatusBadge status={row.status} /></div>
                        <div className="overflow-hidden px-3 py-3">
                          <span className="block truncate whitespace-nowrap" title={formatDate(row.extractedAt)}>
                            {formatDate(row.extractedAt)}
                          </span>
                        </div>
                        <div className="overflow-hidden px-3 py-3">
                          <span className="block truncate whitespace-nowrap" title={formatDate(row.lastVerifiedAt)}>
                            {formatDate(row.lastVerifiedAt)}
                          </span>
                        </div>
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
