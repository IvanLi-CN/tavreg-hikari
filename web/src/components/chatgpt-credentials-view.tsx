import { useEffect, useRef, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ChatGptBatchSupplementDialog } from "@/components/chatgpt-batch-supplement-dialog";
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
import type {
  ChatGptCredentialQuery,
  ChatGptCredentialRecord,
  ChatGptCredentialSort,
  ChatGptCredentialSortBy,
  ChatGptCredentialSupplementPayload,
} from "@/lib/app-types";
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

function resolveCredentialSortState(
  sort: ChatGptCredentialSort,
  column: ChatGptCredentialSortBy,
): "inactive" | "desc" | "asc" {
  if (sort.sortBy !== column) return "inactive";
  return sort.sortDir;
}

function SortableCredentialTimeTableHead(props: {
  label: string;
  column: ChatGptCredentialSortBy;
  sort: ChatGptCredentialSort;
  onSortChange: (value: ChatGptCredentialSort) => void;
}) {
  const state = resolveCredentialSortState(props.sort, props.column);
  const ariaSort = state === "asc" ? "ascending" : state === "desc" ? "descending" : "none";
  const nextSort: ChatGptCredentialSort =
    state === "desc"
      ? { sortBy: props.column, sortDir: "asc" }
      : { sortBy: props.column, sortDir: "desc" };

  return (
    <TableHead aria-sort={ariaSort}>
      <button
        type="button"
        className={cn(
          "inline-flex items-center gap-2 rounded-xl px-1 py-1 text-left transition-colors",
          state === "inactive" ? "text-slate-400 hover:text-slate-100" : "text-cyan-200 hover:text-cyan-100",
        )}
        onClick={() => props.onSortChange(nextSort)}
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

export function ChatGptCredentialsView({
  credentials,
  query,
  sort,
  credentialBusy,
  selectedIds,
  exportOpen,
  exportContent,
  exportBusy,
  groupOptions,
  upstreamSettingsConfigured,
  batchSupplementOpen,
  batchSupplementBusy,
  batchSupplementGroupName,
  batchSupplementResult,
  headerSlot,
  onQueryChange,
  onSortChange,
  onToggleSelection,
  onTogglePageSelection,
  onClearSelection,
  onOpenExport,
  onExportOpenChange,
  onCopyExport,
  onSaveExport,
  onCopyCredential,
  onExportCredential,
  onBatchSupplementOpenChange,
  onBatchSupplementGroupNameChange,
  onOpenBatchSupplement,
  onSubmitBatchSupplement,
}: {
  credentials: ChatGptCredentialRecord[];
  query: ChatGptCredentialQuery;
  sort: ChatGptCredentialSort;
  credentialBusy: boolean;
  selectedIds: number[];
  exportOpen: boolean;
  exportContent: string;
  exportBusy: boolean;
  groupOptions: string[];
  upstreamSettingsConfigured: boolean;
  batchSupplementOpen: boolean;
  batchSupplementBusy: boolean;
  batchSupplementGroupName: string;
  batchSupplementResult: ChatGptCredentialSupplementPayload | null;
  headerSlot?: ReactNode;
  onQueryChange: (value: ChatGptCredentialQuery) => void;
  onSortChange: (value: ChatGptCredentialSort) => void;
  onToggleSelection: (credentialId: number, checked: boolean) => void;
  onTogglePageSelection: (checked: boolean) => void;
  onClearSelection: () => void;
  onOpenExport: () => void;
  onExportOpenChange: (open: boolean) => void;
  onCopyExport: () => void;
  onSaveExport: () => void;
  onCopyCredential: (credential: ChatGptCredentialRecord) => void | Promise<void>;
  onExportCredential: (credential: ChatGptCredentialRecord) => void | Promise<void>;
  onBatchSupplementOpenChange: (open: boolean) => void;
  onBatchSupplementGroupNameChange: (value: string) => void;
  onOpenBatchSupplement: () => void;
  onSubmitBatchSupplement: () => void | Promise<void>;
}) {
  const exportTextareaRef = useRef<HTMLTextAreaElement>(null);
  const selectedOnPage = credentials.filter((row) => selectedIds.includes(row.id)).length;
  const allCurrentPageSelected = credentials.length > 0 && selectedOnPage === credentials.length;

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
        <CardContent className="space-y-4">
          {headerSlot ? <div>{headerSlot}</div> : null}

          <div className="flex flex-col gap-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-slate-400">
              <span>当前页已选 {selectedOnPage} / {credentials.length}</span>
              <span>总已选 {selectedIds.length} / {credentials.length}</span>
            </div>
            <label className="flex items-center gap-3 text-sm text-slate-300 md:hidden">
              <Checkbox
                checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                aria-label="select-current-page-mobile"
                disabled={credentials.length === 0}
              />
              <span>全选当前页</span>
            </label>
            <div className="flex flex-wrap gap-2">
              <Button variant="secondary" onClick={onClearSelection} disabled={selectedIds.length === 0 || exportBusy}>
                清空勾选
              </Button>
              <Button variant="outline" onClick={onOpenBatchSupplement} disabled={selectedIds.length === 0 || exportBusy}>
                批量补号
              </Button>
              <Button onClick={onOpenExport} disabled={selectedIds.length === 0 || exportBusy}>
                {exportBusy ? "导出中…" : "导出"}
              </Button>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <FilterField label="搜索">
              <Input
                name="chatgpt-key-query"
                value={query.q}
                onChange={(event) => onQueryChange({ ...query, q: event.target.value })}
                placeholder="邮箱 / 账号 ID"
              />
            </FilterField>
            <FilterField label="有效期">
              <Select
                value={query.expiryStatus || "__all__"}
                onValueChange={(value) => onQueryChange({ ...query, expiryStatus: value === "__all__" ? "" : (value as ChatGptCredentialQuery["expiryStatus"]) })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="全部" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">全部</SelectItem>
                  <SelectItem value="valid">有效</SelectItem>
                  <SelectItem value="expired">已过期</SelectItem>
                  <SelectItem value="noExpiry">无过期时间</SelectItem>
                </SelectContent>
              </Select>
            </FilterField>
          </div>

          {credentials.length === 0 ? (
            <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
              {query.q || query.expiryStatus ? "没有符合筛选条件的 ChatGPT key 记录。" : "还没有 ChatGPT key 记录。"}
            </div>
          ) : (
            <>
              <div className="space-y-3 md:hidden">
                {credentials.map((credential) => {
                  return (
                    <article key={credential.id} className="rounded-3xl border border-white/8 bg-[#0d1728]/70 p-4">
                      <div className="flex items-start gap-3">
                        <Checkbox
                          checked={selectedIds.includes(credential.id)}
                          onCheckedChange={(checked) => onToggleSelection(credential.id, checked === true)}
                          aria-label={`select-credential-${credential.id}`}
                        />
                        <div className="min-w-0 flex-1 space-y-4">
                          <div className="min-w-0">
                            <div className="break-all text-sm font-medium text-white">{credential.email}</div>
                            <div className="mt-1 text-sm text-slate-400">{credential.accountId || "—"}</div>
                          </div>
                          <dl className="grid gap-3 text-sm text-slate-300">
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">expires</dt>
                              <dd>{formatDate(credential.expiresAt)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">created</dt>
                              <dd>{formatDate(credential.createdAt)}</dd>
                            </div>
                          </dl>
                          <div className="flex flex-nowrap gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              className="shrink-0 whitespace-nowrap"
                              disabled={credentialBusy}
                              onClick={() => void onCopyCredential(credential)}
                            >
                              复制
                            </Button>
                            <Button
                              variant="outline"
                              size="sm"
                              className="shrink-0 whitespace-nowrap"
                              disabled={credentialBusy}
                              onClick={() => void onExportCredential(credential)}
                            >
                              下载
                            </Button>
                          </div>
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>

              <div className="hidden md:block">
                <Table className="min-w-[940px]">
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
                      <TableHead>账号 ID</TableHead>
                      <SortableCredentialTimeTableHead
                        label="过期时间"
                        column="expiresAt"
                        sort={sort}
                        onSortChange={onSortChange}
                      />
                      <SortableCredentialTimeTableHead
                        label="创建时间"
                        column="createdAt"
                        sort={sort}
                        onSortChange={onSortChange}
                      />
                      <TableHead className="w-[14rem]">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {credentials.map((credential) => {
                      return (
                        <TableRow key={credential.id}>
                          <TableCell>
                            <Checkbox
                              checked={selectedIds.includes(credential.id)}
                              onCheckedChange={(checked) => onToggleSelection(credential.id, checked === true)}
                              aria-label={`select-credential-${credential.id}`}
                            />
                          </TableCell>
                          <TableCell className="min-w-[16rem] whitespace-nowrap">{credential.email}</TableCell>
                          <TableCell className="whitespace-nowrap">{credential.accountId || "—"}</TableCell>
                          <TableCell className="whitespace-nowrap">{formatDate(credential.expiresAt)}</TableCell>
                          <TableCell className="whitespace-nowrap">{formatDate(credential.createdAt)}</TableCell>
                          <TableCell className="whitespace-nowrap">
                            <div className="flex flex-nowrap gap-2">
                              <Button
                                variant="outline"
                                size="sm"
                                className="shrink-0 whitespace-nowrap"
                                disabled={credentialBusy}
                                onClick={() => void onCopyCredential(credential)}
                              >
                                复制
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                className="shrink-0 whitespace-nowrap"
                                disabled={credentialBusy}
                                onClick={() => void onExportCredential(credential)}
                              >
                                下载
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={exportOpen} onOpenChange={onExportOpenChange}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>导出 ChatGPT Keys</DialogTitle>
            <DialogDescription>批量导出所选 ChatGPT keys 的 JSON 数组。复制或保存前请确认仅在受控环境内使用。</DialogDescription>
          </DialogHeader>
          <Textarea
            ref={exportTextareaRef}
            readOnly
            value={exportContent}
            aria-label="chatgpt-key-export-content"
            className="min-h-[320px] font-mono text-xs leading-6"
          />
          <DialogFooter className="gap-2 sm:justify-between">
            <div className="text-sm text-slate-400">共 {selectedIds.length} 条选中记录</div>
            <div className="flex flex-wrap gap-2">
              <Button variant="secondary" onClick={onCopyExport} disabled={!exportContent}>
                复制
              </Button>
              <Button onClick={onSaveExport} disabled={!exportContent}>
                下载
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ChatGptBatchSupplementDialog
        open={batchSupplementOpen}
        onOpenChange={onBatchSupplementOpenChange}
        selectedCount={selectedIds.length}
        groupOptions={groupOptions}
        groupName={batchSupplementGroupName}
        busy={batchSupplementBusy}
        configured={upstreamSettingsConfigured}
        result={batchSupplementResult}
        onGroupNameChange={onBatchSupplementGroupNameChange}
        onSubmit={onSubmitBatchSupplement}
      />
    </>
  );
}
