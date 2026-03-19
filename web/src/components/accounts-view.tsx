import type { ReactNode } from "react";
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { GroupCombobox } from "@/components/group-combobox";
import { StatusBadge } from "@/components/status-badge";
import type { AccountImportPreviewPayload, AccountQuery, AccountsPayload } from "@/lib/app-types";
import { formatDate } from "@/lib/format";

function FilterField(props: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function ImportDecisionBadge({ decision }: { decision: string }) {
  if (decision === "create") return <Badge variant="success">新增</Badge>;
  if (decision === "update_password") return <Badge variant="info">更新密码</Badge>;
  if (decision === "keep_existing") return <Badge variant="neutral">保持原值</Badge>;
  if (decision === "input_duplicate") return <Badge variant="warning">输入重复</Badge>;
  return <Badge variant="danger">无效</Badge>;
}

export function AccountsView({
  accounts,
  importContent,
  importGroupName,
  batchGroupName,
  preview,
  previewCommitCount,
  previewOpen,
  query,
  selectedIds,
  revealedPasswordsById,
  importBusy,
  previewBusy,
  batchBusy,
  allCurrentPageSelected,
  onImportContentChange,
  onImportGroupChange,
  onBatchGroupNameChange,
  onOpenPreview,
  onPreviewOpenChange,
  onConfirmImport,
  onQueryChange,
  onToggleSelection,
  onTogglePageSelection,
  onApplyBatchGroup,
  onDeleteSelected,
  onClearSelection,
}: {
  accounts: AccountsPayload;
  importContent: string;
  importGroupName: string;
  batchGroupName: string;
  preview: AccountImportPreviewPayload | null;
  previewCommitCount: number;
  previewOpen: boolean;
  query: AccountQuery;
  selectedIds: number[];
  revealedPasswordsById: Record<number, string>;
  importBusy: boolean;
  previewBusy: boolean;
  batchBusy: boolean;
  allCurrentPageSelected: boolean;
  onImportContentChange: (value: string) => void;
  onImportGroupChange: (value: string) => void;
  onBatchGroupNameChange: (value: string) => void;
  onOpenPreview: () => void;
  onPreviewOpenChange: (open: boolean) => void;
  onConfirmImport: () => void;
  onQueryChange: (value: AccountQuery) => void;
  onToggleSelection: (accountId: number, checked: boolean) => void;
  onTogglePageSelection: (checked: boolean) => void;
  onApplyBatchGroup: () => void;
  onDeleteSelected: () => void;
  onClearSelection: () => void;
}) {
  const readyCount = accounts.rows.filter((row) => row.lastResultStatus === "ready").length;
  const linkedCount = accounts.rows.filter((row) => row.hasApiKey).length;
  const failedCount = accounts.rows.filter((row) => row.lastResultStatus === "failed").length;
  const selectedOnPage = accounts.rows.filter((row) => selectedIds.includes(row.id)).length;
  const pageCount = Math.max(1, Math.ceil(Math.max(1, accounts.total) / Math.max(1, accounts.pageSize)));
  const getPasswordDisplay = (accountId: number, fallbackMasked: string, plaintext?: string | null) =>
    plaintext || revealedPasswordsById[accountId] || fallbackMasked;

  return (
    <>
      <section className="grid gap-4 xl:grid-cols-[minmax(22rem,0.52fr)_minmax(0,1.48fr)]">
        <Card>
          <CardHeader>
            <CardTitle>导入微软账号</CardTitle>
            <CardDescription>
              每行一个账号。支持 <code>email,password</code>、<code>email:password</code>、<code>email|password</code>、
              <code>email password</code>、<code>email----password</code>，也会自动纠正邮箱前后顺序。
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              name="account-import"
              className="min-h-72"
              placeholder={"example@outlook.com,password123\nexample@outlook.com----password123\npassword123 example@outlook.com"}
              value={importContent}
              onChange={(event) => onImportContentChange(event.target.value)}
            />
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <div className="min-w-0 flex-1">
                <GroupCombobox
                  groups={accounts.groups}
                  value={importGroupName}
                  onChange={onImportGroupChange}
                  placeholder="导入分组（可直接新建）"
                  emptyLabel="不设置分组"
                />
              </div>
              <Button onClick={onOpenPreview} disabled={!importContent.trim() || previewBusy} className="sm:self-stretch">
                {previewBusy ? "解析中…" : "导入预览"}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>账号池</CardTitle>
            <CardDescription>
              总数 {accounts.total} 条，已选 {selectedIds.length} 条。支持跨分页勾选、批量分组和批量删除。
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <Badge variant="info">ready · {readyCount}</Badge>
              <Badge variant="success">linked · {linkedCount}</Badge>
              <Badge variant="danger">failed · {failedCount}</Badge>
            </div>

            <div className="flex flex-col gap-3 rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-slate-400">
                <span>当前页已选 {selectedOnPage} / {accounts.rows.length}</span>
                <span>总已选 {selectedIds.length} / {accounts.total}</span>
              </div>
              <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
                <div className="min-w-0 flex-1">
                  <GroupCombobox
                    groups={accounts.groups}
                    value={batchGroupName}
                    onChange={onBatchGroupNameChange}
                    placeholder="批量设置分组"
                    emptyLabel="清空分组"
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" onClick={onApplyBatchGroup} disabled={selectedIds.length === 0 || batchBusy}>
                    应用分组
                  </Button>
                  <Button variant="secondary" onClick={onClearSelection} disabled={selectedIds.length === 0 || batchBusy}>
                    清空勾选
                  </Button>
                  <Button
                    variant="secondary"
                    className="border-rose-300/18 bg-rose-400/8 text-rose-100 hover:bg-rose-400/16"
                    onClick={onDeleteSelected}
                    disabled={selectedIds.length === 0 || batchBusy}
                  >
                    批量删除
                  </Button>
                </div>
              </div>
            </div>

            <div className="grid gap-3 xl:grid-cols-4">
              <FilterField label="搜索">
                <Input
                  name="account-query"
                  value={query.q}
                  onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })}
                  placeholder="邮箱 / 密码 / 分组"
                />
              </FilterField>
              <FilterField label="状态">
                <Select value={query.status || "__all__"} onValueChange={(value) => onQueryChange({ ...query, status: value === "__all__" ? "" : value, page: 1 })}>
                  <SelectTrigger>
                    <SelectValue placeholder="全部" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">全部</SelectItem>
                    <SelectItem value="ready">ready</SelectItem>
                    <SelectItem value="running">running</SelectItem>
                    <SelectItem value="succeeded">succeeded</SelectItem>
                    <SelectItem value="failed">failed</SelectItem>
                    <SelectItem value="skipped_has_key">skipped_has_key</SelectItem>
                  </SelectContent>
                </Select>
              </FilterField>
              <FilterField label="Has API Key">
                <Select value={query.hasApiKey || "__all__"} onValueChange={(value) => onQueryChange({ ...query, hasApiKey: value === "__all__" ? "" : value, page: 1 })}>
                  <SelectTrigger>
                    <SelectValue placeholder="全部" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">全部</SelectItem>
                    <SelectItem value="true">true</SelectItem>
                    <SelectItem value="false">false</SelectItem>
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
                    {accounts.groups.map((group) => (
                      <SelectItem key={group} value={group}>
                        {group}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FilterField>
            </div>

            {accounts.rows.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                当前筛选下没有账号记录。
              </div>
            ) : (
              <>
                <div className="space-y-3 md:hidden">
                  {accounts.rows.map((row) => (
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
                              <div className="mt-1 break-all font-mono text-sm text-slate-300">
                                {getPasswordDisplay(row.id, row.passwordMasked, row.passwordPlaintext)}
                              </div>
                            </div>
                            {row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}
                          </div>
                          <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">分组</dt>
                              <dd>{row.groupName || "—"}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">最近状态</dt>
                              <dd><StatusBadge status={row.lastResultStatus} /></dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">导入时间</dt>
                              <dd>{formatDate(row.importedAt)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">最近使用</dt>
                              <dd>{formatDate(row.lastUsedAt)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">跳过原因</dt>
                              <dd>{row.skipReason || "—"}</dd>
                            </div>
                          </dl>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>

                <div className="hidden md:block">
                  <Table className="min-w-[1180px]">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-14">
                          <Checkbox
                            checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                            onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                            aria-label="select-current-page"
                          />
                        </TableHead>
                        <TableHead>邮箱</TableHead>
                        <TableHead>密码</TableHead>
                        <TableHead>分组</TableHead>
                        <TableHead>Has Key</TableHead>
                        <TableHead>最近状态</TableHead>
                        <TableHead>导入时间</TableHead>
                        <TableHead>最近使用</TableHead>
                        <TableHead>跳过原因</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {accounts.rows.map((row) => (
                        <TableRow key={row.id}>
                          <TableCell>
                            <Checkbox
                              checked={selectedIds.includes(row.id)}
                              onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                              aria-label={`select-${row.microsoftEmail}`}
                            />
                          </TableCell>
                          <TableCell className="min-w-[15rem] whitespace-nowrap">{row.microsoftEmail}</TableCell>
                          <TableCell className="font-mono text-sm text-slate-200">
                            {getPasswordDisplay(row.id, row.passwordMasked, row.passwordPlaintext)}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">{row.groupName || "—"}</TableCell>
                          <TableCell className="whitespace-nowrap">{row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}</TableCell>
                          <TableCell className="whitespace-nowrap"><StatusBadge status={row.lastResultStatus} /></TableCell>
                          <TableCell>{formatDate(row.importedAt)}</TableCell>
                          <TableCell>{formatDate(row.lastUsedAt)}</TableCell>
                          <TableCell className="min-w-[10rem]">{row.skipReason || "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            )}

            <div className="flex flex-col gap-3 border-t border-white/8 pt-4 lg:flex-row lg:items-center lg:justify-between">
              <div className="text-sm text-slate-400">
                第 {accounts.page} / {pageCount} 页，每页 {accounts.pageSize} 条。
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
                <Button variant="secondary" onClick={() => onQueryChange({ ...query, page: Math.max(1, accounts.page - 1) })} disabled={accounts.page <= 1}>
                  上一页
                </Button>
                <Button variant="secondary" onClick={() => onQueryChange({ ...query, page: Math.min(pageCount, accounts.page + 1) })} disabled={accounts.page >= pageCount}>
                  下一页
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      <Dialog open={previewOpen} onOpenChange={onPreviewOpenChange}>
        <DialogContent className="w-[min(96vw,78rem)]">
          <DialogHeader>
            <DialogTitle>导入预览</DialogTitle>
            <DialogDescription>
              这一轮会先展示解析结果、输入内重复和与现有账号的冲突决策。确认后才会真正写入数据库。
              {importGroupName ? ` 导入分组：${importGroupName}` : " 本次未指定分组。"}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 px-6 py-2">
            <div className="flex flex-wrap gap-2">
              <Badge variant="info">parsed · {preview?.summary.parsed || 0}</Badge>
              <Badge variant="success">create · {preview?.summary.create || 0}</Badge>
              <Badge variant="info">update · {preview?.summary.updatePassword || 0}</Badge>
              <Badge variant="neutral">keep · {preview?.summary.keepExisting || 0}</Badge>
              <Badge variant="warning">dup · {preview?.summary.inputDuplicate || 0}</Badge>
              <Badge variant="danger">invalid · {preview?.summary.invalid || 0}</Badge>
            </div>

            <ScrollArea className="max-h-[52vh] rounded-[24px] border border-white/8 bg-[#08111d]/88">
              {preview?.items?.length ? (
                <Table className="min-w-[940px]">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-20">行号</TableHead>
                      <TableHead>邮箱</TableHead>
                      <TableHead>密码</TableHead>
                      <TableHead>决策</TableHead>
                      <TableHead>现有分组</TableHead>
                      <TableHead>说明</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {preview.items.map((item) => (
                      <TableRow key={`${item.lineNumber}-${item.rawLine}`}>
                        <TableCell>#{item.lineNumber}</TableCell>
                        <TableCell className="min-w-[14rem] whitespace-nowrap">{item.email || "—"}</TableCell>
                        <TableCell className="font-mono text-sm text-slate-200">{item.password || "—"}</TableCell>
                        <TableCell className="whitespace-nowrap"><ImportDecisionBadge decision={item.decision} /></TableCell>
                        <TableCell>{item.groupName || "—"}</TableCell>
                        <TableCell className="min-w-[18rem] text-slate-300">{item.note}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="px-4 py-10 text-center text-sm text-slate-500">还没有预览数据。</div>
              )}
            </ScrollArea>
          </div>

          <DialogFooter>
            <Button variant="secondary" onClick={() => onPreviewOpenChange(false)}>
              取消
            </Button>
            <Button onClick={onConfirmImport} disabled={previewCommitCount === 0 || importBusy}>
              {importBusy ? "导入中…" : `确认导入 ${previewCommitCount} 条`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
