import { useState, type ReactNode } from "react";
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
import type {
  AccountExtractorHistoryPayload,
  AccountExtractorHistoryQuery,
  AccountExtractorSettings,
  AccountImportPreviewPayload,
  AccountQuery,
  AccountRecord,
  AccountsPayload,
} from "@/lib/app-types";
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

function ExtractHistoryStatusBadge({ status }: { status: string }) {
  if (status === "accepted") return <Badge variant="success">accepted</Badge>;
  if (status === "rejected") return <Badge variant="warning">rejected</Badge>;
  if (status === "invalid_key") return <Badge variant="danger">invalid_key</Badge>;
  if (status === "insufficient_stock") return <Badge variant="warning">insufficient_stock</Badge>;
  if (status === "parse_failed") return <Badge variant="danger">parse_failed</Badge>;
  return <Badge variant="neutral">{status}</Badge>;
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
  extractorSettings,
  extractorSettingsBusy,
  extractorHistory,
  extractorHistoryQuery,
  extractorHistoryBusy,
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
  onSaveProofMailbox,
  onSaveAvailability,
  onSaveExtractorSettings,
  onExtractorHistoryQueryChange,
  onRefreshExtractorHistory,
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
  extractorSettings: AccountExtractorSettings | null;
  extractorSettingsBusy: boolean;
  extractorHistory: AccountExtractorHistoryPayload;
  extractorHistoryQuery: AccountExtractorHistoryQuery;
  extractorHistoryBusy: boolean;
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
  onSaveProofMailbox: (accountId: number, proofMailboxAddress: string | null, proofMailboxId?: string | null) => Promise<void>;
  onSaveAvailability: (accountId: number, disabled: boolean, disabledReason: string | null) => Promise<void>;
  onSaveExtractorSettings: (patch: Partial<AccountExtractorSettings>) => Promise<void>;
  onExtractorHistoryQueryChange: (value: AccountExtractorHistoryQuery) => void;
  onRefreshExtractorHistory: () => Promise<void>;
}) {
  const [proofDialogOpen, setProofDialogOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<AccountRecord | null>(null);
  const [proofMailboxDraft, setProofMailboxDraft] = useState("");
  const [proofMailboxIdDraft, setProofMailboxIdDraft] = useState("");
  const [proofBusy, setProofBusy] = useState(false);
  const [proofError, setProofError] = useState<string | null>(null);
  const [availabilityDialogOpen, setAvailabilityDialogOpen] = useState(false);
  const [availabilityAccount, setAvailabilityAccount] = useState<AccountRecord | null>(null);
  const [availabilityReasonDraft, setAvailabilityReasonDraft] = useState("");
  const [availabilityBusy, setAvailabilityBusy] = useState(false);
  const [availabilityError, setAvailabilityError] = useState<string | null>(null);
  const [extractorDialogOpen, setExtractorDialogOpen] = useState(false);
  const [zhanghaoyaKeyDraft, setZhanghaoyaKeyDraft] = useState("");
  const [shanyouxiangKeyDraft, setShanyouxiangKeyDraft] = useState("");
  const [extractorSaveError, setExtractorSaveError] = useState<string | null>(null);
  const readyCount = accounts.summary.ready;
  const linkedCount = accounts.summary.linked;
  const failedCount = accounts.summary.failed;
  const disabledCount = accounts.summary.disabled;
  const selectedOnPage = accounts.rows.filter((row) => selectedIds.includes(row.id)).length;
  const pageCount = Math.max(1, Math.ceil(Math.max(1, accounts.total) / Math.max(1, accounts.pageSize)));
  const extractHistoryPageCount = Math.max(
    1,
    Math.ceil(Math.max(1, extractorHistory.total) / Math.max(1, extractorHistory.pageSize)),
  );
  const getPasswordDisplay = (accountId: number, fallbackMasked: string, plaintext?: string | null) =>
    plaintext || revealedPasswordsById[accountId] || fallbackMasked;
  const proofMailboxPreview = editingAccount ? `${editingAccount.proofMailboxProvider || "moemail"} · ${editingAccount.proofMailboxId || "未缓存"}` : "—";

  const openProofDialog = (account: AccountRecord) => {
    setEditingAccount(account);
    setProofMailboxDraft(account.proofMailboxAddress || "");
    setProofMailboxIdDraft(account.proofMailboxId || "");
    setProofError(null);
    setProofDialogOpen(true);
  };

  const closeProofDialog = (open: boolean) => {
    setProofDialogOpen(open);
    if (open) return;
    setEditingAccount(null);
    setProofMailboxDraft("");
    setProofMailboxIdDraft("");
    setProofError(null);
    setProofBusy(false);
  };

  const handleProofMailboxChange = (value: string) => {
    setProofMailboxDraft(value);
    if (!editingAccount) {
      setProofMailboxIdDraft("");
      return;
    }
    const normalized = value.trim().toLowerCase();
    const original = (editingAccount.proofMailboxAddress || "").trim().toLowerCase();
    setProofMailboxIdDraft(normalized && normalized === original ? editingAccount.proofMailboxId || "" : "");
  };

  const handleSaveProofMailbox = async () => {
    if (!editingAccount) return;
    const normalizedAddress = proofMailboxDraft.trim() || null;
    if (normalizedAddress && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedAddress)) {
      setProofError("请输入合法的备用邮箱地址。");
      return;
    }
    try {
      setProofBusy(true);
      setProofError(null);
      await onSaveProofMailbox(editingAccount.id, normalizedAddress, normalizedAddress ? proofMailboxIdDraft.trim() || null : null);
      closeProofDialog(false);
    } catch (error) {
      setProofError(error instanceof Error ? error.message : String(error));
    } finally {
      setProofBusy(false);
    }
  };

  const openAvailabilityDialog = (account: AccountRecord) => {
    setAvailabilityAccount(account);
    setAvailabilityReasonDraft(account.disabledReason || "未知辅助邮箱");
    setAvailabilityError(null);
    setAvailabilityDialogOpen(true);
  };

  const closeAvailabilityDialog = (open: boolean) => {
    setAvailabilityDialogOpen(open);
    if (open) return;
    setAvailabilityAccount(null);
    setAvailabilityReasonDraft("");
    setAvailabilityError(null);
    setAvailabilityBusy(false);
  };

  const handleSaveAvailability = async () => {
    if (!availabilityAccount) return;
    const normalizedReason = availabilityReasonDraft.trim();
    if (!normalizedReason) {
      setAvailabilityError("请填写不可用原因。");
      return;
    }
    try {
      setAvailabilityBusy(true);
      setAvailabilityError(null);
      await onSaveAvailability(availabilityAccount.id, true, normalizedReason);
      closeAvailabilityDialog(false);
    } catch (error) {
      setAvailabilityError(error instanceof Error ? error.message : String(error));
    } finally {
      setAvailabilityBusy(false);
    }
  };

  const handleRestoreAvailability = async (account: AccountRecord) => {
    try {
      setAvailabilityBusy(true);
      setAvailabilityError(null);
      await onSaveAvailability(account.id, false, null);
    } catch (error) {
      setAvailabilityError(error instanceof Error ? error.message : String(error));
    } finally {
      setAvailabilityBusy(false);
    }
  };

  const openExtractorDialog = () => {
    setZhanghaoyaKeyDraft(extractorSettings?.extractorZhanghaoyaKey || "");
    setShanyouxiangKeyDraft(extractorSettings?.extractorShanyouxiangKey || "");
    setExtractorSaveError(null);
    setExtractorDialogOpen(true);
  };

  const handleSaveExtractorKeys = async () => {
    try {
      setExtractorSaveError(null);
      await onSaveExtractorSettings({
        extractorZhanghaoyaKey: zhanghaoyaKeyDraft,
        extractorShanyouxiangKey: shanyouxiangKeyDraft,
      });
      setExtractorDialogOpen(false);
    } catch (error) {
      setExtractorSaveError(error instanceof Error ? error.message : String(error));
    }
  };

  return (
    <>
      <section className="grid gap-4 xl:grid-cols-[minmax(22rem,0.52fr)_minmax(0,1.48fr)]">
        <div className="space-y-4">
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

          <Card className="min-h-[18rem] border-dashed border-cyan-300/20 bg-cyan-300/[0.03]">
            <CardHeader>
              <CardTitle>提取器设置</CardTitle>
              <CardDescription>
                配置账号鸭 / 闪邮箱 KEY，并查询本地提取历史。这里只读取 SQLite 本地记录，不直连远端历史接口。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
                  <div className="text-sm font-medium text-white">账号鸭</div>
                  <div className="mt-1 text-sm text-slate-400">
                    {extractorSettings?.availability.zhanghaoya ? "KEY 已配置" : "KEY 未配置"}
                  </div>
                </div>
                <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
                  <div className="text-sm font-medium text-white">闪邮箱</div>
                  <div className="mt-1 text-sm text-slate-400">
                    {extractorSettings?.availability.shanyouxiang ? "KEY 已配置" : "KEY 未配置"}
                  </div>
                </div>
              </div>
              <div className="rounded-2xl border border-white/8 bg-[#08111d]/80 p-4 text-sm text-slate-400">
                本地历史 {extractorHistory.total} 条，最近分页 {extractorHistory.page}/{extractHistoryPageCount}。
              </div>
              <Button variant="outline" onClick={openExtractorDialog} className="w-full sm:w-auto">
                打开提取器设置
              </Button>
            </CardContent>
          </Card>
        </div>

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
              <Badge variant="warning">disabled · {disabledCount}</Badge>
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
                    <SelectItem value="disabled">disabled</SelectItem>
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
                              <div className="flex shrink-0 flex-col items-end gap-2">
                                {row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}
                                <div className="flex flex-wrap justify-end gap-2">
                                  <Button variant="outline" className="h-8 px-3 text-xs" onClick={() => openProofDialog(row)}>
                                    绑定邮箱
                                  </Button>
                                  {row.disabledAt ? (
                                    <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => handleRestoreAvailability(row)}>
                                      恢复可用
                                    </Button>
                                  ) : (
                                    <Button variant="outline" className="h-8 px-3 text-xs" onClick={() => openAvailabilityDialog(row)}>
                                      标记不可用
                                    </Button>
                                  )}
                                </div>
                              </div>
                            </div>
                          <dl className="mt-4 grid gap-3 text-sm text-slate-300">
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">分组</dt>
                              <dd>{row.groupName || "—"}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">Proof 邮箱</dt>
                              <dd className="break-all text-right">{row.proofMailboxAddress || "—"}</dd>
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
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">不可用原因</dt>
                              <dd className="max-w-[18rem] text-right">{row.disabledReason || "—"}</dd>
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
                        <TableHead>Proof 邮箱</TableHead>
                        <TableHead>Has Key</TableHead>
                        <TableHead>最近状态</TableHead>
                        <TableHead>导入时间</TableHead>
                        <TableHead>最近使用</TableHead>
                        <TableHead>跳过原因</TableHead>
                        <TableHead>不可用原因</TableHead>
                        <TableHead className="text-right">操作</TableHead>
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
                          <TableCell className="min-w-[15rem] break-all text-slate-300">{row.proofMailboxAddress || "—"}</TableCell>
                          <TableCell className="whitespace-nowrap">{row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}</TableCell>
                          <TableCell className="whitespace-nowrap"><StatusBadge status={row.lastResultStatus} /></TableCell>
                          <TableCell>{formatDate(row.importedAt)}</TableCell>
                          <TableCell>{formatDate(row.lastUsedAt)}</TableCell>
                          <TableCell className="min-w-[10rem]">{row.skipReason || "—"}</TableCell>
                          <TableCell className="min-w-[12rem]">{row.disabledReason || "—"}</TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end gap-2">
                              <Button variant="outline" className="h-8 px-3 text-xs" onClick={() => openProofDialog(row)}>
                                绑定邮箱
                              </Button>
                              {row.disabledAt ? (
                                <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => handleRestoreAvailability(row)}>
                                  恢复可用
                                </Button>
                              ) : (
                                <Button variant="outline" className="h-8 px-3 text-xs" onClick={() => openAvailabilityDialog(row)}>
                                  标记不可用
                                </Button>
                              )}
                            </div>
                          </TableCell>
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

      <Dialog
        open={extractorDialogOpen}
        onOpenChange={(open) => {
          setExtractorDialogOpen(open);
          if (!open) setExtractorSaveError(null);
        }}
      >
        <DialogContent className="w-[min(96vw,84rem)] max-w-[96vw]">
          <DialogHeader>
            <DialogTitle>微软账号提取器设置</DialogTitle>
            <DialogDescription>
              分别维护账号鸭与闪邮箱的 KEY，并查询本地提取历史。历史数据来自当前机器上的 SQLite，不依赖站点远端记录。
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 px-6 py-2 xl:grid-cols-[minmax(20rem,0.72fr)_minmax(0,1.28fr)]">
            <div className="space-y-4">
              <div className="rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
                <div className="text-sm font-medium text-white">站点 KEY</div>
                <div className="mt-1 text-sm text-slate-400">保存后会立即用于后续自动提取。历史只展示脱敏 KEY。</div>
              </div>
              <label className="flex flex-col gap-2">
                <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">账号鸭 KEY</span>
                <Input
                  value={zhanghaoyaKeyDraft}
                  onChange={(event) => setZhanghaoyaKeyDraft(event.target.value)}
                  placeholder="请输入 zhanghaoya key"
                />
              </label>
              <label className="flex flex-col gap-2">
                <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">闪邮箱 KEY</span>
                <Input
                  value={shanyouxiangKeyDraft}
                  onChange={(event) => setShanyouxiangKeyDraft(event.target.value)}
                  placeholder="请输入 shanyouxiang key"
                />
              </label>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-white/8 bg-[#08111d]/88 p-4 text-sm text-slate-400">
                  账号鸭：{extractorSettings?.availability.zhanghaoya ? "已配置" : "未配置"}
                </div>
                <div className="rounded-2xl border border-white/8 bg-[#08111d]/88 p-4 text-sm text-slate-400">
                  闪邮箱：{extractorSettings?.availability.shanyouxiang ? "已配置" : "未配置"}
                </div>
              </div>
              {extractorSaveError ? (
                <div className="rounded-2xl border border-rose-300/18 bg-rose-400/8 px-4 py-3 text-sm text-rose-100">{extractorSaveError}</div>
              ) : null}
            </div>

            <div className="min-w-0 space-y-4">
              <div className="grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,0.8fr)_minmax(0,1.4fr)_auto_auto]">
                <FilterField label="Provider">
                  <Select
                    value={extractorHistoryQuery.provider || "__all__"}
                    onValueChange={(value) =>
                      onExtractorHistoryQueryChange({
                        ...extractorHistoryQuery,
                        provider: value === "__all__" ? "" : (value as AccountExtractorHistoryQuery["provider"]),
                        page: 1,
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="全部来源" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__all__">全部来源</SelectItem>
                      <SelectItem value="zhanghaoya">账号鸭</SelectItem>
                      <SelectItem value="shanyouxiang">闪邮箱</SelectItem>
                    </SelectContent>
                  </Select>
                </FilterField>
                <FilterField label="Status">
                  <Select
                    value={extractorHistoryQuery.status || "__all__"}
                    onValueChange={(value) =>
                      onExtractorHistoryQueryChange({
                        ...extractorHistoryQuery,
                        status: value === "__all__" ? "" : value,
                        page: 1,
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="全部状态" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__all__">全部状态</SelectItem>
                      <SelectItem value="accepted">accepted</SelectItem>
                      <SelectItem value="rejected">rejected</SelectItem>
                      <SelectItem value="invalid_key">invalid_key</SelectItem>
                      <SelectItem value="insufficient_stock">insufficient_stock</SelectItem>
                      <SelectItem value="parse_failed">parse_failed</SelectItem>
                      <SelectItem value="error">error</SelectItem>
                    </SelectContent>
                  </Select>
                </FilterField>
                <FilterField label="Search">
                  <Input
                    value={extractorHistoryQuery.q}
                    onChange={(event) =>
                      onExtractorHistoryQueryChange({
                        ...extractorHistoryQuery,
                        q: event.target.value,
                        page: 1,
                      })
                    }
                    placeholder="邮箱 / 原始行 / 拒绝原因"
                  />
                </FilterField>
                <FilterField label="Page Size">
                  <Select
                    value={String(extractorHistoryQuery.pageSize)}
                    onValueChange={(value) =>
                      onExtractorHistoryQueryChange({
                        ...extractorHistoryQuery,
                        pageSize: Number(value),
                        page: 1,
                      })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="每页条数" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="5">5 / 页</SelectItem>
                      <SelectItem value="10">10 / 页</SelectItem>
                      <SelectItem value="20">20 / 页</SelectItem>
                    </SelectContent>
                  </Select>
                </FilterField>
                <div className="flex min-w-0 items-end">
                  <Button variant="outline" onClick={() => void onRefreshExtractorHistory()} disabled={extractorHistoryBusy}>
                    {extractorHistoryBusy ? "刷新中…" : "刷新"}
                  </Button>
                </div>
              </div>

              <ScrollArea className="max-h-[56vh] min-w-0 rounded-[24px] border border-white/8 bg-[#08111d]/88">
                <div className="min-w-0 space-y-4 p-4">
                  {extractorHistory.rows.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-500">
                      当前筛选下还没有本地提取记录。
                    </div>
                  ) : (
                    extractorHistory.rows.map((batch) => (
                      <article key={batch.id} className="min-w-0 rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
                        <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-white">
                              #{batch.id} · {batch.provider} · {batch.accountType}
                            </div>
                            <div className="mt-1 text-xs text-slate-400">
                              job {batch.jobId || "—"} · requested {batch.requestedUsableCount} · accepted {batch.acceptedCount} ·
                              raw {batch.attemptBudget} · {formatDate(batch.startedAt)}
                            </div>
                          </div>
                          <div className="flex shrink-0 flex-wrap gap-2">
                            <ExtractHistoryStatusBadge status={batch.status} />
                            <Badge variant="neutral">{batch.maskedKey || "no-key"}</Badge>
                          </div>
                        </div>
                        {batch.errorMessage ? (
                          <div className="mt-3 rounded-2xl border border-white/8 bg-[#0d1728]/70 px-4 py-3 text-sm text-slate-300">
                            {batch.errorMessage}
                          </div>
                        ) : null}
                        {batch.rawResponse ? (
                          <pre className="mt-3 max-h-32 min-w-0 overflow-auto rounded-2xl border border-white/8 bg-[#030712] p-3 text-xs leading-5 text-slate-400">
                            {batch.rawResponse}
                          </pre>
                        ) : null}
                        <div className="mt-3 min-w-0 overflow-x-auto">
                          <Table className="min-w-[760px]">
                            <TableHeader>
                              <TableRow>
                                <TableHead>邮箱</TableHead>
                                <TableHead>密码</TableHead>
                                <TableHead>Parse</TableHead>
                                <TableHead>Accept</TableHead>
                                <TableHead>Reject Reason</TableHead>
                                <TableHead>Raw Payload</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {batch.items.length === 0 ? (
                                <TableRow>
                                  <TableCell colSpan={6} className="text-center text-sm text-slate-500">
                                    本批次没有可展示的明细行。
                                  </TableCell>
                                </TableRow>
                              ) : (
                                batch.items.map((item) => (
                                  <TableRow key={item.id}>
                                    <TableCell className="min-w-[14rem] break-all">{item.email || "—"}</TableCell>
                                    <TableCell className="font-mono text-sm text-slate-300">{item.password || "—"}</TableCell>
                                    <TableCell>{item.parseStatus}</TableCell>
                                    <TableCell>{item.acceptStatus}</TableCell>
                                    <TableCell className="min-w-[12rem]">{item.rejectReason || "—"}</TableCell>
                                    <TableCell className="min-w-[18rem] break-all text-slate-400">{item.rawPayload}</TableCell>
                                  </TableRow>
                                ))
                              )}
                            </TableBody>
                          </Table>
                        </div>
                      </article>
                    ))
                  )}
                </div>
              </ScrollArea>

              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm text-slate-400">
                  第 {extractorHistory.page} / {extractHistoryPageCount} 页，共 {extractorHistory.total} 条批次记录。
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="secondary"
                    onClick={() =>
                      onExtractorHistoryQueryChange({
                        ...extractorHistoryQuery,
                        page: Math.max(1, extractorHistory.page - 1),
                      })
                    }
                    disabled={extractorHistory.page <= 1}
                  >
                    上一页
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() =>
                      onExtractorHistoryQueryChange({
                        ...extractorHistoryQuery,
                        page: Math.min(extractHistoryPageCount, extractorHistory.page + 1),
                      })
                    }
                    disabled={extractorHistory.page >= extractHistoryPageCount}
                  >
                    下一页
                  </Button>
                </div>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="secondary" onClick={() => setExtractorDialogOpen(false)} disabled={extractorSettingsBusy}>
              关闭
            </Button>
            <Button onClick={handleSaveExtractorKeys} disabled={extractorSettingsBusy}>
              {extractorSettingsBusy ? "保存中…" : "保存 KEY"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={proofDialogOpen} onOpenChange={closeProofDialog}>
        <DialogContent className="w-[min(96vw,34rem)]">
          <DialogHeader>
            <DialogTitle>设置 Microsoft Proof 邮箱</DialogTitle>
            <DialogDescription>
              把备用邮箱映射记录到数据库。运行时若微软弹出绑定或验证码页面，会优先用 MoeMail OpenAPI 自动恢复。
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 px-6 py-2">
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4 text-sm text-slate-300">
              <div className="break-all font-medium text-white">{editingAccount?.microsoftEmail || "—"}</div>
              <div className="mt-2 text-slate-400">{proofMailboxPreview}</div>
            </div>

            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">Proof 邮箱地址</span>
              <Input
                value={proofMailboxDraft}
                onChange={(event) => handleProofMailboxChange(event.target.value)}
                placeholder="someone@example.com"
              />
            </label>

            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">已缓存 mailbox id</span>
              <Input value={proofMailboxIdDraft} readOnly placeholder="首次自动解析后会回填" />
            </label>

            {proofError ? (
              <div className="rounded-2xl border border-rose-300/18 bg-rose-400/8 px-4 py-3 text-sm text-rose-100">{proofError}</div>
            ) : null}
          </div>

          <DialogFooter className="gap-2">
            <Button
              variant="secondary"
              onClick={() => {
                setProofMailboxDraft("");
                setProofMailboxIdDraft("");
              }}
              disabled={proofBusy}
            >
              清空表单
            </Button>
            <Button
              variant="outline"
              onClick={async () => {
                if (!editingAccount) return;
                try {
                  setProofBusy(true);
                  setProofError(null);
                  await onSaveProofMailbox(editingAccount.id, null, null);
                  closeProofDialog(false);
                } catch (error) {
                  setProofError(error instanceof Error ? error.message : String(error));
                } finally {
                  setProofBusy(false);
                }
              }}
              disabled={proofBusy}
            >
              清空映射
            </Button>
            <Button variant="secondary" onClick={() => closeProofDialog(false)} disabled={proofBusy}>
              取消
            </Button>
            <Button onClick={handleSaveProofMailbox} disabled={proofBusy}>
              {proofBusy ? "保存中…" : "保存映射"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={availabilityDialogOpen} onOpenChange={closeAvailabilityDialog}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>标记账号不可用</DialogTitle>
            <DialogDescription>
              停止后续调度使用这个账号，并记录清晰的不可用原因。
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 px-6 py-2">
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
              <div className="break-all font-medium text-white">{availabilityAccount?.microsoftEmail || "—"}</div>
              <div className="mt-1 text-sm text-slate-400">
                当前状态：{availabilityAccount?.disabledAt ? "已标记不可用" : "可调度"}
              </div>
            </div>
            <label className="space-y-2">
              <span className="text-xs uppercase tracking-[0.22em] text-slate-500">不可用原因</span>
              <Textarea
                value={availabilityReasonDraft}
                onChange={(event) => setAvailabilityReasonDraft(event.target.value)}
                placeholder="例如：未知辅助邮箱"
                className="min-h-28"
              />
            </label>
            {availabilityError ? <div className="text-sm text-rose-300">{availabilityError}</div> : null}
          </div>

          <DialogFooter>
            <Button variant="secondary" onClick={() => closeAvailabilityDialog(false)} disabled={availabilityBusy}>
              取消
            </Button>
            <Button onClick={handleSaveAvailability} disabled={availabilityBusy}>
              {availabilityBusy ? "保存中…" : "保存并停用"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
