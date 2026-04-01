import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, SlidersHorizontal } from "lucide-react";
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
  AccountExtractorProvider,
  AccountExtractorRunDraft,
  AccountExtractorRuntime,
  AccountExtractorSettings,
  AccountImportPreviewPayload,
  AccountQuery,
  AccountRecord,
  AccountsPayload,
  ExtractorSseState,
} from "@/lib/app-types";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

const EXTRACTOR_PROVIDER_OPTIONS = [
  { provider: "zhanghaoya", label: "账号鸭" },
  { provider: "shanyouxiang", label: "闪邮箱" },
  { provider: "shankeyun", label: "闪客云" },
  { provider: "hotmail666", label: "Hotmail666" },
] as const satisfies Array<{ provider: AccountExtractorProvider; label: string }>;

function extractorProviderLabel(provider: AccountExtractorProvider): string {
  return EXTRACTOR_PROVIDER_OPTIONS.find((item) => item.provider === provider)?.label || provider;
}

function isRestorableAccountBlock(reason: string | null | undefined): boolean {
  return ["microsoft_password_incorrect", "microsoft_account_locked", "microsoft_unknown_recovery_email"].includes(String(reason || "").trim());
}

function isLockedAccountBlock(account: Pick<AccountRecord, "skipReason" | "lastErrorCode">): boolean {
  return (
    String(account.skipReason || "").trim() === "microsoft_account_locked"
    || /^microsoft_account_locked/i.test(String(account.lastErrorCode || "").trim())
  );
}

function getAccountDisplayStatus(account: Pick<AccountRecord, "lastResultStatus" | "skipReason" | "disabledAt" | "lastErrorCode">): string {
  if (isLockedAccountBlock(account)) return "locked";
  if (account.disabledAt || isRestorableAccountBlock(account.skipReason)) return "disabled";
  return account.lastResultStatus;
}

function isConnectBlockedAccount(account: Pick<AccountRecord, "disabledAt" | "skipReason" | "lastErrorCode">): boolean {
  return Boolean(account.disabledAt) || isLockedAccountBlock(account);
}

function getConnectActionLabel(
  account: Pick<AccountRecord, "disabledAt" | "skipReason" | "lastErrorCode" | "mailboxStatus" | "browserSession">,
  connecting: boolean,
): string {
  if (connecting) return "连接中…";
  if (isLockedAccountBlock(account)) return "已锁定";
  if (account.disabledAt) return "已禁用";
  if (account.browserSession?.status === "bootstrapping") return "Bootstrap 中";
  if (account.browserSession?.status === "failed" || account.browserSession?.status === "blocked") return "重试 Bootstrap";
  if (account.browserSession?.status === "ready") return "重试 Bootstrap";
  return account.mailboxStatus && account.mailboxStatus !== "preparing" ? "重试 Bootstrap" : "启动 Bootstrap";
}

function formatAccountBlockReason(account: Pick<AccountRecord, "skipReason" | "lastErrorCode">): string {
  if (!account.skipReason) return "—";
  if (account.skipReason === "has_api_key") return "已有 API key";
  if (account.skipReason === "microsoft_password_incorrect") return "Microsoft 密码错误";
  if (account.skipReason === "microsoft_account_locked") return "Microsoft 账户已锁定";
  if (account.skipReason === "microsoft_unknown_recovery_email") {
    const detail = String(account.lastErrorCode || "").split(":").slice(1).join(":").trim();
    if (detail && !/challenge_mismatch|unknown_recovery_email/i.test(detail)) {
      return `未知辅助邮箱：${detail}`;
    }
    return "未知辅助邮箱";
  }
  return account.skipReason;
}

function formatBrowserSessionProxy(account: Pick<AccountRecord, "browserSession">): string {
  const session = account.browserSession;
  if (!session) return "—";
  const ip = session.proxyIp?.trim();
  const node = session.proxyNode?.trim();
  const region = session.proxyRegion?.trim();
  const country = session.proxyCountry?.trim();
  if (ip && node) {
    return `${ip} · ${node}`;
  }
  if (ip && region) {
    return `${ip} · ${region}`;
  }
  if (ip) return ip;
  if (node && region) return `${node} · ${region}`;
  if (node && country) return `${node} · ${country}`;
  return node || region || country || "—";
}

function formatBrowserSessionPath(account: Pick<AccountRecord, "browserSession">): string {
  const profilePath = account.browserSession?.profilePath?.trim();
  if (!profilePath) return "—";
  const normalized = profilePath.replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  if (parts.length <= 4) return normalized;
  return `…/${parts.slice(-4).join("/")}`;
}

function formatExtractorSourceSummary(sources: AccountExtractorProvider[]): string {
  if (sources.length === 0) return "未选择号源";
  return sources.map(extractorProviderLabel).join("、");
}

function extractorSseStateCopy(state: ExtractorSseState): { label: string; variant: "neutral" | "success" | "warning" | "danger" | "info" } {
  if (state === "open") return { label: "SSE 已连接", variant: "success" };
  if (state === "connecting") return { label: "SSE 连接中", variant: "info" };
  if (state === "error") return { label: "SSE 异常", variant: "danger" };
  return { label: "SSE 已关闭", variant: "warning" };
}

function normalizeExtractorNumericInput(rawValue: string, committedValue: number): number {
  const trimmed = rawValue.trim();
  if (!trimmed) return committedValue;
  const parsed = Math.trunc(Number(trimmed));
  if (!Number.isFinite(parsed)) return committedValue;
  return Math.max(1, parsed);
}

function FilterField(props: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-1 flex-col gap-2">
      <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{props.label}</span>
      {props.children}
    </label>
  );
}

function resolveAccountSortState(
  query: Pick<AccountQuery, "sortBy" | "sortDir">,
  column: Exclude<AccountQuery["sortBy"], "">,
): "inactive" | "desc" | "asc" {
  if (query.sortBy !== column) return "inactive";
  return query.sortDir;
}

function SortableTimeTableHead(props: {
  label: string;
  column: Exclude<AccountQuery["sortBy"], "">;
  query: AccountQuery;
  onQueryChange: (value: AccountQuery) => void;
}) {
  const state = resolveAccountSortState(props.query, props.column);
  const ariaSort = state === "asc" ? "ascending" : state === "desc" ? "descending" : "none";
  const nextQuery: AccountQuery =
    state === "inactive"
      ? { ...props.query, sortBy: props.column, sortDir: "desc" as const, page: 1 }
      : state === "desc"
        ? { ...props.query, sortBy: props.column, sortDir: "asc" as const, page: 1 }
        : { ...props.query, sortBy: "" as const, sortDir: "desc" as const, page: 1 };

  return (
    <TableHead aria-sort={ariaSort}>
      <button
        type="button"
        className={cn(
          "inline-flex items-center gap-2 rounded-xl px-1 py-1 text-left transition-colors",
          state === "inactive" ? "text-slate-400 hover:text-slate-100" : "text-cyan-200 hover:text-cyan-100",
        )}
        onClick={() => props.onQueryChange(nextQuery)}
        aria-label={`${props.label}排序：${state === "desc" ? "当前降序，再点升序" : state === "asc" ? "当前升序，再点恢复默认" : "当前未排序，点击按降序排序"}`}
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

function ExtractHistoryItemField(props: { label: string; value: ReactNode; className?: string; valueClassName?: string }) {
  return (
    <div className={cn("min-w-0 space-y-1", props.className)}>
      <div className="text-[0.68rem] uppercase tracking-[0.14em] text-slate-500">{props.label}</div>
      <div className={cn("break-all text-sm text-slate-100", props.valueClassName)}>{props.value}</div>
    </div>
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

function PasswordCopyButton(props: {
  accountEmail: string;
  displayValue: string;
  copyStatus: "idle" | "copied" | "failed";
  disabled?: boolean;
  onCopy: () => void;
}) {
  const feedbackLabel = props.copyStatus === "copied" ? "已复制" : props.copyStatus === "failed" ? "复制失败" : "点击复制";
  return (
    <button
      type="button"
      className={cn(
        "group inline-flex max-w-full items-center gap-2 rounded-2xl border border-white/8 bg-white/[0.03] px-3 py-2 text-left transition",
        props.disabled
          ? "cursor-not-allowed opacity-60"
          : "cursor-pointer hover:border-cyan-300/30 hover:bg-cyan-300/[0.06] hover:text-cyan-100",
      )}
      onClick={props.onCopy}
      disabled={props.disabled}
      aria-label={`复制 ${props.accountEmail} 密码`}
      title={props.disabled ? "当前没有可复制的密码" : `点击复制 ${props.accountEmail} 的密码`}
    >
      <span className="max-w-[8.5rem] truncate whitespace-nowrap font-mono text-sm text-slate-200 sm:max-w-[10rem]">
        {props.displayValue}
      </span>
      <span
        className={cn(
          "shrink-0 text-[0.68rem] uppercase tracking-[0.18em]",
          props.copyStatus === "copied"
            ? "text-emerald-300"
            : props.copyStatus === "failed"
              ? "text-rose-200"
              : "text-cyan-300/80 group-hover:text-cyan-200",
        )}
      >
        {feedbackLabel}
      </span>
    </button>
  );
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
  connectBusy,
  connectProgress,
  extractorSettings,
  extractorSettingsBusy,
  extractorRuntime,
  extractorRunDraft,
  extractorRunBusy,
  extractorSseState,
  extractorHistory,
  extractorHistoryQuery,
  extractorHistoryBusy,
  allCurrentPageSelected,
  graphSettingsConfigured,
  connectingAccountIds,
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
  onConnectAccount,
  onConnectSelectedAccounts,
  onSaveProofMailbox,
  onSaveAvailability,
  onSaveExtractorSettings,
  onExtractorRunDraftChange,
  onRunExtractor,
  onExtractorHistoryQueryChange,
  onRefreshExtractorHistory,
  onOpenMailbox,
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
  connectBusy: boolean;
  connectProgress: { current: number; total: number } | null;
  extractorSettings: AccountExtractorSettings | null;
  extractorSettingsBusy: boolean;
  extractorRuntime: AccountExtractorRuntime;
  extractorRunDraft: AccountExtractorRunDraft;
  extractorRunBusy: boolean;
  extractorSseState: ExtractorSseState;
  extractorHistory: AccountExtractorHistoryPayload;
  extractorHistoryQuery: AccountExtractorHistoryQuery;
  extractorHistoryBusy: boolean;
  allCurrentPageSelected: boolean;
  graphSettingsConfigured: boolean;
  connectingAccountIds: number[];
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
  onConnectAccount: (accountId: number) => Promise<void>;
  onConnectSelectedAccounts: () => Promise<void>;
  onSaveProofMailbox: (accountId: number, proofMailboxAddress: string | null, proofMailboxId?: string | null) => Promise<void>;
  onSaveAvailability: (accountId: number, disabled: boolean, disabledReason: string | null) => Promise<void>;
  onSaveExtractorSettings: (patch: Partial<AccountExtractorSettings>) => Promise<void>;
  onExtractorRunDraftChange: (patch: Partial<AccountExtractorRunDraft>) => void;
  onRunExtractor: () => Promise<void>;
  onExtractorHistoryQueryChange: (value: AccountExtractorHistoryQuery) => void;
  onRefreshExtractorHistory: () => Promise<void>;
  onOpenMailbox: (accountId: number) => void;
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
  const [extractorKeyDrafts, setExtractorKeyDrafts] = useState<Record<AccountExtractorProvider, string>>({
    zhanghaoya: "",
    shanyouxiang: "",
    shankeyun: "",
    hotmail666: "",
  });
  const [extractorSaveError, setExtractorSaveError] = useState<string | null>(null);
  const [passwordCopyFeedback, setPasswordCopyFeedback] = useState<{
    accountId: number | null;
    status: "idle" | "copied" | "failed";
  }>({ accountId: null, status: "idle" });
  const passwordCopyResetTimerRef = useRef<number | null>(null);
  const [extractorQuantityInput, setExtractorQuantityInput] = useState(() => String(extractorRunDraft.quantity));
  const [extractorMaxWaitInput, setExtractorMaxWaitInput] = useState(() => String(extractorRunDraft.maxWaitSec));
  const readyCount = accounts.summary.ready;
  const linkedCount = accounts.summary.linked;
  const failedCount = accounts.summary.failed;
  const disabledCount = accounts.summary.disabled;
  const selectedOnPage = accounts.rows.filter((row) => selectedIds.includes(row.id)).length;
  const selectedConnectCount = selectedIds.filter((accountId) => {
    const row = accounts.rows.find((item) => item.id === accountId);
    return !row || (!isConnectBlockedAccount(row) && row.browserSession?.status !== "bootstrapping");
  }).length;
  const pageCount = Math.max(1, Math.ceil(Math.max(1, accounts.total) / Math.max(1, accounts.pageSize)));
  const extractHistoryPageCount = Math.max(
    1,
    Math.ceil(Math.max(1, extractorHistory.total) / Math.max(1, extractorHistory.pageSize)),
  );
  const extractorSseBadge = extractorSseStateCopy(extractorSseState);
  const extractorSummarySources =
    extractorRuntime.enabledSources.length > 0 ? extractorRuntime.enabledSources : extractorRunDraft.sources;
  const extractorCanStart =
    graphSettingsConfigured
    && extractorRuntime.status !== "running"
    && extractorRunDraft.sources.length > 0
    && extractorRunDraft.quantity > 0
    && extractorRunDraft.maxWaitSec > 0;
  useEffect(() => {
    return () => {
      if (passwordCopyResetTimerRef.current != null) {
        window.clearTimeout(passwordCopyResetTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    setExtractorQuantityInput(String(extractorRunDraft.quantity));
  }, [extractorRunDraft.quantity]);

  useEffect(() => {
    setExtractorMaxWaitInput(String(extractorRunDraft.maxWaitSec));
  }, [extractorRunDraft.maxWaitSec]);

  const queuePasswordCopyFeedbackReset = () => {
    if (passwordCopyResetTimerRef.current != null) {
      window.clearTimeout(passwordCopyResetTimerRef.current);
    }
    passwordCopyResetTimerRef.current = window.setTimeout(() => {
      setPasswordCopyFeedback({ accountId: null, status: "idle" });
      passwordCopyResetTimerRef.current = null;
    }, 1800);
  };

  const getPasswordDisplay = (accountId: number, fallbackMasked: string) => revealedPasswordsById[accountId] || fallbackMasked;
  const getPasswordCopyValue = (accountId: number, plaintext?: string | null) => plaintext || revealedPasswordsById[accountId] || "";
  const getPasswordCopyStatus = (accountId: number) =>
    passwordCopyFeedback.accountId === accountId ? passwordCopyFeedback.status : "idle";
  const handleCopyPassword = async (account: AccountRecord) => {
    const copyValue = getPasswordCopyValue(account.id, account.passwordPlaintext);
    if (!copyValue.trim()) {
      setPasswordCopyFeedback({ accountId: account.id, status: "failed" });
      queuePasswordCopyFeedbackReset();
      return;
    }
    try {
      await copyTextToClipboard(copyValue);
      setPasswordCopyFeedback({ accountId: account.id, status: "copied" });
    } catch {
      setPasswordCopyFeedback({ accountId: account.id, status: "failed" });
    }
    queuePasswordCopyFeedbackReset();
  };
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
    setAvailabilityReasonDraft(account.disabledReason || "手动停用");
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
    setExtractorKeyDrafts({
      zhanghaoya: extractorSettings?.extractorZhanghaoyaKey || "",
      shanyouxiang: extractorSettings?.extractorShanyouxiangKey || "",
      shankeyun: extractorSettings?.extractorShankeyunKey || "",
      hotmail666: extractorSettings?.extractorHotmail666Key || "",
    });
    setExtractorSaveError(null);
    setExtractorDialogOpen(true);
  };

  const updateExtractorKeyDraft = (provider: AccountExtractorProvider, value: string) => {
    setExtractorKeyDrafts((current) => ({ ...current, [provider]: value }));
  };

  const handleSaveExtractorKeys = async () => {
    try {
      setExtractorSaveError(null);
      await onSaveExtractorSettings({
        extractorZhanghaoyaKey: extractorKeyDrafts.zhanghaoya,
        extractorShanyouxiangKey: extractorKeyDrafts.shanyouxiang,
        extractorShankeyunKey: extractorKeyDrafts.shankeyun,
        extractorHotmail666Key: extractorKeyDrafts.hotmail666,
      });
      setExtractorDialogOpen(false);
    } catch (error) {
      setExtractorSaveError(error instanceof Error ? error.message : String(error));
    }
  };

  const commitExtractorQuantityInput = () => {
    const normalized = normalizeExtractorNumericInput(extractorQuantityInput, extractorRunDraft.quantity);
    setExtractorQuantityInput(String(normalized));
    if (normalized !== extractorRunDraft.quantity) {
      onExtractorRunDraftChange({ quantity: normalized });
    }
  };

  const commitExtractorMaxWaitInput = () => {
    const normalized = normalizeExtractorNumericInput(extractorMaxWaitInput, extractorRunDraft.maxWaitSec);
    setExtractorMaxWaitInput(String(normalized));
    if (normalized !== extractorRunDraft.maxWaitSec) {
      onExtractorRunDraftChange({ maxWaitSec: normalized });
    }
  };

  return (
    <>
      <section className="grid gap-4 xl:grid-cols-[minmax(22rem,0.52fr)_minmax(0,1.48fr)]">
        <div className="space-y-4">
          <Card className="min-h-[18rem] border-dashed border-cyan-300/20 bg-cyan-300/[0.03]">
            <CardHeader>
              <CardTitle>提号器</CardTitle>
              <CardDescription>
                这里会直接提号、自动登录 Microsoft、保存持久 Profile，并自动连接邮箱。提号状态和账号列表通过 SSE 实时刷新。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <StatusBadge status={extractorRuntime.status} />
                <Badge variant={extractorSseBadge.variant}>{extractorSseBadge.label}</Badge>
                <Badge variant={graphSettingsConfigured ? "success" : "warning"}>
                  {graphSettingsConfigured ? "Graph 已配置" : "Graph 未配置"}
                </Badge>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                {EXTRACTOR_PROVIDER_OPTIONS.map(({ provider, label }) => {
                  const available = Boolean(extractorSettings?.availability[provider]);
                  const checked = extractorRunDraft.sources.includes(provider);
                  return (
                    <label
                      key={provider}
                      className={cn(
                        "flex items-start gap-3 rounded-2xl border border-white/8 bg-white/[0.03] p-4 transition",
                        available ? "cursor-pointer hover:border-cyan-300/24" : "opacity-60",
                      )}
                    >
                      <Checkbox
                        checked={checked}
                        disabled={!available || extractorRuntime.status === "running"}
                        onCheckedChange={(next) => {
                          const enabled = next === true;
                          onExtractorRunDraftChange({
                            sources: enabled
                              ? Array.from(new Set([...extractorRunDraft.sources, provider]))
                              : extractorRunDraft.sources.filter((item) => item !== provider),
                          });
                        }}
                        aria-label={`toggle-${provider}`}
                      />
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-white">{label}</div>
                        <div className="mt-1 text-sm text-slate-400">{available ? "KEY 已配置" : "KEY 未配置"}</div>
                      </div>
                    </label>
                  );
                })}
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <label className="flex flex-col gap-2">
                  <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">提号数量</span>
                  <Input
                    type="number"
                    min={1}
                    step={1}
                    value={extractorQuantityInput}
                    disabled={extractorRuntime.status === "running"}
                    onChange={(event) => setExtractorQuantityInput(event.target.value)}
                    onBlur={commitExtractorQuantityInput}
                  />
                </label>
                <label className="flex flex-col gap-2">
                  <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">最长等待（秒）</span>
                  <Input
                    type="number"
                    min={1}
                    step={1}
                    value={extractorMaxWaitInput}
                    disabled={extractorRuntime.status === "running"}
                    onChange={(event) => setExtractorMaxWaitInput(event.target.value)}
                    onBlur={commitExtractorMaxWaitInput}
                  />
                </label>
              </div>

              <div className="rounded-2xl border border-white/8 bg-[#08111d]/80 p-4 text-sm text-slate-300">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-white">当前号源：</span>
                  <span>{formatExtractorSourceSummary(extractorSummarySources)}</span>
                </div>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  <div>目标接受：{extractorRuntime.acceptedCount} / {extractorRuntime.requestedUsableCount || extractorRunDraft.quantity}</div>
                  <div>原始请求：{extractorRuntime.rawAttemptCount} / {extractorRuntime.attemptBudget || "—"}</div>
                  <div>在途请求：{extractorRuntime.inFlightCount}</div>
                  <div>剩余等待：{extractorRuntime.remainingWaitSec}s / {extractorRuntime.maxWaitSec || extractorRunDraft.maxWaitSec}s</div>
                  <div>最近来源：{extractorRuntime.lastProvider ? extractorProviderLabel(extractorRuntime.lastProvider) : "—"}</div>
                  <div>最近批次：{extractorRuntime.lastBatchId || "—"}</div>
                </div>
                <div className="mt-3 rounded-2xl border border-white/8 bg-[#030712]/60 px-4 py-3 text-sm text-slate-300">
                  {extractorRuntime.errorMessage || extractorRuntime.lastMessage || "等待启动提号器。"}
                </div>
                <div className="mt-2 text-xs text-slate-500">
                  最近更新：{formatDate(extractorRuntime.updatedAt)} · 本地历史 {extractorHistory.total} 条，最近分页 {extractorHistory.page}/{extractHistoryPageCount}。
                </div>
              </div>

              {!graphSettingsConfigured ? (
                <div className="rounded-2xl border border-amber-300/18 bg-amber-400/8 px-4 py-3 text-sm text-amber-100">
                  请先配置 Microsoft Graph 回调，再启动提号器；否则账号无法自动连邮箱。
                </div>
              ) : null}

              <div className="flex flex-col gap-3 sm:flex-row">
                <Button
                  onClick={() => {
                    void onRunExtractor();
                  }}
                  disabled={!extractorCanStart || extractorRunBusy}
                  className="sm:flex-1"
                >
                  {extractorRuntime.status === "running" || extractorRunBusy ? "提号中…" : "开始提号 + 自动 Bootstrap"}
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={openExtractorDialog}
                  className="shrink-0 rounded-2xl"
                  data-testid="open-extractor-settings"
                  aria-label="打开提号器 KEY 与历史"
                  title="打开提号器 KEY 与历史"
                >
                  <SlidersHorizontal className="size-4" />
                  <span className="sr-only">KEY / 历史</span>
                </Button>
              </div>
            </CardContent>
          </Card>

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
                <span>可连接 {selectedConnectCount} 条</span>
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
                  <Button variant="outline" onClick={() => void onConnectSelectedAccounts()} disabled={selectedConnectCount === 0 || connectBusy || !graphSettingsConfigured}>
                    {connectBusy
                      ? `连接中 ${connectProgress?.current || 0}/${connectProgress?.total || selectedConnectCount}`
                      : graphSettingsConfigured
                        ? "批量连接"
                        : "先配置 Graph"}
                  </Button>
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
                                <div className="mt-1">
                                  <PasswordCopyButton
                                    accountEmail={row.microsoftEmail}
                                    displayValue={getPasswordDisplay(row.id, row.passwordMasked)}
                                    copyStatus={getPasswordCopyStatus(row.id)}
                                    onCopy={() => void handleCopyPassword(row)}
                                  />
                                </div>
                              </div>
                              <div className="flex shrink-0 flex-col items-end gap-2">
                                {row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}
                                <div className="flex flex-wrap justify-end gap-2">
                                  <Button
                                    variant={row.mailboxStatus && row.mailboxStatus !== "preparing" ? "secondary" : "outline"}
                                    className="h-8 px-3 text-xs"
                                    onClick={() => void onConnectAccount(row.id)}
                                    disabled={
                                      !graphSettingsConfigured
                                      || batchBusy
                                      || connectBusy
                                      || isConnectBlockedAccount(row)
                                      || connectingAccountIds.includes(row.id)
                                      || row.browserSession?.status === "bootstrapping"
                                    }
                                  >
                                    {getConnectActionLabel(row, connectingAccountIds.includes(row.id))}
                                  </Button>
                                  <Button variant="outline" className="h-8 px-3 text-xs" onClick={() => openProofDialog(row)}>
                                    绑定邮箱
                                  </Button>
                                  {row.disabledAt || isRestorableAccountBlock(row.skipReason) ? (
                                    <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => handleRestoreAvailability(row)}>
                                      恢复可用
                                    </Button>
                                  ) : (
                                    <Button variant="outline" className="h-8 px-3 text-xs" onClick={() => openAvailabilityDialog(row)}>
                                      标记不可用
                                    </Button>
                                  )}
                                  <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => onOpenMailbox(row.id)}>
                                    收件箱
                                  </Button>
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
                              <dt className="text-slate-500">Session</dt>
                              <dd><StatusBadge status={row.browserSession?.status || "pending"} /></dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">Session Proxy</dt>
                              <dd className="max-w-[18rem] text-right">{formatBrowserSessionProxy(row)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">Profile</dt>
                              <dd className="max-w-[18rem] text-right font-mono text-xs">{formatBrowserSessionPath(row)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">最近状态</dt>
                              <dd><StatusBadge status={getAccountDisplayStatus(row)} /></dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">收信状态</dt>
                              <dd className="flex items-center gap-2">
                                <StatusBadge status={row.mailboxStatus} />
                                {row.mailboxUnreadCount > 0 ? <Badge variant="info">{row.mailboxUnreadCount}</Badge> : null}
                              </dd>
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
                              <dt className="text-slate-500">账号阻断</dt>
                              <dd className="max-w-[18rem] text-right">{formatAccountBlockReason(row)}</dd>
                            </div>
                            <div className="flex items-center justify-between gap-3">
                              <dt className="text-slate-500">人工停用</dt>
                              <dd className="max-w-[18rem] text-right">{row.disabledReason || "—"}</dd>
                            </div>
                          </dl>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>

                <div className="hidden md:block">
                  <Table className="min-w-[1420px]">
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
                        <TableHead className="w-[12rem] min-w-[12rem]">密码</TableHead>
                        <TableHead>分组</TableHead>
                        <TableHead>Proof 邮箱</TableHead>
                        <TableHead>Has Key</TableHead>
                        <TableHead>Session</TableHead>
                        <TableHead>Session Proxy</TableHead>
                        <TableHead>Profile</TableHead>
                        <TableHead>最近状态</TableHead>
                        <TableHead>收信状态</TableHead>
                        <SortableTimeTableHead label="导入时间" column="importedAt" query={query} onQueryChange={onQueryChange} />
                        <SortableTimeTableHead label="最近使用" column="lastUsedAt" query={query} onQueryChange={onQueryChange} />
                        <TableHead>账号阻断</TableHead>
                        <TableHead>人工停用</TableHead>
                        <TableHead className="w-[24rem] min-w-[24rem] whitespace-nowrap text-right">操作</TableHead>
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
                          <TableCell className="w-[12rem] min-w-[12rem]">
                            <PasswordCopyButton
                              accountEmail={row.microsoftEmail}
                              displayValue={getPasswordDisplay(row.id, row.passwordMasked)}
                              copyStatus={getPasswordCopyStatus(row.id)}
                              onCopy={() => void handleCopyPassword(row)}
                            />
                          </TableCell>
                          <TableCell className="whitespace-nowrap">{row.groupName || "—"}</TableCell>
                          <TableCell className="min-w-[15rem] break-all text-slate-300">{row.proofMailboxAddress || "—"}</TableCell>
                          <TableCell className="whitespace-nowrap">{row.hasApiKey ? <StatusBadge status="active" /> : <StatusBadge status="no-key" />}</TableCell>
                          <TableCell className="whitespace-nowrap"><StatusBadge status={row.browserSession?.status || "pending"} /></TableCell>
                          <TableCell className="min-w-[12rem]">{formatBrowserSessionProxy(row)}</TableCell>
                          <TableCell className="min-w-[14rem] font-mono text-xs text-slate-300">{formatBrowserSessionPath(row)}</TableCell>
                          <TableCell className="whitespace-nowrap"><StatusBadge status={getAccountDisplayStatus(row)} /></TableCell>
                          <TableCell className="whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <StatusBadge status={row.mailboxStatus} />
                              {row.mailboxUnreadCount > 0 ? <Badge variant="info">{row.mailboxUnreadCount}</Badge> : null}
                            </div>
                          </TableCell>
                          <TableCell>{formatDate(row.importedAt)}</TableCell>
                          <TableCell>{formatDate(row.lastUsedAt)}</TableCell>
                          <TableCell className="min-w-[10rem]">{formatAccountBlockReason(row)}</TableCell>
                          <TableCell className="min-w-[12rem]">{row.disabledReason || "—"}</TableCell>
                          <TableCell className="w-[24rem] min-w-[24rem] whitespace-nowrap text-right">
                            <div className="ml-auto flex w-max min-w-full flex-nowrap justify-end gap-2">
                              <Button
                                variant={row.mailboxStatus && row.mailboxStatus !== "preparing" ? "secondary" : "outline"}
                                className="h-8 shrink-0 px-3 text-xs"
                                onClick={() => void onConnectAccount(row.id)}
                                disabled={
                                  !graphSettingsConfigured
                                  || batchBusy
                                  || connectBusy
                                  || isConnectBlockedAccount(row)
                                  || connectingAccountIds.includes(row.id)
                                  || row.browserSession?.status === "bootstrapping"
                                }
                              >
                                {getConnectActionLabel(row, connectingAccountIds.includes(row.id))}
                              </Button>
                              <Button variant="outline" className="h-8 shrink-0 px-3 text-xs" onClick={() => openProofDialog(row)}>
                                绑定邮箱
                              </Button>
                              {row.disabledAt || isRestorableAccountBlock(row.skipReason) ? (
                                <Button variant="secondary" className="h-8 shrink-0 px-3 text-xs" onClick={() => handleRestoreAvailability(row)}>
                                  恢复可用
                                </Button>
                              ) : (
                                <Button variant="outline" className="h-8 shrink-0 px-3 text-xs" onClick={() => openAvailabilityDialog(row)}>
                                  标记不可用
                                </Button>
                              )}
                              <Button variant="secondary" className="h-8 shrink-0 px-3 text-xs" onClick={() => onOpenMailbox(row.id)}>
                                收件箱
                              </Button>
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
        <DialogContent
          className="!flex w-[min(96vw,var(--extractor-dialog-preview-width,84rem))] max-h-[88vh] max-w-[96vw] !flex-col"
          data-testid="extractor-settings-dialog"
        >
          <DialogHeader className="shrink-0">
            <DialogTitle>微软账号提取器设置</DialogTitle>
            <DialogDescription>
              分别维护四个号源的 KEY，并查询本地提取历史。历史数据来自当前机器上的 SQLite，不依赖站点远端记录。
            </DialogDescription>
          </DialogHeader>

          <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto overflow-x-hidden px-6 py-2 xl:grid xl:overflow-hidden xl:grid-cols-[minmax(20rem,0.72fr)_minmax(0,1.28fr)]">
            <div className="shrink-0 space-y-4 xl:min-h-0 xl:overflow-auto xl:pr-1">
              <div className="rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
                <div className="text-sm font-medium text-white">站点 KEY</div>
                <div className="mt-1 text-sm text-slate-400">保存后会立即用于后续自动提取。历史只展示脱敏 KEY。</div>
              </div>
              {EXTRACTOR_PROVIDER_OPTIONS.map(({ provider, label }) => (
                <label key={provider} className="flex flex-col gap-2">
                  <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">{label} KEY</span>
                  <Input
                    value={extractorKeyDrafts[provider]}
                    onChange={(event) => updateExtractorKeyDraft(provider, event.target.value)}
                    placeholder={`请输入 ${label} KEY`}
                  />
                </label>
              ))}
              <div className="grid gap-3 sm:grid-cols-2">
                {EXTRACTOR_PROVIDER_OPTIONS.map(({ provider, label }) => (
                  <div key={provider} className="rounded-2xl border border-white/8 bg-[#08111d]/88 p-4 text-sm text-slate-400">
                    {label}：{extractorSettings?.availability[provider] ? "已配置" : "未配置"}
                  </div>
                ))}
              </div>
              {extractorSaveError ? (
                <div className="rounded-2xl border border-rose-300/18 bg-rose-400/8 px-4 py-3 text-sm text-rose-100">{extractorSaveError}</div>
              ) : null}
            </div>

            <div className="min-w-0 flex flex-col gap-4 xl:min-h-0 xl:flex-1">
              <div className="grid min-w-0 gap-3 sm:grid-cols-2 2xl:grid-cols-[minmax(0,0.8fr)_minmax(0,0.8fr)_minmax(0,1.35fr)_minmax(8.5rem,0.6fr)_auto]">
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
                      {EXTRACTOR_PROVIDER_OPTIONS.map(({ provider, label }) => (
                        <SelectItem key={provider} value={provider}>{label}</SelectItem>
                      ))}
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

              <ScrollArea
                className="h-[min(40vh,28rem)] min-w-0 rounded-[24px] border border-white/8 bg-[#08111d]/88 sm:h-[min(44vh,32rem)] xl:min-h-0 xl:h-auto xl:flex-1"
                data-testid="extractor-history-scroll-area"
              >
                <div className="min-w-0 space-y-4 p-4 pr-6" data-testid="extractor-history-panel">
                  {extractorHistory.rows.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-500">
                      当前筛选下还没有本地提取记录。
                    </div>
                  ) : (
                    extractorHistory.rows.map((batch) => (
                      <article key={batch.id} className="min-w-0 overflow-hidden rounded-[24px] border border-white/8 bg-white/[0.03] p-4">
                        <div className="flex min-w-0 flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                          <div className="min-w-0 flex-1">
                            <div className="text-sm font-medium text-white">
                              #{batch.id} · {extractorProviderLabel(batch.provider)} · {batch.accountType}
                            </div>
                            <div className="mt-1 text-xs text-slate-400">
                              job {batch.jobId || "—"} · requested {batch.requestedUsableCount} · accepted {batch.acceptedCount} ·
                              raw {batch.attemptBudget} · {formatDate(batch.startedAt)}
                            </div>
                          </div>
                          <div className="flex min-w-0 flex-wrap items-start gap-2 lg:max-w-[19rem] lg:justify-end">
                            <ExtractHistoryStatusBadge status={batch.status} />
                            <Badge variant="neutral" className="min-w-0 max-w-full whitespace-normal break-all text-left normal-case tracking-[0.08em]">
                              {batch.maskedKey || "no-key"}
                            </Badge>
                          </div>
                        </div>
                        {batch.errorMessage ? (
                          <div className="mt-3 min-w-0 break-all rounded-2xl border border-white/8 bg-[#0d1728]/70 px-4 py-3 text-sm text-slate-300">
                            {batch.errorMessage}
                          </div>
                        ) : null}
                        {batch.rawResponse ? (
                          <pre className="mt-3 max-h-36 min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-2xl border border-white/8 bg-[#030712] p-3 text-xs leading-5 text-slate-400">
                            {batch.rawResponse}
                          </pre>
                        ) : null}
                        <div className="mt-3 grid min-w-0 gap-3">
                          {batch.items.length === 0 ? (
                            <div className="rounded-2xl border border-dashed border-white/10 px-4 py-6 text-center text-sm text-slate-500">
                              本批次没有可展示的明细行。
                            </div>
                          ) : (
                            batch.items.map((item) => (
                              <div
                                key={item.id}
                                className="grid min-w-0 gap-3 rounded-2xl border border-white/8 bg-[#0d1728]/55 p-4 sm:grid-cols-2 xl:grid-cols-3"
                              >
                                <ExtractHistoryItemField label="邮箱" value={item.email || "—"} />
                                <ExtractHistoryItemField label="密码" value={item.password || "—"} valueClassName="font-mono text-slate-300" />
                                <ExtractHistoryItemField label="Parse" value={item.parseStatus} />
                                <ExtractHistoryItemField label="Accept" value={item.acceptStatus} />
                                <ExtractHistoryItemField label="Reject Reason" value={item.rejectReason || "—"} className="sm:col-span-2 xl:col-span-3" />
                                <ExtractHistoryItemField
                                  label="Raw Payload"
                                  value={item.rawPayload}
                                  className="sm:col-span-2 xl:col-span-3"
                                  valueClassName="max-h-32 overflow-auto whitespace-pre-wrap break-all font-mono text-xs leading-5 text-slate-400"
                                />
                              </div>
                            ))
                          )}
                        </div>
                      </article>
                    ))
                  )}
                </div>
              </ScrollArea>

              <div className="flex shrink-0 flex-wrap items-center justify-between gap-2">
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

          <DialogFooter className="shrink-0">
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
