import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, Inbox, KeyRound, Mail, PencilLine, RefreshCw, RotateCcw, Settings2, ShieldOff, SlidersHorizontal } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
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
import { Popover, PopoverAnchor, PopoverContent } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { GroupCombobox } from "@/components/group-combobox";
import { StatusBadge } from "@/components/status-badge";
import { CopyIconButton } from "@/components/ui/copy-icon-button";
import { copyTextToClipboard } from "@/lib/clipboard";
import type {
  AccountBatchBootstrapMode,
  AccountBusinessFlowMode,
  AccountBusinessFlowSite,
  AccountBatchBootstrapPreviewPayload,
  AccountExtractorAccountType,
  AccountExtractorHistoryPayload,
  AccountExtractorHistoryQuery,
  AccountBrowserSessionStatus,
  AccountExtractorProvider,
  AccountExtractorRunDraft,
  AccountExtractorRuntime,
  AccountExtractorSettings,
  AccountImportPreviewPayload,
  AccountQuery,
  AccountRecord,
  AccountsPayload,
  ExtractorSseState,
  MailboxStatus,
  ProxyCheckState,
  ProxyNode,
} from "@/lib/app-types";
import { DEFAULT_ACCOUNT_QUERY_SORT, isDefaultAccountQuerySort } from "@/lib/account-query";
import { formatDate } from "@/lib/format";
import { cn } from "@/lib/utils";

const EXTRACTOR_PROVIDER_OPTIONS = [
  { provider: "zhanghaoya", label: "账号鸭" },
  { provider: "shanyouxiang", label: "闪邮箱" },
  { provider: "shankeyun", label: "闪客云" },
  { provider: "hotmail666", label: "Hotmail666" },
] as const satisfies Array<{ provider: AccountExtractorProvider; label: string }>;
const EXTRACTOR_ACCOUNT_TYPE_OPTIONS = [
  { value: "outlook", label: "Outlook" },
  { value: "hotmail", label: "Hotmail" },
  { value: "unlimited", label: "不限" },
] as const satisfies Array<{ value: AccountExtractorAccountType; label: string }>;
const SESSION_STATUS_OPTIONS = [
  { value: "pending", label: "pending" },
  { value: "bootstrapping", label: "bootstrapping" },
  { value: "ready", label: "ready" },
  { value: "failed", label: "failed" },
  { value: "blocked", label: "blocked" },
] as const satisfies Array<{ value: AccountBrowserSessionStatus; label: string }>;
const MAILBOX_STATUS_OPTIONS = [
  { value: "preparing", label: "preparing" },
  { value: "available", label: "available" },
  { value: "failed", label: "failed" },
  { value: "invalidated", label: "invalidated" },
  { value: "locked", label: "locked" },
] as const satisfies Array<{ value: MailboxStatus; label: string }>;
const DESKTOP_TOOLS_STORAGE_KEY = "tavreg-hikari.accounts.desktopToolsCollapsed";
const ACCOUNT_BUSINESS_FLOW_MODE_STORAGE_KEY = "tavreg-hikari.accounts.businessFlowMode";
const ACCOUNT_BUSINESS_FLOW_MODE_OPTIONS = [
  { value: "headless", label: "无头", description: "自动完成业务流，浏览器不保留。" },
  { value: "headed", label: "有头", description: "自动完成业务流，并在 DE 环境里可见。" },
  { value: "fingerprint", label: "指纹", description: "只完成登录并保留浏览器，便于接管。" },
] as const satisfies Array<{
  value: AccountBusinessFlowMode;
  label: string;
  description: string;
}>;
const ACCOUNT_BUSINESS_FLOW_SITE_OPTIONS = [
  { value: "tavily", label: "Tavily" },
  { value: "grok", label: "Grok" },
  { value: "chatgpt", label: "ChatGPT" },
] as const satisfies Array<{
  value: AccountBusinessFlowSite;
  label: string;
}>;

function extractorProviderLabel(provider: AccountExtractorProvider): string {
  return EXTRACTOR_PROVIDER_OPTIONS.find((item) => item.provider === provider)?.label || provider;
}

function extractorAccountTypeLabel(accountType: AccountExtractorAccountType): string {
  return EXTRACTOR_ACCOUNT_TYPE_OPTIONS.find((item) => item.value === accountType)?.label || accountType;
}

function formatRawAttemptProgress(rawAttemptCount: number, attemptBudget: number): string {
  return attemptBudget > 0 ? `${rawAttemptCount} / ${attemptBudget}` : String(rawAttemptCount);
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
  if (connecting) return "Bootstrap 中…";
  if (isLockedAccountBlock(account)) return "已锁定";
  if (account.disabledAt) return "已禁用";
  if (account.browserSession?.status === "bootstrapping") return "Bootstrap 中";
  if (account.browserSession?.status === "failed" || account.browserSession?.status === "blocked") return "重试 Bootstrap";
  if (account.browserSession?.status === "ready") return "重新 Bootstrap";
  return account.mailboxStatus && account.mailboxStatus !== "preparing" ? "重新 Bootstrap" : "启动 Bootstrap";
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

function formatProxyLatency(latencyMs: number | null | undefined): string {
  return latencyMs == null ? "—" : `${Math.max(0, Math.trunc(latencyMs))} ms`;
}

function clampBusinessFlowMode(mode: AccountBusinessFlowMode, account: Pick<AccountRecord, "businessFlowAvailability"> | null | undefined): AccountBusinessFlowMode {
  if (!account) return mode;
  if (mode === "headed" && !account.businessFlowAvailability.headed) return "headless";
  if (mode === "fingerprint" && !account.businessFlowAvailability.fingerprint) return "headless";
  return mode;
}

function getBusinessFlowModeDisabledReason(mode: AccountBusinessFlowMode, account: Pick<AccountRecord, "businessFlowAvailability">): string | null {
  if (mode === "headed") return account.businessFlowAvailability.headed ? null : account.businessFlowAvailability.headedReason;
  if (mode === "fingerprint") return account.businessFlowAvailability.fingerprint ? null : account.businessFlowAvailability.fingerprintReason;
  return null;
}

function describeBusinessFlowState(account: Pick<AccountRecord, "businessFlowState">): string {
  if (!account.businessFlowState) return "未启动";
  const retainedText = account.businessFlowState.browserRetained ? " · 浏览器保留中" : "";
  if (account.businessFlowState.status === "failed" && account.businessFlowState.lastError) {
    return `${account.businessFlowState.site}/${account.businessFlowState.mode} · ${account.businessFlowState.lastError}`;
  }
  return `${account.businessFlowState.site}/${account.businessFlowState.mode}${retainedText}`;
}

type AccountCopyField = "email" | "password" | "proofMailboxAddress";

function getCopyFeedbackKey(accountId: number, field: AccountCopyField): string {
  return `${accountId}:${field}`;
}

function formatAvailabilitySummary(account: Pick<AccountRecord, "skipReason" | "lastErrorCode" | "disabledReason">): string {
  const parts = [formatAccountBlockReason(account), account.disabledReason || "—"].filter((value) => value && value !== "—");
  return parts.length > 0 ? parts.join(" / ") : "—";
}

function buildAccountStatusBadges(
  account: Pick<AccountRecord, "hasApiKey" | "skipReason" | "disabledAt" | "lastResultStatus" | "browserSession" | "lastErrorCode">,
): Array<{ label: string; variant: "success" | "warning" | "danger" }> {
  const badges: Array<{ label: string; variant: "success" | "warning" | "danger" }> = [];
  const usedByTavily = account.hasApiKey || account.skipReason === "has_api_key";
  const failedRecently = account.lastResultStatus === "failed" || account.browserSession?.status === "failed" || account.browserSession?.status === "blocked";
  const retired = Boolean(account.disabledAt) || isLockedAccountBlock(account);
  if (usedByTavily) {
    badges.push({ label: "Tavily", variant: "success" });
  }
  if (failedRecently) {
    badges.push({ label: usedByTavily ? "已失败" : "Tavily 失败", variant: "warning" });
  }
  if (retired) {
    badges.push({ label: usedByTavily ? "已废弃" : "Tavily 废弃", variant: "danger" });
  }

  return badges;
}

function resolveConnectButtonDisabled(account: AccountRecord, input: {
  graphSettingsConfigured: boolean;
  batchBusy: boolean;
  connectBusy: boolean;
  connectingAccountIds: number[];
}): boolean {
  return (
    !input.graphSettingsConfigured
    || input.batchBusy
    || input.connectBusy
    || isConnectBlockedAccount(account)
    || input.connectingAccountIds.includes(account.id)
    || account.browserSession?.status === "bootstrapping"
  );
}

function resolveConnectActionIcon(account: Pick<AccountRecord, "disabledAt" | "skipReason" | "lastErrorCode" | "mailboxStatus" | "browserSession">, connecting: boolean) {
  const spinning = connecting || account.browserSession?.status === "bootstrapping";
  return <RefreshCw className={cn("size-4", spinning ? "animate-spin" : "")} aria-hidden="true" />;
}

function FieldLabel(props: { children: ReactNode }) {
  return <div className="text-[0.68rem] uppercase tracking-[0.16em] text-slate-500">{props.children}</div>;
}

function FieldValue(props: { children: ReactNode; className?: string; align?: "left" | "right"; compact?: boolean }) {
  return (
    <div
      className={cn(
        "flex min-w-0 items-center overflow-hidden whitespace-nowrap",
        props.compact ? "mt-0 gap-1" : "mt-1 gap-2",
        props.align === "right" ? "justify-end text-right" : "text-left",
        props.className,
      )}
    >
      {props.children}
    </div>
  );
}

function TwoLineFieldCell(props: {
  primaryLabel: string;
  primaryValue: ReactNode;
  secondaryLabel: string;
  secondaryValue: ReactNode;
  className?: string;
  align?: "left" | "right";
}) {
  return (
    <div className={cn("grid min-w-0 gap-3", props.className)}>
      <div className="min-w-0">
        <FieldLabel>{props.primaryLabel}</FieldLabel>
        <FieldValue align={props.align}>{props.primaryValue}</FieldValue>
      </div>
      <div className="min-w-0">
        <FieldLabel>{props.secondaryLabel}</FieldLabel>
        <FieldValue align={props.align}>{props.secondaryValue}</FieldValue>
      </div>
    </div>
  );
}

function DesktopGroupHeader(props: {
  title: string;
  primaryLabel: ReactNode;
  secondaryLabel: ReactNode;
  align?: "left" | "right";
}) {
  return (
    <div className={cn("grid min-w-0 gap-1", props.align === "right" ? "text-right" : "text-left")}>
      <div className="text-sm font-medium text-slate-100">{props.title}</div>
      <div
        className={cn(
          "flex min-w-0 items-center gap-1.5 overflow-hidden whitespace-nowrap text-[0.68rem] uppercase tracking-[0.16em] text-slate-500",
          props.align === "right" ? "justify-end text-right" : "justify-start text-left",
        )}
      >
        <span className="min-w-0 shrink truncate">{props.primaryLabel}</span>
        <span className="shrink-0 text-slate-600">/</span>
        <span className="min-w-0 shrink truncate">{props.secondaryLabel}</span>
      </div>
    </div>
  );
}

function DesktopTwoLineValueCell(props: {
  primaryValue: ReactNode;
  secondaryValue: ReactNode;
  className?: string;
  align?: "left" | "right";
}) {
  return (
    <div className={cn("grid min-w-0 gap-0.5", props.className)}>
      <div className="min-w-0">
        <FieldValue align={props.align} compact>{props.primaryValue}</FieldValue>
      </div>
      <div className="min-w-0">
        <FieldValue align={props.align} compact>{props.secondaryValue}</FieldValue>
      </div>
    </div>
  );
}

function IconActionButton(props: {
  label: string;
  icon: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "default" | "secondary" | "outline" | "danger" | "ghost";
  className?: string;
  size?: "default" | "compact" | "dense";
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex">
          <Button
            type="button"
            variant={props.variant || "ghost"}
            size="icon"
            className={cn(
              props.size === "dense"
                ? "size-5 shrink-0 rounded-md"
                : props.size === "compact"
                  ? "size-7 shrink-0 rounded-lg"
                  : "size-8 shrink-0 rounded-xl",
              props.className,
            )}
            onClick={props.onClick}
            disabled={props.disabled}
            aria-label={props.label}
          >
            {props.icon}
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{props.label}</TooltipContent>
    </Tooltip>
  );
}

function GroupBadge(props: { groupName: string | null }) {
  if (!props.groupName) return null;
  return (
    <Badge variant="neutral" className="px-2 py-0.5 text-[0.62rem] tracking-[0.1em]">
      {props.groupName}
    </Badge>
  );
}

function describeCopyField(field: AccountCopyField): string {
  if (field === "email") return "邮箱";
  if (field === "password") return "密码";
  return "辅助邮箱";
}

function formatCopySuccessMessage(label: string): string {
  return `${label}已复制到剪贴板。若系统拦截粘贴，可在下方手动复制完整内容。`;
}

function formatCopyPendingMessage(label: string): string {
  return `正在尝试自动复制${label}。如果浏览器没有成功写入剪贴板，你也可以直接复制下方完整内容。`;
}

function formatCopyFailureMessage(error: unknown, label: string): string {
  const rawMessage = error instanceof Error ? error.message.trim() : String(error || "").trim();
  if (rawMessage && rawMessage !== "clipboard unavailable") {
    return `${label}自动复制失败：${rawMessage}`;
  }
  return `${label}自动复制失败。请手动复制下方完整内容。`;
}

function UsageBadgesRow(props: { account: AccountRecord; fallback?: ReactNode }) {
  const usageBadges = buildAccountStatusBadges(props.account);
  if (usageBadges.length === 0) {
    return props.fallback ? <>{props.fallback}</> : <span className="text-slate-500">—</span>;
  }
  return (
    <>
      {usageBadges.map((badge) => (
        <Badge key={`${props.account.id}-${badge.label}`} variant={badge.variant} className="px-2 py-0.5 text-[0.62rem] tracking-[0.12em]">
          {badge.label}
        </Badge>
      ))}
    </>
  );
}

function SessionProxyCell(props: {
  account: Pick<AccountRecord, "id" | "microsoftEmail" | "browserSession" | "disabledAt" | "skipReason" | "lastErrorCode">;
  disabled: boolean;
  onEdit: () => void;
  align?: "left" | "right";
}) {
  return (
    <div className={cn("flex max-w-full items-center gap-2", props.align === "right" ? "justify-end" : "justify-start")}>
      <span className={cn("min-w-0 truncate whitespace-nowrap text-slate-100", props.align === "right" ? "text-right" : "text-left")}>
        {formatBrowserSessionProxy(props.account)}
      </span>
      <IconActionButton
        label={`更换 ${props.account.microsoftEmail} 的 Session Proxy`}
        icon={<PencilLine className="size-3.5" aria-hidden="true" />}
        onClick={props.onEdit}
        disabled={props.disabled}
        size="dense"
        className="text-cyan-200 hover:text-cyan-100"
      />
    </div>
  );
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
  const defaultActive = props.column === DEFAULT_ACCOUNT_QUERY_SORT.sortBy && isDefaultAccountQuerySort(props.query);
  const ariaSort = state === "asc" ? "ascending" : state === "desc" ? "descending" : "none";
  const nextQuery: AccountQuery =
    state === "inactive"
      ? { ...props.query, sortBy: props.column, sortDir: "desc" as const, page: 1 }
      : state === "desc"
        ? { ...props.query, sortBy: props.column, sortDir: "asc" as const, page: 1 }
        : { ...props.query, sortBy: DEFAULT_ACCOUNT_QUERY_SORT.sortBy, sortDir: DEFAULT_ACCOUNT_QUERY_SORT.sortDir, page: 1 };

  return (
    <TableHead aria-sort={ariaSort}>
      <button
        type="button"
        className={cn(
          "inline-flex items-center gap-2 rounded-xl px-1 py-1 text-left transition-colors",
          state === "inactive" ? "text-slate-400 hover:text-slate-100" : "text-cyan-200 hover:text-cyan-100",
        )}
        onClick={() => props.onQueryChange(nextQuery)}
        aria-label={`${props.label}排序：${
          state === "asc"
            ? "当前升序，再点恢复默认"
            : state === "desc"
              ? defaultActive
                ? "当前默认降序，再点升序"
                : "当前降序，再点升序"
              : "当前未排序，点击按降序排序"
        }`}
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
  if (status === "pending_bootstrap") return <Badge variant="info">pending_bootstrap</Badge>;
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
  batchBootstrapPreview,
  batchBootstrapPreviewBusy,
  activeBatchBootstrapMode,
  initialDesktopToolsCollapsed,
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
  proxyNodes,
  proxyCheckState,
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
  onCheckProxyNode,
  onSwitchSessionProxy,
  onSaveProofMailbox,
  onSaveAvailability,
  onSaveExtractorSettings,
  onExtractorRunDraftChange,
  onRunExtractor,
  onStopExtractor,
  onExtractorHistoryQueryChange,
  onRefreshExtractorHistory,
  onOpenMailbox,
  onStartBusinessFlow,
  onOpenMailboxSettings,
  onOpenStandaloneMailboxWorkspace,
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
  batchBootstrapPreview: AccountBatchBootstrapPreviewPayload | null;
  batchBootstrapPreviewBusy: boolean;
  activeBatchBootstrapMode: AccountBatchBootstrapMode | null;
  initialDesktopToolsCollapsed?: boolean;
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
  proxyNodes: ProxyNode[];
  proxyCheckState: ProxyCheckState | null;
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
  onConnectSelectedAccounts: (mode?: AccountBatchBootstrapMode) => Promise<void>;
  onCheckProxyNode: (nodeName: string) => Promise<void>;
  onSwitchSessionProxy: (accountId: number, proxyNode: string) => Promise<void>;
  onSaveProofMailbox: (accountId: number, proofMailboxAddress: string | null, proofMailboxId?: string | null) => Promise<void>;
  onSaveAvailability: (accountId: number, disabled: boolean, disabledReason: string | null) => Promise<void>;
  onSaveExtractorSettings: (patch: Partial<AccountExtractorSettings>) => Promise<void>;
  onExtractorRunDraftChange: (patch: Partial<AccountExtractorRunDraft>) => void;
  onRunExtractor: () => Promise<void>;
  onStopExtractor: () => Promise<void>;
  onExtractorHistoryQueryChange: (value: AccountExtractorHistoryQuery) => void;
  onRefreshExtractorHistory: () => Promise<void>;
  onOpenMailbox: (accountId: number) => void;
  onStartBusinessFlow: (accountId: number, site: AccountBusinessFlowSite, mode: AccountBusinessFlowMode) => Promise<void>;
  onOpenMailboxSettings: () => void;
  onOpenStandaloneMailboxWorkspace: () => void;
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
  const [sessionProxyDialogOpen, setSessionProxyDialogOpen] = useState(false);
  const [sessionProxyAccountId, setSessionProxyAccountId] = useState<number | null>(null);
  const [sessionProxyActionError, setSessionProxyActionError] = useState<string | null>(null);
  const [checkingProxyNodeName, setCheckingProxyNodeName] = useState<string | null>(null);
  const [selectingProxyNodeName, setSelectingProxyNodeName] = useState<string | null>(null);
  const [extractorDialogOpen, setExtractorDialogOpen] = useState(false);
  const [extractorKeyDrafts, setExtractorKeyDrafts] = useState<Record<AccountExtractorProvider, string>>({
    zhanghaoya: "",
    shanyouxiang: "",
    shankeyun: "",
    hotmail666: "",
  });
  const [extractorDefaultAccountTypeDraft, setExtractorDefaultAccountTypeDraft] = useState<AccountExtractorAccountType>("outlook");
  const [extractorSaveError, setExtractorSaveError] = useState<string | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<{
    key: string | null;
    status: "idle" | "copied" | "failed";
  }>({ key: null, status: "idle" });
  const [copyPopoverState, setCopyPopoverState] = useState<{
    key: string;
    title: string;
    message: string;
    value: string;
    anchorRect: {
      left: number;
      top: number;
      width: number;
      height: number;
    };
  } | null>(null);
  const copyFeedbackResetTimerRef = useRef<number | null>(null);
  const copyPopoverOpenTimerRef = useRef<number | null>(null);
  const [extractorQuantityInput, setExtractorQuantityInput] = useState(() => String(extractorRunDraft.quantity));
  const [extractorMaxWaitInput, setExtractorMaxWaitInput] = useState(() => String(extractorRunDraft.maxWaitSec));
  const extractorActionTimerRef = useRef<number | null>(null);
  const [extractorActionCooldown, setExtractorActionCooldown] = useState<"start" | "cancel" | null>(null);
  const [extractorActionPending, setExtractorActionPending] = useState<"start" | "cancel" | null>(null);
  const [businessFlowLauncherKey, setBusinessFlowLauncherKey] = useState<string | null>(null);
  const [businessFlowPendingKey, setBusinessFlowPendingKey] = useState<string | null>(null);
  const [businessFlowMode, setBusinessFlowMode] = useState<AccountBusinessFlowMode>(() => {
    if (typeof window === "undefined") return "headless";
    const rawValue = window.localStorage.getItem(ACCOUNT_BUSINESS_FLOW_MODE_STORAGE_KEY);
    return rawValue === "headed" || rawValue === "fingerprint" ? rawValue : "headless";
  });
  const [desktopToolsCollapsed, setDesktopToolsCollapsed] = useState(() => {
    if (typeof initialDesktopToolsCollapsed === "boolean") {
      return initialDesktopToolsCollapsed;
    }
    if (typeof window === "undefined") return false;
    try {
      return window.localStorage.getItem(DESKTOP_TOOLS_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const readyCount = accounts.summary.ready;
  const linkedCount = accounts.summary.linked;
  const failedCount = accounts.summary.failed;
  const disabledCount = accounts.summary.disabled;
  const selectedOnPage = accounts.rows.filter((row) => selectedIds.includes(row.id)).length;
  const selectedBootstrapCount = batchBootstrapPreview?.summary.queueableCount ?? 0;
  const pageCount = Math.max(1, Math.ceil(Math.max(1, accounts.total) / Math.max(1, accounts.pageSize)));
  const extractHistoryPageCount = Math.max(
    1,
    Math.ceil(Math.max(1, extractorHistory.total) / Math.max(1, extractorHistory.pageSize)),
  );
  const extractorSseBadge = extractorSseStateCopy(extractorSseState);
  const extractorSummarySources =
    extractorRuntime.enabledSources.length > 0 ? extractorRuntime.enabledSources : extractorRunDraft.sources;
  const extractorIsRunning = extractorRuntime.status === "running" || extractorRuntime.status === "stopping";
  const extractorSummaryAccountType = extractorRuntime.status === "idle"
    ? extractorRunDraft.accountType
    : extractorRuntime.accountType;
  const extractorCanStart =
    graphSettingsConfigured
    && !extractorIsRunning
    && extractorRunDraft.sources.length > 0
    && extractorRunDraft.quantity > 0
    && extractorRunDraft.maxWaitSec > 0;
  useEffect(() => {
    return () => {
      if (copyFeedbackResetTimerRef.current != null) {
        window.clearTimeout(copyFeedbackResetTimerRef.current);
      }
      if (copyPopoverOpenTimerRef.current != null) {
        window.clearTimeout(copyPopoverOpenTimerRef.current);
      }
      if (extractorActionTimerRef.current != null) {
        window.clearTimeout(extractorActionTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    setExtractorQuantityInput(String(extractorRunDraft.quantity));
  }, [extractorRunDraft.quantity]);

  useEffect(() => {
    setExtractorMaxWaitInput(String(extractorRunDraft.maxWaitSec));
  }, [extractorRunDraft.maxWaitSec]);

  const businessFlowModeGuardAccount = useMemo(
    () => accounts.rows.find((row) => row.businessFlowAvailability) || null,
    [accounts.rows],
  );

  useEffect(() => {
    if (!businessFlowModeGuardAccount) return;
    const nextMode = clampBusinessFlowMode(businessFlowMode, businessFlowModeGuardAccount);
    if (nextMode !== businessFlowMode) {
      setBusinessFlowMode(nextMode);
    }
  }, [businessFlowMode, businessFlowModeGuardAccount]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(ACCOUNT_BUSINESS_FLOW_MODE_STORAGE_KEY, businessFlowMode);
    } catch {
      // ignore storage failures
    }
  }, [businessFlowMode]);

  const queueCopyFeedbackReset = () => {
    if (copyFeedbackResetTimerRef.current != null) {
      window.clearTimeout(copyFeedbackResetTimerRef.current);
    }
    copyFeedbackResetTimerRef.current = window.setTimeout(() => {
      setCopyFeedback({ key: null, status: "idle" });
      copyFeedbackResetTimerRef.current = null;
    }, 1800);
  };

  const queueCopyPopoverState = (nextState: {
    key: string;
    title: string;
    message: string;
    value: string;
    anchorRect: {
      left: number;
      top: number;
      width: number;
      height: number;
    };
  }) => {
    if (copyPopoverOpenTimerRef.current != null) {
      window.clearTimeout(copyPopoverOpenTimerRef.current);
    }
    copyPopoverOpenTimerRef.current = window.setTimeout(() => {
      setCopyPopoverState(nextState);
      copyPopoverOpenTimerRef.current = null;
    }, 0);
  };

  const getPasswordCopyValue = (accountId: number, plaintext?: string | null) => plaintext || revealedPasswordsById[accountId] || "";
  const getCopyStatus = (accountId: number, field: AccountCopyField) =>
    copyFeedback.key === getCopyFeedbackKey(accountId, field) ? copyFeedback.status : "idle";
  const selectCopyContent = (event: ReactMouseEvent<HTMLElement> | React.FocusEvent<HTMLElement>) => {
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(event.currentTarget);
    selection.removeAllRanges();
    selection.addRange(range);
  };
  const handleCopyField = async (account: AccountRecord, field: AccountCopyField, copyValue: string, anchorElement: HTMLElement) => {
    const feedbackKey = getCopyFeedbackKey(account.id, field);
    const label = `${account.microsoftEmail} ${describeCopyField(field)}`;
    const anchorRect = anchorElement.getBoundingClientRect();
    if (!copyValue.trim()) {
      queueCopyPopoverState({
        key: feedbackKey,
        title: "自动复制失败",
        value: copyValue,
        message: `${label}当前没有可复制内容。`,
        anchorRect,
      });
      setCopyFeedback({ key: feedbackKey, status: "failed" });
      return;
    }
    queueCopyPopoverState({
      key: feedbackKey,
      title: "复制中",
      value: copyValue,
      message: formatCopyPendingMessage(label),
      anchorRect,
    });
    try {
      await copyTextToClipboard(copyValue);
      queueCopyPopoverState({
        key: feedbackKey,
        title: "已复制",
        value: copyValue,
        message: formatCopySuccessMessage(label),
        anchorRect,
      });
      setCopyFeedback({ key: feedbackKey, status: "copied" });
      queueCopyFeedbackReset();
    } catch (error) {
      queueCopyPopoverState({
        key: feedbackKey,
        title: "自动复制失败",
        value: copyValue,
        message: formatCopyFailureMessage(error, label),
        anchorRect,
      });
      setCopyFeedback({ key: feedbackKey, status: "failed" });
      return;
    }
  };
  const handleCopyPassword = async (account: AccountRecord, anchorElement: HTMLElement) => handleCopyField(account, "password", getPasswordCopyValue(account.id, account.passwordPlaintext), anchorElement);
  const handleCopyEmail = async (account: AccountRecord, anchorElement: HTMLElement) => handleCopyField(account, "email", account.microsoftEmail || "", anchorElement);
  const handleCopyProofMailbox = async (account: AccountRecord, anchorElement: HTMLElement) => handleCopyField(account, "proofMailboxAddress", account.proofMailboxAddress || "", anchorElement);
  const proofMailboxPreview = editingAccount ? `${editingAccount.proofMailboxProvider || "cfmail"} · ${editingAccount.proofMailboxId || "未缓存"}` : "—";
  const sessionProxyAccount = sessionProxyAccountId == null
    ? null
    : accounts.rows.find((row) => row.id === sessionProxyAccountId) || null;
  const currentSessionProxyNode = sessionProxyAccount?.browserSession?.proxyNode?.trim() || null;

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
      setProofError("请输入合法的辅助邮箱地址。");
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

  const handleStartBusinessFlowClick = async (account: AccountRecord, site: AccountBusinessFlowSite) => {
    const effectiveMode = clampBusinessFlowMode(businessFlowMode, account);
    const pendingKey = `${account.id}:${site}`;
    try {
      setBusinessFlowPendingKey(pendingKey);
      await onStartBusinessFlow(account.id, site, effectiveMode);
      setBusinessFlowLauncherKey(null);
    } finally {
      setBusinessFlowPendingKey((current) => (current === pendingKey ? null : current));
    }
  };

  const openSessionProxyDialog = (account: AccountRecord) => {
    setSessionProxyAccountId(account.id);
    setSessionProxyActionError(null);
    setCheckingProxyNodeName(null);
    setSelectingProxyNodeName(null);
    setSessionProxyDialogOpen(true);
  };

  const closeSessionProxyDialog = (open: boolean) => {
    setSessionProxyDialogOpen(open);
    if (open) return;
    setSessionProxyAccountId(null);
    setSessionProxyActionError(null);
    setCheckingProxyNodeName(null);
    setSelectingProxyNodeName(null);
  };

  const handleCheckProxyNode = async (nodeName: string) => {
    try {
      setCheckingProxyNodeName(nodeName);
      setSessionProxyActionError(null);
      await onCheckProxyNode(nodeName);
    } catch (error) {
      setSessionProxyActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCheckingProxyNodeName((current) => (current === nodeName ? null : current));
    }
  };

  const handleSwitchSessionProxy = async (nodeName: string) => {
    if (!sessionProxyAccount) return;
    try {
      setSelectingProxyNodeName(nodeName);
      setSessionProxyActionError(null);
      await onSwitchSessionProxy(sessionProxyAccount.id, nodeName);
      closeSessionProxyDialog(false);
    } catch (error) {
      setSessionProxyActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setSelectingProxyNodeName((current) => (current === nodeName ? null : current));
    }
  };

  const isSessionProxySwitchBlocked = (
    account: Pick<AccountRecord, "disabledAt" | "skipReason" | "lastErrorCode" | "browserSession">,
  ) => isConnectBlockedAccount(account) || account.browserSession?.status === "bootstrapping";
  const isProxyNodeChecking = (nodeName: string) =>
    checkingProxyNodeName === nodeName
    || (
      proxyCheckState?.status === "running"
      && Array.isArray(proxyCheckState.currentNodeNames)
      && proxyCheckState.currentNodeNames.includes(nodeName)
    );

  const openExtractorDialog = () => {
    setExtractorKeyDrafts({
      zhanghaoya: extractorSettings?.extractorZhanghaoyaKey || "",
      shanyouxiang: extractorSettings?.extractorShanyouxiangKey || "",
      shankeyun: extractorSettings?.extractorShankeyunKey || "",
      hotmail666: extractorSettings?.extractorHotmail666Key || "",
    });
    setExtractorDefaultAccountTypeDraft(extractorSettings?.defaultAutoExtractAccountType || "outlook");
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
        defaultAutoExtractAccountType: extractorDefaultAccountTypeDraft,
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

  const beginExtractorActionCooldown = (action: "start" | "cancel") => {
    if (extractorActionTimerRef.current != null) {
      window.clearTimeout(extractorActionTimerRef.current);
    }
    setExtractorActionCooldown(action);
    extractorActionTimerRef.current = window.setTimeout(() => {
      setExtractorActionCooldown((current) => (current === action ? null : current));
      extractorActionTimerRef.current = null;
    }, 1000);
  };

  const handleRunExtractorClick = async () => {
    beginExtractorActionCooldown("start");
    setExtractorActionPending("start");
    try {
      await onRunExtractor();
    } finally {
      setExtractorActionPending((current) => (current === "start" ? null : current));
    }
  };

  const handleStopExtractorClick = async () => {
    beginExtractorActionCooldown("cancel");
    setExtractorActionPending("cancel");
    try {
      await onStopExtractor();
    } finally {
      setExtractorActionPending((current) => (current === "cancel" ? null : current));
    }
  };

  const showExtractorCancelButton = extractorIsRunning && extractorActionCooldown !== "start";
  const extractorPrimaryBusy = extractorRunBusy || extractorActionPending != null;
  const extractorPrimaryDisabled = showExtractorCancelButton
    ? extractorPrimaryBusy || extractorActionCooldown === "cancel"
    : !extractorCanStart || extractorPrimaryBusy || extractorActionCooldown === "start";
  const extractorPrimaryLabel = showExtractorCancelButton
    ? extractorActionPending === "cancel" || extractorRuntime.status === "stopping"
      ? "取消中…"
      : "取消提号"
    : extractorActionPending === "start" || extractorActionCooldown === "start" || extractorRunBusy
      ? "提号中…"
      : "开始提号 + 自动 Bootstrap";

  const renderAccountActions = (row: AccountRecord, surface: "mobile" | "desktop") => {
    const connectDisabled = resolveConnectButtonDisabled(row, {
      graphSettingsConfigured,
      batchBusy,
      connectBusy,
      connectingAccountIds,
    });
    const connectLabel = `对 ${row.microsoftEmail} ${getConnectActionLabel(row, connectingAccountIds.includes(row.id))}`;
    const launcherKey = `${surface}:${row.id}`;
    const effectiveBusinessFlowMode = clampBusinessFlowMode(businessFlowMode, row);
    const businessFlowRunning = row.businessFlowState?.status === "starting" || row.businessFlowState?.status === "running";
    const activeBusinessFlowKey = row.businessFlowState ? `${row.id}:${row.businessFlowState.site}` : null;
    const pendingForThisRow = businessFlowPendingKey?.startsWith(`${row.id}:`) ?? false;
    const businessFlowActionDisabled = batchBusy || connectBusy || pendingForThisRow || businessFlowRunning;
    const selectedModeReason =
      effectiveBusinessFlowMode !== businessFlowMode
        ? getBusinessFlowModeDisabledReason(businessFlowMode, row)
        : getBusinessFlowModeDisabledReason(effectiveBusinessFlowMode, row);
    const headlessOnlyReason =
      !row.businessFlowAvailability.deAvailable
        ? row.businessFlowAvailability.fingerprintReason || row.businessFlowAvailability.headedReason
        : null;

    return (
      <div className="flex flex-wrap items-center justify-end gap-1">
        <IconActionButton
          label={connectLabel}
          icon={resolveConnectActionIcon(row, connectingAccountIds.includes(row.id))}
          onClick={() => void onConnectAccount(row.id)}
          disabled={connectDisabled}
          variant={row.mailboxStatus && row.mailboxStatus !== "preparing" ? "secondary" : "outline"}
          size="compact"
          className="size-7 rounded-lg"
        />
        <IconActionButton
          label={`设置 ${row.microsoftEmail} 的辅助邮箱`}
          icon={<Mail className="size-4" aria-hidden="true" />}
          onClick={() => openProofDialog(row)}
          variant="outline"
          size="compact"
          className="size-7 rounded-lg"
        />
        {row.disabledAt || isRestorableAccountBlock(row.skipReason) ? (
          <IconActionButton
            label={`恢复 ${row.microsoftEmail} 可用`}
            icon={<RotateCcw className="size-4" aria-hidden="true" />}
          onClick={() => void handleRestoreAvailability(row)}
          variant="secondary"
          size="compact"
          className="size-7 rounded-lg"
        />
        ) : (
          <IconActionButton
            label={`标记 ${row.microsoftEmail} 不可用`}
            icon={<ShieldOff className="size-4" aria-hidden="true" />}
            onClick={() => openAvailabilityDialog(row)}
            variant="outline"
            size="compact"
            className="size-7 rounded-lg"
          />
        )}
        <IconActionButton
          label={`打开 ${row.microsoftEmail} 的收件箱`}
          icon={<Inbox className="size-4" aria-hidden="true" />}
          onClick={() => onOpenMailbox(row.id)}
          variant="secondary"
          size="compact"
          className="size-7 rounded-lg"
        />
        <Popover
          open={businessFlowLauncherKey === launcherKey}
          onOpenChange={(open) => setBusinessFlowLauncherKey((current) => (open ? launcherKey : current === launcherKey ? null : current))}
        >
          <PopoverAnchor className="inline-flex">
            <button
              type="button"
              className={cn(buttonVariants({ variant: "outline", size: "icon" }), "size-7 shrink-0 rounded-lg")}
              aria-label={`打开 ${row.microsoftEmail} 的业务流工具`}
              aria-haspopup="dialog"
              aria-expanded={businessFlowLauncherKey === launcherKey}
              onClick={() => setBusinessFlowLauncherKey((current) => (current === launcherKey ? null : launcherKey))}
            >
              <SlidersHorizontal className="size-4" aria-hidden="true" />
            </button>
          </PopoverAnchor>
          <PopoverContent align="end" className="w-[22rem] p-0">
            <div className="space-y-4 p-4">
              <div className="space-y-1">
                <div className="text-sm font-semibold text-white">单账号业务流</div>
                <div className="truncate text-xs text-slate-400">{row.microsoftEmail}</div>
              </div>

              <div className="space-y-2">
                <div className="text-[0.68rem] uppercase tracking-[0.18em] text-slate-500">模式</div>
                <div className="grid grid-cols-3 gap-2">
                  {ACCOUNT_BUSINESS_FLOW_MODE_OPTIONS.map((option) => {
                    const disabledReason = getBusinessFlowModeDisabledReason(option.value, row);
                    const selected = effectiveBusinessFlowMode === option.value;
                    return (
                      <Button
                        key={option.value}
                        type="button"
                        size="sm"
                        variant={selected ? "default" : "outline"}
                        disabled={Boolean(disabledReason)}
                        onClick={() => setBusinessFlowMode(option.value)}
                        className="h-auto min-h-10 rounded-xl px-3 py-2 text-xs"
                      >
                        {option.label}
                      </Button>
                    );
                  })}
                </div>
                <div className="rounded-2xl border border-white/8 bg-white/[0.03] px-3 py-2 text-xs leading-5 text-slate-300">
                  {ACCOUNT_BUSINESS_FLOW_MODE_OPTIONS.find((option) => option.value === effectiveBusinessFlowMode)?.description}
                  {selectedModeReason || headlessOnlyReason ? (
                    <div className="mt-1 text-amber-200">{selectedModeReason || headlessOnlyReason}</div>
                  ) : null}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-[0.68rem] uppercase tracking-[0.18em] text-slate-500">业务流</div>
                <div className="grid grid-cols-3 gap-2">
                  {ACCOUNT_BUSINESS_FLOW_SITE_OPTIONS.map((option) => {
                    const pending = businessFlowPendingKey === `${row.id}:${option.value}`;
                    const currentState = row.businessFlowState?.site === option.value ? row.businessFlowState : null;
                    return (
                      <Button
                        key={option.value}
                        type="button"
                        size="sm"
                        variant={currentState ? "secondary" : "outline"}
                        disabled={businessFlowActionDisabled}
                        onClick={() => void handleStartBusinessFlowClick(row, option.value)}
                        className="h-auto min-h-10 rounded-xl px-3 py-2 text-xs"
                      >
                        {pending ? "启动中…" : currentState?.status === "running" || currentState?.status === "starting" ? "运行中…" : option.label}
                      </Button>
                    );
                  })}
                </div>
              </div>

              <div className="rounded-2xl border border-white/8 bg-[#0b1423]/80 px-3 py-2 text-xs leading-5 text-slate-300">
                <div className="flex items-center gap-2 text-slate-100">
                  <StatusBadge status={row.businessFlowState?.status || "idle"} />
                  <span className="truncate">{describeBusinessFlowState(row)}</span>
                </div>
                {row.businessFlowState?.browserRetained ? (
                  <div className="mt-1 text-emerald-200">浏览器已保留，可继续接管。</div>
                ) : null}
                {row.businessFlowState?.status === "failed" && row.businessFlowState.lastError ? (
                  <div className="mt-1 text-rose-200">{row.businessFlowState.lastError}</div>
                ) : null}
                {!row.businessFlowState ? (
                  <div className="mt-1 text-slate-400">当前选择 {effectiveBusinessFlowMode}，点击上方站点即可启动。</div>
                ) : null}
                {activeBusinessFlowKey && businessFlowActionDisabled && !businessFlowPendingKey ? (
                  <div className="mt-1 text-slate-400">已有业务流在运行，完成后才能重新启动。</div>
                ) : null}
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </div>
    );
  };

  const renderAccountIdentityCell = (row: AccountRecord) => (
    <TwoLineFieldCell
      primaryLabel="账号"
      secondaryLabel="辅助邮箱 / 分组"
      primaryValue={
        <>
          <span className="min-w-0 truncate whitespace-nowrap font-medium text-white">{row.microsoftEmail}</span>
          <CopyIconButton
            label={`${row.microsoftEmail} 邮箱`}
            copyStatus={getCopyStatus(row.id, "email")}
            onCopy={(anchorElement) => void handleCopyEmail(row, anchorElement)}
            size="dense"
            feedbackEnabled={false}
          />
          <CopyIconButton
            label={`${row.microsoftEmail} 密码`}
            copyStatus={getCopyStatus(row.id, "password")}
            disabled={!getPasswordCopyValue(row.id, row.passwordPlaintext).trim()}
            onCopy={(anchorElement) => void handleCopyPassword(row, anchorElement)}
            size="dense"
            feedbackEnabled={false}
            idleIcon={<KeyRound className="size-4" aria-hidden="true" />}
          />
        </>
      }
      secondaryValue={
        <>
          <span className="min-w-0 truncate whitespace-nowrap text-slate-300">{row.proofMailboxAddress || "—"}</span>
          <CopyIconButton
            label={`${row.microsoftEmail} 辅助邮箱`}
            copyStatus={getCopyStatus(row.id, "proofMailboxAddress")}
            disabled={!row.proofMailboxAddress}
            onCopy={(anchorElement) => void handleCopyProofMailbox(row, anchorElement)}
            size="dense"
            feedbackEnabled={false}
          />
          <GroupBadge groupName={row.groupName} />
        </>
      }
      className="min-w-0"
    />
  );

  useEffect(() => {
    if (typeof initialDesktopToolsCollapsed === "boolean" || typeof window === "undefined") return;
    try {
      window.localStorage.setItem(DESKTOP_TOOLS_STORAGE_KEY, desktopToolsCollapsed ? "1" : "0");
    } catch {
      // ignore storage failures
    }
  }, [desktopToolsCollapsed, initialDesktopToolsCollapsed]);

  const renderSessionCell = (row: AccountRecord, align?: "left" | "right") => (
    <TwoLineFieldCell
      primaryLabel="Session"
      secondaryLabel="Session Proxy"
      primaryValue={<StatusBadge status={row.browserSession?.status || "pending"} />}
      secondaryValue={
        <SessionProxyCell
          account={row}
          align={align}
          disabled={isSessionProxySwitchBlocked(row) || batchBusy || connectBusy}
          onEdit={() => openSessionProxyDialog(row)}
        />
      }
      className="min-w-0"
      align={align}
    />
  );

  const renderStatusCell = (row: AccountRecord, align?: "left" | "right") => (
    <TwoLineFieldCell
      primaryLabel="状态"
      secondaryLabel="阻断 / 停用"
      primaryValue={<StatusBadge status={getAccountDisplayStatus(row)} />}
      secondaryValue={<UsageBadgesRow account={row} fallback={<span className="min-w-0 truncate whitespace-nowrap text-slate-300">{formatAvailabilitySummary(row)}</span>} />}
      className="min-w-0"
      align={align}
    />
  );

  const renderMailboxCell = (row: AccountRecord, align?: "left" | "right") => (
    <TwoLineFieldCell
      primaryLabel="收信"
      secondaryLabel="Profile"
      primaryValue={
        <>
          <StatusBadge status={row.mailboxStatus} />
          {row.mailboxUnreadCount > 0 ? <Badge variant="info">{row.mailboxUnreadCount}</Badge> : null}
        </>
      }
      secondaryValue={<span className="min-w-0 truncate whitespace-nowrap font-mono text-xs text-slate-300">{formatBrowserSessionPath(row)}</span>}
      className="min-w-0"
      align={align}
    />
  );

  const renderTimeCell = (row: AccountRecord, align?: "left" | "right") => (
    <TwoLineFieldCell
      primaryLabel="导入时间"
      secondaryLabel="最近使用"
      primaryValue={<span className="min-w-0 truncate whitespace-nowrap text-slate-300">{formatDate(row.importedAt)}</span>}
      secondaryValue={<span className="min-w-0 truncate whitespace-nowrap text-slate-300">{formatDate(row.lastUsedAt)}</span>}
      className="min-w-0"
      align={align}
    />
  );

  const renderDesktopAccountIdentityCell = (row: AccountRecord) => (
    <DesktopTwoLineValueCell
      primaryValue={
        <>
          <span className="min-w-0 truncate whitespace-nowrap font-medium text-white">{row.microsoftEmail}</span>
          <CopyIconButton
            label={`${row.microsoftEmail} 邮箱`}
            copyStatus={getCopyStatus(row.id, "email")}
            onCopy={(anchorElement) => void handleCopyEmail(row, anchorElement)}
            size="dense"
            feedbackEnabled={false}
          />
          <CopyIconButton
            label={`${row.microsoftEmail} 密码`}
            copyStatus={getCopyStatus(row.id, "password")}
            disabled={!getPasswordCopyValue(row.id, row.passwordPlaintext).trim()}
            onCopy={(anchorElement) => void handleCopyPassword(row, anchorElement)}
            size="dense"
            feedbackEnabled={false}
            idleIcon={<KeyRound className="size-4" aria-hidden="true" />}
          />
        </>
      }
      secondaryValue={
        <>
          <span className="min-w-0 truncate whitespace-nowrap text-slate-300">{row.proofMailboxAddress || "—"}</span>
          <CopyIconButton
            label={`${row.microsoftEmail} 辅助邮箱`}
            copyStatus={getCopyStatus(row.id, "proofMailboxAddress")}
            disabled={!row.proofMailboxAddress}
            onCopy={(anchorElement) => void handleCopyProofMailbox(row, anchorElement)}
            size="dense"
            feedbackEnabled={false}
          />
          <GroupBadge groupName={row.groupName} />
        </>
      }
    />
  );

  const renderDesktopSessionCell = (row: AccountRecord) => (
    <DesktopTwoLineValueCell
      primaryValue={<StatusBadge status={row.browserSession?.status || "pending"} />}
      secondaryValue={
        <SessionProxyCell
          account={row}
          disabled={isSessionProxySwitchBlocked(row) || batchBusy || connectBusy}
          onEdit={() => openSessionProxyDialog(row)}
        />
      }
    />
  );

  const renderDesktopStatusCell = (row: AccountRecord) => (
    <DesktopTwoLineValueCell
      primaryValue={<StatusBadge status={getAccountDisplayStatus(row)} />}
      secondaryValue={<UsageBadgesRow account={row} fallback={<span className="min-w-0 truncate whitespace-nowrap text-slate-300">{formatAvailabilitySummary(row)}</span>} />}
    />
  );

  const renderDesktopMailboxCell = (row: AccountRecord) => (
    <DesktopTwoLineValueCell
      primaryValue={
        <>
          <StatusBadge status={row.mailboxStatus} />
          {row.mailboxUnreadCount > 0 ? <Badge variant="info">{row.mailboxUnreadCount}</Badge> : null}
        </>
      }
      secondaryValue={<span className="min-w-0 truncate whitespace-nowrap font-mono text-xs text-slate-300">{formatBrowserSessionPath(row)}</span>}
    />
  );

  const renderDesktopTimeCell = (row: AccountRecord) => (
    <DesktopTwoLineValueCell
      primaryValue={<span className="min-w-0 truncate whitespace-nowrap text-slate-300">{formatDate(row.importedAt)}</span>}
      secondaryValue={<span className="min-w-0 truncate whitespace-nowrap text-slate-300">{formatDate(row.lastUsedAt)}</span>}
    />
  );

  return (
    <TooltipProvider>
      <>
      <section
        className={cn(
          "grid gap-4",
          desktopToolsCollapsed
            ? "xl:grid-cols-[minmax(0,1fr)]"
            : "xl:grid-cols-[minmax(22rem,0.52fr)_minmax(0,1.48fr)]",
        )}
      >
        <div className={cn("space-y-4", desktopToolsCollapsed && "xl:hidden")}>
          <Card className="min-h-[18rem] border-dashed border-cyan-300/20 bg-cyan-300/[0.03]">
            <CardHeader>
              <CardTitle>提号器</CardTitle>
              <CardDescription>
                这里会直接提号、自动登录 Microsoft、保存持久 Profile，并自动完成邮箱 Bootstrap。提号状态和账号列表通过 SSE 实时刷新。
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
                        disabled={!available || extractorIsRunning}
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

              <div className="grid gap-3 sm:grid-cols-3">
                <label className="flex flex-col gap-2">
                  <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">提号数量</span>
                  <Input
                    type="number"
                    min={1}
                    step={1}
                    value={extractorQuantityInput}
                    disabled={extractorIsRunning}
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
                    disabled={extractorIsRunning}
                    onChange={(event) => setExtractorMaxWaitInput(event.target.value)}
                    onBlur={commitExtractorMaxWaitInput}
                  />
                </label>
                <label className="flex flex-col gap-2">
                  <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">邮箱类型</span>
                  <Select
                    value={extractorRunDraft.accountType}
                    onValueChange={(value) => onExtractorRunDraftChange({ accountType: value as AccountExtractorAccountType })}
                    disabled={extractorIsRunning}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="选择邮箱类型" />
                    </SelectTrigger>
                    <SelectContent>
                      {EXTRACTOR_ACCOUNT_TYPE_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </label>
              </div>
              {extractorRunDraft.accountType === "unlimited" ? (
                <div className="rounded-2xl border border-cyan-300/16 bg-cyan-300/[0.05] px-4 py-3 text-sm text-cyan-100">
                  选择“不限”后会优先直传上游支持的不限值；当前未确认支持的号源会按各自请求序号在 Outlook / Hotmail 之间交替。
                </div>
              ) : null}

              <div className="rounded-2xl border border-white/8 bg-[#08111d]/80 p-4 text-sm text-slate-300">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-white">当前号源：</span>
                  <span>{formatExtractorSourceSummary(extractorSummarySources)}</span>
                </div>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  <div>目标接受：{extractorRuntime.acceptedCount} / {extractorRuntime.requestedUsableCount || extractorRunDraft.quantity}</div>
                  <div>原始请求：{formatRawAttemptProgress(extractorRuntime.rawAttemptCount, extractorRuntime.attemptBudget)}</div>
                  <div>在途请求：{extractorRuntime.inFlightCount}</div>
                  <div>剩余等待：{extractorRuntime.remainingWaitSec}s / {extractorRuntime.maxWaitSec || extractorRunDraft.maxWaitSec}s</div>
                  <div>邮箱类型：{extractorAccountTypeLabel(extractorSummaryAccountType)}</div>
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
                    void (showExtractorCancelButton ? handleStopExtractorClick() : handleRunExtractorClick());
                  }}
                  disabled={extractorPrimaryDisabled}
                  variant={showExtractorCancelButton ? "danger" : "default"}
                  className="sm:flex-1"
                >
                  {extractorPrimaryLabel}
                </Button>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="inline-flex">
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={openExtractorDialog}
                        className="shrink-0 rounded-2xl"
                        data-testid="open-extractor-settings"
                        aria-label="打开提号器 KEY 与历史"
                      >
                        <SlidersHorizontal className="size-4" />
                        <span className="sr-only">KEY / 历史</span>
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent>打开提号器 KEY 与历史</TooltipContent>
                </Tooltip>
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
                placeholder={"example@example.test,password123\nexample@example.test----password123\npassword123 example@example.test"}
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
          <CardHeader className="gap-3">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <CardTitle>账号池</CardTitle>
                <CardDescription>
                  总数 {accounts.total} 条，已选 {selectedIds.length} 条。支持跨分页勾选、批量分组、批量 Bootstrap 和批量删除。
                </CardDescription>
              </div>
              <div className="flex flex-wrap gap-2 xl:justify-end">
                <Button type="button" variant="outline" className="xl:self-start" onClick={onOpenStandaloneMailboxWorkspace}>
                  <Inbox className="mr-1 size-4" aria-hidden="true" />
                  微软邮箱
                </Button>
                <Button type="button" variant="outline" className="xl:self-start" onClick={onOpenMailboxSettings}>
                  <Settings2 className="mr-1 size-4" aria-hidden="true" />
                  Graph 设置
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="hidden xl:inline-flex xl:self-start"
                  onClick={() => setDesktopToolsCollapsed((current) => !current)}
                >
                  {desktopToolsCollapsed ? (
                    <ChevronRight className="mr-1 size-4" aria-hidden="true" />
                  ) : (
                    <ChevronLeft className="mr-1 size-4" aria-hidden="true" />
                  )}
                  {desktopToolsCollapsed ? "展开工具列" : "收起工具列"}
                </Button>
              </div>
            </div>
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
                <span>{batchBootstrapPreviewBusy ? "可 Bootstrap 计算中…" : `可 Bootstrap ${selectedBootstrapCount} 条`}</span>
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
                  <Button
                    variant="outline"
                    onClick={() => void onConnectSelectedAccounts("pending_only")}
                    disabled={selectedBootstrapCount === 0 || connectBusy || batchBootstrapPreviewBusy || !graphSettingsConfigured}
                  >
                    {connectBusy && activeBatchBootstrapMode === "pending_only"
                      ? `Bootstrap 中 ${connectProgress?.current || 0}/${connectProgress?.total || selectedBootstrapCount}`
                      : graphSettingsConfigured
                        ? "批量 Bootstrap"
                        : "先配置 Graph"}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => void onConnectSelectedAccounts("force")}
                    disabled={selectedIds.length === 0 || connectBusy || batchBootstrapPreviewBusy || !graphSettingsConfigured}
                  >
                    {connectBusy && activeBatchBootstrapMode === "force"
                      ? `强制 Bootstrap 中 ${connectProgress?.current || 0}/${connectProgress?.total || selectedIds.length}`
                      : graphSettingsConfigured
                        ? "强制 Bootstrap"
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

            <div className="grid gap-3 xl:grid-cols-6">
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
              <FilterField label="Session">
                <Select
                  value={query.sessionStatus || "__all__"}
                  onValueChange={(value) => onQueryChange({ ...query, sessionStatus: value === "__all__" ? "" : value as AccountQuery["sessionStatus"], page: 1 })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="全部" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">全部</SelectItem>
                    {SESSION_STATUS_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FilterField>
              <FilterField label="收信状态">
                <Select
                  value={query.mailboxStatus || "__all__"}
                  onValueChange={(value) => onQueryChange({ ...query, mailboxStatus: value === "__all__" ? "" : value as AccountQuery["mailboxStatus"], page: 1 })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="全部" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">全部</SelectItem>
                    {MAILBOX_STATUS_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                    ))}
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
                            <div className="min-w-0 flex-1">{renderAccountIdentityCell(row)}</div>
                            <div className="shrink-0">{renderAccountActions(row, "mobile")}</div>
                          </div>
                          <div className="mt-4 grid gap-4 sm:grid-cols-2">
                            <div className="min-w-0">{renderSessionCell(row, "right")}</div>
                            <div className="min-w-0">{renderMailboxCell(row, "right")}</div>
                            <div className="min-w-0">{renderStatusCell(row, "right")}</div>
                            <div className="min-w-0 sm:col-span-2">{renderTimeCell(row, "right")}</div>
                          </div>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>

                <div className="hidden md:block">
                  <Table className="min-w-[1210px]">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-14 align-top">
                          <Checkbox
                            checked={allCurrentPageSelected ? true : selectedOnPage > 0 ? "indeterminate" : false}
                            onCheckedChange={(checked) => onTogglePageSelection(checked === true)}
                            aria-label="select-current-page"
                          />
                        </TableHead>
                        <TableHead className="min-w-[23rem] align-top">
                          <DesktopGroupHeader title="账号" primaryLabel="邮箱" secondaryLabel="辅助邮箱 / 分组" />
                        </TableHead>
                        <TableHead className="min-w-[13rem] align-top">
                          <DesktopGroupHeader title="会话" primaryLabel="Session" secondaryLabel="Session Proxy" />
                        </TableHead>
                        <TableHead className="min-w-[11rem] align-top">
                          <DesktopGroupHeader title="收信" primaryLabel="收信状态" secondaryLabel="Profile" />
                        </TableHead>
                        <TableHead className="min-w-[15rem] align-top">
                          <DesktopGroupHeader title="状态" primaryLabel="最近状态" secondaryLabel="阻断 / 停用" />
                        </TableHead>
                        <TableHead className="min-w-[10.5rem] align-top">
                          <DesktopGroupHeader
                            title="时间"
                            primaryLabel={
                              <button
                                type="button"
                                className={cn(
                                  "inline-flex items-center gap-2 rounded-xl px-1 py-0.5 text-left transition-colors",
                                  resolveAccountSortState(query, "importedAt") === "inactive" ? "text-slate-400 hover:text-slate-100" : "text-cyan-200 hover:text-cyan-100",
                                )}
                                onClick={() => {
                                  const state = resolveAccountSortState(query, "importedAt");
                                  onQueryChange(
                                    state === "inactive"
                                      ? { ...query, sortBy: "importedAt", sortDir: "desc", page: 1 }
                                      : state === "desc"
                                        ? { ...query, sortBy: "importedAt", sortDir: "asc", page: 1 }
                                        : { ...query, sortBy: DEFAULT_ACCOUNT_QUERY_SORT.sortBy, sortDir: DEFAULT_ACCOUNT_QUERY_SORT.sortDir, page: 1 },
                                  );
                                }}
                                aria-label={`导入时间排序：${
                                  resolveAccountSortState(query, "importedAt") === "asc"
                                    ? "当前升序，再点恢复默认"
                                    : resolveAccountSortState(query, "importedAt") === "desc"
                                      ? isDefaultAccountQuerySort(query)
                                        ? "当前默认降序，再点升序"
                                        : "当前降序，再点升序"
                                      : "当前未排序，点击按降序排序"
                                }`}
                              >
                                <span>导入时间</span>
                                {resolveAccountSortState(query, "importedAt") === "desc" ? (
                                  <ArrowDown className="size-3.5" aria-hidden="true" />
                                ) : resolveAccountSortState(query, "importedAt") === "asc" ? (
                                  <ArrowUp className="size-3.5" aria-hidden="true" />
                                ) : (
                                  <ArrowUpDown className="size-3.5" aria-hidden="true" />
                                )}
                              </button>
                            }
                            secondaryLabel={
                              <button
                                type="button"
                                className={cn(
                                  "inline-flex items-center gap-2 rounded-xl px-1 py-0.5 text-left transition-colors",
                                  resolveAccountSortState(query, "lastUsedAt") === "inactive" ? "text-slate-400 hover:text-slate-100" : "text-cyan-200 hover:text-cyan-100",
                                )}
                                onClick={() => {
                                  const state = resolveAccountSortState(query, "lastUsedAt");
                                  onQueryChange(
                                    state === "inactive"
                                      ? { ...query, sortBy: "lastUsedAt", sortDir: "desc", page: 1 }
                                      : state === "desc"
                                        ? { ...query, sortBy: "lastUsedAt", sortDir: "asc", page: 1 }
                                        : { ...query, sortBy: DEFAULT_ACCOUNT_QUERY_SORT.sortBy, sortDir: DEFAULT_ACCOUNT_QUERY_SORT.sortDir, page: 1 },
                                  );
                                }}
                                aria-label={`最近使用排序：${
                                  resolveAccountSortState(query, "lastUsedAt") === "asc"
                                    ? "当前升序，再点恢复默认"
                                    : resolveAccountSortState(query, "lastUsedAt") === "desc"
                                      ? "当前降序，再点升序"
                                      : "当前未排序，点击按降序排序"
                                }`}
                              >
                                <span>最近使用</span>
                                {resolveAccountSortState(query, "lastUsedAt") === "desc" ? (
                                  <ArrowDown className="size-3.5" aria-hidden="true" />
                                ) : resolveAccountSortState(query, "lastUsedAt") === "asc" ? (
                                  <ArrowUp className="size-3.5" aria-hidden="true" />
                                ) : (
                                  <ArrowUpDown className="size-3.5" aria-hidden="true" />
                                )}
                              </button>
                            }
                          />
                          </TableHead>
                        <TableHead className="min-w-[10.5rem] whitespace-nowrap text-right align-top">
                          <DesktopGroupHeader title="操作" primaryLabel="Bootstrap / 编辑" secondaryLabel="停用 / 收件箱" align="right" />
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {accounts.rows.map((row) => (
                        <TableRow key={row.id}>
                          <TableCell className="py-2 align-top">
                            <Checkbox
                              checked={selectedIds.includes(row.id)}
                              onCheckedChange={(checked) => onToggleSelection(row.id, checked === true)}
                              aria-label={`select-${row.microsoftEmail}`}
                            />
                          </TableCell>
                          <TableCell className="py-2 align-top">{renderDesktopAccountIdentityCell(row)}</TableCell>
                          <TableCell className="py-2 align-top">{renderDesktopSessionCell(row)}</TableCell>
                          <TableCell className="py-2 align-top">{renderDesktopMailboxCell(row)}</TableCell>
                          <TableCell className="py-2 align-top">{renderDesktopStatusCell(row)}</TableCell>
                          <TableCell className="py-2 align-top">{renderDesktopTimeCell(row)}</TableCell>
                          <TableCell className="py-2 align-top text-right">
                            <div className="ml-auto flex w-max flex-nowrap justify-end">{renderAccountActions(row, "desktop")}</div>
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
                <div className="mt-1 text-sm text-slate-400">保存后会立即用于后续自动提取。历史只展示脱敏 KEY，默认类型会同步到自动补号和手动提号默认值。</div>
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
              <label className="flex flex-col gap-2">
                <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">默认邮箱类型</span>
                <Select
                  value={extractorDefaultAccountTypeDraft}
                  onValueChange={(value) => setExtractorDefaultAccountTypeDraft(value as AccountExtractorAccountType)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择默认邮箱类型" />
                  </SelectTrigger>
                  <SelectContent>
                    {EXTRACTOR_ACCOUNT_TYPE_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </label>
              {extractorDefaultAccountTypeDraft === "unlimited" ? (
                <div className="rounded-2xl border border-cyan-300/16 bg-cyan-300/[0.05] px-4 py-3 text-sm text-cyan-100">
                  作为默认值时，手动提号与自动补号都会继承“不限”；未确认支持不限字段的上游会自动在 Outlook / Hotmail 之间交替请求。
                </div>
              ) : null}
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
                      <SelectItem value="pending_bootstrap">pending_bootstrap</SelectItem>
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
                              #{batch.id} · {extractorProviderLabel(batch.provider)} · {extractorAccountTypeLabel(batch.accountType)}
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

      <Dialog open={sessionProxyDialogOpen} onOpenChange={closeSessionProxyDialog}>
        <DialogContent className="!flex w-[min(96vw,72rem)] max-h-[88vh] max-w-[96vw] !flex-col">
          <DialogHeader className="shrink-0">
            <DialogTitle>更换 Session Proxy</DialogTitle>
            <DialogDescription>
              为当前微软账号指定新的代理节点，并立即重新 Bootstrap 会话。列表展示名称、IP、延迟与可执行操作。
            </DialogDescription>
          </DialogHeader>

          <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto overflow-x-hidden px-6 py-2 xl:grid xl:overflow-hidden xl:grid-cols-[minmax(16rem,17.5rem)_minmax(0,1fr)]">
            <div className="shrink-0 space-y-4 xl:min-h-0 xl:overflow-auto xl:pr-1">
              <div className="rounded-[24px] border border-white/8 bg-white/[0.03] p-4 text-sm text-slate-300">
                <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">当前账号</div>
                <div className="mt-2 break-all text-base font-medium text-white">{sessionProxyAccount?.microsoftEmail || "—"}</div>
              </div>

              <div className="rounded-[24px] border border-white/8 bg-white/[0.03] p-4 text-sm text-slate-300">
                <div className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">当前节点信息</div>
                <dl className="mt-3 space-y-3">
                  <div>
                    <dt className="text-slate-500">当前节点</dt>
                    <dd className="mt-1 font-medium text-white">{currentSessionProxyNode || "未绑定"}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">当前代理</dt>
                    <dd className="mt-1 break-all text-slate-300">{sessionProxyAccount ? formatBrowserSessionProxy(sessionProxyAccount) : "—"}</dd>
                  </div>
                </dl>
              </div>

              <div className="rounded-[24px] border border-cyan-300/14 bg-cyan-300/[0.05] px-4 py-3 text-sm text-cyan-100">
                选择后会立即重新 Bootstrap；如果节点临时异常，会保留失败态供后续重试。
              </div>
            </div>

            {proxyNodes.length === 0 ? (
              <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] px-4 py-8 text-center text-sm text-slate-500">
                当前没有可选代理节点，请先去代理节点页同步库存。
              </div>
            ) : (
              <div className="min-h-0 min-w-0 xl:flex xl:flex-col">
                <div className="mb-3 flex items-center justify-between gap-3 px-1">
                  <div>
                    <div className="text-sm font-medium text-white">候选代理节点</div>
                    <div className="text-xs text-slate-500">桌面端列表保持独立滚动，当前节点信息固定在侧栏。</div>
                  </div>
                  <div className="text-xs text-slate-500">共 {proxyNodes.length} 个节点</div>
                </div>
                <ScrollArea
                  className="h-[min(52vh,36rem)] min-w-0 rounded-3xl border border-white/8 bg-[#0d1728]/70 xl:min-h-0 xl:h-full"
                  data-testid="session-proxy-scroll-area"
                >
                  <div className="w-full rounded-[24px] bg-[rgba(15,23,42,0.62)] shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
                    <table className="w-full min-w-0 table-fixed text-sm">
                      <TableHeader>
                        <TableRow>
                          <TableHead className="sticky top-0 z-10 w-[34%] min-w-[10rem] bg-[#132033]/95 backdrop-blur supports-[backdrop-filter]:bg-[#132033]/80">名称</TableHead>
                          <TableHead className="sticky top-0 z-10 w-[25%] min-w-[8.5rem] bg-[#132033]/95 backdrop-blur supports-[backdrop-filter]:bg-[#132033]/80">IP</TableHead>
                          <TableHead className="sticky top-0 z-10 w-[16%] min-w-[6.5rem] bg-[#132033]/95 backdrop-blur supports-[backdrop-filter]:bg-[#132033]/80">延迟</TableHead>
                          <TableHead className="sticky top-0 z-10 w-[25%] min-w-[9rem] bg-[#132033]/95 text-right backdrop-blur supports-[backdrop-filter]:bg-[#132033]/80">操作</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {proxyNodes.map((node) => {
                          const checking = isProxyNodeChecking(node.nodeName);
                          const selecting = selectingProxyNodeName === node.nodeName;
                          const current = currentSessionProxyNode === node.nodeName;
                          const blocked = !sessionProxyAccount || isSessionProxySwitchBlocked(sessionProxyAccount) || connectBusy || batchBusy;
                          return (
                            <TableRow key={node.id}>
                              <TableCell className="min-w-0">
                                <div className="flex min-w-0 items-center gap-2">
                                  <span className="truncate font-medium text-white">{node.nodeName}</span>
                                  {current ? <Badge variant="info">当前</Badge> : null}
                                </div>
                              </TableCell>
                              <TableCell className="font-mono text-xs text-slate-300">
                                <span className="block truncate">{node.lastEgressIp || "—"}</span>
                              </TableCell>
                              <TableCell className="whitespace-nowrap text-slate-200">
                                {checking ? "测速中…" : formatProxyLatency(node.lastLatencyMs)}
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="ml-auto flex max-w-full items-center justify-end gap-2">
                                  <Button
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    className="h-8 shrink-0 px-2.5 text-xs"
                                    onClick={() => void handleCheckProxyNode(node.nodeName)}
                                    disabled={selectingProxyNodeName != null || blocked || checking}
                                  >
                                    {checking ? "测速中…" : "测速"}
                                  </Button>
                                  <Button
                                    type="button"
                                    variant={current ? "secondary" : "default"}
                                    size="sm"
                                    className="h-8 shrink-0 px-2.5 text-xs"
                                    onClick={() => void handleSwitchSessionProxy(node.nodeName)}
                                    disabled={blocked || checking || selecting || current}
                                  >
                                    {selecting ? "切换中…" : current ? "已选中" : "选择"}
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </table>
                  </div>
                </ScrollArea>
              </div>
            )}

            {sessionProxyActionError ? (
              <div className="rounded-2xl border border-rose-300/18 bg-rose-400/8 px-4 py-3 text-sm text-rose-100">
                {sessionProxyActionError}
              </div>
            ) : null}
          </div>

          <DialogFooter className="shrink-0">
            <Button variant="secondary" onClick={() => closeSessionProxyDialog(false)} disabled={selectingProxyNodeName != null}>
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={proofDialogOpen} onOpenChange={closeProofDialog}>
        <DialogContent className="w-[min(96vw,34rem)]">
          <DialogHeader>
            <DialogTitle>设置辅助邮箱</DialogTitle>
            <DialogDescription>
              把辅助邮箱映射记录到数据库。运行时若微软弹出绑定或验证码页面，会优先通过 CF Mail 自动恢复。
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 px-6 py-2">
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4 text-sm text-slate-300">
              <div className="break-all font-medium text-white">{editingAccount?.microsoftEmail || "—"}</div>
              <div className="mt-2 text-slate-400">{proofMailboxPreview}</div>
            </div>

            <label className="flex flex-col gap-2">
              <span className="text-[0.68rem] uppercase tracking-[0.22em] text-slate-500">辅助邮箱地址</span>
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

      {copyPopoverState ? (
        <Popover
          open
          onOpenChange={(open) => {
            if (!open) {
              setCopyPopoverState(null);
            }
          }}
        >
          <PopoverAnchor asChild>
            <div
              aria-hidden="true"
              className="pointer-events-none fixed z-40 size-px"
              style={{
                left: copyPopoverState.anchorRect.left + (copyPopoverState.anchorRect.width / 2),
                top: copyPopoverState.anchorRect.top + copyPopoverState.anchorRect.height,
              }}
            />
          </PopoverAnchor>
          <PopoverContent
            className="w-[min(92vw,24rem)] rounded-2xl border border-white/12 bg-[linear-gradient(180deg,rgba(12,22,38,0.98),rgba(7,14,27,0.98))] p-3"
            side="bottom"
            align="start"
            sideOffset={10}
            onOpenAutoFocus={(event) => event.preventDefault()}
          >
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 space-y-1">
                  <div className="text-sm font-medium text-white">{copyPopoverState.title}</div>
                  <div className="text-xs leading-5 text-slate-300">{copyPopoverState.message}</div>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7 shrink-0 rounded-lg text-slate-400 hover:text-white"
                  onClick={() => setCopyPopoverState(null)}
                  aria-label="关闭复制反馈"
                >
                  <ChevronRight className="size-4 rotate-45" aria-hidden="true" />
                </Button>
              </div>
              <div className="space-y-2">
                <div className="text-[0.68rem] uppercase tracking-[0.14em] text-slate-500">完整内容（点击全选）</div>
                <div
                  role="textbox"
                  tabIndex={0}
                  aria-label="完整内容（点击全选）"
                  className="rounded-xl border border-white/10 bg-[#0b1423]/90 px-3 py-2 font-mono text-xs text-slate-100 outline-none transition focus-visible:border-cyan-300/50 focus-visible:ring-2 focus-visible:ring-cyan-300/20"
                  onClick={selectCopyContent}
                  onFocus={selectCopyContent}
                >
                  {copyPopoverState.value || "—"}
                </div>
              </div>
            </div>
          </PopoverContent>
        </Popover>
      ) : null}
      </>
    </TooltipProvider>
  );
}
