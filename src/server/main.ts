import { config as loadDotenv } from "dotenv";
import path from "node:path";
import process from "node:process";
import {
  normalizeMoeMailBaseUrl,
  provisionMoeMailMailbox,
  resolveMoeMailMailboxId,
  type MoeMailHttpJson,
} from "../moemail-openapi.js";
import { startMihomo } from "../proxy/mihomo.js";
import { checkAllNodes, checkNode, type NodeCheckResult } from "../proxy/check.js";
import {
  AppDatabase,
  type AccountExtractorProvider,
  type AppSettings,
  type JobAttemptRecord,
  type MicrosoftAccountRecord,
} from "../storage/app-db.js";
import { buildNextSettings, validateBeforePersist } from "./app-settings.js";
import { buildImportPreview, parseImportContent, type InvalidImportRow, type ParsedImportEntry } from "./account-import.js";
import { serializeAttemptForApi } from "./attempt-view.js";
import { createExclusiveRunner } from "./exclusive-runner.js";
import { JobScheduler, type ServerEvent } from "./scheduler.js";
import { resolveStaticAssetPath, shouldServeSpaFallback } from "./static-assets.js";
import { buildApiKeyExportContent } from "./api-key-export.js";

loadDotenv({ path: ".env.local", quiet: true });

const REPO_ROOT = process.cwd();
const OUTPUT_ROOT = path.join(REPO_ROOT, "output");
const LEGACY_PROXY_USAGE_PATH = path.join(OUTPUT_ROOT, "proxy", "node-usage.json");
const DEFAULT_DB_PATH = path.resolve(process.env.TASK_LEDGER_DB_PATH || path.join(OUTPUT_ROOT, "registry", "signup-tasks.sqlite"));
const WEB_DIST_DIR = path.join(REPO_ROOT, "web", "dist");

function toInt(value: string | undefined, fallback: number): number {
  if (!value || !value.trim()) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function nowIso(): string {
  return new Date().toISOString();
}

function json(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(data), {
    status: init?.status || 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...init?.headers,
    },
  });
}

function badRequest(message: string, status = 400): Response {
  return json({ error: message }, { status });
}

function parseBody(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed;
  }
}

const serverHttpJson: MoeMailHttpJson = async (method, url, options) => {
  const headers: Record<string, string> = { ...(options?.headers || {}) };
  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
    body = JSON.stringify(options.body);
  }
  const resp = await fetch(url, {
    method,
    headers,
    body,
  });
  const text = await resp.text();
  const parsed = parseBody(text);
  if (!resp.ok) {
    throw new Error(`http_failed:${resp.status}:${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed as never;
};

function splitEmailAddress(email: string): { local: string; domain: string } | null {
  const normalized = email.trim().toLowerCase();
  const atIndex = normalized.indexOf("@");
  if (atIndex <= 0 || atIndex === normalized.length - 1) {
    return null;
  }
  return {
    local: normalized.slice(0, atIndex),
    domain: normalized.slice(atIndex + 1),
  };
}

function canFallbackToHintedProofMailboxId(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /moemail_api_key_missing|fetch failed|network|timed out|timeout|ECONN|ENOTFOUND|http_failed:(401|403|429|5\d\d)|HTTP 5\d\d|HTTP 429|HTTP 403|HTTP 401/i.test(
    message,
  );
}

async function ensureSavedProofMailbox(input: {
  address: string;
  mailboxId?: string | null;
}): Promise<{ provider: "moemail"; address: string; mailboxId: string }> {
  const address = input.address.trim().toLowerCase();
  const hintedMailboxId = String(input.mailboxId || "").trim();
  const apiKey = (process.env.MOEMAIL_API_KEY || "").trim();
  if (!apiKey) {
    if (hintedMailboxId) {
      return {
        provider: "moemail",
        address,
        mailboxId: hintedMailboxId,
      };
    }
    throw new Error("moemail_api_key_missing");
  }
  const baseUrl = normalizeMoeMailBaseUrl(process.env.MOEMAIL_BASE_URL || "https://moemail.707079.xyz");
  let mailboxId = "";
  try {
    mailboxId =
      (await resolveMoeMailMailboxId({
        baseUrl,
        apiKey,
        address,
        httpJson: serverHttpJson,
      })) || "";
  } catch (error) {
    if (hintedMailboxId && canFallbackToHintedProofMailboxId(error)) {
      return {
        provider: "moemail",
        address,
        mailboxId: hintedMailboxId,
      };
    }
    throw error;
  }
  if (!mailboxId) {
    const parts = splitEmailAddress(address);
    if (!parts) {
      throw new Error("invalid proof mailbox address");
    }
    let provisioned;
    try {
      provisioned = await provisionMoeMailMailbox({
        baseUrl,
        apiKey,
        httpJson: serverHttpJson,
        name: parts.local,
        domain: parts.domain,
        expiryTime: 0,
      });
    } catch (error) {
      if (hintedMailboxId && canFallbackToHintedProofMailboxId(error)) {
        return {
          provider: "moemail",
          address,
          mailboxId: hintedMailboxId,
        };
      }
      throw error;
    }
    if (provisioned.address.trim().toLowerCase() !== address) {
      throw new Error(`moemail_mailbox_not_found:${address}`);
    }
    mailboxId = provisioned.id;
  }
  return {
    provider: "moemail",
    address,
    mailboxId,
  };
}

function parseBool(value: string | null): boolean | undefined {
  if (value == null) return undefined;
  if (["1", "true", "yes", "on"].includes(value.toLowerCase())) return true;
  if (["0", "false", "no", "off"].includes(value.toLowerCase())) return false;
  return undefined;
}

function maskSecret(secret: string, visible = 4): string {
  if (!secret) return "";
  if (secret.length <= visible) return "*".repeat(secret.length);
  return `${"*".repeat(Math.max(4, secret.length - visible))}${secret.slice(-visible)}`;
}

function normalizeLoopbackHost(host: string | undefined): string {
  const normalized = String(host || "").trim();
  if (normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1") {
    return normalized;
  }
  return "127.0.0.1";
}

function normalizeExtractorSources(value: unknown): AccountExtractorProvider[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(value.filter((item): item is AccountExtractorProvider => item === "zhanghaoya" || item === "shanyouxiang")),
  );
}

function toOptionalPositiveInt(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(1, Math.trunc(value));
  if (typeof value === "string" && value.trim()) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) return Math.max(1, parsed);
  }
  return undefined;
}

function serializeExtractorSettings(settings: AppSettings) {
  return {
    extractorZhanghaoyaKey: settings.extractorZhanghaoyaKey,
    extractorShanyouxiangKey: settings.extractorShanyouxiangKey,
    defaultAutoExtractSources: settings.defaultAutoExtractSources,
    defaultAutoExtractQuantity: settings.defaultAutoExtractQuantity,
    defaultAutoExtractMaxWaitSec: settings.defaultAutoExtractMaxWaitSec,
    defaultAutoExtractAccountType: settings.defaultAutoExtractAccountType,
    availability: {
      zhanghaoya: Boolean(settings.extractorZhanghaoyaKey.trim()),
      shanyouxiang: Boolean(settings.extractorShanyouxiangKey.trim()),
    },
  };
}

function buildSettingsCodeDefaults(): AppSettings {
  return {
    subscriptionUrl: "",
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: "https://www.cloudflare.com/cdn-cgi/trace",
    timeoutMs: 8000,
    maxLatencyMs: 3000,
    apiPort: 39090,
    mixedPort: 49090,
    serverHost: "127.0.0.1",
    serverPort: 3717,
    defaultRunMode: "headed",
    defaultNeed: 1,
    defaultParallel: 1,
    defaultMaxAttempts: 5,
    extractorZhanghaoyaKey: "",
    extractorShanyouxiangKey: "",
    defaultAutoExtractSources: [],
    defaultAutoExtractQuantity: 1,
    defaultAutoExtractMaxWaitSec: 60,
    defaultAutoExtractAccountType: "outlook",
  };
}

function buildInitialSettingsFromEnv(baseDefaults: AppSettings): AppSettings {
  return {
    ...baseDefaults,
    subscriptionUrl: (process.env.MIHOMO_SUBSCRIPTION_URL || "").trim(),
    groupName: (process.env.MIHOMO_GROUP_NAME || baseDefaults.groupName).trim() || baseDefaults.groupName,
    routeGroupName: (process.env.MIHOMO_ROUTE_GROUP_NAME || baseDefaults.routeGroupName).trim() || baseDefaults.routeGroupName,
    checkUrl: (process.env.PROXY_CHECK_URL || baseDefaults.checkUrl).trim(),
    timeoutMs: toInt(process.env.PROXY_CHECK_TIMEOUT_MS, baseDefaults.timeoutMs),
    maxLatencyMs: toInt(process.env.PROXY_LATENCY_MAX_MS, baseDefaults.maxLatencyMs),
    apiPort: toInt(process.env.MIHOMO_API_PORT, baseDefaults.apiPort),
    mixedPort: toInt(process.env.MIHOMO_MIXED_PORT, baseDefaults.mixedPort),
    serverHost: normalizeLoopbackHost(process.env.WEB_HOST || baseDefaults.serverHost),
    serverPort: toInt(process.env.WEB_PORT, baseDefaults.serverPort),
    defaultRunMode: (process.env.RUN_MODE || "").trim().toLowerCase() === "headless" ? "headless" : baseDefaults.defaultRunMode,
    defaultNeed: toInt(process.env.WEB_DEFAULT_NEED, baseDefaults.defaultNeed),
    defaultParallel: toInt(process.env.WEB_DEFAULT_PARALLEL, baseDefaults.defaultParallel),
    defaultMaxAttempts: toInt(process.env.WEB_DEFAULT_MAX_ATTEMPTS, baseDefaults.defaultMaxAttempts),
    extractorZhanghaoyaKey: (process.env.EXTRACTOR_ZHANGHAOYA_KEY || "").trim(),
    extractorShanyouxiangKey: (process.env.EXTRACTOR_SHANYOUXIANG_KEY || "").trim(),
    defaultAutoExtractSources: normalizeExtractorSources(
      (process.env.WEB_DEFAULT_AUTO_EXTRACT_SOURCES || "")
        .split(",")
        .map((item: string) => item.trim())
        .filter(Boolean),
    ),
    defaultAutoExtractQuantity: toInt(process.env.WEB_DEFAULT_AUTO_EXTRACT_QUANTITY, baseDefaults.defaultAutoExtractQuantity),
    defaultAutoExtractMaxWaitSec: toInt(process.env.WEB_DEFAULT_AUTO_EXTRACT_MAX_WAIT_SEC, baseDefaults.defaultAutoExtractMaxWaitSec),
  };
}

function getRuntimeServerBinding(settings: AppSettings): { host: string; port: number } {
  const envHost = (process.env.WEB_HOST || "").trim();
  const envPort = (process.env.WEB_PORT || "").trim();
  return {
    host: normalizeLoopbackHost(envHost || settings.serverHost),
    port: envPort ? toInt(envPort, settings.serverPort) : settings.serverPort,
  };
}

function serializeAccount(row: MicrosoftAccountRecord): Record<string, unknown> {
  return {
    id: row.id,
    microsoftEmail: row.microsoftEmail,
    passwordMasked: maskSecret(row.passwordPlaintext),
    proofMailboxProvider: row.proofMailboxProvider,
    proofMailboxAddress: row.proofMailboxAddress,
    proofMailboxId: row.proofMailboxId,
    hasApiKey: row.hasApiKey,
    apiKeyId: row.apiKeyId,
    importedAt: row.importedAt,
    updatedAt: row.updatedAt,
    importSource: row.importSource,
    accountSource: row.accountSource,
    sourceRawPayload: row.sourceRawPayload,
    lastUsedAt: row.lastUsedAt,
    lastResultStatus: row.lastResultStatus,
    lastResultAt: row.lastResultAt,
    lastErrorCode: row.lastErrorCode,
    skipReason: row.skipReason,
    groupName: row.groupName,
    disabledAt: row.disabledAt,
    disabledReason: row.disabledReason,
  };
}

function serializeImportedAccount(row: MicrosoftAccountRecord): Record<string, unknown> {
  return {
    id: row.id,
    microsoftEmail: row.microsoftEmail,
    passwordPlaintext: row.passwordPlaintext,
    passwordMasked: maskSecret(row.passwordPlaintext),
  };
}

function serializeJobSnapshot(db: AppDatabase, scheduler: JobScheduler) {
  const job = db.getCurrentJob();
  if (!job) {
    return {
      job: null,
      activeAttempts: [],
      recentAttempts: [],
      eligibleCount: 0,
      autoExtractState: null,
    };
  }
  return {
    job,
    activeAttempts: scheduler.activeAttemptRows().map((row) => serializeAttemptForApi(db, row)),
    recentAttempts: db
      .listAttempts(job.id, false)
      .slice(0, 20)
      .map((row) => serializeAttemptForApi(db, row)),
    eligibleCount: db.countEligibleAccounts(job.id),
    autoExtractState: scheduler.getAutoExtractSnapshot(job.id),
  };
}

function toEventMessage(event: ServerEvent): string {
  return JSON.stringify(event);
}

async function createProxyController(settings: AppSettings) {
  if (!settings.subscriptionUrl.trim()) {
    throw new Error("MIHOMO_SUBSCRIPTION_URL is not configured");
  }
  return await startMihomo({
    subscriptionUrl: settings.subscriptionUrl,
    groupName: settings.groupName,
    routeGroupName: settings.routeGroupName,
    checkUrl: settings.checkUrl,
    apiPort: settings.apiPort,
    mixedPort: settings.mixedPort,
    workDir: path.join(OUTPUT_ROOT, "mihomo", "web-admin"),
    downloadDir: path.join(REPO_ROOT, "downloads", "mihomo"),
  });
}

async function fetchProxyInventory(settings: AppSettings): Promise<{ selected: string | null; nodeNames: string[] }> {
  const controller = await createProxyController(settings);
  try {
    const nodes = await controller.listGroupNodes();
    const selected = await controller.getGroupSelection();
    return {
      selected,
      nodeNames: nodes.map((item) => item.name),
    };
  } finally {
    await controller.stop().catch(() => {});
  }
}

async function syncProxyInventory(db: AppDatabase, settings: AppSettings) {
  const inventory = await fetchProxyInventory(settings);
  db.upsertProxyInventory(inventory.nodeNames, inventory.selected);
  return { selected: inventory.selected, nodes: db.listProxyNodes() };
}

async function serveStatic(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const targetPath = resolveStaticAssetPath(WEB_DIST_DIR, url.pathname);
  if (!targetPath) {
    return new Response("Not found", { status: 404 });
  }
  const file = Bun.file(targetPath);
  if (await file.exists()) {
    return new Response(file);
  }
  if (!shouldServeSpaFallback(url.pathname)) {
    return new Response("Not found", { status: 404 });
  }
  const indexFile = Bun.file(path.join(WEB_DIST_DIR, "index.html"));
  if (await indexFile.exists()) {
    return new Response(indexFile);
  }
  return new Response("Frontend build not found. Run `bun run web:build` first.", { status: 503 });
}

async function main(): Promise<void> {
  const db = await AppDatabase.open(DEFAULT_DB_PATH, LEGACY_PROXY_USAGE_PATH);
  const settingsDefaults = buildSettingsCodeDefaults();
  const bootstrapSettings = buildInitialSettingsFromEnv(settingsDefaults);
  const defaults = db.ensureSettings(bootstrapSettings);
  const readSettings = () => db.getSettings(settingsDefaults);
  const runtimeBinding = getRuntimeServerBinding(defaults);
  const clients = new Set<any>();
  const runExclusiveProxyOp = createExclusiveRunner();
  const scheduler = new JobScheduler(db, REPO_ROOT, DEFAULT_DB_PATH, readSettings, (event) => {
    const message = toEventMessage(event);
    for (const ws of clients) {
      ws.send(message);
    }
  });

  const broadcast = (event: ServerEvent) => {
    const message = toEventMessage(event);
    for (const ws of clients) {
      ws.send(message);
    }
  };

  await runExclusiveProxyOp(() => syncProxyInventory(db, defaults)).catch(() => {});

  const server = Bun.serve({
    hostname: runtimeBinding.host,
    port: runtimeBinding.port,
    websocket: {
      open(ws: any) {
        clients.add(ws);
        ws.send(
          toEventMessage({
            type: "toast",
            payload: { level: "info", message: "websocket connected" },
            timestamp: nowIso(),
          }),
        );
      },
      message() {},
      close(ws: any) {
        clients.delete(ws);
      },
    },
    async fetch(req, server) {
      const url = new URL(req.url);
      const pathname = url.pathname;
      const accountDetailMatch = pathname.match(/^\/api\/accounts\/(\d+)$/);

      try {
        if (pathname === "/api/events/ws") {
          if (server.upgrade(req)) {
            return new Response(null);
          }
          return badRequest("websocket upgrade failed", 500);
        }

        if (pathname === "/api/health") {
          return json({ ok: true, now: nowIso() });
        }

        if (pathname === "/api/accounts/import-preview" && req.method === "POST") {
          const body = (await req.json().catch(() => null)) as {
            entries?: ParsedImportEntry[];
            invalidRows?: InvalidImportRow[];
          } | null;
          const entries = Array.isArray(body?.entries) ? body.entries : [];
          const invalidRows = Array.isArray(body?.invalidRows) ? body.invalidRows : [];
          const existingAccounts = db.getAccountsByEmails(entries.map((entry) => String(entry?.email || "")));
          const preview = buildImportPreview(
            entries.map((entry, index) => ({
              lineNumber: Number(entry.lineNumber || index + 1),
              rawLine: String(entry.rawLine || ""),
              email: String(entry.email || "").trim(),
              normalizedEmail: String(entry.normalizedEmail || String(entry.email || "").trim().toLowerCase()),
              password: String(entry.password || ""),
            })),
            invalidRows.map((row, index) => ({
              lineNumber: Number(row.lineNumber || index + 1),
              rawLine: String(row.rawLine || ""),
              reason: String(row.reason || "invalid"),
            })),
            existingAccounts.map((account) => ({
              id: account.id,
              microsoftEmail: account.microsoftEmail,
              passwordPlaintext: account.passwordPlaintext,
              hasApiKey: account.hasApiKey,
              groupName: account.groupName,
            })),
          );
          return json(preview);
        }

        if (pathname === "/api/accounts/import" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as {
          content?: string;
          entries?: Array<{ email?: string; password?: string }>;
          groupName?: string | null;
        } | null;
        const content = String(body?.content || "");
        const parsedEntries = Array.isArray(body?.entries)
          ? body.entries.map((entry) => ({
              email: String(entry?.email || "").trim(),
              password: String(entry?.password || ""),
            }))
          : parseImportContent(content).entries.map((entry) => ({ email: entry.email, password: entry.password }));
        const effectiveEntries = parsedEntries.filter((entry) => entry.email && entry.password);
        if (effectiveEntries.length === 0) {
          return badRequest("no valid account entries to import");
        }
        const summary = db.importAccounts(effectiveEntries, {
          source: "manual",
          groupName: body?.groupName ?? null,
        });
        broadcast({
          type: "account.updated",
          payload: { affectedIds: summary.affectedIds, action: "import" },
          timestamp: nowIso(),
        });
        return json({
          ok: true,
          summary: { created: summary.created, updated: summary.updated, total: summary.total },
          affectedIds: summary.affectedIds,
          revealedAccounts: summary.affectedIds
            .map((accountId) => db.getAccount(accountId))
            .filter((account): account is MicrosoftAccountRecord => account != null)
            .map((account) => serializeImportedAccount(account)),
        });
      }

        if (pathname === "/api/accounts" && req.method === "GET") {
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const data = db.listAccounts({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          hasApiKey: parseBool(url.searchParams.get("hasApiKey")),
          skipReason: url.searchParams.get("skipReason") || undefined,
          groupName: url.searchParams.get("groupName") || undefined,
          page,
          pageSize,
        });
        return json({
          total: data.total,
          page,
          pageSize,
          summary: data.summary,
          groups: db.listAccountGroups(),
          rows: data.rows.map((row) => serializeAccount(row)),
        });
      }

        if (pathname === "/api/accounts/group" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { ids?: number[]; groupName?: string | null } | null;
        const ids = Array.isArray(body?.ids) ? body.ids.map((id) => Number(id)) : [];
        const result = db.updateAccountsGroup(ids, body?.groupName ?? null);
        broadcast({
          type: "account.updated",
          payload: { ids, action: "group", groupName: result.groupName },
          timestamp: nowIso(),
        });
        return json({ ok: true, ...result });
      }

        if (accountDetailMatch && req.method === "PATCH") {
        const accountId = Number.parseInt(accountDetailMatch[1] || "", 10);
        if (!Number.isInteger(accountId) || accountId < 1) {
          return badRequest("invalid account id");
        }
        const body = (await req.json().catch(() => null)) as {
          proofMailboxProvider?: string | null;
          proofMailboxAddress?: string | null;
          proofMailboxId?: string | null;
          disabled?: boolean;
          disabledReason?: string | null;
        } | null;
        const hasProofMailboxAddress = !!body && Object.prototype.hasOwnProperty.call(body, "proofMailboxAddress");
        const hasProofMailboxId = !!body && Object.prototype.hasOwnProperty.call(body, "proofMailboxId");
        const hasProofMailboxProvider = !!body && Object.prototype.hasOwnProperty.call(body, "proofMailboxProvider");
        const proofMailboxAddress = !hasProofMailboxAddress ? undefined : body?.proofMailboxAddress == null ? null : String(body.proofMailboxAddress).trim() || null;
        const proofMailboxId = !hasProofMailboxId ? undefined : body?.proofMailboxId == null ? null : String(body.proofMailboxId).trim() || null;
        const rawProvider = !hasProofMailboxProvider ? undefined : body?.proofMailboxProvider == null ? null : String(body.proofMailboxProvider).trim().toLowerCase() || null;
        const disabled = body?.disabled == null ? undefined : Boolean(body.disabled);
        const disabledReason = body?.disabledReason == null ? undefined : String(body.disabledReason).trim() || null;
        if (rawProvider != null && rawProvider !== "moemail") {
          return badRequest("unsupported proof mailbox provider");
        }
        if (proofMailboxAddress && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(proofMailboxAddress)) {
          return badRequest("invalid proof mailbox address");
        }
        if (disabled === true && !disabledReason) {
          return badRequest("disabled reason is required");
        }
        const currentAccount = db.getAccount(accountId);
        if (!currentAccount) {
          return badRequest(`account not found: ${accountId}`, 404);
        }
        try {
          if (rawProvider !== undefined || proofMailboxAddress !== undefined || proofMailboxId !== undefined) {
            const requestedProofMailboxId = proofMailboxId?.trim() || null;
            const requestedProofMailboxAddress = proofMailboxAddress?.trim().toLowerCase() || null;
            const unchangedSavedProofMailbox =
              requestedProofMailboxAddress != null &&
              requestedProofMailboxId != null &&
              currentAccount.proofMailboxAddress?.trim().toLowerCase() === requestedProofMailboxAddress &&
              currentAccount.proofMailboxId === requestedProofMailboxId;
            const nextProofMailbox: {
              provider?: "moemail" | null;
              address?: string | null;
              mailboxId?: string | null;
            } =
              proofMailboxAddress == null
                ? {
                    provider: rawProvider === "moemail" ? "moemail" : rawProvider === null ? null : undefined,
                    address: proofMailboxAddress,
                    mailboxId: proofMailboxId,
                  }
                : unchangedSavedProofMailbox
                  ? {
                      provider: currentAccount.proofMailboxProvider || "moemail",
                      address: currentAccount.proofMailboxAddress,
                      mailboxId: currentAccount.proofMailboxId,
                    }
                  : await ensureSavedProofMailbox({
                      address: proofMailboxAddress,
                      mailboxId: proofMailboxId,
                    });
            db.updateAccountProofMailbox(accountId, {
              provider: nextProofMailbox.provider,
              address: nextProofMailbox.address,
              mailboxId: nextProofMailbox.mailboxId,
            });
          }
          if (disabled !== undefined || disabledReason !== undefined) {
            db.updateAccountAvailability(accountId, {
              disabled,
              reason: disabledReason,
            });
          }
          const account = db.getAccount(accountId);
          if (!account) {
            return badRequest(`account not found: ${accountId}`, 404);
          }
          broadcast({
            type: "account.updated",
            payload: { ids: [accountId], action: "account_meta" },
            timestamp: nowIso(),
          });
          return json({ ok: true, account: serializeAccount(account) });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (/account not found/i.test(message)) {
            return badRequest(message, 404);
          }
          return badRequest(message);
        }
      }

        if (pathname === "/api/accounts" && req.method === "DELETE") {
        const body = (await req.json().catch(() => null)) as { ids?: number[] } | null;
        const ids = Array.isArray(body?.ids) ? body.ids.map((id) => Number(id)) : [];
        const result = db.deleteAccounts(ids);
        broadcast({
          type: "account.updated",
          payload: { ids, action: "delete", blockedIds: result.blockedIds },
          timestamp: nowIso(),
        });
        return json({ ok: true, ...result });
      }

        if (pathname === "/api/api-keys" && req.method === "GET") {
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const data = db.listApiKeys({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          groupName: url.searchParams.get("groupName") || undefined,
          page,
          pageSize,
        });
        return json({
          total: data.total,
          page,
          pageSize,
          summary: data.summary,
          groups: db.listAccountGroups(),
          rows: data.rows.map((row) => ({
            ...row,
            apiKeyMasked: maskSecret(row.apiKey),
            apiKey: undefined,
          })),
        });
      }

      if (pathname === "/api/api-keys/export" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { ids?: number[] } | null;
        const ids = Array.isArray(body?.ids)
          ? Array.from(new Set(body.ids.map((id) => Number(id)).filter((id) => Number.isInteger(id) && id > 0)))
          : [];
        if (ids.length === 0) {
          return badRequest("api key ids are required");
        }
        const items = db.listApiKeysForExport(ids).map((row) => ({
          id: row.id,
          apiKey: row.apiKey,
          extractedIp: row.extractedIp,
        }));
        return json({
          items,
          content: buildApiKeyExportContent(items),
        });
      }

      if (pathname === "/api/jobs/current" && req.method === "GET") {
        return json(serializeJobSnapshot(db, scheduler));
      }

      if (pathname === "/api/account-extractors/settings" && req.method === "GET") {
        const settings = readSettings();
        return json({
          ok: true,
          settings: serializeExtractorSettings(settings),
        });
      }

      if (pathname === "/api/account-extractors/settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Partial<AppSettings> | null;
        const current = readSettings();
        const next = buildNextSettings(current, {
          extractorZhanghaoyaKey: typeof body?.extractorZhanghaoyaKey === "string" ? body.extractorZhanghaoyaKey : undefined,
          extractorShanyouxiangKey:
            typeof body?.extractorShanyouxiangKey === "string" ? body.extractorShanyouxiangKey : undefined,
          defaultAutoExtractSources:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractSources")
              ? normalizeExtractorSources(body.defaultAutoExtractSources)
              : undefined,
          defaultAutoExtractQuantity:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractQuantity")
              ? toOptionalPositiveInt(body.defaultAutoExtractQuantity)
              : undefined,
          defaultAutoExtractMaxWaitSec:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractMaxWaitSec")
              ? toOptionalPositiveInt(body.defaultAutoExtractMaxWaitSec)
              : undefined,
          defaultAutoExtractAccountType:
            body && Object.prototype.hasOwnProperty.call(body, "defaultAutoExtractAccountType") && body.defaultAutoExtractAccountType === "outlook"
              ? "outlook"
              : undefined,
        });
        db.setSettings(next);
        return json({
          ok: true,
          settings: serializeExtractorSettings(next),
        });
      }

        if (pathname === "/api/account-extractors/history" && req.method === "GET") {
        const page = toInt(url.searchParams.get("page") || undefined, 1);
        const pageSize = toInt(url.searchParams.get("pageSize") || undefined, 20);
        const providerParam = url.searchParams.get("provider");
        const provider =
          providerParam === "zhanghaoya" || providerParam === "shanyouxiang" ? providerParam : undefined;
        return json(
          db.listAccountExtractHistory({
            provider,
            status: url.searchParams.get("status") || undefined,
            q: url.searchParams.get("q") || undefined,
            page,
            pageSize,
          }),
        );
      }

        if (pathname === "/api/jobs/current/control" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
        const action = String(body?.action || "");
        try {
          if (action === "start") {
            const settings = readSettings();
            const requestedRunMode = body?.runMode === "headless" || body?.runMode === "headed" ? body.runMode : settings.defaultRunMode;
            const job = await scheduler.startJob({
              runMode: requestedRunMode,
              need: Math.max(1, Number(body?.need || settings.defaultNeed)),
              parallel: Math.max(1, Number(body?.parallel || settings.defaultParallel)),
              maxAttempts: Math.max(1, Number(body?.maxAttempts || settings.defaultMaxAttempts)),
              autoExtractSources: normalizeExtractorSources(body?.autoExtractSources ?? settings.defaultAutoExtractSources),
              autoExtractQuantity:
                toOptionalPositiveInt(body?.autoExtractQuantity) ?? settings.defaultAutoExtractQuantity,
              autoExtractMaxWaitSec:
                toOptionalPositiveInt(body?.autoExtractMaxWaitSec) ?? settings.defaultAutoExtractMaxWaitSec,
              autoExtractAccountType: "outlook",
            });
            return json({ ok: true, job });
          }
          if (action === "pause") {
            return json({ ok: true, job: scheduler.pauseCurrentJob() });
          }
          if (action === "resume") {
            return json({ ok: true, job: scheduler.resumeCurrentJob() });
          }
          if (action === "update_limits") {
            const job = scheduler.updateCurrentJobLimits({
              parallel: body?.parallel == null ? undefined : Number(body.parallel),
              need: body?.need == null ? undefined : Number(body.need),
              maxAttempts: body?.maxAttempts == null ? undefined : Number(body.maxAttempts),
              autoExtractSources:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractSources")
                  ? normalizeExtractorSources(body.autoExtractSources)
                  : undefined,
              autoExtractQuantity:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractQuantity")
                  ? toOptionalPositiveInt(body.autoExtractQuantity)
                  : undefined,
              autoExtractMaxWaitSec:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractMaxWaitSec")
                  ? toOptionalPositiveInt(body.autoExtractMaxWaitSec)
                  : undefined,
              autoExtractAccountType:
                body && Object.prototype.hasOwnProperty.call(body, "autoExtractAccountType") && body.autoExtractAccountType === "outlook"
                  ? "outlook"
                  : undefined,
            });
            return json({ ok: true, job });
          }
          return badRequest(`unsupported action: ${action}`);
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/proxies" && req.method === "GET") {
        const settings = readSettings();
        if (!settings.subscriptionUrl.trim()) {
          return json({
            settings,
            selectedName: null,
            nodes: [],
            syncError: null,
          });
        }
        try {
          const inventory = await runExclusiveProxyOp(() => syncProxyInventory(db, settings));
          return json({
            settings,
            selectedName: inventory.selected,
            pinnedName: db.getPinnedProxyName(),
            nodes: inventory.nodes,
            syncError: null,
          });
        } catch (error) {
          return json({
            settings,
            selectedName: db.getSelectedProxyName(),
            pinnedName: db.getPinnedProxyName(),
            nodes: db.listProxyNodes(),
            syncError: error instanceof Error ? error.message : String(error),
          });
        }
      }

      if (pathname === "/api/proxies/settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Partial<AppSettings> | null;
        const current = readSettings();
        const optimisticNext = buildNextSettings(current, body);
        if (!optimisticNext.subscriptionUrl.trim()) {
          db.setSettings(optimisticNext);
          db.upsertProxyInventory([], null);
          return json({
            ok: true,
            settings: optimisticNext,
            selectedName: null,
            pinnedName: db.getPinnedProxyName(),
            nodes: [],
            syncError: null,
          });
        }
        const { settings: next, result: inventory } = await runExclusiveProxyOp(() =>
          validateBeforePersist({
            current,
            input: body,
            sync: fetchProxyInventory,
            persist: (validatedSettings) => db.setSettings(validatedSettings),
          }),
        );
        db.upsertProxyInventory(inventory.nodeNames, inventory.selected);
        return json({ ok: true, settings: next, selectedName: inventory.selected, pinnedName: db.getPinnedProxyName(), nodes: db.listProxyNodes() });
      }

      if (pathname === "/api/proxies/select" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { nodeName?: string } | null;
        const nodeName = String(body?.nodeName || "").trim();
        if (!nodeName) {
          db.setPinnedProxyName(null);
          return json({ ok: true, selectedName: db.getSelectedProxyName(), pinnedName: null, nodes: db.listProxyNodes() });
        }
        const settings = readSettings();
        return await runExclusiveProxyOp(async () => {
          const controller = await createProxyController(settings);
          try {
            await controller.setGroupProxy(nodeName);
            db.setSelectedProxy(nodeName);
            db.setPinnedProxyName(nodeName);
            const selected = await controller.getGroupSelection();
            return json({ ok: true, selectedName: selected || nodeName, pinnedName: db.getPinnedProxyName(), nodes: db.listProxyNodes() });
          } finally {
            await controller.stop().catch(() => {});
          }
        });
      }

      if (pathname === "/api/proxies/check" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { scope?: string; nodeName?: string } | null;
        const settings = readSettings();
        const { response, event } = await runExclusiveProxyOp(async () => {
          const controller = await createProxyController(settings);
          let response: Response | null = null;
          let event: ServerEvent | null = null;
          try {
            let results: NodeCheckResult[] = [];
            if (body?.scope === "all") {
              results = await checkAllNodes(controller, {
                checkUrl: settings.checkUrl,
                timeoutMs: settings.timeoutMs,
                maxLatencyMs: settings.maxLatencyMs,
                ipinfoToken: (process.env.IPINFO_TOKEN || "").trim() || undefined,
              });
            } else {
              const targetNode =
                body?.scope === "node"
                  ? String(body.nodeName || "").trim()
                  : (await controller.getGroupSelection()) || db.getSelectedProxyName() || "";
              if (!targetNode) {
                response = badRequest("no proxy node selected");
              } else {
                results = [
                  await checkNode(controller, targetNode, {
                    checkUrl: settings.checkUrl,
                    timeoutMs: settings.timeoutMs,
                    maxLatencyMs: settings.maxLatencyMs,
                    ipinfoToken: (process.env.IPINFO_TOKEN || "").trim() || undefined,
                  }),
                ];
              }
            }
            if (!response) {
              for (const result of results) {
                db.recordProxyCheck({
                  nodeName: String(result.name),
                  status: result.ok ? "ok" : "fail",
                  latencyMs: typeof result.latencyMs === "number" ? result.latencyMs : null,
                  egressIp: result.geo?.ip || null,
                  country: result.geo?.country || null,
                  city: result.geo?.city || null,
                  org: result.geo?.org || null,
                  error: typeof result.error === "string" ? result.error : null,
                });
              }
              const nodes = db.listProxyNodes();
              const payload = { ok: true, results, nodes, selectedName: await controller.getGroupSelection() };
              event = {
                type: "proxy.check.completed",
                payload,
                timestamp: nowIso(),
              };
              response = json(payload);
            }
          } finally {
            await controller.stop().catch(() => {});
          }
          return { response, event };
        });
        if (event) {
          broadcast(event);
        }
        return response || badRequest("proxy check failed");
      }

        return await serveStatic(req);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[web-admin] ${req.method} ${pathname} failed: ${message}`);
        if (error instanceof Error && error.stack) {
          console.error(error.stack);
        }
        return badRequest(message, 500);
      }
    },
  });

  console.log(`Tavreg Hikari web admin ready at http://${server.hostname}:${server.port}`);

  const shutdown = async () => {
    await scheduler.shutdown().catch(() => {});
    db.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
