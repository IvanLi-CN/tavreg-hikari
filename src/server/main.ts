import { config as loadDotenv } from "dotenv";
import path from "node:path";
import process from "node:process";
import { startMihomo } from "../proxy/mihomo.js";
import { checkAllNodes, checkNode, type NodeCheckResult } from "../proxy/check.js";
import { AppDatabase, type AppSettings, type JobAttemptRecord, type MicrosoftAccountRecord } from "../storage/app-db.js";
import { JobScheduler, type ServerEvent } from "./scheduler.js";

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

function normalizeSettings(input: Partial<AppSettings>): Partial<AppSettings> {
  const next: Partial<AppSettings> = {};
  if (typeof input.subscriptionUrl === "string") next.subscriptionUrl = input.subscriptionUrl.trim();
  if (typeof input.groupName === "string") next.groupName = input.groupName.trim();
  if (typeof input.routeGroupName === "string") next.routeGroupName = input.routeGroupName.trim();
  if (typeof input.checkUrl === "string") next.checkUrl = input.checkUrl.trim();
  if (typeof input.timeoutMs === "number" && Number.isFinite(input.timeoutMs)) next.timeoutMs = Math.max(1000, input.timeoutMs);
  if (typeof input.maxLatencyMs === "number" && Number.isFinite(input.maxLatencyMs)) next.maxLatencyMs = Math.max(100, input.maxLatencyMs);
  if (typeof input.apiPort === "number" && Number.isFinite(input.apiPort)) next.apiPort = Math.max(1, input.apiPort);
  if (typeof input.mixedPort === "number" && Number.isFinite(input.mixedPort)) next.mixedPort = Math.max(1, input.mixedPort);
  if (typeof input.serverHost === "string") next.serverHost = input.serverHost.trim();
  if (typeof input.serverPort === "number" && Number.isFinite(input.serverPort)) next.serverPort = Math.max(1, input.serverPort);
  if (input.defaultRunMode === "headed" || input.defaultRunMode === "headless") next.defaultRunMode = input.defaultRunMode;
  if (typeof input.defaultNeed === "number" && Number.isFinite(input.defaultNeed)) next.defaultNeed = Math.max(1, input.defaultNeed);
  if (typeof input.defaultParallel === "number" && Number.isFinite(input.defaultParallel)) next.defaultParallel = Math.max(1, input.defaultParallel);
  if (typeof input.defaultMaxAttempts === "number" && Number.isFinite(input.defaultMaxAttempts)) next.defaultMaxAttempts = Math.max(1, input.defaultMaxAttempts);
  return next;
}

function getDefaultSettings(): AppSettings {
  return {
    subscriptionUrl: (process.env.MIHOMO_SUBSCRIPTION_URL || "").trim(),
    groupName: "CODEX_AUTO",
    routeGroupName: "CODEX_ROUTE",
    checkUrl: (process.env.PROXY_CHECK_URL || "https://www.cloudflare.com/cdn-cgi/trace").trim(),
    timeoutMs: toInt(process.env.PROXY_CHECK_TIMEOUT_MS, 8000),
    maxLatencyMs: toInt(process.env.PROXY_LATENCY_MAX_MS, 3000),
    apiPort: toInt(process.env.MIHOMO_API_PORT, 39090),
    mixedPort: toInt(process.env.MIHOMO_MIXED_PORT, 49090),
    serverHost: (process.env.WEB_HOST || "127.0.0.1").trim() || "127.0.0.1",
    serverPort: toInt(process.env.WEB_PORT, 3717),
    defaultRunMode: (process.env.RUN_MODE || "").trim().toLowerCase() === "headless" ? "headless" : "headed",
    defaultNeed: toInt(process.env.WEB_DEFAULT_NEED, 1),
    defaultParallel: toInt(process.env.WEB_DEFAULT_PARALLEL, 1),
    defaultMaxAttempts: toInt(process.env.WEB_DEFAULT_MAX_ATTEMPTS, 5),
  };
}

function getRuntimeServerBinding(settings: AppSettings): { host: string; port: number } {
  const envHost = (process.env.WEB_HOST || "").trim();
  const envPort = (process.env.WEB_PORT || "").trim();
  return {
    host: envHost || settings.serverHost,
    port: envPort ? toInt(envPort, settings.serverPort) : settings.serverPort,
  };
}

function serializeAccount(row: MicrosoftAccountRecord): Record<string, unknown> {
  return {
    id: row.id,
    microsoftEmail: row.microsoftEmail,
    passwordMasked: maskSecret(row.passwordPlaintext),
    hasApiKey: row.hasApiKey,
    apiKeyId: row.apiKeyId,
    importedAt: row.importedAt,
    updatedAt: row.updatedAt,
    importSource: row.importSource,
    lastUsedAt: row.lastUsedAt,
    lastResultStatus: row.lastResultStatus,
    lastResultAt: row.lastResultAt,
    lastErrorCode: row.lastErrorCode,
    skipReason: row.skipReason,
    disabledAt: row.disabledAt,
  };
}

function serializeAttempt(db: AppDatabase, row: JobAttemptRecord): Record<string, unknown> {
  return {
    ...row,
    accountEmail: db.getAccount(row.accountId)?.microsoftEmail || null,
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
    };
  }
  return {
    job,
    activeAttempts: scheduler.activeAttemptRows().map((row) => serializeAttempt(db, row)),
    recentAttempts: db
      .listAttempts(job.id, false)
      .slice(0, 20)
      .map((row) => serializeAttempt(db, row)),
    eligibleCount: db.countEligibleAccounts(job.id),
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

async function syncProxyInventory(db: AppDatabase, settings: AppSettings) {
  const controller = await createProxyController(settings);
  try {
    const nodes = await controller.listGroupNodes();
    const selected = await controller.getGroupSelection();
    db.upsertProxyInventory(
      nodes.map((item) => item.name),
      selected,
    );
    return { selected, nodes: db.listProxyNodes() };
  } finally {
    await controller.stop().catch(() => {});
  }
}

async function serveStatic(req: Request): Promise<Response> {
  const url = new URL(req.url);
  let assetPath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  if (!assetPath) assetPath = "index.html";
  const targetPath = path.join(WEB_DIST_DIR, assetPath);
  const file = Bun.file(targetPath);
  if (await file.exists()) {
    return new Response(file);
  }
  const indexFile = Bun.file(path.join(WEB_DIST_DIR, "index.html"));
  if (await indexFile.exists()) {
    return new Response(indexFile);
  }
  return new Response("Frontend build not found. Run `bun run web:build` first.", { status: 503 });
}

async function main(): Promise<void> {
  const db = await AppDatabase.open(DEFAULT_DB_PATH, LEGACY_PROXY_USAGE_PATH);
  const defaults = db.ensureSettings(getDefaultSettings());
  const runtimeBinding = getRuntimeServerBinding(defaults);
  const clients = new Set<any>();
  const scheduler = new JobScheduler(db, REPO_ROOT, DEFAULT_DB_PATH, (event) => {
    const message = toEventMessage(event);
    for (const ws of clients) {
      ws.send(message);
    }
  });

  await syncProxyInventory(db, defaults).catch(() => {});

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

      if (pathname === "/api/events/ws") {
        if (server.upgrade(req)) {
          return new Response(null);
        }
        return badRequest("websocket upgrade failed", 500);
      }

      if (pathname === "/api/health") {
        return json({ ok: true, now: nowIso() });
      }

      if (pathname === "/api/accounts/import" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { content?: string } | null;
        const content = String(body?.content || "");
        const parsed = content
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => {
            const [email, ...rest] = line.split(",");
            return { email: (email || "").trim(), password: rest.join(",").trim() };
          })
          .filter((item) => item.email && item.password);
        const summary = db.importAccounts(parsed);
        return json({ ok: true, summary });
      }

      if (pathname === "/api/accounts" && req.method === "GET") {
        const data = db.listAccounts({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          hasApiKey: parseBool(url.searchParams.get("hasApiKey")),
          skipReason: url.searchParams.get("skipReason") || undefined,
          page: toInt(url.searchParams.get("page") || undefined, 1),
          pageSize: toInt(url.searchParams.get("pageSize") || undefined, 20),
        });
        return json({ total: data.total, rows: data.rows.map((row) => serializeAccount(row)) });
      }

      if (pathname === "/api/api-keys" && req.method === "GET") {
        const data = db.listApiKeys({
          q: url.searchParams.get("q") || undefined,
          status: url.searchParams.get("status") || undefined,
          page: toInt(url.searchParams.get("page") || undefined, 1),
          pageSize: toInt(url.searchParams.get("pageSize") || undefined, 20),
        });
        return json({
          total: data.total,
          rows: data.rows.map((row) => ({
            ...row,
            apiKeyMasked: maskSecret(row.apiKey),
            apiKey: undefined,
          })),
        });
      }

      if (pathname === "/api/jobs/current" && req.method === "GET") {
        return json(serializeJobSnapshot(db, scheduler));
      }

      if (pathname === "/api/jobs/current/control" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
        const action = String(body?.action || "");
        try {
          if (action === "start") {
            const settings = db.getSettings(getDefaultSettings());
            const requestedRunMode = body?.runMode === "headless" || body?.runMode === "headed" ? body.runMode : settings.defaultRunMode;
            const job = await scheduler.startJob({
              runMode: requestedRunMode,
              need: Math.max(1, Number(body?.need || settings.defaultNeed)),
              parallel: Math.max(1, Number(body?.parallel || settings.defaultParallel)),
              maxAttempts: Math.max(1, Number(body?.maxAttempts || settings.defaultMaxAttempts)),
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
            });
            return json({ ok: true, job });
          }
          return badRequest(`unsupported action: ${action}`);
        } catch (error) {
          return badRequest(error instanceof Error ? error.message : String(error), 409);
        }
      }

      if (pathname === "/api/proxies" && req.method === "GET") {
        const settings = db.getSettings(getDefaultSettings());
        const inventory = await syncProxyInventory(db, settings);
        return json({
          settings,
          selectedName: inventory.selected,
          nodes: inventory.nodes,
        });
      }

      if (pathname === "/api/proxies/settings" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as Partial<AppSettings> | null;
        const next: AppSettings = {
          ...db.getSettings(getDefaultSettings()),
          ...normalizeSettings(body || {}),
        } as AppSettings;
        db.setSettings(next);
        const inventory = await syncProxyInventory(db, next);
        return json({ ok: true, settings: next, selectedName: inventory.selected, nodes: inventory.nodes });
      }

      if (pathname === "/api/proxies/select" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { nodeName?: string } | null;
        const nodeName = String(body?.nodeName || "").trim();
        if (!nodeName) return badRequest("nodeName is required");
        const settings = db.getSettings(getDefaultSettings());
        const controller = await createProxyController(settings);
        try {
          await controller.setGroupProxy(nodeName);
          db.setSelectedProxy(nodeName);
          const selected = await controller.getGroupSelection();
          return json({ ok: true, selectedName: selected || nodeName, nodes: db.listProxyNodes() });
        } finally {
          await controller.stop().catch(() => {});
        }
      }

      if (pathname === "/api/proxies/check" && req.method === "POST") {
        const body = (await req.json().catch(() => null)) as { scope?: string; nodeName?: string } | null;
        const settings = db.getSettings(getDefaultSettings());
        const controller = await createProxyController(settings);
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
            if (!targetNode) return badRequest("no proxy node selected");
            results = [
              await checkNode(controller, targetNode, {
                checkUrl: settings.checkUrl,
                timeoutMs: settings.timeoutMs,
                maxLatencyMs: settings.maxLatencyMs,
                ipinfoToken: (process.env.IPINFO_TOKEN || "").trim() || undefined,
              }),
            ];
          }
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
          const event: ServerEvent = {
            type: "proxy.check.completed",
            payload,
            timestamp: nowIso(),
          };
          const message = toEventMessage(event);
          for (const ws of clients) {
            ws.send(message);
          }
          return json(payload);
        } finally {
          await controller.stop().catch(() => {});
        }
      }

      return await serveStatic(req);
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
