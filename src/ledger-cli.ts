import { config as loadDotenv } from "dotenv";
import { Database } from "bun:sqlite";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

loadDotenv({ path: ".env.local", quiet: true });

const OUTPUT_DIR = new URL("../output/", import.meta.url);
const OUTPUT_PATH = fileURLToPath(OUTPUT_DIR);

type TaskStatus = "running" | "succeeded" | "failed";

interface QueryOptions {
  dbPath: string;
  status?: TaskStatus;
  errorCode?: string;
  proxyIp?: string;
  emailDomain?: string;
  fromIso?: string;
  toIso?: string;
  hasIpRateLimit?: boolean;
  hasSuspiciousActivity?: boolean;
  hasExtensibilityError?: boolean;
  hasInvalidCaptcha?: boolean;
  minRequestCount?: number;
  limit: number;
  json: boolean;
  includeJsonFields: boolean;
  includeApiKey: boolean;
}

interface RowRecord {
  id: number;
  started_at: string;
  status: string;
  mode: string;
  attempt_index: number;
  proxy_ip?: string;
  proxy_node?: string;
  error_code?: string;
  failure_stage?: string;
  has_ip_rate_limit: number;
  has_suspicious_activity: number;
  has_extensibility_error: number;
  has_invalid_captcha: number;
  request_count: number;
  suspicious_hit_count: number;
  captcha_submit_count: number;
  max_captcha_length?: number;
  email_domain?: string;
  email_address?: string;
  password?: string;
  api_key?: string;
  model_name?: string;
  notes_json?: string;
  details_json?: string;
}

function usage(): void {
  console.log("Usage: bun run ledger:query -- [options]");
  console.log("");
  console.log("Options:");
  console.log("  --db <path>                          SQLite path (default from TASK_LEDGER_DB_PATH)");
  console.log("  --status <running|succeeded|failed>  Filter by status");
  console.log("  --error-code <value>                 Filter by exact error_code");
  console.log("  --proxy-ip <ip>                      Filter by proxy_ip");
  console.log("  --email-domain <domain>              Filter by email_domain");
  console.log("  --from <ISO-8601>                    started_at >= from");
  console.log("  --to <ISO-8601>                      started_at <= to");
  console.log("  --has-ip-rate-limit <true|false>     Filter by has_ip_rate_limit");
  console.log("  --has-suspicious <true|false>        Filter by has_suspicious_activity");
  console.log("  --has-extensibility <true|false>     Filter by has_extensibility_error");
  console.log("  --has-invalid-captcha <true|false>   Filter by has_invalid_captcha");
  console.log("  --min-request-count <n>              Filter by minimum request_count");
  console.log("  --limit <n>                          Max rows (default 30)");
  console.log("  --json                               Output rows as JSON");
  console.log("  --include-json-fields                Include notes_json/details_json in output");
  console.log("  --include-api-key                    Include email_address/password/api_key in query output");
  console.log("  -h, --help                           Show help");
}

function toBool(raw: string | undefined): boolean | undefined {
  if (!raw) return undefined;
  const v = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  return undefined;
}

function parseBoolArg(flag: string, raw: string): boolean {
  const value = toBool(raw);
  if (value == null) {
    throw new Error(`invalid boolean for ${flag}: ${raw}`);
  }
  return value;
}

function toInt(raw: string | undefined, fallback: number): number {
  if (!raw || !raw.trim()) return fallback;
  const value = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(value)) return fallback;
  return value;
}

function parseIso(raw: string | undefined): string | undefined {
  if (!raw || !raw.trim()) return undefined;
  const value = raw.trim();
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) {
    throw new Error(`invalid datetime: ${value}`);
  }
  return new Date(ts).toISOString();
}

function normalizeStatus(raw: string | undefined): TaskStatus | undefined {
  if (!raw || !raw.trim()) return undefined;
  const status = raw.trim().toLowerCase();
  if (status === "running" || status === "succeeded" || status === "failed") return status;
  throw new Error(`invalid status: ${raw}`);
}

function defaultDbPath(): string {
  const fromEnv = (process.env.TASK_LEDGER_DB_PATH || "").trim();
  if (fromEnv) return path.resolve(fromEnv);
  return path.resolve(path.join(OUTPUT_PATH, "registry", "signup-tasks.sqlite"));
}

function parseArgs(argv: string[]): QueryOptions {
  const options: QueryOptions = {
    dbPath: defaultDbPath(),
    limit: 30,
    json: false,
    includeJsonFields: false,
    includeApiKey: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const readValue = (): string => {
      const next = argv[i + 1];
      if (!next) throw new Error(`missing value for ${arg}`);
      i += 1;
      return next;
    };

    if (arg === "-h" || arg === "--help") {
      usage();
      process.exit(0);
    }
    if (arg === "--json") {
      options.json = true;
      continue;
    }
    if (arg === "--include-json-fields") {
      options.includeJsonFields = true;
      continue;
    }
    if (arg === "--include-api-key") {
      options.includeApiKey = true;
      continue;
    }
    if (arg === "--db") {
      options.dbPath = path.resolve(readValue());
      continue;
    }
    if (arg.startsWith("--db=")) {
      options.dbPath = path.resolve(arg.slice("--db=".length));
      continue;
    }
    if (arg === "--status") {
      options.status = normalizeStatus(readValue());
      continue;
    }
    if (arg.startsWith("--status=")) {
      options.status = normalizeStatus(arg.slice("--status=".length));
      continue;
    }
    if (arg === "--error-code") {
      options.errorCode = readValue().trim();
      continue;
    }
    if (arg.startsWith("--error-code=")) {
      options.errorCode = arg.slice("--error-code=".length).trim();
      continue;
    }
    if (arg === "--proxy-ip") {
      options.proxyIp = readValue().trim();
      continue;
    }
    if (arg.startsWith("--proxy-ip=")) {
      options.proxyIp = arg.slice("--proxy-ip=".length).trim();
      continue;
    }
    if (arg === "--email-domain") {
      options.emailDomain = readValue().trim().toLowerCase();
      continue;
    }
    if (arg.startsWith("--email-domain=")) {
      options.emailDomain = arg.slice("--email-domain=".length).trim().toLowerCase();
      continue;
    }
    if (arg === "--from") {
      options.fromIso = parseIso(readValue());
      continue;
    }
    if (arg.startsWith("--from=")) {
      options.fromIso = parseIso(arg.slice("--from=".length));
      continue;
    }
    if (arg === "--to") {
      options.toIso = parseIso(readValue());
      continue;
    }
    if (arg.startsWith("--to=")) {
      options.toIso = parseIso(arg.slice("--to=".length));
      continue;
    }
    if (arg === "--has-ip-rate-limit") {
      options.hasIpRateLimit = parseBoolArg(arg, readValue());
      continue;
    }
    if (arg.startsWith("--has-ip-rate-limit=")) {
      options.hasIpRateLimit = parseBoolArg("--has-ip-rate-limit", arg.slice("--has-ip-rate-limit=".length));
      continue;
    }
    if (arg === "--has-suspicious") {
      options.hasSuspiciousActivity = parseBoolArg(arg, readValue());
      continue;
    }
    if (arg.startsWith("--has-suspicious=")) {
      options.hasSuspiciousActivity = parseBoolArg("--has-suspicious", arg.slice("--has-suspicious=".length));
      continue;
    }
    if (arg === "--has-extensibility") {
      options.hasExtensibilityError = parseBoolArg(arg, readValue());
      continue;
    }
    if (arg.startsWith("--has-extensibility=")) {
      options.hasExtensibilityError = parseBoolArg("--has-extensibility", arg.slice("--has-extensibility=".length));
      continue;
    }
    if (arg === "--has-invalid-captcha") {
      options.hasInvalidCaptcha = parseBoolArg(arg, readValue());
      continue;
    }
    if (arg.startsWith("--has-invalid-captcha=")) {
      options.hasInvalidCaptcha = parseBoolArg("--has-invalid-captcha", arg.slice("--has-invalid-captcha=".length));
      continue;
    }
    if (arg === "--min-request-count") {
      options.minRequestCount = Math.max(0, toInt(readValue(), 0));
      continue;
    }
    if (arg.startsWith("--min-request-count=")) {
      options.minRequestCount = Math.max(0, toInt(arg.slice("--min-request-count=".length), 0));
      continue;
    }
    if (arg === "--limit") {
      options.limit = Math.max(1, toInt(readValue(), 30));
      continue;
    }
    if (arg.startsWith("--limit=")) {
      options.limit = Math.max(1, toInt(arg.slice("--limit=".length), 30));
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return options;
}

function buildWhere(options: QueryOptions): { whereSql: string; params: Array<string | number> } {
  const clauses: string[] = [];
  const params: Array<string | number> = [];
  const pushClause = (sql: string, value: string | number): void => {
    clauses.push(sql);
    params.push(value);
  };

  if (options.status) pushClause("status = ?", options.status);
  if (options.errorCode) pushClause("error_code = ?", options.errorCode);
  if (options.proxyIp) pushClause("proxy_ip = ?", options.proxyIp);
  if (options.emailDomain) pushClause("email_domain = ?", options.emailDomain);
  if (options.fromIso) pushClause("started_at >= ?", options.fromIso);
  if (options.toIso) pushClause("started_at <= ?", options.toIso);
  if (options.hasIpRateLimit != null) pushClause("has_ip_rate_limit = ?", options.hasIpRateLimit ? 1 : 0);
  if (options.hasSuspiciousActivity != null) pushClause("has_suspicious_activity = ?", options.hasSuspiciousActivity ? 1 : 0);
  if (options.hasExtensibilityError != null) pushClause("has_extensibility_error = ?", options.hasExtensibilityError ? 1 : 0);
  if (options.hasInvalidCaptcha != null) pushClause("has_invalid_captcha = ?", options.hasInvalidCaptcha ? 1 : 0);
  if (options.minRequestCount != null) pushClause("request_count >= ?", options.minRequestCount);

  return {
    whereSql: clauses.length > 0 ? ` WHERE ${clauses.join(" AND ")}` : "",
    params,
  };
}

function buildQuery(options: QueryOptions): { sql: string; params: Array<string | number> } {
  const columns = [
    "id",
    "started_at",
    "status",
    "mode",
    "attempt_index",
    "proxy_ip",
    "proxy_node",
    "error_code",
    "failure_stage",
    "has_ip_rate_limit",
    "has_suspicious_activity",
    "has_extensibility_error",
    "has_invalid_captcha",
    "request_count",
    "suspicious_hit_count",
    "captcha_submit_count",
    "max_captcha_length",
    "email_domain",
    "model_name",
  ];
  if (options.includeJsonFields) {
    columns.push("notes_json", "details_json");
  }
  if (options.includeApiKey) {
    columns.push("email_address", "password", "api_key");
  }
  const { whereSql, params } = buildWhere(options);
  const sql = `SELECT ${columns.join(", ")} FROM signup_tasks${whereSql} ORDER BY id DESC LIMIT ?`;
  params.push(options.limit);
  return { sql, params };
}

function toCell(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  return String(value);
}

function renderTable(rows: RowRecord[], options: QueryOptions): void {
  if (rows.length === 0) {
    console.log("No rows matched.");
    return;
  }
  const headers = [
    "id",
    "started_at",
    "status",
    "mode",
    "attempt",
    "proxy_ip",
    "error_code",
    "ip_limit",
    "suspicious",
    "ext",
    "invalid_captcha",
    "req",
    "captcha_req",
    "email_domain",
  ];
  if (options.includeApiKey) {
    headers.push("email_address", "password", "api_key");
  }

  const dataRows = rows.map((row) => {
    const cells = [
      toCell(row.id),
      toCell(row.started_at),
      toCell(row.status),
      toCell(row.mode),
      toCell(row.attempt_index),
      toCell(row.proxy_ip),
      toCell(row.error_code),
      toCell(row.has_ip_rate_limit),
      toCell(row.has_suspicious_activity),
      toCell(row.has_extensibility_error),
      toCell(row.has_invalid_captcha),
      toCell(row.request_count),
      toCell(row.captcha_submit_count),
      toCell(row.email_domain),
    ];
    if (options.includeApiKey) {
      cells.push(toCell(row.email_address), toCell(row.password), toCell(row.api_key));
    }
    return cells;
  });

  const widths = headers.map((header, idx) => {
    let maxLen = header.length;
    for (const row of dataRows) {
      maxLen = Math.max(maxLen, row[idx]?.length || 0);
    }
    return maxLen;
  });

  const pad = (value: string, width: number): string => value.padEnd(width, " ");
  const separator = widths.map((w) => "-".repeat(w)).join("  ");
  console.log(headers.map((h, idx) => pad(h, widths[idx]!)).join("  "));
  console.log(separator);
  for (const row of dataRows) {
    console.log(row.map((cell, idx) => pad(cell, widths[idx]!)).join("  "));
  }
}

function printSummary(db: Database, options: QueryOptions): void {
  const { whereSql, params } = buildWhere(options);
  const sql = `
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status='succeeded' THEN 1 ELSE 0 END) AS succeeded,
      SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed,
      SUM(CASE WHEN has_ip_rate_limit=1 THEN 1 ELSE 0 END) AS ip_rate_limit,
      SUM(CASE WHEN has_suspicious_activity=1 THEN 1 ELSE 0 END) AS suspicious,
      SUM(CASE WHEN has_extensibility_error=1 THEN 1 ELSE 0 END) AS extensibility,
      SUM(CASE WHEN has_invalid_captcha=1 THEN 1 ELSE 0 END) AS invalid_captcha
    FROM signup_tasks${whereSql}
  `;
  const row = db.prepare(sql).get(...params) as Record<string, unknown> | null;
  if (!row) return;
  console.log(
    [
      `summary total=${toCell(row.total)}`,
      `succeeded=${toCell(row.succeeded)}`,
      `failed=${toCell(row.failed)}`,
      `ip_rate_limit=${toCell(row.ip_rate_limit)}`,
      `suspicious=${toCell(row.suspicious)}`,
      `extensibility=${toCell(row.extensibility)}`,
      `invalid_captcha=${toCell(row.invalid_captcha)}`,
    ].join(" | "),
  );
}

function runQuery(options: QueryOptions): void {
  const db = new Database(options.dbPath, { create: false, strict: true });
  // Bun's readonly mode may fail on WAL databases; use query_only to keep the session read-only.
  db.exec("PRAGMA query_only=ON;");
  db.exec("PRAGMA busy_timeout=3000;");
  try {
    const { sql, params } = buildQuery(options);
    const rows = db.prepare(sql).all(...params) as RowRecord[];
    printSummary(db, options);
    if (options.json) {
      console.log(JSON.stringify(rows, null, 2));
      return;
    }
    renderTable(rows, options);
  } finally {
    db.close(false);
  }
}

function main(): void {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === "-h" || command === "--help") {
    usage();
    return;
  }
  if (command !== "query") {
    throw new Error(`unsupported command: ${command}`);
  }
  const options = parseArgs(args);
  runQuery(options);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
