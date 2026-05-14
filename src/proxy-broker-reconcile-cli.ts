import { config as loadDotenv } from "dotenv";
import { AppDatabase, type AppSettings } from "./storage/app-db.js";
import { reconcileProxyBrokerSessions } from "./server/proxy-broker-reconciler.js";

loadDotenv({ path: ".env.local", quiet: true });

function toInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : fallback;
}

function brokerSettingsDefaults(): Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs"> {
  return {
    proxyBrokerBaseUrl: (process.env.PROXY_BROKER_BASE_URL || "https://proxy-broker.ivanli.cc").trim().replace(/\/+$/g, ""),
    proxyBrokerProfileId: (process.env.PROXY_BROKER_PROFILE_ID || "Tavily").trim() || "Tavily",
    timeoutMs: toInt(process.env.PROXY_BROKER_TIMEOUT_MS || process.env.PROXY_CHECK_TIMEOUT_MS, 30_000),
  };
}

function parseArgs(argv: string[]): { apply: boolean; dbPath: string } {
  let apply = false;
  let dbPath = process.env.TASK_LEDGER_DB_PATH || "output/registry/tavreg-hikari.sqlite";
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg) continue;
    if (arg === "--apply") {
      apply = true;
      continue;
    }
    if (arg === "--dry-run") {
      apply = false;
      continue;
    }
    if (arg === "--db" && argv[index + 1]) {
      dbPath = argv[index + 1]!;
      index += 1;
      continue;
    }
    if (arg.startsWith("--db=")) {
      dbPath = arg.slice("--db=".length);
    }
  }
  return { apply, dbPath };
}

async function main(): Promise<void> {
  const { apply, dbPath } = parseArgs(process.argv.slice(2));
  const db = await AppDatabase.open(dbPath);
  try {
    const settings = db.getSettings(brokerSettingsDefaults());
    const bootstrapGuards = db.listBrowserSessionBootstrapGuards();
    if (apply && bootstrapGuards.length > 0) {
      console.error(JSON.stringify({
        apply,
        blocked: true,
        reason: "active_browser_session_bootstraps",
        message: "refusing to apply while browser session bootstraps may own live Proxy Broker sessions",
        browserSessionBootstraps: bootstrapGuards,
      }, null, 2));
      process.exit(2);
    }
    const result = await reconcileProxyBrokerSessions({
      settings,
      references: db.listActiveBrokerSessionReferences(),
      apply,
    });
    console.log(JSON.stringify({
      apply,
      activeBrokerSessions: result.activeSessionIds.length,
      referencedBrokerSessions: result.referencedSessionIds.length,
      orphanBrokerSessions: result.orphanSessions.length,
      closedSessions: result.closedSessionIds.length,
      closeErrors: result.closeErrors,
      browserSessionBootstraps: bootstrapGuards,
      orphanSessions: result.orphanSessions.map((session) => ({
        sessionId: session.session_id,
        selectedIp: session.selected_ip,
        proxyName: session.proxy_name,
        displayAddress: session.display_address,
        nodeId: session.node_id,
      })),
    }, null, 2));
  } finally {
    db.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
