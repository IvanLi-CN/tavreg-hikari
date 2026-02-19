import { config as loadDotenv } from "dotenv";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { startMihomo, type MihomoConfig } from "./proxy/mihomo.js";
import { checkAllNodes, checkNode, type NodeCheckResult } from "./proxy/check.js";

loadDotenv({ path: ".env.local", quiet: true });

const OUTPUT_DIR = new URL("../output/", import.meta.url);

function mustEnv(name: string): string {
  const value = (process.env[name] || "").trim();
  if (!value) {
    throw new Error(`Missing env: ${name}`);
  }
  return value;
}

function toInt(raw: string | undefined, fallback: number): number {
  if (!raw || !raw.trim()) return fallback;
  const value = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(value) ? value : fallback;
}

function getProxyConfig(): {
  mihomo: MihomoConfig;
  timeoutMs: number;
  maxLatencyMs: number;
  ipinfoToken?: string;
} {
  const defaultApiPort = 39090 + Math.floor(Math.random() * 2000);
  const defaultMixedPort = 49090 + Math.floor(Math.random() * 2000);
  const subscriptionUrl = mustEnv("MIHOMO_SUBSCRIPTION_URL");
  const apiPort = toInt(process.env.MIHOMO_API_PORT, defaultApiPort);
  const mixedPort = toInt(process.env.MIHOMO_MIXED_PORT, defaultMixedPort);
  const checkUrl = (process.env.PROXY_CHECK_URL || "https://www.cloudflare.com/cdn-cgi/trace").trim();
  const timeoutMs = toInt(process.env.PROXY_CHECK_TIMEOUT_MS, 8000);
  const maxLatencyMs = toInt(process.env.PROXY_LATENCY_MAX_MS, 3000);
  const ipinfoToken = (process.env.IPINFO_TOKEN || "").trim() || undefined;

  const outputPath = fileURLToPath(OUTPUT_DIR);
  const mihomoWorkDir = path.join(outputPath, "mihomo");
  const downloadDir = path.resolve("downloads", "mihomo");

  return {
    mihomo: {
      subscriptionUrl,
      apiPort,
      mixedPort,
      groupName: "CODEX_AUTO",
      routeGroupName: "CODEX_ROUTE",
      checkUrl,
      workDir: mihomoWorkDir,
      downloadDir,
    },
    timeoutMs,
    maxLatencyMs,
    ipinfoToken,
  };
}

function parseArgs(argv: string[]): { node?: string } {
  const args = [...argv];
  let node: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === "--node" && args[i + 1]) {
      node = args[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith("--node=")) {
      node = arg.slice("--node=".length);
      continue;
    }
  }
  return { node: node?.trim() || undefined };
}

async function writeJson(filename: string, payload: unknown): Promise<void> {
  const target = new URL(filename, OUTPUT_DIR);
  await mkdir(path.dirname(fileURLToPath(target)), { recursive: true });
  await writeFile(target, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function printResult(result: NodeCheckResult): void {
  const geo = result.geo;
  const parts = [
    result.name,
    result.ok ? "OK" : "FAIL",
    typeof result.latencyMs === "number" ? `${result.latencyMs}ms` : "n/a",
    geo?.country || "",
    geo?.city || "",
    geo?.org || "",
  ].filter(Boolean);
  console.log(parts.join(" | "));
}

async function run(): Promise<void> {
  const [command] = process.argv.slice(2);
  const args = parseArgs(process.argv.slice(3));
  const cfg = getProxyConfig();

  if (!command || ["check-all", "check", "set"].includes(command) === false) {
    console.log("Usage: bun run proxy:check-all");
    console.log("       bun run proxy:check --node <name>");
    console.log("       bun run proxy:set --node <name>");
    process.exit(1);
  }

  const controller = await startMihomo(cfg.mihomo);
  try {
    if (command === "set") {
      if (!args.node) throw new Error("--node is required");
      await controller.setGroupProxy(args.node);
      const now = await controller.getGroupSelection();
      console.log(`Selected: ${now || args.node}`);
      return;
    }

    if (command === "check") {
      if (!args.node) throw new Error("--node is required");
      const result = await checkNode(controller, args.node, {
        checkUrl: cfg.mihomo.checkUrl,
        timeoutMs: cfg.timeoutMs,
        maxLatencyMs: cfg.maxLatencyMs,
        ipinfoToken: cfg.ipinfoToken,
      });
      printResult(result);
      await writeJson("proxy/check-single.json", result);
      return;
    }

    if (command === "check-all") {
      const results = await checkAllNodes(controller, {
        checkUrl: cfg.mihomo.checkUrl,
        timeoutMs: cfg.timeoutMs,
        maxLatencyMs: cfg.maxLatencyMs,
        ipinfoToken: cfg.ipinfoToken,
      });
      for (const result of results) {
        printResult(result);
      }
      await writeJson("proxy/check-all.json", results);
      return;
    }
  } finally {
    await controller.stop();
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
