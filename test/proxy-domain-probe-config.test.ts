import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dir, "..");

async function readSource(relativePath: string): Promise<string> {
  return readFile(path.join(repoRoot, relativePath), "utf8");
}

test("business launch paths use site-bound proxy broker domain probes", async () => {
  const [
    runtimeSource,
    tavilySchedulerSource,
    chatgptSchedulerSource,
    grokSchedulerSource,
    accountFlowSource,
    mainSource,
  ] = await Promise.all([
    readSource("src/server/proxy-broker-runtime.ts"),
    readSource("src/server/scheduler.ts"),
    readSource("src/server/chatgpt-scheduler.ts"),
    readSource("src/server/grok-scheduler.ts"),
    readSource("src/server/account-business-flow.ts"),
    readSource("src/server/main.ts"),
  ]);

  expect(runtimeSource).toContain('microsoft: ["https://login.microsoftonline.com/"]');
  expect(runtimeSource).toContain('tavily: ["https://app.tavily.com/home", "https://auth.tavily.com/"]');
  expect(runtimeSource).toContain('chatgpt: ["https://chatgpt.com/", "https://auth.openai.com/"]');
  expect(runtimeSource).toContain('grok: ["https://grok.com/", "https://accounts.x.ai/", "https://console.x.ai/home"]');
  expect(runtimeSource).toContain("new Impit({ proxyUrl: input.proxyUrl, timeout: input.timeoutMs, followRedirects: false })");

  expect(tavilySchedulerSource).toContain("openDomainProbedProxyBrokerRuntimeSession({");
  expect(tavilySchedulerSource).toContain('businessSite: "tavily"');
  expect(chatgptSchedulerSource).toContain("openDomainProbedProxyBrokerRuntimeSession({");
  expect(chatgptSchedulerSource).toContain('businessSite: "chatgpt"');
  expect(grokSchedulerSource).toContain("openDomainProbedProxyBrokerRuntimeSession({");
  expect(grokSchedulerSource).toContain('businessSite: "grok"');
  expect(mainSource).toContain("openDomainProbedProxyBrokerRuntimeSession({");
  expect(mainSource).toContain('businessSite: "microsoft"');

  for (const site of ["tavily", "microsoft", "chatgpt", "grok"]) {
    expect(accountFlowSource).toContain(`businessSite: "${site}"`);
  }
});
