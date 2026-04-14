import {
  buildCfMailAuthHeaders,
  fetchCfMailMeta,
  getCfMailMessage,
  listCfMailMessages,
  normalizeCfMailBaseUrl,
  provisionCfMailMailbox,
  type CfMailHttpJson,
} from "../cfmail-api.js";
import { extractEmailCodeFromPayload, loadConfig, type AppConfig, type MailboxSession } from "../main.js";
import {
  resolveMailboxProviderIdentity,
  withMailboxProviderProvisioningGuard,
} from "./mailbox-provider-guard.js";

export type GrokMailProvider = "cfmail";
export type GrokMailbox = MailboxSession & { provider: "cfmail" };

const learnedBlockedDomains = new Set<string>();
const GROK_CFMAIL_ROOT_DOMAIN_PREFERENCES = ["707979.xyz"] as const;

function parseCsv(raw: string | undefined): string[] {
  return String(raw || "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function normalizeDomain(value: string | null | undefined): string | null {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return null;
  const domain = raw.includes("@") ? raw.split("@").pop() || "" : raw;
  const normalized = domain.trim().toLowerCase();
  const parts = normalized.split(".").filter(Boolean);
  if (parts.length >= 3) {
    return parts.slice(-2).join(".");
  }
  return normalized || null;
}

function normalizeBlockedDomains(input: AppConfig, override?: ReadonlySet<string> | string[]): ReadonlySet<string> {
  const merged = new Set(input.blockedMailboxDomains);
  for (const item of parseCsv(process.env.GROK_BLOCKED_MAILBOX_DOMAINS)) {
    merged.add(item);
  }
  for (const item of learnedBlockedDomains) {
    merged.add(item);
  }
  if (!override) {
    return merged;
  }
  if (override instanceof Set) {
    for (const item of override) {
      merged.add(item);
    }
    return merged;
  }
  for (const item of override) {
    merged.add(String(item).trim().toLowerCase());
  }
  return merged;
}

function randomMailboxSegment(prefix: string): string {
  const suffix = Math.random().toString(16).slice(2, 10).padEnd(8, "0").slice(0, 8);
  return `${prefix}-${suffix}`;
}

const httpJson: CfMailHttpJson = async (method, url, options) => {
  const headers: Record<string, string> = { ...(options?.headers || {}) };
  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
    body = JSON.stringify(options.body);
  }
  const response = await fetch(url, {
    method,
    headers,
    body,
  });
  const text = await response.text();
  const parsed = text.trim() ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(`http_failed:${response.status}:${typeof parsed === "string" ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed as never;
};

function resolveCfMailApiKey(cfg: AppConfig, mailbox?: Pick<MailboxSession, "headers">): string {
  const configured = String(cfg.cfmailApiKey || "").trim();
  if (configured) return configured;
  const authorization = String(mailbox?.headers?.Authorization || mailbox?.headers?.authorization || "").trim();
  const matched = authorization.match(/^Bearer\s+(.+)$/i);
  if (matched?.[1]?.trim()) {
    return matched[1].trim();
  }
  throw new Error("cfmail_api_key_missing");
}

function buildMailboxSession(cfg: AppConfig, input: { id: string; address: string }): GrokMailbox {
  const baseUrl = normalizeCfMailBaseUrl(cfg.cfmailBaseUrl);
  const apiKey = resolveCfMailApiKey(cfg);
  return {
    provider: "cfmail",
    baseUrl,
    address: input.address.trim().toLowerCase(),
    accountId: String(input.id || "").trim(),
    headers: buildCfMailAuthHeaders(apiKey),
  };
}

async function resolvePreferredRootDomains(cfg: AppConfig, proxyUrl: string | undefined, blockedDomains: ReadonlySet<string>): Promise<string[]> {
  const explicitRootDomain = String(process.env.GROK_CFMAIL_ROOT_DOMAIN || process.env.CHATGPT_CFMAIL_ROOT_DOMAIN || "").trim().toLowerCase();
  if (explicitRootDomain) {
    return blockedDomains.has(explicitRootDomain) ? [] : [explicitRootDomain];
  }
  try {
    const meta = await fetchCfMailMeta({
      baseUrl: normalizeCfMailBaseUrl(cfg.cfmailBaseUrl),
      httpJson,
      proxyUrl,
    });
    const dedupedDomains = Array.from(
      new Set(meta.domains.map((item) => item.trim().toLowerCase()).filter((item) => item && !blockedDomains.has(item))),
    );
    if (dedupedDomains.length <= 1) {
      return dedupedDomains;
    }
    const weighted = new Map<string, number>();
    for (const [index, domain] of dedupedDomains.entries()) {
      weighted.set(domain, index + GROK_CFMAIL_ROOT_DOMAIN_PREFERENCES.length);
    }
    for (const [index, domain] of GROK_CFMAIL_ROOT_DOMAIN_PREFERENCES.entries()) {
      if (!weighted.has(domain)) continue;
      weighted.set(domain, index);
    }
    return dedupedDomains.slice().sort((left, right) => (weighted.get(left) || 0) - (weighted.get(right) || 0));
  } catch {
    return [];
  }
}

export function rememberGrokBlockedMailbox(value: string | null | undefined): string | null {
  const domain = normalizeDomain(value);
  if (!domain) return null;
  learnedBlockedDomains.add(domain);
  return domain;
}

export function resetRememberedGrokBlockedMailboxes(): void {
  learnedBlockedDomains.clear();
}

export async function createGrokMailbox(input?: {
  cfg?: AppConfig;
  proxyUrl?: string;
  blockedDomains?: ReadonlySet<string> | string[];
}): Promise<GrokMailbox> {
  const cfg = input?.cfg || loadConfig();
  const apiKey = String(cfg.cfmailApiKey || "").trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const blockedDomains = normalizeBlockedDomains(cfg, input?.blockedDomains);
  const preferredRootDomains = await resolvePreferredRootDomains(cfg, input?.proxyUrl, blockedDomains);
  const maxAttempts = Math.max(4, preferredRootDomains.length * 2 || 0);
  let lastBlockedDomain: string | null = null;
  const baseUrl = normalizeCfMailBaseUrl(cfg.cfmailBaseUrl);
  const identity = resolveMailboxProviderIdentity({
    provider: "cfmail",
    baseUrl,
    credential: apiKey,
  });
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const preferredRootDomain = preferredRootDomains.length > 0 ? preferredRootDomains[attempt % preferredRootDomains.length] : undefined;
    const mailbox = await withMailboxProviderProvisioningGuard(identity, async () =>
      provisionCfMailMailbox({
        baseUrl,
        apiKey,
        httpJson,
        proxyUrl: input?.proxyUrl,
        localPart: randomMailboxSegment("grok"),
        subdomain: randomMailboxSegment("box"),
        rootDomain: preferredRootDomain || undefined,
      }));
    const domain = normalizeDomain(mailbox.address);
    if (!domain || !blockedDomains.has(domain)) {
      return buildMailboxSession(cfg, mailbox);
    }
    learnedBlockedDomains.add(domain);
    lastBlockedDomain = domain;
  }
  throw new Error(`grok_mailbox_domain_blocked:${lastBlockedDomain || "unknown"}`);
}

export async function waitForGrokEmailCode(input: {
  mailbox: GrokMailbox;
  cfg?: AppConfig;
  proxyUrl?: string;
  timeoutMs?: number;
  pollMs?: number;
  notBefore?: string;
}): Promise<{ code: string }> {
  const cfg = input.cfg || loadConfig();
  const baseUrl = normalizeCfMailBaseUrl(input.mailbox.baseUrl || cfg.cfmailBaseUrl);
  const apiKey = resolveCfMailApiKey(cfg, input.mailbox);
  const timeoutMs = input.timeoutMs ?? cfg.emailWaitMs;
  const pollMs = input.pollMs ?? cfg.mailPollMs;
  const since = String(input.notBefore || new Date(Date.now() - 15_000).toISOString()).trim();
  const mailboxId = String(input.mailbox.accountId || "").trim();
  const address = String(input.mailbox.address || "").trim().toLowerCase();
  const seen = new Set<string>();
  let lastMessageCount = 0;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let messages = [] as Awaited<ReturnType<typeof listCfMailMessages>>;
    try {
      messages = await listCfMailMessages({
        baseUrl,
        apiKey,
        mailboxId,
        address,
        httpJson,
        proxyUrl: input.proxyUrl,
        since,
      });
      if (mailboxId || address) {
        messages = messages.filter((message) => {
          const messageMailboxId = String(message?.mailboxId || "").trim();
          const messageAddress = String(message?.mailboxAddress || "").trim().toLowerCase();
          if (mailboxId && messageMailboxId === mailboxId) return true;
          if (address && messageAddress === address) return true;
          return false;
        });
      }
      lastMessageCount = messages.length;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, pollMs));
      continue;
    }
    for (const message of messages) {
      const messageId = String(message?.id || "").trim();
      if (!messageId || seen.has(messageId)) continue;
      seen.add(messageId);
      try {
        const payload = await getCfMailMessage({
          baseUrl,
          apiKey,
          messageId,
          httpJson,
          proxyUrl: input.proxyUrl,
        });
        const code = extractEmailCodeFromPayload(payload);
        if (code) {
          return { code };
        }
      } catch {
        // continue polling
      }
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(`grok_email_code_timeout:provider=cfmail:messages=${lastMessageCount}`);
}
