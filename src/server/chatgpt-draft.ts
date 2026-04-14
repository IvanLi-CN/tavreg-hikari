import {
  normalizeCfMailBaseUrl,
  provisionCfMailMailbox,
  type CfMailHttpJson,
  type CfMailMailboxRecord,
} from "../cfmail-api.js";
import {
  generateRealisticMailboxLocalPart,
  generateRealisticMailboxSubdomain,
  isMailboxAddressConflictError,
  shouldFallbackCfMailProviderManagedMailbox,
  shouldRetryCfMailFallbackWithSubdomain,
} from "../mailbox-address.js";
import {
  resolveMailboxProviderIdentity,
  withMailboxProviderProvisioningGuard,
} from "./mailbox-provider-guard.js";

export interface ChatGptDraftRecord {
  email: string;
  password: string;
  nickname: string;
  birthDate: string;
  mailboxId: string;
  generatedAt: string;
}

export interface BuildChatGptDraftOptions {
  apiKey: string;
  baseUrl: string;
  httpJson: CfMailHttpJson;
  proxyUrl?: string;
  rootDomain?: string;
  createPassword: () => string;
  createNickname: () => string;
  createBirthDate: () => string;
  nowIso: () => string;
}

async function provisionProviderManagedMailbox(
  options: Pick<BuildChatGptDraftOptions, "apiKey" | "baseUrl" | "httpJson" | "proxyUrl" | "rootDomain">,
): Promise<CfMailMailboxRecord> {
  return await provisionCfMailMailbox({
    baseUrl: options.baseUrl,
    apiKey: options.apiKey,
    httpJson: options.httpJson,
    proxyUrl: options.proxyUrl,
    rootDomain: options.rootDomain,
  });
}

async function provisionMailboxWithRealisticLocalPart(
  options: Pick<BuildChatGptDraftOptions, "apiKey" | "baseUrl" | "httpJson" | "proxyUrl" | "rootDomain">,
): Promise<CfMailMailboxRecord> {
  const maxAttempts = 5;
  let lastError: unknown = null;
  let includeSubdomain = false;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await provisionCfMailMailbox({
        baseUrl: options.baseUrl,
        apiKey: options.apiKey,
        httpJson: options.httpJson,
        proxyUrl: options.proxyUrl,
        localPart: generateRealisticMailboxLocalPart(),
        subdomain: includeSubdomain ? generateRealisticMailboxSubdomain() : undefined,
        rootDomain: options.rootDomain,
      });
    } catch (error) {
      lastError = error;
      if (!includeSubdomain && shouldRetryCfMailFallbackWithSubdomain(error)) {
        includeSubdomain = true;
        continue;
      }
      if (!isMailboxAddressConflictError(error) || attempt === maxAttempts) {
        throw error;
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error("cfmail_mailbox_provision_failed");
}

async function provisionChatGptMailbox(
  options: Pick<BuildChatGptDraftOptions, "apiKey" | "baseUrl" | "httpJson" | "proxyUrl" | "rootDomain">,
): Promise<CfMailMailboxRecord> {
  try {
    return await provisionProviderManagedMailbox(options);
  } catch (error) {
    if (!shouldFallbackCfMailProviderManagedMailbox(error)) {
      throw error;
    }
  }
  return await provisionMailboxWithRealisticLocalPart(options);
}

export async function buildChatGptDraft(options: BuildChatGptDraftOptions): Promise<ChatGptDraftRecord> {
  const apiKey = options.apiKey.trim();
  if (!apiKey) {
    throw new Error("cfmail_api_key_missing");
  }
  const baseUrl = normalizeCfMailBaseUrl(options.baseUrl);
  const identity = resolveMailboxProviderIdentity({
    provider: "cfmail",
    baseUrl,
    credential: apiKey,
  });
  const mailbox = await withMailboxProviderProvisioningGuard(identity, async () =>
    provisionChatGptMailbox({
      apiKey,
      baseUrl,
      httpJson: options.httpJson,
      proxyUrl: options.proxyUrl,
      rootDomain: options.rootDomain?.trim() || undefined,
    }));
  return {
    email: mailbox.address,
    password: options.createPassword(),
    nickname: options.createNickname(),
    birthDate: options.createBirthDate(),
    mailboxId: mailbox.id,
    generatedAt: options.nowIso(),
  };
}
