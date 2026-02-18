import { config as loadDotenv } from "dotenv";
import { Camoufox } from "camoufox-js";
import { Resvg } from "@resvg/resvg-js";
import { randomBytes, randomInt } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import process from "node:process";
import readline from "node:readline/promises";

type JsonRecord = Record<string, unknown>;

interface AppConfig {
  openaiBaseUrl: string;
  openaiKey: string;
  preferredModel: string;
  headless: boolean;
  slowMoMs: number;
  maxCaptchaRounds: number;
  ocrRetryWindowMs: number;
  ocrInitialCooldownMs: number;
  ocrMaxCooldownMs: number;
  ocrRequestTimeoutMs: number;
  humanConfirmBeforeSignup: boolean;
  humanConfirmText: string;
  duckmailBaseUrl: string;
  duckmailApiKey?: string;
  duckmailDomain?: string;
  duckmailPollMs: number;
  emailWaitMs: number;
  keyName: string;
  keyLimit: number;
  existingEmail?: string;
  existingPassword?: string;
  spoofIpHeader?: string;
}

interface DuckmailSession {
  baseUrl: string;
  address: string;
  accountId: string;
  token: string;
}

interface ResultPayload {
  email: string;
  password: string;
  verificationLink: string | null;
  apiKey: string | null;
  model: string;
  notes: string[];
}

loadDotenv({ path: ".env.local", quiet: true });

const OUTPUT_DIR = new URL("../output/", import.meta.url);

function ts(): string {
  return new Date().toISOString();
}

function log(message: string): void {
  console.log(`[${ts()}] ${message}`);
}

function mustEnv(name: string): string {
  const value = (process.env[name] || "").trim();
  if (!value) {
    throw new Error(`Missing env: ${name}`);
  }
  return value;
}

function toBool(raw: string | undefined, fallback: boolean): boolean {
  if (!raw || !raw.trim()) return fallback;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

function toInt(raw: string | undefined, fallback: number): number {
  if (!raw || !raw.trim()) return fallback;
  const value = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(value) ? value : fallback;
}

function randomPassword(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let seed = "";
  const buf = randomBytes(8);
  for (const b of buf) seed += alphabet[b % alphabet.length];
  const tail = String(Date.now()).slice(-4);
  return `Aa!${seed}${tail}`;
}

function randomPublicIpv4(): string {
  const firstOctetPool = [13, 23, 36, 45, 52, 61, 73, 84, 96, 103, 114, 121, 131, 142, 153, 166, 175, 183, 196, 203];
  const a = firstOctetPool[randomInt(0, firstOctetPool.length)]!;
  const b = randomInt(1, 255);
  const c = randomInt(1, 255);
  const d = randomInt(1, 255);
  return `${a}.${b}.${c}.${d}`;
}

function sanitizeCaptchaText(value: string): string {
  return (value || "").replace(/[^A-Za-z0-9]/g, "").trim();
}

function isLikelyTavilyKey(value: string): boolean {
  return /^tvly-[A-Za-z0-9_-]{8,}$/i.test(value.trim());
}

function extractTavilyKeyDeep(node: unknown): string | null {
  if (node == null) return null;
  if (typeof node === "string") {
    return isLikelyTavilyKey(node) ? node.trim() : null;
  }
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = extractTavilyKeyDeep(item);
      if (found) return found;
    }
    return null;
  }
  if (typeof node === "object") {
    const record = node as JsonRecord;
    for (const keyName of ["key", "api_key", "apiKey", "token", "secret", "value"]) {
      const value = record[keyName];
      if (typeof value === "string" && isLikelyTavilyKey(value)) return value.trim();
    }
    for (const value of Object.values(record)) {
      const found = extractTavilyKeyDeep(value);
      if (found) return found;
    }
  }
  return null;
}

async function writeJson(path: URL, payload: unknown): Promise<void> {
  await mkdir(OUTPUT_DIR, { recursive: true });
  await writeFile(path, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function parseBody(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function trunc(value: unknown, max = 240): string {
  try {
    return JSON.stringify(value).slice(0, max);
  } catch {
    return String(value).slice(0, max);
  }
}

async function httpJson<T = unknown>(
  method: string,
  url: string,
  options?: { headers?: Record<string, string>; body?: unknown; timeoutMs?: number },
): Promise<T> {
  const timeoutMs = options?.timeoutMs ?? 25000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let body: string | undefined;
  if (typeof options?.body === "string") {
    body = options.body;
  } else if (options?.body !== undefined) {
    body = JSON.stringify(options.body);
  }

  const headers: Record<string, string> = { ...(options?.headers || {}) };
  if (options?.body !== undefined && typeof options.body !== "string") {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }

  try {
    const resp = await fetch(url, {
      method: method.toUpperCase(),
      headers,
      body,
      signal: controller.signal,
    });

    const text = await resp.text();
    const parsed = parseBody(text);

    if (!resp.ok) {
      throw new Error(`http_failed:${resp.status}:${trunc(parsed)}`);
    }
    return parsed as T;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("http_failed:network:timeout");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function collectStrings(value: unknown, bucket: string[], depth = 0): void {
  if (depth > 8 || value == null) return;
  if (typeof value === "string") {
    bucket.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, bucket, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value as JsonRecord)) collectStrings(item, bucket, depth + 1);
  }
}

function extractVerificationLinkFromPayload(payload: unknown): string | null {
  const texts: string[] = [];
  collectStrings(payload, texts);

  for (const text of texts) {
    const normalized = text
      .replaceAll("\\/", "/")
      .replaceAll("&amp;", "&")
      .replaceAll("\\u003d", "=")
      .replaceAll("\\u0026", "&");

    const matches = normalized.match(/https?:\/\/[^\s"'<>`\\)]+/gi) || [];
    for (const raw of matches) {
      const candidate = raw.replace(/[),.;\s]+$/, "");
      if (/tavily\.com/i.test(candidate) && /(verify|email|callback|auth)/i.test(candidate)) {
        return candidate;
      }
    }
  }

  return null;
}

function normalizeModelName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isVisionLikeModel(name: string): boolean {
  return /(vl|vision|ocr)/i.test(name);
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i += 1) dp[i]![0] = i;
  for (let j = 0; j <= n; j += 1) dp[0]![j] = j;

  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + cost);
    }
  }

  return dp[m]![n]!;
}

async function listModels(cfg: AppConfig): Promise<string[]> {
  let payload: { data?: Array<{ id?: string }> } | null = null;
  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      payload = await httpJson<{ data?: Array<{ id?: string }> }>("GET", `${cfg.openaiBaseUrl.replace(/\/+$/, "")}/models`, {
        headers: { Authorization: `Bearer ${cfg.openaiKey}` },
        timeoutMs: 25000,
      });
      break;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const transient = /:429:|:5\d\d:|network|timeout/i.test(message);
      if (!transient || attempt === 5) {
        lastError = error instanceof Error ? error : new Error(message);
        break;
      }
      const waitMs = 1200 * attempt;
      log(`models endpoint transient error, retry in ${waitMs}ms (attempt=${attempt})`);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }
  if (!payload) {
    throw lastError || new Error("failed to load models");
  }

  const models: string[] = [];
  for (const item of payload.data || []) {
    if (item && typeof item.id === "string" && item.id.trim()) {
      models.push(item.id.trim());
    }
  }
  return models;
}

function resolveModelName(preferred: string, allModels: string[]): string {
  if (allModels.includes(preferred)) {
    return preferred;
  }

  const lowerPreferred = preferred.toLowerCase();
  const caseInsensitive = allModels.find((name) => name.toLowerCase() === lowerPreferred);
  if (caseInsensitive) {
    return caseInsensitive;
  }

  const visionModels = allModels.filter(isVisionLikeModel);
  if (visionModels.length === 0) {
    throw new Error("No vision/OCR models found in /models response");
  }

  const normalizedPreferred = normalizeModelName(preferred);
  const normalizedExact = visionModels.find((name) => normalizeModelName(name) === normalizedPreferred);
  if (normalizedExact) {
    return normalizedExact;
  }

  let best: { name: string; dist: number } | null = null;
  for (const name of visionModels) {
    const dist = levenshtein(normalizedPreferred, normalizeModelName(name));
    if (!best || dist < best.dist) {
      best = { name, dist };
    }
  }

  const maxAllowedDist = Math.max(2, Math.floor(normalizedPreferred.length * 0.25));
  if (best && best.dist <= maxAllowedDist) {
    return best.name;
  }

  throw new Error(
    `MODEL_NAME not found in related vision/OCR models: requested=${preferred}, candidates=${visionModels.join(", ")}`,
  );
}

class CaptchaSolver {
  private readonly cfg: AppConfig;

  private readonly model: string;

  constructor(cfg: AppConfig, model: string) {
    this.cfg = cfg;
    this.model = model;
  }

  private readonly promptVariants = [
    "OCR captcha text from this image. Return only visible letters and digits, no explanation.",
    "Read this captcha exactly (case-sensitive). Reply with only the letters and numbers.",
    "Return only the captcha code from this image, no spaces, no punctuation.",
  ];

  private extractTextFromResponses(payload: unknown): string {
    if (!payload || typeof payload !== "object") return "";
    const record = payload as JsonRecord;

    const outputText = record.output_text;
    if (typeof outputText === "string" && outputText.trim()) {
      return outputText;
    }

    const output = record.output;
    if (!Array.isArray(output)) return "";

    for (const item of output) {
      if (!item || typeof item !== "object") continue;
      const content = (item as JsonRecord).content;
      if (!Array.isArray(content)) continue;
      for (const piece of content) {
        if (!piece || typeof piece !== "object") continue;
        const text = (piece as JsonRecord).text;
        if (typeof text === "string" && text.trim()) {
          return text;
        }
      }
    }

    return "";
  }

  private pickBestCandidate(candidates: string[]): string {
    const cleaned = candidates.map((v) => sanitizeCaptchaText(v)).filter((v) => v.length > 0);
    if (cleaned.length === 0) return "";

    const inRange = cleaned.filter((v) => v.length >= 4 && v.length <= 10);
    if (inRange.length === 0) return "";

    const exactSix = inRange.filter((v) => v.length === 6);
    const pool = exactSix.length > 0 ? exactSix : inRange;

    const counts = new Map<string, number>();
    for (const item of pool) counts.set(item, (counts.get(item) || 0) + 1);

    let best = pool[0]!;
    let bestCount = counts.get(best) || 0;
    for (const item of pool) {
      const current = counts.get(item) || 0;
      if (current > bestCount) {
        best = item;
        bestCount = current;
      }
    }
    return best;
  }

  private async callResponsesWithPrompt(pngData: Buffer, prompt: string): Promise<string> {
    const dataUrl = `data:image/png;base64,${pngData.toString("base64")}`;
    const payload = {
      model: this.model,
      temperature: 0,
      input: [
        {
          role: "user",
          content: [
            { type: "input_text", text: prompt },
            { type: "input_image", image_url: dataUrl },
          ],
        },
      ],
    };

    const response = await httpJson("POST", `${this.cfg.openaiBaseUrl.replace(/\/+$/, "")}/responses`, {
      headers: {
        Authorization: `Bearer ${this.cfg.openaiKey}`,
        "Content-Type": "application/json",
      },
      body: payload,
      timeoutMs: Math.max(10000, this.cfg.ocrRequestTimeoutMs),
    });

    return sanitizeCaptchaText(this.extractTextFromResponses(response));
  }

  private async callResponses(pngData: Buffer): Promise<string> {
    const results: string[] = [];
    let lastError: Error | null = null;

    for (const prompt of this.promptVariants) {
      try {
        const text = await this.callResponsesWithPrompt(pngData, prompt);
        if (text) results.push(text);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
      }
      await new Promise((resolve) => setTimeout(resolve, 120));
    }

    const picked = this.pickBestCandidate(results);
    if (picked) {
      log(`captcha OCR candidates (${this.model}): ${results.join(", ")} -> ${picked}`);
      return picked;
    }

    if (lastError) {
      throw lastError;
    }
    return "";
  }

  private isTransient(reason: string): boolean {
    const lower = reason.toLowerCase();
    return [":429:", ":500:", ":502:", ":503:", ":504:", ":520:", ":521:", ":522:", "timeout", "network", "temporarily unavailable", "rate limit"].some((k) =>
      lower.includes(k),
    );
  }

  private isPermanentModelError(reason: string): boolean {
    const lower = reason.toLowerCase();
    return [":400:", ":401:", ":403:", ":422:", "model_not_found", "invalid_model_error", "forbidden", "bad request"].some(
      (k) => lower.includes(k),
    );
  }

  async solve(pngData: Buffer): Promise<string> {
    const deadline = Date.now() + this.cfg.ocrRetryWindowMs;
    let cooldownMs = this.cfg.ocrInitialCooldownMs;
    const errors: string[] = [];
    let blocked = false;
    let round = 0;

    while (Date.now() < deadline) {
      round += 1;
      let transientSeen = false;

      try {
        const solved = await this.callResponses(pngData);
        if (solved.length >= 4 && solved.length <= 10) {
          log(`captcha solved by ${this.model}: ${solved}`);
          return solved;
        }
        errors.push(`${this.model}:invalid_result:${solved}`);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        errors.push(`${this.model}:${reason}`);

        if (this.isPermanentModelError(reason)) {
          blocked = true;
        }
        if (this.isTransient(reason)) {
          transientSeen = true;
        }
      }

      if (blocked) break;
      if (!transientSeen) break;

      const waitMs = Math.min(cooldownMs, Math.max(0, deadline - Date.now()));
      if (waitMs <= 0) break;
      log(`captcha OCR throttled/upstream unstable (round=${round}), wait ${waitMs}ms`);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      cooldownMs = Math.min(Math.floor(cooldownMs * 1.7), this.cfg.ocrMaxCooldownMs);
    }

    throw new Error(
      `captcha OCR failed within retry window. models=1 blocked=${blocked ? 1 : 0} last_errors=${errors
        .slice(-8)
        .join(" | ")}`,
    );
  }
}

async function createDuckmailSession(cfg: AppConfig): Promise<DuckmailSession> {
  const baseUrl = cfg.duckmailBaseUrl.replace(/\/+$/, "");
  const headers: Record<string, string> = {};
  if (cfg.duckmailApiKey) {
    headers.Authorization = `Bearer ${cfg.duckmailApiKey}`;
  }

  const domainsResp = await httpJson<{ "hydra:member"?: Array<{ domain?: string }> }>("GET", `${baseUrl}/domains`, {
    headers,
  });

  const domains = (domainsResp["hydra:member"] || [])
    .map((item) => (item?.domain || "").trim())
    .filter((domain) => domain.length > 0);

  if (domains.length === 0) {
    throw new Error("duckmail returned empty domain list");
  }

  let pickedDomain = cfg.duckmailDomain;
  if (pickedDomain) {
    const matched = domains.find((item) => item.toLowerCase() === pickedDomain!.toLowerCase());
    if (!matched) {
      throw new Error(`duckmail requested domain not found: ${pickedDomain}`);
    }
    pickedDomain = matched;
  } else {
    pickedDomain = domains[0];
  }

  const localPart = `ctf${Date.now()}${randomInt(1000, 10000)}`;
  const address = `${localPart}@${pickedDomain}`;
  const mailboxPassword = randomPassword();

  const created = await httpJson<JsonRecord>("POST", `${baseUrl}/accounts`, {
    headers: { ...headers, "Content-Type": "application/json" },
    body: { address, password: mailboxPassword },
  });

  let accountId = typeof created.id === "string" ? created.id : "";

  const tokenResp = await httpJson<JsonRecord>("POST", `${baseUrl}/token`, {
    headers: { "Content-Type": "application/json" },
    body: { address, password: mailboxPassword },
  });

  const token = typeof tokenResp.token === "string" ? tokenResp.token : "";
  if (!accountId && typeof tokenResp.id === "string") {
    accountId = tokenResp.id;
  }

  if (!token) throw new Error("duckmail token response missing token");
  if (!accountId) throw new Error("duckmail account id missing");

  return {
    baseUrl,
    address,
    accountId,
    token,
  };
}

async function waitForVerificationLink(mailbox: DuckmailSession, timeoutMs: number, pollMs: number): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  const seen = new Set<string>();

  while (Date.now() < deadline) {
    const messages = await httpJson<JsonRecord>("GET", `${mailbox.baseUrl}/messages`, {
      headers: { Authorization: `Bearer ${mailbox.token}` },
    });

    const items = (messages["hydra:member"] as unknown[]) || [];

    for (const item of items) {
      const fromSummary = extractVerificationLinkFromPayload(item);
      if (fromSummary) return fromSummary;

      if (!item || typeof item !== "object") continue;
      const messageId = String((item as JsonRecord).id || "").trim();
      if (!messageId || seen.has(messageId)) continue;
      seen.add(messageId);

      const detail = await httpJson("GET", `${mailbox.baseUrl}/messages/${encodeURIComponent(messageId)}`, {
        headers: { Authorization: `Bearer ${mailbox.token}` },
      });

      const fromDetail = extractVerificationLinkFromPayload(detail);
      if (fromDetail) return fromDetail;
    }

    await new Promise((resolve) => setTimeout(resolve, Math.max(200, pollMs)));
  }

  return null;
}

async function fillInput(page: any, selector: string, value: string): Promise<void> {
  await page.waitForSelector(selector, { timeout: 30000 });
  const input = page.locator(selector).first();
  await input.fill("");
  await input.type(value);
}

async function safeGoto(page: any, url: string, timeout = 90000): Promise<void> {
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/NS_BINDING_ABORTED|interrupted by another navigation|frame was detached|Navigation/i.test(message)) {
      log(`safeGoto transient (${url}): ${message.split("\n")[0]}`);
      await page.waitForTimeout(900);
      return;
    }
    throw error;
  }
}

async function waitHomeStable(page: any, stableMs = 6000): Promise<boolean> {
  const step = 800;
  const rounds = Math.max(1, Math.floor(stableMs / step));
  for (let i = 0; i < rounds; i += 1) {
    const url = page.url();
    if (!/app\.tavily\.com\/home/i.test(url) || /auth\.tavily\.com/i.test(url)) {
      return false;
    }
    await page.waitForTimeout(step);
  }
  return true;
}

async function getProcessedCaptchaPng(page: any): Promise<Buffer> {
  await page.waitForSelector('img[alt="captcha"]', { timeout: 30000 });
  const src = await page.$eval('img[alt="captcha"]', (el: any) => String(el.src || ""));
  const match = src.match(/^data:image\/svg\+xml;base64,(.+)$/i);
  if (match && match[1]) {
    try {
      const svgBinary = Buffer.from(match[1], "base64");
      const rendered = new Resvg(svgBinary, {
        fitTo: { mode: "width", value: 900 },
        background: "white",
      }).render();
      return Buffer.from(rendered.asPng());
    } catch {
      // fallback to screenshot path
    }
  }

  const image = page.locator('img[alt="captcha"]').first();
  const screenshot = await image.screenshot({ type: "png" });
  return Buffer.from(screenshot);
}

async function clickSubmit(page: any): Promise<void> {
  const btn = page.locator('button[type="submit"], input[type="submit"]').first();
  try {
    await btn.click({ timeout: 10000 });
    return;
  } catch {
    await page.evaluate(() => {
      const form = document.querySelector('form[data-form-primary="true"], form') as HTMLFormElement | null;
      const submitEl = form?.querySelector('button[type="submit"], input[type="submit"]') as
        | HTMLButtonElement
        | HTMLInputElement
        | null;
      if (submitEl) {
        submitEl.click();
      } else if (form?.requestSubmit) {
        form.requestSubmit();
      } else if (form) {
        form.submit();
      }
    });
  }
}

async function clickSignUp(page: any): Promise<void> {
  const direct = page.locator('a[href*="/u/signup/identifier"]').first();
  if ((await direct.count()) > 0) {
    await direct.click();
    return;
  }

  const clicked = await page.evaluate(() => {
    const links = Array.from(document.querySelectorAll("a"));
    const target = links.find((el) => /sign up/i.test(el.textContent || ""));
    if (!target) return false;
    (target as HTMLAnchorElement).click();
    return true;
  });

  if (!clicked) {
    throw new Error("Sign up entry not found");
  }
}

async function solveCaptchaForm(
  page: any,
  solver: CaptchaSolver,
  formKind: "signup" | "login",
  email: string,
  maxRounds: number,
): Promise<void> {
  const emailSelector = formKind === "signup" ? 'input[name="email"]' : 'input[name="username"]';
  const successUrlPattern =
    formKind === "signup"
      ? /\/u\/signup\/password|app\.tavily\.com\/home/i
      : /\/u\/login\/password|app\.tavily\.com\/home/i;

  for (let attempt = 1; attempt <= maxRounds; attempt += 1) {
    let hasCaptcha = (await page.locator('img[alt="captcha"]').count()) > 0;
    if (!hasCaptcha) {
      try {
        await page.waitForSelector('img[alt="captcha"]', { timeout: 2500 });
        hasCaptcha = true;
      } catch {
        hasCaptcha = false;
      }
    }

    let previousCaptchaSrc = "";
    if (hasCaptcha) {
      previousCaptchaSrc = await page.$eval('img[alt="captcha"]', (el: any) => String(el.src || ""));
      const pngData = await getProcessedCaptchaPng(page);
      const captchaCode = await solver.solve(pngData);
      if ((await page.locator('input[name="captcha"]').count()) > 0) {
        await fillInput(page, 'input[name="captcha"]', captchaCode);
      }
    }

    await fillInput(page, emailSelector, email);

    const previousUrl = page.url();
    await clickSubmit(page);

    try {
      await page.waitForURL(successUrlPattern, { timeout: 10000 });
      return;
    } catch {
      // continue with explicit checks
    }

    await page.waitForTimeout(2200);
    const currentUrl = page.url();
    if (successUrlPattern.test(currentUrl)) {
      return;
    }
    if (currentUrl !== previousUrl) {
      log(`${formKind} flow moved to ${currentUrl} after captcha submit`);
      return;
    }

    const currentCaptchaSrc = hasCaptcha
      ? ((await page
          .$eval('img[alt="captcha"]', (el: any) => String(el.src || ""))
          .catch(() => "")) || "")
      : "";

    if (hasCaptcha && currentCaptchaSrc && currentCaptchaSrc !== previousCaptchaSrc) {
      log(`${formKind} captcha refreshed after attempt ${attempt}, retrying`);
      continue;
    }

    log(`${formKind} captcha rejected on attempt ${attempt}, retrying`);
  }

  throw new Error(`${formKind} captcha failed after ${maxRounds} rounds`);
}

async function completeSignup(page: any, solver: CaptchaSolver, email: string, password: string, cfg: AppConfig): Promise<void> {
  await safeGoto(page, "https://app.tavily.com/api/auth/login");
  await page.waitForURL(/auth\.tavily\.com/i, { timeout: 90000 });

  if (!/\/u\/signup\/identifier|\/u\/signup\/password/i.test(page.url())) {
    if (/\/u\/login\/identifier/i.test(page.url())) {
      await clickSignUp(page);
    } else {
      await safeGoto(page, "https://auth.tavily.com/u/signup/identifier");
    }
  }

  await page.waitForURL(/\/u\/signup\/identifier|\/u\/signup\/password/i, { timeout: 90000 });
  if (/\/u\/signup\/identifier/i.test(page.url())) {
    await solveCaptchaForm(page, solver, "signup", email, cfg.maxCaptchaRounds);
    await page.waitForTimeout(1200);
  }

  if (/app\.tavily\.com\/home/i.test(page.url())) {
    return;
  }
  if (!/\/u\/signup\/password/i.test(page.url())) {
    throw new Error(`signup did not reach password step, current=${page.url()}`);
  }

  if (/\/u\/signup\/password/i.test(page.url())) {
    for (let attempt = 1; attempt <= cfg.maxCaptchaRounds; attempt += 1) {
      if (attempt === 1) {
        await writeFile(new URL("signup_password_before.html", OUTPUT_DIR), await page.content(), "utf8");
        const snap = await page.screenshot({ fullPage: true });
        await writeFile(new URL("signup_password_before.png", OUTPUT_DIR), snap);
      }

      const passwordInputs = page.locator('input[type="password"]');
      const pwdCount = await passwordInputs.count();
      if (pwdCount === 0) {
        await fillInput(page, 'input[name="password"]', password);
      } else {
        for (let i = 0; i < pwdCount; i += 1) {
          const input = passwordInputs.nth(i);
          await input.fill("");
          await input.type(password);
        }
      }

      if ((await page.locator('input[name="captcha"]').count()) > 0) {
        const pngData = await getProcessedCaptchaPng(page);
        const code = await solver.solve(pngData);
        await fillInput(page, 'input[name="captcha"]', code);
      }

      const passwordDiag = await page.evaluate(() => {
        const value = (document.querySelector('input[name="password"]') as HTMLInputElement | null)?.value || "";
        return {
          len: value.length,
          lower: /[a-z]/.test(value),
          upper: /[A-Z]/.test(value),
          digit: /\d/.test(value),
          special: /[^A-Za-z0-9]/.test(value),
        };
      });
      log(`signup password diag attempt=${attempt} ${JSON.stringify(passwordDiag)}`);

      await clickSubmit(page);
      await page.waitForTimeout(2200);

      if (attempt === 1) {
        await writeFile(new URL("signup_password_after1.html", OUTPUT_DIR), await page.content(), "utf8");
        const snap = await page.screenshot({ fullPage: true });
        await writeFile(new URL("signup_password_after1.png", OUTPUT_DIR), snap);
      }

      if (!/\/u\/signup\/password/i.test(page.url())) {
        return;
      }

      const formErrors = await page.evaluate(() => {
        const visible = (el: Element): boolean => {
          const style = window.getComputedStyle(el as HTMLElement);
          return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
        };
        const nodes = Array.from(
          document.querySelectorAll(
            '.ulp-error-info,[data-error-code],#error-element-captcha,[role="alert"],.error,[class*="error"]',
          ),
        );
        const texts = nodes
          .filter(visible)
          .map((el) => (el.textContent || "").trim())
          .filter((t) => t.length > 0)
          .slice(0, 6);
        return texts;
      });
      log(`signup password step still present after submit (attempt=${attempt}) errors=${formErrors.join(" | ") || "n/a"}`);
    }
    throw new Error(`signup password step failed after ${cfg.maxCaptchaRounds} attempts`);
  }
}

async function loginAndReachHome(page: any, solver: CaptchaSolver, email: string, password: string, cfg: AppConfig): Promise<void> {
  for (let cycle = 1; cycle <= 5; cycle += 1) {
    await safeGoto(page, "https://app.tavily.com/home");
    await page.waitForTimeout(1200);

    if (/app\.tavily\.com\/home/i.test(page.url()) && !/auth\.tavily\.com/i.test(page.url())) {
      if (await waitHomeStable(page, 6500)) {
        return;
      }
    }

    await safeGoto(page, "https://app.tavily.com/api/auth/login");
    await page.waitForTimeout(900);

    if (/\/u\/login\/identifier/i.test(page.url())) {
      await solveCaptchaForm(page, solver, "login", email, cfg.maxCaptchaRounds);
    }

    if ((await page.locator('input[name="password"]').count()) > 0) {
      await fillInput(page, 'input[name="password"]', password);
      await clickSubmit(page);
      await page.waitForTimeout(1400);
    }

    const current = page.url();
    if (/app\.tavily\.com\/home/i.test(current) && !/auth\.tavily\.com/i.test(current)) {
      if (await waitHomeStable(page, 5000)) {
        return;
      }
    }

    log(`login cycle ${cycle} not yet on home, current=${current}`);
  }

  throw new Error(`login flow did not reach home, last_url=${page.url()}`);
}

async function getDefaultApiKey(page: any, cfg: AppConfig): Promise<string | null> {
  await page.waitForLoadState("domcontentloaded", { timeout: 30000 });

  for (let round = 1; round <= 6; round += 1) {
    await page.waitForTimeout(1200);

    const fromDom = await page.evaluate(() => {
      const pick = (value: unknown): string | null => {
        if (typeof value !== "string") return null;
        const match = value.match(/tvly-[A-Za-z0-9_-]{8,}/i);
        return match ? match[0] : null;
      };

      const selectOption = Array.from(document.querySelectorAll("option"))
        .map((el) => (el as HTMLOptionElement).value || "")
        .map((v) => pick(v))
        .find((v) => !!v);
      if (selectOption) return { key: selectOption, source: "dom-option" };

      const inputVal = Array.from(document.querySelectorAll("input,textarea"))
        .map((el) => {
          const node = el as HTMLInputElement | HTMLTextAreaElement;
          return [node.value, node.getAttribute("value"), node.getAttribute("placeholder")];
        })
        .flat()
        .map((v) => pick(v))
        .find((v) => !!v);
      if (inputVal) return { key: inputVal, source: "dom-input" };

      const textMatch = pick(document.body?.innerText || "");
      if (textMatch) return { key: textMatch, source: "dom-text" };
      return { key: null, source: "none" };
    });

    if (fromDom?.key && isLikelyTavilyKey(fromDom.key)) {
      log(`default api key found from ${fromDom.source}`);
      return fromDom.key;
    }

    const pageResult = await page.evaluate(
      async ({ keyName, keyLimit }: { keyName: string; keyLimit: number }) => {
        const isLikelyKey = (value: string): boolean => /^tvly-[A-Za-z0-9_-]{8,}$/i.test((value || "").trim());
        const extractKey = (node: any): string | null => {
          if (!node) return null;
          if (typeof node === "string") return isLikelyKey(node) ? node.trim() : null;
          if (Array.isArray(node)) {
            for (const item of node) {
              const key = extractKey(item);
              if (key) return key;
            }
            return null;
          }
          if (typeof node === "object") {
            for (const k of ["key", "api_key", "apiKey", "token", "secret", "value"]) {
              const v = node[k];
              if (typeof v === "string" && isLikelyKey(v)) return v.trim();
            }
            for (const v of Object.values(node)) {
              const key = extractKey(v);
              if (key) return key;
            }
          }
          return null;
        };

        const parse = async (res: Response) => {
          const text = await res.text();
          let body: unknown;
          try {
            body = JSON.parse(text);
          } catch {
            body = text;
          }
          return { ok: res.ok, status: res.status, body };
        };

        const safeFetch = async (url: string, init?: RequestInit) => {
          try {
            const resp = await fetch(url, { credentials: "include", ...(init || {}) });
            return await parse(resp);
          } catch (error) {
            return { ok: false, status: 0, body: { error: String(error) } };
          }
        };

        const oidCandidates = new Set<string>();
        const collectOidFromNode = (node: any) => {
          if (!node) return;
          if (Array.isArray(node)) {
            node.forEach(collectOidFromNode);
            return;
          }
          if (typeof node !== "object") return;
          for (const [k, v] of Object.entries(node)) {
            if (typeof v === "string" && /(^|_)oid$|organization.?id|org.?id|selected.?oid/i.test(k) && v.trim()) {
              oidCandidates.add(v.trim());
            } else {
              collectOidFromNode(v);
            }
          }
        };

        const fromStorage = [localStorage.getItem("selected_oid"), sessionStorage.getItem("selected_oid")];
        for (const oid of fromStorage) {
          if (oid && oid.trim()) oidCandidates.add(oid.trim());
        }

        const account = await safeFetch("/api/account");
        collectOidFromNode(account.body);

        const endpoints: string[] = [];
        for (const oid of oidCandidates) endpoints.push(`/api/keys?oid=${encodeURIComponent(oid)}`);
        endpoints.push("/api/keys?oid=");
        endpoints.push("/api/keys");

        const debug: Array<{ step: string; status: number }> = [];
        for (const endpoint of endpoints) {
          const listed = await safeFetch(endpoint);
          debug.push({ step: `list:${endpoint}`, status: listed.status });
          const existing = extractKey(listed.body);
          if (existing) return { key: existing, debug };

          const createPayload = {
            name: keyName,
            limit: keyLimit > 0 ? keyLimit : 2147483647,
            key_type: "development",
            search_egress_policy: "allow_external",
          };
          const created = await safeFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(createPayload),
          });
          debug.push({ step: `create:${endpoint}`, status: created.status });
          const createdKey = extractKey(created.body);
          if (createdKey) return { key: createdKey, debug };

          const listedAgain = await safeFetch(endpoint);
          debug.push({ step: `list2:${endpoint}`, status: listedAgain.status });
          const listedAgainKey = extractKey(listedAgain.body);
          if (listedAgainKey) return { key: listedAgainKey, debug };
        }

        return { key: null, debug };
      },
      { keyName: cfg.keyName, keyLimit: cfg.keyLimit },
    );

    const debugInfo = pageResult && typeof pageResult === "object" ? (pageResult as JsonRecord).debug : null;
    if (debugInfo) {
      log(`api key page-flow debug round=${round} ${trunc(debugInfo, 600)}`);
    }

    if (pageResult && typeof pageResult === "object") {
      const key = (pageResult as JsonRecord).key;
      if (typeof key === "string" && isLikelyTavilyKey(key)) {
        return key;
      }
    }
  }

  return null;
}

async function confirmHumanControl(cfg: AppConfig, email: string, stage: string): Promise<void> {
  if (!cfg.humanConfirmBeforeSignup) return;

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("human confirmation requires an interactive terminal (TTY)");
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (
      await rl.question(
        `Manual check ${stage}. Type "${cfg.humanConfirmText}" to continue for ${email}, or anything else to abort: `,
      )
    ).trim();

    if (answer !== cfg.humanConfirmText) {
      throw new Error(`human confirmation rejected (expected "${cfg.humanConfirmText}")`);
    }
  } finally {
    rl.close();
  }
}

function loadConfig(): AppConfig {
  return {
    openaiBaseUrl: mustEnv("OPENAI_BASE_URL"),
    openaiKey: mustEnv("OPENAI_KEY"),
    preferredModel: mustEnv("MODEL_NAME"),
    headless: toBool(process.env.HEADLESS, false),
    slowMoMs: toInt(process.env.SLOWMO_MS, 50),
    maxCaptchaRounds: toInt(process.env.MAX_CAPTCHA_ROUNDS, 30),
    ocrRetryWindowMs: toInt(process.env.OCR_RETRY_WINDOW_MS, 300_000),
    ocrInitialCooldownMs: toInt(process.env.OCR_INITIAL_COOLDOWN_MS, 12_000),
    ocrMaxCooldownMs: toInt(process.env.OCR_MAX_COOLDOWN_MS, 120_000),
    ocrRequestTimeoutMs: toInt(process.env.OCR_REQUEST_TIMEOUT_MS, 25_000),
    humanConfirmBeforeSignup: toBool(process.env.HUMAN_CONFIRM_BEFORE_SIGNUP, true),
    humanConfirmText: (process.env.HUMAN_CONFIRM_TEXT || "CONFIRM").trim() || "CONFIRM",
    duckmailBaseUrl: (process.env.DUCKMAIL_BASE_URL || "https://api.duckmail.sbs").trim(),
    duckmailApiKey: (process.env.DUCKMAIL_API_KEY || "").trim() || undefined,
    duckmailDomain: (process.env.DUCKMAIL_DOMAIN || "").trim() || undefined,
    duckmailPollMs: toInt(process.env.DUCKMAIL_POLL_MS, 2500),
    emailWaitMs: toInt(process.env.EMAIL_WAIT_MS, 180_000),
    keyName: (process.env.KEY_NAME || "").trim() || `ctf-key-${String(Date.now()).slice(-6)}`,
    keyLimit: toInt(process.env.KEY_LIMIT, 1000),
    existingEmail: (process.env.EXISTING_EMAIL || "").trim() || undefined,
    existingPassword: (process.env.EXISTING_PASSWORD || "").trim() || undefined,
    spoofIpHeader: (process.env.SPOOF_IP || "").trim() || undefined,
  };
}

async function run(): Promise<void> {
  const cfg = loadConfig();

  log(`start (headless=${cfg.headless})`);

  const allModels = await listModels(cfg);
  const resolvedModel = resolveModelName(cfg.preferredModel, allModels);
  log(`captcha model selected: ${resolvedModel}`);

  const solver = new CaptchaSolver(cfg, resolvedModel);
  const notes: string[] = [];

  let mailbox: DuckmailSession | null = null;
  let email = cfg.existingEmail || "";
  let password = cfg.existingPassword || "";

  if (email && password) {
    log(`existing account mode: ${email}`);
    notes.push("existing account mode enabled");
  } else {
    mailbox = await createDuckmailSession(cfg);
    email = mailbox.address;
    password = randomPassword();

    log(`duckmail mailbox: ${email}`);
    log(`generated password: ${password}`);
    notes.push(`duckmail mailbox created (${mailbox.accountId})`);
  }

  let verificationLink: string | null = null;
  let apiKey: string | null = null;

  const browser = await Camoufox({
    headless: cfg.headless,
    humanize: true,
    debug: false,
  });

  try {
    const page = await browser.newPage();
    const observedApiKeys = new Set<string>();
    const networkLog: Array<{ url: string; status: number; contentType: string; bodyPreview?: string }> = [];

    page.on("response", async (resp: any) => {
      try {
        const url = String(resp.url?.() || "");
        if (!/https?:\/\/(app|auth)\.tavily\.com/i.test(url)) return;
        if (/\.(?:css|js|png|jpg|jpeg|webp|gif|svg|woff2?|ttf|ico)(?:\?|$)/i.test(url)) return;

        const status = Number(resp.status?.() || 0);
        const headers = resp.headers?.() || {};
        const contentType = String(headers["content-type"] || "");
        const shouldSampleBody = /\/api\/|json|text\//i.test(`${url} ${contentType}`);
        let bodyText = "";
        if (shouldSampleBody) {
          bodyText = await resp.text();
        }

        const bodyPreview = bodyText ? bodyText.slice(0, 600) : undefined;
        networkLog.push({ url, status, contentType, bodyPreview });
        if (networkLog.length > 240) networkLog.shift();

        if (status >= 400 && !/\/api\//i.test(url)) return;
        if (!shouldSampleBody) return;

        const matches = bodyText.match(/tvly-[A-Za-z0-9_-]{8,}/g) || [];
        for (const m of matches) observedApiKeys.add(m);
      } catch {
        // ignore response sampling errors
      }
    });

    const headers: Record<string, string> = {
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    };
    if (!cfg.existingEmail || !cfg.existingPassword) {
      const spoofIp = cfg.spoofIpHeader || randomPublicIpv4();
      log(`using spoof ip headers: ${spoofIp}`);
      headers["X-Forwarded-For"] = spoofIp;
      headers["X-Real-IP"] = spoofIp;
      headers["CF-Connecting-IP"] = spoofIp;
    }
    await page.setExtraHTTPHeaders(headers);

    if (cfg.existingEmail && cfg.existingPassword) {
      notes.push("skip signup (existing account)");
    } else {
      await completeSignup(page, solver, email, password, cfg);
      notes.push("signup flow submitted");

      verificationLink = await waitForVerificationLink(mailbox!, cfg.emailWaitMs, cfg.duckmailPollMs);
      if (verificationLink) {
        log("verification link found");
        await safeGoto(page, verificationLink, 120000);
        await page.waitForTimeout(2000);
        notes.push("email verification link opened");
      } else {
        notes.push("verification email not found within timeout");
      }
    }

    await loginAndReachHome(page, solver, email, password, cfg);
    notes.push("reached app home");
    log(`current page before api key: ${page.url()}`);

    let lastKeyError: Error | null = null;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      try {
        const sampled = Array.from(observedApiKeys).find((key) => isLikelyTavilyKey(key));
        if (sampled) {
          apiKey = sampled;
          break;
        }

        await loginAndReachHome(page, solver, email, password, cfg);
        await page.waitForTimeout(1500);
        if (attempt === 1) {
          await writeFile(new URL("home.html", OUTPUT_DIR), await page.content(), "utf8");
          await writeJson(new URL("network.json", OUTPUT_DIR), networkLog.slice(-120));
        }

        apiKey = await getDefaultApiKey(page, cfg);
        if (apiKey) break;

        const sampledAfter = Array.from(observedApiKeys).find((key) => isLikelyTavilyKey(key));
        if (sampledAfter) {
          apiKey = sampledAfter;
          break;
        }

        log(`api key not found on attempt ${attempt}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (
          /Execution context was destroyed|Target closed|Navigation|Cannot find context/i.test(message) &&
          attempt < 5
        ) {
          log(`api key fetch retry after navigation/context reset (attempt=${attempt})`);
          await loginAndReachHome(page, solver, email, password, cfg);
          await page.waitForTimeout(1200);
          continue;
        }
        lastKeyError = error instanceof Error ? error : new Error(message);
        break;
      }
    }

    if (lastKeyError) {
      throw lastKeyError;
    }
    if (apiKey) {
      log("default api key fetched");
      notes.push("default api key fetched");
    } else {
      throw new Error("default api key missing from app responses");
    }
  } finally {
    await browser.close();
  }

  const result: ResultPayload = {
    email,
    password,
    verificationLink,
    apiKey,
    model: resolvedModel,
    notes,
  };

  await writeJson(new URL("result.json", OUTPUT_DIR), result);
  log("saved output/result.json");

  console.log(`ACCOUNT=${email}`);
  console.log(`PASSWORD=${password}`);
  console.log(`DEFAULT_API_KEY=${apiKey}`);
}

async function main(): Promise<void> {
  try {
    await run();
  } catch (error) {
    const message = error instanceof Error ? error.stack || error.message : String(error);
    console.error(`[${ts()}] fatal: ${message}`);
    await writeJson(new URL("error.json", OUTPUT_DIR), {
      failedAt: new Date().toISOString(),
      error: message,
    });
    process.exitCode = 1;
  }
}

await main();
