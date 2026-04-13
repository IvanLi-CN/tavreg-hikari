import process from "node:process";

interface LocalSolverTaskResponse {
  taskId?: string | number;
  token?: string;
  solution?: { token?: string };
  value?: string;
  errorId?: number;
  errorCode?: string;
  errorDescription?: string;
}

interface YesCaptchaResponse {
  errorId?: number;
  errorCode?: string;
  errorDescription?: string;
  taskId?: number;
  solution?: { token?: string };
  status?: string;
}

type LocalSolverOutcome =
  | { status: "solved"; token: string }
  | { status: "failed"; reason: string }
  | { status: "unavailable"; reason: string };

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeUrl(raw: string, fallback: string): string {
  const normalized = String(raw || "").trim() || fallback;
  return normalized.replace(/\/+$/, "");
}

function extractLocalToken(payload: LocalSolverTaskResponse | null | undefined): string | null {
  const candidates = [payload?.solution?.token, payload?.token, payload?.value];
  for (const candidate of candidates) {
    const normalized = typeof candidate === "string" ? candidate.trim() : "";
    if (normalized && normalized !== "CAPTCHA_FAIL") {
      return normalized;
    }
  }
  return null;
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    method: "GET",
  });
  const payload = (await response.json().catch(() => null)) as T | null;
  if (!response.ok) {
    throw new Error(`http_failed:${response.status}:${JSON.stringify(payload)}`);
  }
  return payload as T;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const payload = (await response.json().catch(() => null)) as T | null;
  if (!response.ok) {
    throw new Error(`http_failed:${response.status}:${JSON.stringify(payload)}`);
  }
  return payload as T;
}

async function solveWithLocalSolverOnce(input: {
  siteUrl: string;
  siteKey: string;
  action?: string | null;
  cdata?: string | null;
  solverUrl?: string | null;
}): Promise<LocalSolverOutcome> {
  const solverUrl = normalizeUrl(input.solverUrl || process.env.TURNSTILE_SOLVER_URL || "", "http://127.0.0.1:5072");
  const params = new URLSearchParams({
    url: input.siteUrl,
    sitekey: input.siteKey,
  });
  if (input.action?.trim()) params.set("action", input.action.trim());
  if (input.cdata?.trim()) params.set("cdata", input.cdata.trim());
  let created: LocalSolverTaskResponse;
  try {
    created = await getJson<LocalSolverTaskResponse>(`${solverUrl}/turnstile?${params.toString()}`);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return { status: "unavailable", reason };
  }
  if (created.errorId) {
    return {
      status: "failed",
      reason: created.errorDescription || created.errorCode || "turnstile_local_create_failed",
    };
  }
  const taskId = String(created.taskId || "").trim();
  if (!taskId) {
    const immediate = extractLocalToken(created);
    if (immediate) return { status: "solved", token: immediate };
    return { status: "failed", reason: "turnstile_local_task_id_missing" };
  }
  const maxRetries = Math.max(1, Number.parseInt(String(process.env.LOCAL_TURNSTILE_POLL_MAX_RETRIES || "50"), 10) || 50);
  const initialDelay = Math.max(0, Number.parseInt(String(process.env.LOCAL_TURNSTILE_POLL_INITIAL_DELAY || "2"), 10) || 2);
  const retryDelay = Math.max(1, Number.parseInt(String(process.env.LOCAL_TURNSTILE_POLL_RETRY_DELAY || "2"), 10) || 2);
  if (initialDelay > 0) {
    await sleep(initialDelay * 1_000);
  }
  for (let index = 0; index < maxRetries; index += 1) {
    let result: LocalSolverTaskResponse;
    try {
      result = await getJson<LocalSolverTaskResponse>(`${solverUrl}/result?id=${encodeURIComponent(taskId)}`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return { status: "unavailable", reason };
    }
    if (result.errorId) {
      return {
        status: "failed",
        reason: result.errorDescription || result.errorCode || "turnstile_local_result_failed",
      };
    }
    const token = extractLocalToken(result);
    if (token) return { status: "solved", token };
    if (String(result.token || result.value || result.solution?.token || "").trim() === "CAPTCHA_FAIL") {
      return { status: "failed", reason: "CAPTCHA_FAIL" };
    }
    await sleep(retryDelay * 1_000);
  }
  return { status: "failed", reason: "turnstile_local_timeout" };
}

async function solveWithYesCaptcha(input: { siteUrl: string; siteKey: string; clientKey: string }): Promise<string | null> {
  const apiBase = "https://api.yescaptcha.com";
  const createResponse = await postJson<YesCaptchaResponse>(`${apiBase}/createTask`, {
    clientKey: input.clientKey,
    task: {
      type: "TurnstileTaskProxyless",
      websiteURL: input.siteUrl,
      websiteKey: input.siteKey,
    },
  });
  if (createResponse.errorId && createResponse.errorId !== 0) {
    throw new Error(createResponse.errorDescription || createResponse.errorCode || "yescaptcha_create_failed");
  }
  const taskId = Number(createResponse.taskId || 0);
  if (!Number.isInteger(taskId) || taskId <= 0) {
    throw new Error("yescaptcha_task_id_missing");
  }
  for (let index = 0; index < 45; index += 1) {
    await sleep(2_000);
    const result = await postJson<YesCaptchaResponse>(`${apiBase}/getTaskResult`, {
      clientKey: input.clientKey,
      taskId,
    });
    if (result.errorId && result.errorId !== 0) {
      throw new Error(result.errorDescription || result.errorCode || "yescaptcha_result_failed");
    }
    if (result.status === "processing") {
      continue;
    }
    const token = typeof result.solution?.token === "string" ? result.solution.token.trim() : "";
    if (token) {
      return token;
    }
  }
  return null;
}

export async function solveTurnstileToken(input: {
  siteUrl: string;
  siteKey: string;
  action?: string | null;
  cdata?: string | null;
  solverUrl?: string | null;
  yesCaptchaKey?: string | null;
}): Promise<{ token: string; provider: "turnstile_local" | "yescaptcha" }> {
  const localTaskMax = Math.max(
    1,
    Number.parseInt(String(process.env.GROK_TURNSTILE_LOCAL_MAX_TASKS || "2"), 10) || 2,
  );
  let lastLocalOutcome: LocalSolverOutcome | null = null;
  for (let attempt = 1; attempt <= localTaskMax; attempt += 1) {
    const localOutcome = await solveWithLocalSolverOnce(input);
    lastLocalOutcome = localOutcome;
    if (localOutcome.status === "solved") {
      return { token: localOutcome.token, provider: "turnstile_local" };
    }
    if (localOutcome.status === "unavailable") {
      break;
    }
  }
  const yesCaptchaKey = String(input.yesCaptchaKey || process.env.YESCAPTCHA_KEY || "").trim();
  if (!yesCaptchaKey) {
    if (lastLocalOutcome?.status === "failed") {
      throw new Error(`grok_turnstile_failed:local_solver_failed:${lastLocalOutcome.reason}`);
    }
    const unavailableReason = lastLocalOutcome?.status === "unavailable" ? `:${lastLocalOutcome.reason}` : "";
    throw new Error(`grok_turnstile_failed:local_solver_unavailable${unavailableReason}`);
  }
  const token = await solveWithYesCaptcha({
    siteUrl: input.siteUrl,
    siteKey: input.siteKey,
    clientKey: yesCaptchaKey,
  });
  if (!token) {
    throw new Error("grok_turnstile_failed:yescaptcha_unavailable");
  }
  return { token, provider: "yescaptcha" };
}
