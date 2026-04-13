import { afterEach, describe, expect, test } from "bun:test";
import { solveTurnstileToken } from "../src/server/grok-turnstile";

const originalFetch = globalThis.fetch;
const envBackup = { ...process.env };

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const key of Object.keys(process.env)) {
    if (!(key in envBackup)) {
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(envBackup)) {
    process.env[key] = value;
  }
});

describe("grok turnstile", () => {
  test("reports local solver failure when solver returns CAPTCHA_FAIL", async () => {
    process.env.GROK_TURNSTILE_LOCAL_MAX_TASKS = "1";
    process.env.LOCAL_TURNSTILE_POLL_INITIAL_DELAY = "0";
    process.env.LOCAL_TURNSTILE_POLL_RETRY_DELAY = "0";
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("http://127.0.0.1:5072/turnstile?")) {
        return new Response(JSON.stringify({ taskId: "task-1" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "http://127.0.0.1:5072/result?id=task-1") {
        return new Response(JSON.stringify({ solution: { token: "CAPTCHA_FAIL" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    await expect(
      solveTurnstileToken({
        siteUrl: "https://accounts.x.ai",
        siteKey: "site-key",
      }),
    ).rejects.toThrow("grok_turnstile_failed:local_solver_failed:CAPTCHA_FAIL");
  });

  test("retries local solver tasks before failing", async () => {
    process.env.GROK_TURNSTILE_LOCAL_MAX_TASKS = "2";
    process.env.LOCAL_TURNSTILE_POLL_INITIAL_DELAY = "0";
    process.env.LOCAL_TURNSTILE_POLL_RETRY_DELAY = "0";
    const calls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.startsWith("http://127.0.0.1:5072/turnstile?")) {
        const taskId = calls.filter((item) => item.startsWith("http://127.0.0.1:5072/turnstile?")).length;
        return new Response(JSON.stringify({ taskId: `task-${taskId}` }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "http://127.0.0.1:5072/result?id=task-1") {
        return new Response(JSON.stringify({ solution: { token: "CAPTCHA_FAIL" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "http://127.0.0.1:5072/result?id=task-2") {
        return new Response(JSON.stringify({ solution: { token: "solver-token-2" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected_url:${url}`);
    }) as typeof fetch;

    const result = await solveTurnstileToken({
      siteUrl: "https://accounts.x.ai",
      siteKey: "site-key",
    });
    expect(result).toEqual({ token: "solver-token-2", provider: "turnstile_local" });
  });
});
