import { afterEach, expect, test } from "bun:test";

import { ProxyBrokerClient, ProxyBrokerError } from "../src/proxy/broker";
import { buildProxyBrokerConfig, openProxyBrokerRuntimeSession } from "../src/server/proxy-broker-runtime";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function createClient() {
  return new ProxyBrokerClient({
    baseUrl: "https://proxy-broker.example.test/",
    profileId: "Tavily",
    apiKey: "pbk_test_secret",
    timeoutMs: 1000,
  });
}

test("proxy broker client sends bearer auth and joins api paths", async () => {
  const seen: Array<{ url: string; authorization: string | null }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    seen.push({
      url: String(url),
      authorization: headers.get("authorization"),
    });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;

  await createClient().authMe();

  expect(seen).toEqual([
    {
      url: "https://proxy-broker.example.test/api/v1/auth/me",
      authorization: "Bearer pbk_test_secret",
    },
  ]);
});

test("proxy broker client opens lists and closes project sessions", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const rawBody = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body: rawBody });
    if (String(url).endsWith("/sessions/open")) {
      return Response.json({
        session_id: "sess_1",
        profile_id: "Tavily",
        node_id: "node_1",
        proxy_name: "Tokyo-01",
        selected_ip: "203.0.113.10",
        display_address: "127.0.0.1:43123",
        listener_type: "mixed",
        status: "active",
        opened_at: "2026-05-09T00:00:00.000Z",
        last_used_at: null,
      });
    }
    return Response.json([]);
  }) as unknown as typeof fetch;

  const client = createClient();
  const opened = await client.openSession({ selection_mode: "ip", specified_ips: ["203.0.113.10"] });
  const listed = await client.listSessions();
  await client.closeSession("sess_1");

  expect(opened.session_id).toBe("sess_1");
  expect(listed.sessions).toEqual([]);
  expect(client.proxyUrl(opened)).toBe("http://127.0.0.1:43123");
  expect(requests).toEqual([
    {
      method: "POST",
      url: "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/open",
      body: {
        selection_mode: "ip",
        specified_ips: ["203.0.113.10"],
        excluded_ips: [],
        country_codes: [],
        cities: [],
        sort_mode: "lru",
        desired_port: null,
      },
    },
    {
      method: "GET",
      url: "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions",
      body: null,
    },
    {
      method: "DELETE",
      url: "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/sess_1",
      body: null,
    },
  ]);
});

test("proxy broker client normalizes bare-array session lists", async () => {
  globalThis.fetch = (async () =>
    Response.json([
      {
        session_id: "sess_array",
        node_id: "node_array",
        proxy_name: "Tokyo-Array",
        selected_ip: "203.0.113.12",
        display_address: "127.0.0.1:43125",
      },
    ])) as unknown as typeof fetch;

  const listed = await createClient().listSessions();

  expect(listed.sessions).toEqual([
    expect.objectContaining({
      session_id: "sess_array",
      display_address: "127.0.0.1:43125",
    }),
  ]);
});

test("proxy broker client maps auth and server failures", async () => {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ error: "nope" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;

  try {
    await createClient().listCatalog();
    throw new Error("expected listCatalog to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(ProxyBrokerError);
    expect((error as ProxyBrokerError).status).toBe(401);
    expect((error as ProxyBrokerError).code).toBe("unauthorized");
  }

  globalThis.fetch = (async () =>
    new Response("gateway down", {
      status: 502,
      headers: { "content-type": "text/plain" },
    })) as unknown as typeof fetch;

  try {
    await createClient().listSessions();
    throw new Error("expected listSessions to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(ProxyBrokerError);
    expect((error as ProxyBrokerError).status).toBe(502);
    expect((error as ProxyBrokerError).code).toBe("server_error");
  }
});

test("proxy broker client requires base url and api key", async () => {
  const client = new ProxyBrokerClient({
    baseUrl: "",
    profileId: "Tavily",
    apiKey: "",
    timeoutMs: 1000,
  });

  await expect(client.authMe()).rejects.toBeInstanceOf(ProxyBrokerError);
});

test("proxy broker runtime falls back when preferred ip cannot open", async () => {
  const bodies: unknown[] = [];
  globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    bodies.push(body);
    if (bodies.length === 1) {
      return new Response(JSON.stringify({ code: "not_found", message: "preferred ip unavailable" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
    return Response.json({
      session_id: "sess_fallback",
      listen: "127.0.0.1:43124",
      bind_host: "127.0.0.1",
      display_host: "127.0.0.1",
      display_address: "127.0.0.1:43124",
      port: 43124,
      selected_ip: "203.0.113.20",
      proxy_name: "Osaka-02",
      node_id: "node_osaka_02",
    });
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    const runtime = await openProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://proxy-broker.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
      },
      preferredIp: "203.0.113.10",
    });

    expect(runtime.session.session_id).toBe("sess_fallback");
    expect(bodies).toEqual([
      {
        selection_mode: "ip",
        specified_ips: ["203.0.113.10"],
        excluded_ips: [],
        country_codes: [],
        cities: [],
        sort_mode: "lru",
        desired_port: null,
      },
      {
        selection_mode: "any",
        specified_ips: [],
        excluded_ips: [],
        country_codes: [],
        cities: [],
        sort_mode: "lru",
        desired_port: null,
      },
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime can require an exact preferred ip", async () => {
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(JSON.stringify({ code: "not_found", message: "preferred ip unavailable" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    await expect(
      openProxyBrokerRuntimeSession({
        settings: {
          proxyBrokerBaseUrl: "https://ignored.example.test",
          proxyBrokerProfileId: "Tavily",
          timeoutMs: 1000,
        },
        preferredIp: "203.0.113.10",
        fallbackOnPreferredIpFailure: false,
      }),
    ).rejects.toBeInstanceOf(ProxyBrokerError);
    expect(calls).toBe(1);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime excludes catalog nodes by name pattern", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json({
        view: "global",
        profile_id: "Tavily",
        groups: [
          {
            import: { import_id: "imp_1", proxy_count: 2, distinct_ip_count: 2 },
            nodes: [
              {
                import_id: "imp_1",
                node_id: "hk_1",
                proxy_name: "Hong Kong-01",
                proxy_type: "ss",
                server: "hk.example",
                resolved_ips: ["198.51.100.10"],
                primary_ip: "198.51.100.11",
                can_open_session: true,
              },
            ],
          },
        ],
      });
    }
    return Response.json({
      session_id: "sess_1",
      listen: "127.0.0.1:43124",
      bind_host: "127.0.0.1",
      display_host: "127.0.0.1",
      display_address: "127.0.0.1:43124",
      port: 43124,
      selected_ip: "203.0.113.20",
      proxy_name: "Tokyo-01",
      node_id: "node_tokyo_01",
    });
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    await openProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://ignored.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
      },
      excludedIps: ["203.0.113.30"],
      excludedNodeNamePattern: /hong\s*kong/i,
    });
    expect(requests[0]?.url).toBe("https://ignored.example.test/api/v1/proxy-catalog?profile_id=Tavily");
    expect(requests[1]?.body).toMatchObject({
      excluded_ips: ["203.0.113.30", "198.51.100.11", "198.51.100.10"],
    });
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime still opens sessions when catalog is admin-only", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json({ code: "forbidden", message: "admin access required" }, { status: 403 });
    }
    return Response.json({
      session_id: "sess_without_catalog",
      display_address: "127.0.0.1:43126",
      selected_ip: "203.0.113.26",
      proxy_name: "Tokyo-26",
      node_id: "node_tokyo_26",
    });
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    const runtime = await openProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://proxy-broker.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
      },
      excludedNodeNamePattern: /hong\s*kong/i,
    });

    expect(runtime.session.session_id).toBe("sess_without_catalog");
    expect(requests.map((request) => request.url)).toEqual([
      "https://proxy-broker.example.test/api/v1/proxy-catalog?profile_id=Tavily",
      "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/open",
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker config lets dedicated timeout env override app default", () => {
  const previousTimeout = process.env.PROXY_BROKER_TIMEOUT_MS;
  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_TIMEOUT_MS = "12000";
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    expect(
      buildProxyBrokerConfig({
        proxyBrokerBaseUrl: "https://proxy-broker.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 8000,
      }),
    ).toMatchObject({
      timeoutMs: 12000,
      apiKey: "pbk_test_secret",
    });
  } finally {
    if (previousTimeout == null) {
      delete process.env.PROXY_BROKER_TIMEOUT_MS;
    } else {
      process.env.PROXY_BROKER_TIMEOUT_MS = previousTimeout;
    }
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker config honors persisted base url when env is absent", () => {
  const previousBaseUrl = process.env.PROXY_BROKER_BASE_URL;
  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  delete process.env.PROXY_BROKER_BASE_URL;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    expect(
      buildProxyBrokerConfig({
        proxyBrokerBaseUrl: "https://proxy-broker.persisted.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 8000,
      }),
    ).toMatchObject({
      baseUrl: "https://proxy-broker.persisted.example.test",
      apiKey: "pbk_test_secret",
    });
  } finally {
    if (previousBaseUrl == null) {
      delete process.env.PROXY_BROKER_BASE_URL;
    } else {
      process.env.PROXY_BROKER_BASE_URL = previousBaseUrl;
    }
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker config lets profile env override persisted default", () => {
  const previousProfileId = process.env.PROXY_BROKER_PROFILE_ID;
  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_PROFILE_ID = "prod";
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    expect(
      buildProxyBrokerConfig({
        proxyBrokerBaseUrl: "https://proxy-broker.persisted.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 8000,
      }),
    ).toMatchObject({
      profileId: "prod",
      apiKey: "pbk_test_secret",
    });
  } finally {
    if (previousProfileId == null) {
      delete process.env.PROXY_BROKER_PROFILE_ID;
    } else {
      process.env.PROXY_BROKER_PROFILE_ID = previousProfileId;
    }
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});
