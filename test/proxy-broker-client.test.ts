import { afterEach, expect, test } from "bun:test";

import { ProxyBrokerClient, ProxyBrokerError } from "../src/proxy/broker";
import {
  buildProxyBrokerConfig,
  openDomainProbedProxyBrokerRuntimeSession,
  openProxyBrokerRuntimeSession,
  ProxyBrokerDomainProbeError,
  reusableBrowserSessionProxyIp,
} from "../src/server/proxy-broker-runtime";

const originalFetch = globalThis.fetch;
const originalDisplayHostOverride = process.env.PROXY_BROKER_DISPLAY_HOST_OVERRIDE;

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDisplayHostOverride == null) {
    delete process.env.PROXY_BROKER_DISPLAY_HOST_OVERRIDE;
  } else {
    process.env.PROXY_BROKER_DISPLAY_HOST_OVERRIDE = originalDisplayHostOverride;
  }
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
        project_id: "Tavily",
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

test("proxy broker client can override session display host for external local runs", async () => {
  process.env.PROXY_BROKER_DISPLAY_HOST_OVERRIDE = "192.168.31.11";
  const client = createClient();

  expect(client.proxyUrl({ display_address: "proxy-broker:20000" })).toBe("http://192.168.31.11:20000");
});

test("proxy broker client refreshes project probe metadata", async () => {
  const requests: Array<{ method: string; url: string; body: unknown; authorization: string | null }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    requests.push({
      method: init?.method || "GET",
      url: String(url),
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null,
      authorization: headers.get("authorization"),
    });
    return Response.json({ probed_ips: 12, geo_updated: 3, skipped_cached: 9 });
  }) as unknown as typeof fetch;

  const refreshed = await createClient().refreshProject();

  expect(refreshed).toMatchObject({ probed_ips: 12, geo_updated: 3, skipped_cached: 9 });
  expect(requests).toEqual([
    {
      method: "POST",
      url: "https://proxy-broker.example.test/api/v1/projects/Tavily/refresh",
      body: {},
      authorization: "Bearer pbk_test_secret",
    },
  ]);
});

function freshProbeTime(): string {
  return new Date().toISOString();
}

function staleProbeTime(): string {
  return new Date(Date.now() - 60 * 60 * 1000).toISOString();
}

function brokerCatalog(nodes: Array<Record<string, unknown>>) {
  return {
    view: "project",
    project_id: "Tavily",
    groups: [
      {
        import: { import_id: "imp_1", proxy_count: nodes.length, distinct_ip_count: nodes.length },
        nodes,
      },
    ],
  };
}

function healthyNode(input: { nodeId: string; name: string; ip: string; latencyMs?: number; probeUpdatedAt?: string; canOpen?: boolean }) {
  return {
    import_id: "imp_1",
    node_id: input.nodeId,
    proxy_name: input.name,
    proxy_type: "ss",
    server: `${input.nodeId}.example`,
    resolved_ips: [input.ip],
    primary_ip: input.ip,
    can_open_session: input.canOpen ?? true,
    ip_metadata: [
      {
        ip: input.ip,
        last_probe_ok: true,
        last_latency_ms: input.latencyMs ?? 220,
        median_latency_ms: input.latencyMs ?? 220,
        probe_updated_at: input.probeUpdatedAt ?? freshProbeTime(),
      },
    ],
  };
}

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

test("proxy broker client classifies aborted requests as timeouts", async () => {
  globalThis.fetch = (async () => {
    throw new DOMException("The operation was aborted.", "AbortError");
  }) as unknown as typeof fetch;

  try {
    await createClient().listCatalog();
    throw new Error("expected listCatalog to time out");
  } catch (error) {
    expect(error).toBeInstanceOf(ProxyBrokerError);
    expect((error as ProxyBrokerError).code).toBe("proxy_broker_request_timeout");
    expect((error as ProxyBrokerError).message).toContain("timed out after 1000ms");
    expect((error as ProxyBrokerError).details).toMatchObject({
      method: "GET",
      path: "/api/v1/proxy-catalog",
      timeoutMs: 1000,
    });
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

test("proxy broker runtime defaults API timeout to 30 seconds and only reuses ready session IPs", () => {
  const previousTimeout = process.env.PROXY_BROKER_TIMEOUT_MS;
  delete process.env.PROXY_BROKER_TIMEOUT_MS;
  try {
    const cfg = buildProxyBrokerConfig({
      proxyBrokerBaseUrl: "https://proxy-broker.example.test",
      proxyBrokerProfileId: "Tavily",
      timeoutMs: 8000,
    });

    expect(cfg.timeoutMs).toBe(30000);
    expect(reusableBrowserSessionProxyIp({ status: "ready", proxyIp: " 203.0.113.10 " } as never)).toBe("203.0.113.10");
    expect(reusableBrowserSessionProxyIp({ status: "failed", proxyIp: "203.0.113.11" } as never)).toBeNull();
    expect(reusableBrowserSessionProxyIp({ status: "blocked", proxyIp: "203.0.113.12" } as never)).toBeNull();
  } finally {
    if (previousTimeout == null) {
      delete process.env.PROXY_BROKER_TIMEOUT_MS;
    } else {
      process.env.PROXY_BROKER_TIMEOUT_MS = previousTimeout;
    }
  }
});

test("proxy broker runtime falls back when preferred ip cannot open", async () => {
  const requests: Array<{ url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "preferred", name: "Preferred", ip: "203.0.113.10" }),
        healthyNode({ nodeId: "fallback", name: "Fallback", ip: "203.0.113.20" }),
      ]));
    }
    if (requests.filter((request) => request.url.endsWith("/sessions/open")).length === 1) {
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
        maxLatencyMs: 500,
      },
      preferredIp: "203.0.113.10",
    });

    expect(runtime.session.session_id).toBe("sess_fallback");
    expect(requests.map((request) => request.body).filter(Boolean)).toEqual([
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
        selection_mode: "ip",
        specified_ips: ["203.0.113.20"],
        excluded_ips: ["203.0.113.10"],
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

test("proxy broker runtime retries another healthy ip after broker open timeout", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "first", name: "First", ip: "203.0.113.10" }),
        healthyNode({ nodeId: "second", name: "Second", ip: "203.0.113.20" }),
      ]));
    }
    if (requests.filter((request) => request.url.endsWith("/sessions/open")).length === 1) {
      throw new DOMException("The operation was aborted.", "AbortError");
    }
    return Response.json({
      session_id: "sess_second",
      listen: "127.0.0.1:43124",
      bind_host: "127.0.0.1",
      display_host: "127.0.0.1",
      display_address: "127.0.0.1:43124",
      port: 43124,
      selected_ip: "203.0.113.20",
      proxy_name: "Second",
      node_id: "second",
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
        maxLatencyMs: 500,
      },
    });

    expect(runtime.session.session_id).toBe("sess_second");
    expect(requests.filter((request) => request.method === "POST").map((request) => request.body)).toEqual([
      expect.objectContaining({ specified_ips: ["203.0.113.10"], excluded_ips: [] }),
      expect.objectContaining({ specified_ips: ["203.0.113.20"], excluded_ips: ["203.0.113.10"] }),
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime keeps retrying all healthy catalog candidates by default", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "node-1", name: "Node 1", ip: "203.0.113.10" }),
        healthyNode({ nodeId: "node-2", name: "Node 2", ip: "203.0.113.20" }),
        healthyNode({ nodeId: "node-3", name: "Node 3", ip: "203.0.113.30" }),
        healthyNode({ nodeId: "node-4", name: "Node 4", ip: "203.0.113.40" }),
      ]));
    }
    const openCount = requests.filter((request) => request.url.endsWith("/sessions/open")).length;
    if (openCount < 4) {
      throw new DOMException("The operation was aborted.", "AbortError");
    }
    return Response.json({
      session_id: "sess_fourth",
      listen: "127.0.0.1:43124",
      bind_host: "127.0.0.1",
      display_host: "127.0.0.1",
      display_address: "127.0.0.1:43124",
      port: 43124,
      selected_ip: "203.0.113.40",
      proxy_name: "Node 4",
      node_id: "node-4",
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
        maxLatencyMs: 500,
      },
    });

    expect(runtime.session.session_id).toBe("sess_fourth");
    expect(requests.filter((request) => request.method === "POST").map((request) => request.body)).toEqual([
      expect.objectContaining({ specified_ips: ["203.0.113.10"], excluded_ips: [] }),
      expect.objectContaining({ specified_ips: ["203.0.113.20"], excluded_ips: ["203.0.113.10"] }),
      expect.objectContaining({ specified_ips: ["203.0.113.30"], excluded_ips: ["203.0.113.10", "203.0.113.20"] }),
      expect.objectContaining({ specified_ips: ["203.0.113.40"], excluded_ips: ["203.0.113.10", "203.0.113.20", "203.0.113.30"] }),
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime closes and rotates sessions when business domain probing fails", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  const sessions = [
    {
      session_id: "sess_bad",
      display_address: "127.0.0.1:43123",
      selected_ip: "203.0.113.10",
      proxy_name: "Singapore-04",
      node_id: "node_sg_04",
    },
    {
      session_id: "sess_good",
      display_address: "127.0.0.1:43124",
      selected_ip: "203.0.113.20",
      proxy_name: "Singapore-05",
      node_id: "node_sg_05",
    },
  ];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "sg_04", name: "Singapore-04", ip: "203.0.113.10" }),
        healthyNode({ nodeId: "sg_05", name: "Singapore-05", ip: "203.0.113.20" }),
      ]));
    }
    if (method === "DELETE") {
      return Response.json({ ok: true });
    }
    return Response.json(sessions.shift());
  }) as unknown as typeof fetch;

  const probeCalls: Array<{ proxyUrl: string; url: string }> = [];
  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    const runtime = await openDomainProbedProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://proxy-broker.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
        maxLatencyMs: 500,
      },
      businessSite: "chatgpt",
      probeFetch: async ({ proxyUrl, url }) => {
        probeCalls.push({ proxyUrl, url });
        if (proxyUrl === "http://127.0.0.1:43123") {
          throw new Error("ERR_PROXY_CONNECTION_FAILED");
        }
        return { status: 403 };
      },
    });

    expect(runtime.session.session_id).toBe("sess_good");
    expect(probeCalls).toEqual([
      { proxyUrl: "http://127.0.0.1:43123", url: "https://chatgpt.com/" },
      { proxyUrl: "http://127.0.0.1:43124", url: "https://chatgpt.com/" },
      { proxyUrl: "http://127.0.0.1:43124", url: "https://auth.openai.com/" },
    ]);
    expect(requests).toEqual([
      {
        method: "GET",
        url: "https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
        body: null,
      },
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
        method: "DELETE",
        url: "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/sess_bad",
        body: null,
      },
      {
        method: "GET",
        url: "https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
        body: null,
      },
      {
        method: "POST",
        url: "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/open",
        body: {
          selection_mode: "ip",
          specified_ips: ["203.0.113.20"],
          excluded_ips: ["203.0.113.10"],
          country_codes: [],
          cities: [],
          sort_mode: "lru",
          desired_port: null,
        },
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

test("proxy broker runtime reports proxy_domain_unreachable after probe rotations are exhausted", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  const sessions = [
    {
      session_id: "sess_fail_1",
      display_address: "127.0.0.1:43123",
      selected_ip: "203.0.113.10",
      proxy_name: "Singapore-04",
      node_id: "node_sg_04",
    },
    {
      session_id: "sess_fail_2",
      display_address: "127.0.0.1:43124",
      selected_ip: "203.0.113.20",
      proxy_name: "Singapore-05",
      node_id: "node_sg_05",
    },
  ];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "sg_04", name: "Singapore-04", ip: "203.0.113.10" }),
        healthyNode({ nodeId: "sg_05", name: "Singapore-05", ip: "203.0.113.20" }),
      ]));
    }
    if (method === "DELETE") {
      return Response.json({ ok: true });
    }
    return Response.json(sessions.shift());
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    await expect(
      openDomainProbedProxyBrokerRuntimeSession({
        settings: {
          proxyBrokerBaseUrl: "https://proxy-broker.example.test",
          proxyBrokerProfileId: "Tavily",
          timeoutMs: 1000,
          maxLatencyMs: 500,
        },
        businessSite: "tavily",
        maxProbeRotations: 1,
        probeFetch: async () => {
          throw new Error("network timeout");
        },
      }),
    ).rejects.toMatchObject({
      code: "proxy_domain_unreachable",
      name: "proxy_domain_unreachable",
      attempts: 2,
      site: "tavily",
      url: "https://app.tavily.com/home",
    } satisfies Partial<ProxyBrokerDomainProbeError>);
    expect(requests.filter((request) => request.method === "DELETE").map((request) => request.url)).toEqual([
      "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/sess_fail_1",
      "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/sess_fail_2",
    ]);
    expect(requests.filter((request) => request.method === "POST").map((request) => request.body)).toEqual([
      expect.objectContaining({ excluded_ips: [] }),
      expect.objectContaining({ excluded_ips: ["203.0.113.10"] }),
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime does not rotate exact preferred ip after domain probe failure", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "sg_04", name: "Singapore-04", ip: "203.0.113.10" }),
        healthyNode({ nodeId: "sg_05", name: "Singapore-05", ip: "203.0.113.20" }),
      ]));
    }
    if (method === "DELETE") {
      return Response.json({ ok: true });
    }
    return Response.json({
      session_id: "sess_requested",
      display_address: "127.0.0.1:43123",
      selected_ip: "203.0.113.10",
      proxy_name: "Singapore-04",
      node_id: "node_sg_04",
    });
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    await expect(
      openDomainProbedProxyBrokerRuntimeSession({
        settings: {
          proxyBrokerBaseUrl: "https://proxy-broker.example.test",
          proxyBrokerProfileId: "Tavily",
          timeoutMs: 1000,
          maxLatencyMs: 500,
        },
        businessSite: "microsoft",
        preferredIp: "203.0.113.10",
        fallbackOnPreferredIpFailure: false,
        maxProbeRotations: 3,
        probeFetch: async () => {
          throw new Error("ERR_PROXY_CONNECTION_FAILED");
        },
      }),
    ).rejects.toMatchObject({
      code: "proxy_domain_unreachable",
      attempts: 1,
      sessionId: "sess_requested",
      selectedIp: "203.0.113.10",
    } satisfies Partial<ProxyBrokerDomainProbeError>);
    expect(requests.filter((request) => request.method === "DELETE").map((request) => request.url)).toEqual([
      "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/sess_requested",
    ]);
    expect(requests.filter((request) => request.method === "POST").map((request) => request.body)).toEqual([
      expect.objectContaining({ specified_ips: ["203.0.113.10"], excluded_ips: [] }),
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime preserves proxy_domain_unreachable when failed probes exhaust healthy candidates", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "sg_04", name: "Singapore-04", ip: "203.0.113.10" }),
      ]));
    }
    if (method === "DELETE") {
      return Response.json({ ok: true });
    }
    return Response.json({
      session_id: "sess_only_candidate",
      display_address: "127.0.0.1:43123",
      selected_ip: "203.0.113.10",
      proxy_name: "Singapore-04",
      node_id: "node_sg_04",
    });
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    await expect(
      openDomainProbedProxyBrokerRuntimeSession({
        settings: {
          proxyBrokerBaseUrl: "https://proxy-broker.example.test",
          proxyBrokerProfileId: "Tavily",
          timeoutMs: 1000,
          maxLatencyMs: 500,
        },
        businessSite: "grok",
        maxProbeRotations: 3,
        probeFetch: async () => {
          throw new Error("ERR_PROXY_CONNECTION_FAILED");
        },
      }),
    ).rejects.toMatchObject({
      code: "proxy_domain_unreachable",
      name: "proxy_domain_unreachable",
      attempts: 1,
      site: "grok",
      url: "https://grok.com/",
      sessionId: "sess_only_candidate",
      nodeName: "Singapore-04",
      selectedIp: "203.0.113.10",
    } satisfies Partial<ProxyBrokerDomainProbeError>);
    expect(requests.filter((request) => request.method === "DELETE").map((request) => request.url)).toEqual([
      "https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/sess_only_candidate",
    ]);
    expect(requests.filter((request) => request.url.endsWith("/sessions/open")).map((request) => request.body)).toEqual([
      expect.objectContaining({ specified_ips: ["203.0.113.10"], excluded_ips: [] }),
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
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (method === "POST" && String(url).endsWith("/sessions/open")) {
      return Response.json({
        session_id: "sess_exact",
        listen: "127.0.0.1:43124",
        bind_host: "127.0.0.1",
        display_host: "127.0.0.1",
        display_address: "127.0.0.1:43124",
        port: 43124,
        selected_ip: "203.0.113.10",
        proxy_name: "Preferred",
        node_id: "preferred",
      });
    }
    throw new Error(`unexpected request: ${method} ${String(url)}`);
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    const runtime = await openProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://ignored.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
        maxLatencyMs: 500,
      },
      preferredIp: "203.0.113.10",
      fallbackOnPreferredIpFailure: false,
    });
    expect(runtime.session.session_id).toBe("sess_exact");
    expect(requests.map((request) => request.method)).toEqual(["POST"]);
    expect(requests[0]?.body).toEqual(expect.objectContaining({
      selection_mode: "ip",
      specified_ips: ["203.0.113.10"],
      excluded_ips: [],
      sort_mode: "lru",
    }));
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
      return Response.json(brokerCatalog([
        {
          ...healthyNode({ nodeId: "hk_1", name: "Hong Kong-01", ip: "198.51.100.11" }),
          resolved_ips: ["198.51.100.10"],
          primary_ip: "198.51.100.11",
        },
        healthyNode({ nodeId: "tokyo_1", name: "Tokyo-01", ip: "203.0.113.20" }),
      ]));
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
        maxLatencyMs: 500,
      },
      excludedIps: ["203.0.113.30"],
      excludedNodeNamePattern: /hong\s*kong/i,
    });
    expect(requests[0]?.url).toBe("https://ignored.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily");
    expect(requests[1]?.body).toMatchObject({
      excluded_ips: ["203.0.113.30", "198.51.100.11", "198.51.100.10"],
      specified_ips: ["203.0.113.20"],
    });
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime fails clearly when catalog is not readable", async () => {
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
    await expect(openProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://proxy-broker.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
        maxLatencyMs: 500,
      },
      excludedNodeNamePattern: /hong\s*kong/i,
    })).rejects.toBeInstanceOf(ProxyBrokerError);

    expect(requests.map((request) => request.url)).toEqual([
      "https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime refreshes stale probes before opening a healthy session", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  let catalogCalls = 0;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      catalogCalls += 1;
      return Response.json(brokerCatalog([
        healthyNode({
          nodeId: "tokyo_1",
          name: "Tokyo-01",
          ip: "203.0.113.20",
          probeUpdatedAt: catalogCalls === 1 ? staleProbeTime() : freshProbeTime(),
        }),
      ]));
    }
    if (String(url).endsWith("/refresh")) {
      return Response.json({ probed_ips: 1, geo_updated: 0, skipped_cached: 0 });
    }
    return Response.json({
      session_id: "sess_refreshed",
      display_address: "127.0.0.1:43127",
      selected_ip: "203.0.113.20",
      proxy_name: "Tokyo-01",
      node_id: "tokyo_1",
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
        maxLatencyMs: 500,
      },
    });

    expect(runtime.session.session_id).toBe("sess_refreshed");
    expect(requests.map((request) => `${request.method} ${request.url}`)).toEqual([
      "GET https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
      "POST https://proxy-broker.example.test/api/v1/projects/Tavily/refresh",
      "GET https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
      "POST https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/open",
    ]);
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime refreshes mixed fresh and stale catalogs before opening", async () => {
  const requests: Array<{ method: string; url: string; body: unknown }> = [];
  let catalogCalls = 0;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method || "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    requests.push({ method, url: String(url), body });
    if (String(url).includes("/proxy-catalog")) {
      catalogCalls += 1;
      return Response.json(brokerCatalog([
        healthyNode({
          nodeId: "fresh_1",
          name: "Fresh-01",
          ip: "203.0.113.20",
          probeUpdatedAt: freshProbeTime(),
        }),
        healthyNode({
          nodeId: "stale_1",
          name: "Stale-01",
          ip: "203.0.113.21",
          probeUpdatedAt: catalogCalls === 1 ? staleProbeTime() : freshProbeTime(),
        }),
      ]));
    }
    if (String(url).endsWith("/refresh")) {
      return Response.json({ probed_ips: 2, geo_updated: 0, skipped_cached: 0 });
    }
    return Response.json({
      session_id: "sess_mixed_refreshed",
      display_address: "127.0.0.1:43128",
      selected_ip: "203.0.113.20",
      proxy_name: "Fresh-01",
      node_id: "fresh_1",
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
        maxLatencyMs: 500,
      },
    });

    expect(runtime.session.session_id).toBe("sess_mixed_refreshed");
    expect(requests.map((request) => `${request.method} ${request.url}`)).toEqual([
      "GET https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
      "POST https://proxy-broker.example.test/api/v1/projects/Tavily/refresh",
      "GET https://proxy-broker.example.test/api/v1/proxy-catalog?view=project&project_id=Tavily",
      "POST https://proxy-broker.example.test/api/v1/projects/Tavily/sessions/open",
    ]);
    expect(requests.at(-1)?.body).toMatchObject({
      selection_mode: "ip",
      specified_ips: ["203.0.113.20"],
    });
  } finally {
    if (previousApiKey == null) {
      delete process.env.PROXY_BROKER_API_KEY;
    } else {
      process.env.PROXY_BROKER_API_KEY = previousApiKey;
    }
  }
});

test("proxy broker runtime rejects when no probed node passes latency gate", async () => {
  globalThis.fetch = (async (url: RequestInfo | URL) => {
    if (String(url).includes("/proxy-catalog")) {
      return Response.json(brokerCatalog([
        healthyNode({ nodeId: "slow_1", name: "Slow-01", ip: "203.0.113.40", latencyMs: 1200 }),
      ]));
    }
    if (String(url).endsWith("/refresh")) {
      return Response.json({ probed_ips: 1, geo_updated: 0, skipped_cached: 1 });
    }
    throw new Error("openSession should not be called without healthy candidates");
  }) as unknown as typeof fetch;

  const previousApiKey = process.env.PROXY_BROKER_API_KEY;
  process.env.PROXY_BROKER_API_KEY = "pbk_test_secret";
  try {
    await expect(openProxyBrokerRuntimeSession({
      settings: {
        proxyBrokerBaseUrl: "https://proxy-broker.example.test",
        proxyBrokerProfileId: "Tavily",
        timeoutMs: 1000,
        maxLatencyMs: 500,
      },
    })).rejects.toMatchObject({ code: "proxy_broker_no_healthy_nodes" });
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
