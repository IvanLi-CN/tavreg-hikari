import { describe, expect, test } from "bun:test";
import viteConfig, { buildBackendTarget } from "../vite.config.ts";

describe("vite dev proxy", () => {
  test("proxies api and websocket traffic to the Bun backend", () => {
    const resolvedConfig = viteConfig as any;
    const server =
      typeof resolvedConfig === "function"
        ? resolvedConfig({ command: "serve", mode: "test", isSsrBuild: false, isPreview: false })
        : resolvedConfig;
    const proxy = server.server?.proxy;
    const apiProxy = proxy && !Array.isArray(proxy) ? proxy["/api"] : undefined;
    const target = typeof apiProxy === "object" && apiProxy ? apiProxy.target : undefined;
    const ws = typeof apiProxy === "object" && apiProxy ? apiProxy.ws : undefined;

    expect(target).toBe("http://127.0.0.1:3717");
    expect(ws).toBe(true);
  });

  test("brackets IPv6 localhost targets", () => {
    expect(buildBackendTarget("::1", 3717)).toBe("http://[::1]:3717");
  });
});
