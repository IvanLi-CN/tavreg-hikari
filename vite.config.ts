import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export function resolveBackendHost(rawValue = process.env.WEB_HOST): string {
  const value = String(rawValue || "").trim();
  if (value === "localhost" || value === "127.0.0.1" || value === "::1") {
    return value;
  }
  return "127.0.0.1";
}

export function resolveBackendPort(rawValue = process.env.WEB_PORT): number {
  const parsed = Number.parseInt(String(rawValue || "").trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 3717;
}

export function buildBackendTarget(host = resolveBackendHost(), port = resolveBackendPort()): string {
  const normalizedHost = host.includes(":") ? `[${host}]` : host;
  return `http://${normalizedHost}:${port}`;
}

const backendTarget = buildBackendTarget();

export default defineConfig({
  root: "web",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "web/src"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": {
        target: backendTarget,
        changeOrigin: false,
        ws: true,
      },
    },
  },
});
