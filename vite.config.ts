import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const backendHost = (() => {
  const value = String(process.env.WEB_HOST || "").trim();
  if (value === "localhost" || value === "127.0.0.1" || value === "::1") {
    return value;
  }
  return "127.0.0.1";
})();

const backendPort = (() => {
  const parsed = Number.parseInt(String(process.env.WEB_PORT || "").trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 3717;
})();

const backendTarget = `http://${backendHost}:${backendPort}`;

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
