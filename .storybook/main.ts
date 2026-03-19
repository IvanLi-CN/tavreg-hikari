import path from "node:path";
import { fileURLToPath } from "node:url";
import type { StorybookConfig } from "@storybook/react-vite";

const srcRoot = fileURLToPath(new URL("../web/src", import.meta.url));

const config: StorybookConfig = {
  stories: ["../web/src/**/*.stories.@(ts|tsx|mdx)"],
  addons: ["@storybook/addon-docs", "@storybook/addon-a11y"],
  framework: {
    name: "@storybook/react-vite",
    options: {
      strictMode: true,
    },
  },
  async viteFinal(config) {
    return {
      ...config,
      resolve: {
        ...config.resolve,
        alias: {
          ...(config.resolve?.alias ?? {}),
          "@": path.resolve(srcRoot),
        },
      },
      build: {
        ...config.build,
        chunkSizeWarningLimit: 1400,
      },
    };
  },
};

export default config;
