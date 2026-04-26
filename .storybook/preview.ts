import type { Preview } from "@storybook/react-vite";
import { create } from "storybook/theming";
import { MINIMAL_VIEWPORTS } from "storybook/viewport";
import "../web/src/styles.css";

const docsTheme = create({
  base: "dark",
  appBg: "#050b16",
  appContentBg: "#07111f",
  appPreviewBg: "#07111f",
  appBorderColor: "rgba(148, 163, 184, 0.14)",
  appBorderRadius: 24,
  colorPrimary: "#22c55e",
  colorSecondary: "#38bdf8",
  textColor: "#f8fafc",
  textInverseColor: "#020617",
  textMutedColor: "#94a3b8",
  barBg: "#050b16",
  barTextColor: "#cbd5e1",
  barHoverColor: "#f8fafc",
  barSelectedColor: "#22c55e",
  buttonBg: "rgba(15, 23, 42, 0.92)",
  buttonBorder: "rgba(148, 163, 184, 0.18)",
  inputBg: "rgba(15, 23, 42, 0.92)",
  inputBorder: "rgba(148, 163, 184, 0.18)",
  inputTextColor: "#f8fafc",
  fontBase: "\"Fira Sans\", \"SF Pro Display\", \"PingFang SC\", \"Noto Sans SC\", sans-serif",
  fontCode: "\"Fira Code\", \"SF Mono\", \"JetBrains Mono\", monospace",
});

const customViewports = {
  extractorCompact375: {
    name: "Extractor Compact 375",
    styles: {
      width: "375px",
      height: "812px",
    },
  },
  keysCompact700: {
    name: "Keys Compact 700",
    styles: {
      width: "700px",
      height: "1180px",
    },
  },
  keysMedium820: {
    name: "Keys Medium 820",
    styles: {
      width: "820px",
      height: "1180px",
    },
  },
  keysWide1120: {
    name: "Keys Wide 1120",
    styles: {
      width: "1120px",
      height: "1180px",
    },
  },
};

const preview: Preview = {
  tags: ["autodocs"],
  parameters: {
    layout: "fullscreen",
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    backgrounds: {
      default: "night",
      values: [
        { name: "night", value: "#07111f" },
        { name: "paper", value: "#f6f8fc" },
      ],
    },
    docs: {
      theme: docsTheme,
    },
    viewport: {
      options: {
        ...MINIMAL_VIEWPORTS,
        ...customViewports,
      },
    },
    options: {
      storySort: {
        order: ["UI", "Shell", "Views"],
      },
    },
  },
};

export default preview;
