import type { Preview } from "@storybook/react-vite";
import "../web/src/styles.css";

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
    options: {
      storySort: {
        order: ["UI", "Shell", "Views"],
      },
    },
  },
};

export default preview;
