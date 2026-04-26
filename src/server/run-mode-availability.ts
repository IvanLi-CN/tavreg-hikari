import type { BrowserRunModeAvailability } from "./browser-availability.js";

export type { BrowserRunModeAvailability };

export function clampRunModeToAvailability(
  requested: "headed" | "headless",
  availability: BrowserRunModeAvailability,
): "headed" | "headless" {
  if (requested === "headed" && !availability.headed) {
    return "headless";
  }
  return requested;
}

export function assertRunModeAvailable(
  requested: "headed" | "headless",
  availability: BrowserRunModeAvailability,
): void {
  if (requested === "headed" && !availability.headed) {
    throw new Error(availability.headedReason || "当前环境无法启动有头浏览器。");
  }
}
