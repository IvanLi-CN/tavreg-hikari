import type { RunModeAvailability } from "@/lib/app-types";

export function clampRunModeToAvailability(
  runMode: "headed" | "headless",
  availability: RunModeAvailability,
): "headed" | "headless" {
  if (runMode === "headed" && !availability.headed) {
    return "headless";
  }
  return runMode;
}
