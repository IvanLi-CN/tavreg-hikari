import type { RunModeAvailability } from "@/lib/app-types";

export const RUN_MODE_AVAILABILITY_PENDING_REASON = "正在检测当前环境的浏览器能力。";
export const RUN_MODE_AVAILABILITY_FALLBACK_REASON = "暂时无法确认当前环境是否支持有头浏览器，先仅开放 headless。";

export function createPendingRunModeAvailability(): RunModeAvailability {
  return {
    headed: true,
    headless: true,
    headedReason: RUN_MODE_AVAILABILITY_PENDING_REASON,
  };
}

export function isRunModeAvailabilityPending(availability: RunModeAvailability): boolean {
  return availability.headedReason === RUN_MODE_AVAILABILITY_PENDING_REASON;
}

export function createHeadlessOnlyRunModeAvailability(
  reason = RUN_MODE_AVAILABILITY_FALLBACK_REASON,
): RunModeAvailability {
  return {
    headed: false,
    headless: true,
    headedReason: reason,
  };
}

export function resolvePendingRunModeAvailabilityFallback(
  availability: RunModeAvailability,
  reason = RUN_MODE_AVAILABILITY_FALLBACK_REASON,
): RunModeAvailability {
  if (!isRunModeAvailabilityPending(availability)) {
    return availability;
  }
  return createHeadlessOnlyRunModeAvailability(reason);
}

export function clampRunModeToAvailability(
  runMode: "headed" | "headless",
  availability: RunModeAvailability,
): "headed" | "headless" {
  if (runMode === "headed" && !availability.headed) {
    return "headless";
  }
  return runMode;
}
