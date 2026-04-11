import { expect, test } from "bun:test";

import {
  RUN_MODE_AVAILABILITY_FALLBACK_REASON,
  createHeadlessOnlyRunModeAvailability,
  createPendingRunModeAvailability,
  resolvePendingRunModeAvailabilityFallback,
} from "../web/src/lib/run-mode";

test("pending web run-mode availability falls back to headless-only after bootstrap failure", () => {
  const pending = createPendingRunModeAvailability();
  expect(resolvePendingRunModeAvailabilityFallback(pending)).toEqual({
    headed: false,
    headless: true,
    headedReason: RUN_MODE_AVAILABILITY_FALLBACK_REASON,
  });
});

test("resolved web run-mode availability stays unchanged when bootstrap fallback runs", () => {
  const availability = createHeadlessOnlyRunModeAvailability("已有结论");
  expect(resolvePendingRunModeAvailabilityFallback(availability)).toBe(availability);
});
