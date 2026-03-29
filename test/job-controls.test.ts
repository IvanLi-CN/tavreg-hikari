import { expect, test } from "bun:test";

import {
  canForceStop,
  canGracefullyStop,
  canUpdateJobLimits,
  primaryJobActionDisabled,
  resolvePrimaryJobAction,
  resolvePrimaryJobLabel,
  resolveStopHint,
} from "../web/src/lib/job-controls";

test("primary job action collapses start, pause, and resume into one contextual button", () => {
  expect(resolvePrimaryJobAction(null)).toBe("start");
  expect(resolvePrimaryJobAction("idle")).toBe("start");
  expect(resolvePrimaryJobAction("running")).toBe("pause");
  expect(resolvePrimaryJobAction("paused")).toBe("resume");
  expect(resolvePrimaryJobAction("stopping")).toBeNull();
  expect(resolvePrimaryJobAction("force_stopping")).toBeNull();
  expect(resolvePrimaryJobAction("stopped")).toBe("start");
});

test("stop controls only stay enabled for supported states", () => {
  expect(canGracefullyStop("running")).toBe(true);
  expect(canGracefullyStop("paused")).toBe(true);
  expect(canGracefullyStop("stopping")).toBe(false);
  expect(canForceStop("running")).toBe(true);
  expect(canForceStop("paused")).toBe(true);
  expect(canForceStop("stopping")).toBe(true);
  expect(canForceStop("force_stopping")).toBe(false);
  expect(canUpdateJobLimits("running")).toBe(true);
  expect(canUpdateJobLimits("paused")).toBe(true);
  expect(canUpdateJobLimits("completing")).toBe(true);
  expect(canUpdateJobLimits("stopping")).toBe(false);
});

test("disabled primary states expose explicit stop-mode copy", () => {
  expect(primaryJobActionDisabled("stopping")).toBe(true);
  expect(resolvePrimaryJobLabel("stopping")).toBe("停止中");
  expect(resolvePrimaryJobLabel("force_stopping")).toBe("强停中");
  expect(resolvePrimaryJobLabel("completing")).toBe("收尾中");
  expect(resolveStopHint("stopped")).toContain("已手动停止");
});
