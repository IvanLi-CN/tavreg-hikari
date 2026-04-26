import { expect, test } from "bun:test";

import type { BrowserRunModeAvailability } from "../src/server/run-mode-availability.js";
import { assertRunModeAvailable, clampRunModeToAvailability } from "../src/server/run-mode-availability.js";

test("headless-only availability clamps headed requests", () => {
  const availability: BrowserRunModeAvailability = {
    headed: false,
    headless: true,
    headedReason: "当前环境缺少可用的指纹浏览器，无法启动有头浏览器。",
  };
  expect(availability).toEqual({
    headed: false,
    headless: true,
    headedReason: "当前环境缺少可用的指纹浏览器，无法启动有头浏览器。",
  });
  expect(clampRunModeToAvailability("headed", availability)).toBe("headless");
  expect(() => assertRunModeAvailable("headed", availability)).toThrow(
    "当前环境缺少可用的指纹浏览器，无法启动有头浏览器。",
  );
});

test("headed availability preserves explicit headed requests", () => {
  const availability: BrowserRunModeAvailability = {
    headed: true,
    headless: true,
    headedReason: null,
  };
  expect(availability).toEqual({
    headed: true,
    headless: true,
    headedReason: null,
  });
  expect(clampRunModeToAvailability("headed", availability)).toBe("headed");
  expect(() => assertRunModeAvailable("headed", availability)).not.toThrow();
});

test("assertRunModeAvailable uses generic fallback when reason is absent", () => {
  const availability: BrowserRunModeAvailability = {
    headed: false,
    headless: true,
    headedReason: null,
  };
  expect(() => assertRunModeAvailable("headed", availability)).toThrow("当前环境无法启动有头浏览器。");
});
