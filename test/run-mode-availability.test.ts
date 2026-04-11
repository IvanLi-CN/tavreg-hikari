import { expect, test } from "bun:test";

import { assertRunModeAvailable, clampRunModeToAvailability, detectBrowserRunModeAvailability } from "../src/server/run-mode-availability.js";

test("linux without display only exposes headless mode", () => {
  const availability = detectBrowserRunModeAvailability({}, "linux");
  expect(availability).toEqual({
    headed: false,
    headless: true,
    headedReason: "当前环境缺少 DISPLAY / WAYLAND_DISPLAY，无法启动有头浏览器。",
  });
});

test("linux with DISPLAY keeps headed mode available", () => {
  const availability = detectBrowserRunModeAvailability({ DISPLAY: ":99" }, "linux");
  expect(availability.headed).toBe(true);
  expect(availability.headless).toBe(true);
  expect(availability.headedReason).toBeNull();
});

test("explicit headed availability override disables headed mode everywhere", () => {
  const availability = detectBrowserRunModeAvailability({ WEB_HEADED_BROWSER_AVAILABLE: "false" }, "darwin");
  expect(availability).toEqual({
    headed: false,
    headless: true,
    headedReason: "当前环境已显式禁用有头浏览器。",
  });
  expect(clampRunModeToAvailability("headed", availability)).toBe("headless");
  expect(() => assertRunModeAvailable("headed", availability)).toThrow("当前环境已显式禁用有头浏览器。");
});

test("explicit headed availability override can force-enable headed mode", () => {
  const availability = detectBrowserRunModeAvailability({ HEADED_BROWSER_AVAILABLE: "1" }, "linux");
  expect(availability).toEqual({
    headed: true,
    headless: true,
    headedReason: null,
  });
  expect(clampRunModeToAvailability("headed", availability)).toBe("headed");
  expect(() => assertRunModeAvailable("headed", availability)).not.toThrow();
});
