import { expect, test } from "bun:test";

import { assertRunModeAvailable, clampRunModeToAvailability, detectBrowserRunModeAvailability } from "../src/server/run-mode-availability.js";

test("linux without display only exposes headless mode", () => {
  const availability = detectBrowserRunModeAvailability({}, "linux");
  expect(availability).toEqual({
    headed: false,
    headless: true,
    headedReason: "当前环境缺少 DISPLAY / WAYLAND_DISPLAY，无法启动有头浏览器。",
  });
  expect(clampRunModeToAvailability("headed", availability)).toBe("headless");
  expect(() => assertRunModeAvailable("headed", availability)).toThrow(
    "当前环境缺少 DISPLAY / WAYLAND_DISPLAY，无法启动有头浏览器。",
  );
});

test("linux with DISPLAY keeps headed mode available", () => {
  const availability = detectBrowserRunModeAvailability({ DISPLAY: ":99" }, "linux");
  expect(availability).toEqual({
    headed: true,
    headless: true,
    headedReason: null,
  });
  expect(clampRunModeToAvailability("headed", availability)).toBe("headed");
  expect(() => assertRunModeAvailable("headed", availability)).not.toThrow();
});

test("linux with WAYLAND_DISPLAY keeps headed mode available", () => {
  const availability = detectBrowserRunModeAvailability({ WAYLAND_DISPLAY: "wayland-1" }, "linux");
  expect(availability).toEqual({
    headed: true,
    headless: true,
    headedReason: null,
  });
});

test("darwin keeps headed mode available without manual overrides", () => {
  const availability = detectBrowserRunModeAvailability({}, "darwin");
  expect(availability).toEqual({
    headed: true,
    headless: true,
    headedReason: null,
  });
});
