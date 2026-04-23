import { expect, test } from "bun:test";
import { detectAccountBusinessFlowAvailability } from "../src/server/account-business-flow.ts";

test("account business-flow availability stays headless-only without DISPLAY or WAYLAND_DISPLAY", () => {
  expect(detectAccountBusinessFlowAvailability({ DISPLAY: "", WAYLAND_DISPLAY: "" })).toEqual({
    headless: true,
    headed: false,
    fingerprint: false,
    headedReason: "当前环境未检测到 DISPLAY 或 WAYLAND_DISPLAY。",
    fingerprintReason: "当前环境未检测到 DISPLAY 或 WAYLAND_DISPLAY。",
    deAvailable: false,
  });
});

test("account business-flow availability enables headed and fingerprint when DISPLAY is present", () => {
  expect(detectAccountBusinessFlowAvailability({ DISPLAY: ":99", WAYLAND_DISPLAY: "" })).toEqual({
    headless: true,
    headed: true,
    fingerprint: true,
    headedReason: null,
    fingerprintReason: null,
    deAvailable: true,
  });
});
