export type BrowserRunModeAvailability = {
  headed: boolean;
  headless: true;
  headedReason: string | null;
};

function parseOptionalBoolean(value: unknown): boolean | null {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return null;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return null;
}

export function detectBrowserRunModeAvailability(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): BrowserRunModeAvailability {
  const override =
    parseOptionalBoolean(env.WEB_HEADED_BROWSER_AVAILABLE)
    ?? parseOptionalBoolean(env.HEADED_BROWSER_AVAILABLE);
  if (override === true) {
    return { headed: true, headless: true, headedReason: null };
  }
  if (override === false) {
    return {
      headed: false,
      headless: true,
      headedReason: "当前环境已显式禁用有头浏览器。",
    };
  }

  if (platform === "linux") {
    const hasDisplay = Boolean(String(env.DISPLAY || "").trim() || String(env.WAYLAND_DISPLAY || "").trim());
    return {
      headed: hasDisplay,
      headless: true,
      headedReason: hasDisplay ? null : "当前环境缺少 DISPLAY / WAYLAND_DISPLAY，无法启动有头浏览器。",
    };
  }

  return {
    headed: true,
    headless: true,
    headedReason: null,
  };
}

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
