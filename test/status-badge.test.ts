import { expect, test } from "bun:test";

import { formatStatusBadgeLabel, normalizeStatusBadgeVariant } from "../web/src/components/status-badge";

test("stopped badges render with the stop-state warning variant", () => {
  expect(normalizeStatusBadgeVariant("stopped")).toBe("warning");
  expect(formatStatusBadgeLabel("stopped")).toBe("已停止");
});
