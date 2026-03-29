import { expect, test } from "bun:test";

import { formatStatusBadgeLabel, normalizeStatusBadgeVariant } from "../web/src/components/status-badge";

test("stopped badges render with the stop-state warning variant", () => {
  expect(normalizeStatusBadgeVariant("stopped")).toBe("warning");
  expect(formatStatusBadgeLabel("stopped")).toBe("已停止");
});

test("locked badges render with the danger variant", () => {
  expect(normalizeStatusBadgeVariant("locked")).toBe("danger");
  expect(formatStatusBadgeLabel("locked")).toBe("locked");
});
