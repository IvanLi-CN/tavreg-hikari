import { expect, test } from "bun:test";

import { formatFailureTooltip, formatStatusBadgeLabel, normalizeStatusBadgeVariant } from "../web/src/components/status-badge";

test("stopped badges render with the stop-state warning variant", () => {
  expect(normalizeStatusBadgeVariant("stopped")).toBe("warning");
  expect(formatStatusBadgeLabel("stopped")).toBe("已停止");
});

test("locked badges render with the danger variant", () => {
  expect(normalizeStatusBadgeVariant("locked")).toBe("danger");
  expect(formatStatusBadgeLabel("locked")).toBe("locked");
});

test("failure tooltip includes stage, code, and detailed reason", () => {
  expect(
    formatFailureTooltip({
      heading: "Tavily 失败详情",
      stage: "login_home",
      errorCode: "microsoft_account_locked",
      errorMessage: "提交密码后被打到 account.live.com/Abuse",
    }),
  ).toBe("Tavily 失败详情\n阶段：login_home\n错误代码：microsoft_account_locked\n失败原因：提交密码后被打到 account.live.com/Abuse");
});
