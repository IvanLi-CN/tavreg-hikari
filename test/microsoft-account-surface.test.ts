import { expect, test } from "bun:test";
import {
  assessMicrosoftAccountSurface,
  formatMicrosoftAccountSurfaceSummary,
  isMicrosoftAccountAuthIntermediateUrl,
  isMicrosoftAccountHomeUrl,
  isMicrosoftLoginSurfaceUrl,
} from "../src/server/microsoft-account-surface.ts";

test("recognizes authenticated Microsoft account home from account navigation signals", () => {
  const assessment = assessMicrosoftAccountSurface({
    url: "https://account.microsoft.com/account",
    title: "Microsoft account | Home",
    bodyText:
      "Your info Devices Privacy Security Services & subscriptions Payment options Order history Microsoft Rewards",
    visibleActions: ["Your info", "Devices", "Payment options"],
  });

  expect(assessment.authenticated).toBe(true);
  expect(assessment.requiresLogin).toBe(false);
  expect(assessment.reason).toBe("authenticated_account_home");
});

test("treats account.microsoft.com shells with visible sign-in actions as not authenticated", () => {
  const assessment = assessMicrosoftAccountSurface({
    url: "https://account.microsoft.com/account",
    title: "Microsoft account",
    bodyText: "Microsoft account Sign in to your Microsoft account to access services and support.",
    visibleActions: ["Sign in", "Create account"],
  });

  expect(assessment.authenticated).toBe(false);
  expect(assessment.requiresLogin).toBe(true);
  expect(assessment.reason).toBe("account_home_login_required");
  expect(formatMicrosoftAccountSurfaceSummary(
    {
      url: "https://account.microsoft.com/account",
      title: "Microsoft account",
      bodyText: "",
      visibleActions: ["Sign in"],
    },
    assessment,
  )).toContain("login=visible_sign_in");
});

test("recognizes Microsoft login surfaces separately from account home", () => {
  expect(isMicrosoftLoginSurfaceUrl("https://login.live.com/login.srf")).toBe(true);
  expect(isMicrosoftLoginSurfaceUrl("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")).toBe(true);
  expect(isMicrosoftAccountHomeUrl("https://account.microsoft.com/account")).toBe(true);
  const assessment = assessMicrosoftAccountSurface({
    url: "https://login.live.com/login.srf",
    title: "Sign in to your Microsoft account",
    bodyText: "Enter password",
    visibleActions: ["Next", "Sign in"],
  });
  expect(assessment.authenticated).toBe(false);
  expect(assessment.requiresLogin).toBe(true);
  expect(assessment.reason).toBe("microsoft_login_surface");
});

test("does not treat Microsoft auth callback intermediates as account home", () => {
  expect(isMicrosoftAccountHomeUrl("https://account.microsoft.com/auth/complete-client-signin-oauth-silent?state=abc")).toBe(false);
});



test("recognizes Microsoft auth callback intermediates explicitly", () => {
  expect(isMicrosoftAccountAuthIntermediateUrl("https://account.microsoft.com/auth/complete-client-signin-oauth-silent?state=abc")).toBe(true);
  expect(isMicrosoftAccountAuthIntermediateUrl("https://account.microsoft.com/account")).toBe(false);
});


test("does not mistake account home refd query parameters for a login surface", () => {
  expect(isMicrosoftLoginSurfaceUrl("https://account.microsoft.com/?lang=en-US&refd=account.live.com&refp=landing&mkt=EN-US")).toBe(false);
});
