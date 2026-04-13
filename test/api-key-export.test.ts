import { describe, expect, test } from "bun:test";
import { buildApiKeyExportContent, buildGrokSsoExportContent } from "../src/server/api-key-export.ts";
import { buildApiKeyExportFilename } from "../web/src/lib/api-key-export.ts";

describe("api key export helpers", () => {
  test("formats export content as key | ip lines while preserving empty ip slots", () => {
    expect(
      buildApiKeyExportContent([
        { id: 1, apiKey: "tvly-real-key-a", extractedIp: "1.2.3.4" },
        { id: 2, apiKey: "tvly-real-key-b", extractedIp: null },
      ]),
    ).toBe("tvly-real-key-a | 1.2.3.4\ntvly-real-key-b | ");
  });

  test("builds timestamped export filenames", () => {
    const now = new Date(2026, 2, 20, 8, 9, 10);
    expect(buildApiKeyExportFilename(now)).toBe("tavily-api-keys-20260320-080910.txt");
  });

  test("formats grok export content as one sso token per line", () => {
    expect(
      buildGrokSsoExportContent([
        {
          id: 11,
          email: "grok-1697@mail.example.test",
          password: "pw-a",
          sso: "sso_live_alpha",
          ssoRw: "sso_rw_alpha",
          cfClearance: "cf_alpha",
          checkoutUrl: "https://checkout.example/a",
          birthDate: "1996-03-18T16:00:00.000Z",
        },
        {
          id: 12,
          email: "grok-1601@mail.example.test",
          password: "pw-b",
          sso: "sso_live_beta",
          ssoRw: "sso_rw_beta",
          cfClearance: "cf_beta",
          checkoutUrl: "https://checkout.example/b",
          birthDate: "1998-11-07T16:00:00.000Z",
        },
      ]),
    ).toBe("sso_live_alpha\nsso_live_beta");
  });
});
