import { describe, expect, test } from "bun:test";
import { buildApiKeyExportContent } from "../src/server/api-key-export.ts";
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
});
