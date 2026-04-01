import { describe, expect, test } from "bun:test";
import {
  decideManualExtractorAcceptance,
  normalizeExtractorSources,
} from "../src/server/account-extractor-runtime.ts";

function createExistingAccount(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    passwordPlaintext: "same-pass",
    disabledAt: null,
    skipReason: null,
    lastErrorCode: null,
    hasApiKey: false,
    leaseJobId: null,
    browserSession: null,
    ...overrides,
  };
}

describe("account extractor runtime helpers", () => {
  test("normalizeExtractorSources filters unknown items and deduplicates in order", () => {
    expect(
      normalizeExtractorSources([
        "zhanghaoya",
        "hotmail666",
        "zhanghaoya",
        "shankeyun",
        "invalid-provider" as never,
      ]),
    ).toEqual(["zhanghaoya", "hotmail666", "shankeyun"]);
  });

  test("accepts new accounts and imports them", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: null,
        candidatePassword: "fresh-pass",
      }),
    ).toEqual({
      accept: true,
      rejectReason: null,
      shouldImport: true,
      forceBootstrap: false,
    });
  });

  test("rejects ready sessions when the password is unchanged", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          browserSession: { status: "ready" },
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "session_ready",
      shouldImport: false,
      forceBootstrap: false,
    });
  });

  test("allows failed sessions to retry bootstrap without reimporting", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          browserSession: { status: "failed" },
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: true,
      rejectReason: null,
      shouldImport: false,
      forceBootstrap: true,
    });
  });

  test("reimports existing accounts when the password changes", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          browserSession: { status: "ready" },
        }),
        candidatePassword: "next-pass",
      }),
    ).toEqual({
      accept: true,
      rejectReason: null,
      shouldImport: true,
      forceBootstrap: true,
    });
  });

  test("rejects locked, disabled, leased, and linked accounts", () => {
    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          skipReason: "microsoft_account_locked",
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "microsoft_account_locked",
      shouldImport: false,
      forceBootstrap: false,
    });

    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          disabledAt: "2026-04-01T00:00:00.000Z",
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "disabled",
      shouldImport: false,
      forceBootstrap: false,
    });

    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          leaseJobId: 42,
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "leased",
      shouldImport: false,
      forceBootstrap: false,
    });

    expect(
      decideManualExtractorAcceptance({
        existingAccount: createExistingAccount({
          hasApiKey: true,
        }),
        candidatePassword: "same-pass",
      }),
    ).toEqual({
      accept: false,
      rejectReason: "has_api_key",
      shouldImport: false,
      forceBootstrap: false,
    });
  });
});
