import { describe, expect, test } from "bun:test";
import { parseMailboxVerificationCodes, parseProofMailboxVerificationCodes } from "../src/server/verification-codes.ts";

describe("verification code parsers", () => {
  test("parses mailbox subject/body codes and dedupes them", () => {
    const parsed = parseMailboxVerificationCodes({
      subject: "Your verification code is 456123",
      bodyPreview: "Use 456123 to continue sign in.",
      bodyContent: "Backup code ABC-DEF can also finish verification.",
    });

    expect(parsed).toEqual([
      expect.objectContaining({ code: "456123", source: "subject" }),
      expect.objectContaining({ code: "ABCDEF", kind: "alphanumeric" }),
    ]);
  });

  test("parses cfmail proof mailbox payloads", () => {
    const parsed = parseProofMailboxVerificationCodes({
      summary: {
        subject: "Microsoft account security code",
        previewText: "Your security code is 918273.",
      },
      detail: {
        text: "Use security code 918273 to verify your Microsoft account.",
      },
    });

    expect(parsed[0]).toMatchObject({
      code: "918273",
      kind: "microsoftProof",
    });
  });
});
