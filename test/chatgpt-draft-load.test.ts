import { describe, expect, test } from "bun:test";
import { shouldLoadChatGptDraft } from "../web/src/lib/chatgpt-draft-load";

describe("shouldLoadChatGptDraft", () => {
  test("only preloads draft on chatgpt page when draft is absent and not busy", () => {
    expect(shouldLoadChatGptDraft({ activePage: "grok", draft: null, busy: false })).toBe(false);
    expect(shouldLoadChatGptDraft({ activePage: "keys", draft: null, busy: false })).toBe(false);
    expect(shouldLoadChatGptDraft({ activePage: "chatgpt", draft: null, busy: false })).toBe(true);
  });

  test("skips preload when draft already exists or request is in flight", () => {
    expect(
      shouldLoadChatGptDraft({
        activePage: "chatgpt",
        draft: {
          email: "draft@example.test",
          password: "pass-123",
          nickname: "Draft",
          birthDate: "1998-08-08",
          mailboxId: "mailbox-1",
          generatedAt: "2026-04-10T15:00:00.000Z",
        },
        busy: false,
      }),
    ).toBe(false);
    expect(shouldLoadChatGptDraft({ activePage: "chatgpt", draft: null, busy: true })).toBe(false);
  });
});
