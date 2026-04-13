import type { ChatGptDraft, PageKey } from "@/lib/app-types";

export function shouldLoadChatGptDraft(input: {
  activePage: PageKey;
  draft: ChatGptDraft | null;
  busy: boolean;
}): boolean {
  return input.activePage === "chatgpt" && !input.draft && !input.busy;
}
