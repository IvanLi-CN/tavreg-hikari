function fallbackCopyTextToClipboard(value: string): void {
  if (typeof document === "undefined") {
    throw new Error("clipboard unavailable");
  }

  const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const selection = typeof window !== "undefined" ? window.getSelection() : null;
  const selectedRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.top = "0";
  textarea.style.left = "0";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  textarea.style.zIndex = "-1";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);

  const succeeded = document.execCommand("copy");
  textarea.remove();

  if (selection) {
    selection.removeAllRanges();
    if (selectedRange) {
      selection.addRange(selectedRange);
    }
  }
  activeElement?.focus();

  if (!succeeded) {
    throw new Error("clipboard unavailable");
  }
}

export async function copyTextToClipboard(value: string): Promise<void> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Fall through to the legacy copy path for IAB / permission-restricted contexts.
    }
  }

  fallbackCopyTextToClipboard(value);
}
