export function isMicrosoftPasskeyInterruptUrl(url: string | null | undefined): boolean {
  const normalized = String(url || "").trim();
  if (!normalized) return false;
  return /login\.microsoft\.com\/consumers\/fido\/create|account\.live\.com\/interrupt\/passkey\/enroll/i.test(normalized);
}
