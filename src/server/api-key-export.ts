export interface ApiKeyExportItem {
  id: number;
  apiKey: string;
  extractedIp: string | null;
}

export function buildApiKeyExportContent(items: ApiKeyExportItem[]): string {
  return items.map((item) => `${item.apiKey} | ${item.extractedIp || ""}`).join("\n");
}

export interface GrokSsoExportItem {
  id: number;
  email: string;
  password: string;
  sso: string;
  ssoRw?: string | null;
  cfClearance?: string | null;
  checkoutUrl?: string | null;
  birthDate?: string | null;
}

export function buildGrokSsoExportContent(items: GrokSsoExportItem[]): string {
  return items.map((item) => item.sso).join("\n");
}
