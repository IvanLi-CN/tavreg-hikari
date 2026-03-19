export interface ApiKeyExportItem {
  id: number;
  apiKey: string;
  extractedIp: string | null;
}

export function buildApiKeyExportContent(items: ApiKeyExportItem[]): string {
  return items.map((item) => `${item.apiKey} | ${item.extractedIp || ""}`).join("\n");
}
