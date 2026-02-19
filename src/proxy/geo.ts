export interface GeoInfo {
  ip: string;
  country?: string;
  region?: string;
  city?: string;
  org?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
  raw?: unknown;
}

const COUNTRY_LOCALE_MAP: Record<string, string> = {
  US: "en-US",
  GB: "en-GB",
  AU: "en-AU",
  CA: "en-CA",
  NZ: "en-NZ",
  SG: "en-SG",
  IN: "en-IN",
  ZA: "en-ZA",
  CN: "zh-CN",
  HK: "zh-HK",
  TW: "zh-TW",
  JP: "ja-JP",
  KR: "ko-KR",
  FR: "fr-FR",
  DE: "de-DE",
  IT: "it-IT",
  ES: "es-ES",
  PT: "pt-PT",
  BR: "pt-BR",
  RU: "ru-RU",
  ID: "id-ID",
  TH: "th-TH",
  VN: "vi-VN",
  MY: "ms-MY",
  PH: "en-PH",
  MX: "es-MX",
  AR: "es-AR",
  CL: "es-CL",
  CO: "es-CO",
  NL: "nl-NL",
  SE: "sv-SE",
  NO: "nb-NO",
  DK: "da-DK",
  FI: "fi-FI",
  PL: "pl-PL",
  TR: "tr-TR",
  SA: "ar-SA",
  AE: "ar-AE",
  IL: "he-IL",
  CZ: "cs-CZ",
  HU: "hu-HU",
  RO: "ro-RO",
  UA: "uk-UA",
};

export function deriveLocale(country?: string): string {
  if (!country) return "en-US";
  const upper = country.trim().toUpperCase();
  if (COUNTRY_LOCALE_MAP[upper]) return COUNTRY_LOCALE_MAP[upper]!;
  if (/^[A-Z]{2}$/.test(upper)) return `en-${upper}`;
  return "en-US";
}

export function buildAcceptLanguage(locale: string): string {
  const normalized = locale || "en-US";
  const [language] = normalized.split("-");
  const lang = (language || "en").toLowerCase();
  if (lang === "zh") {
    return `${normalized},zh;q=0.9,en;q=0.8`;
  }
  return `${normalized},${lang};q=0.9,en;q=0.8`;
}

function parseLoc(loc: unknown): { latitude?: number; longitude?: number } {
  if (typeof loc !== "string") return {};
  const [latRaw, lonRaw] = loc.split(",");
  const latitude = latRaw ? Number.parseFloat(latRaw) : NaN;
  const longitude = lonRaw ? Number.parseFloat(lonRaw) : NaN;
  return {
    latitude: Number.isFinite(latitude) ? latitude : undefined,
    longitude: Number.isFinite(longitude) ? longitude : undefined,
  };
}

export function parseIpInfoPayload(payload: Record<string, unknown>): GeoInfo {
  const ip = typeof payload.ip === "string" ? payload.ip : "";
  const { latitude, longitude } = parseLoc(payload.loc);
  return {
    ip,
    country: typeof payload.country === "string" ? payload.country : undefined,
    region: typeof payload.region === "string" ? payload.region : undefined,
    city: typeof payload.city === "string" ? payload.city : undefined,
    org: typeof payload.org === "string" ? payload.org : undefined,
    timezone: typeof payload.timezone === "string" ? payload.timezone : undefined,
    latitude,
    longitude,
    raw: payload,
  };
}

export async function lookupIpInfo(ip: string, token?: string): Promise<GeoInfo> {
  const url = new URL(`https://ipinfo.io/${encodeURIComponent(ip)}/json`);
  if (token && token.trim()) {
    url.searchParams.set("token", token.trim());
  }

  const resp = await fetch(url, { headers: { Accept: "application/json" } });
  if (!resp.ok) {
    throw new Error(`ipinfo_failed:${resp.status}`);
  }
  const payload = (await resp.json()) as Record<string, unknown>;
  return parseIpInfoPayload(payload);
}
