import { describe, expect, test } from "bun:test";

import {
  generateRealisticMailboxLocalPart,
  generateRealisticMailboxSubdomain,
  isRealisticMailboxLocalPart,
  shouldFallbackCfMailProviderManagedMailbox,
  shouldRetryCfMailFallbackWithSubdomain,
} from "../src/mailbox-address.ts";

describe("mailbox address helpers", () => {
  test("generates realistic local parts without synthetic mail-box hex patterns", () => {
    for (let index = 0; index < 64; index += 1) {
      const localPart = generateRealisticMailboxLocalPart();
      expect(isRealisticMailboxLocalPart(localPart)).toBe(true);
      expect(localPart).toMatch(/^[a-z0-9]+(?:-?[a-z0-9]+)*$/);
      expect(localPart).not.toMatch(/[._]/);
      expect(localPart).not.toMatch(/^mail-/);
      expect(localPart).not.toMatch(/^box-/);
      expect(localPart).not.toMatch(/[a-f0-9]{8,}/);
    }
  });

  test("falls back for provider-managed cfmail validation and invalid-response failures only", () => {
    expect(shouldFallbackCfMailProviderManagedMailbox(new Error("cfmail_mailbox_provision_failed:invalid_response"))).toBe(true);
    expect(
      shouldFallbackCfMailProviderManagedMailbox(new Error('http_failed:422:{"error":"provider-managed mailbox requires localPart"}')),
    ).toBe(true);
    expect(shouldFallbackCfMailProviderManagedMailbox(new Error('http_failed:422:{"error":"rootDomain unsupported"}'))).toBe(false);
    expect(shouldFallbackCfMailProviderManagedMailbox(new Error("http_failed:401:{\"error\":\"unauthorized\"}"))).toBe(false);
    expect(shouldFallbackCfMailProviderManagedMailbox(new Error("cfmail_api_key_missing"))).toBe(false);
  });

  test("provides human-friendly fallback subdomains only when cfmail explicitly requires them", () => {
    for (let index = 0; index < 16; index += 1) {
      expect(generateRealisticMailboxSubdomain()).toMatch(/^[a-z]+$/);
    }
    expect(shouldRetryCfMailFallbackWithSubdomain(new Error('http_failed:422:{"error":"subdomain required"}'))).toBe(true);
    expect(
      shouldRetryCfMailFallbackWithSubdomain(new Error('http_failed:422:{"error":"subdomain format invalid"}')),
    ).toBe(true);
    expect(
      shouldRetryCfMailFallbackWithSubdomain(new Error('http_failed:422:{"error":"localPart required"}')),
    ).toBe(false);
  });
});
