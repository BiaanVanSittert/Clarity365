import { describe, expect, it } from "vitest";
import { getSecretExpiryStatus, resolveOwnAppSecretExpiry } from "./credential-expiry";

const NOW = new Date("2026-10-01T00:00:00Z");
const app = (...passwordCredentials: { hint?: string; endDateTime?: string }[]) => ({ appId: "app-1", passwordCredentials });

describe("resolveOwnAppSecretExpiry", () => {
  it("picks the secret in use by its hint (the first three characters)", () => {
    const expiry = resolveOwnAppSecretExpiry(app({ hint: "abc", endDateTime: "2027-01-01T00:00:00Z" }, { hint: "xyz", endDateTime: "2026-11-01T00:00:00Z" }), "abcDEF123", NOW);
    expect(expiry).toEqual({ expiresAt: "2027-01-01T00:00:00.000Z", exact: true, checkedAt: NOW.toISOString() });
  });

  it("ignores an expired secret with the same hint", () => {
    const expiry = resolveOwnAppSecretExpiry(app({ hint: "abc", endDateTime: "2026-01-01T00:00:00Z" }, { hint: "abc", endDateTime: "2027-03-01T00:00:00Z" }), "abcDEF123", NOW);
    expect(expiry).toMatchObject({ expiresAt: "2027-03-01T00:00:00.000Z", exact: true });
  });

  it("falls back to the soonest unexpired secret when the hint is ambiguous or missing", () => {
    const twoSameHint = resolveOwnAppSecretExpiry(app({ hint: "abc", endDateTime: "2027-01-01T00:00:00Z" }, { hint: "abc", endDateTime: "2026-12-01T00:00:00Z" }), "abcDEF123", NOW);
    expect(twoSameHint).toMatchObject({ expiresAt: "2026-12-01T00:00:00.000Z", exact: false });
    const noHintMatch = resolveOwnAppSecretExpiry(app({ hint: "qqq", endDateTime: "2027-01-01T00:00:00Z" }, { endDateTime: "2026-10-20T00:00:00Z" }), "abcDEF123", NOW);
    expect(noHintMatch).toMatchObject({ expiresAt: "2026-10-20T00:00:00.000Z", exact: false });
  });

  it("returns nothing when there is no usable secret to report", () => {
    expect(resolveOwnAppSecretExpiry(app(), "abc", NOW)).toBeUndefined();
    expect(resolveOwnAppSecretExpiry(app({ hint: "abc", endDateTime: "2020-01-01T00:00:00Z" }), "abc", NOW)).toBeUndefined();
    expect(resolveOwnAppSecretExpiry(undefined, "abc", NOW)).toBeUndefined();
    expect(resolveOwnAppSecretExpiry(app({ hint: "abc", endDateTime: "not a date" }), "abc", NOW)).toBeUndefined();
  });
});

describe("getSecretExpiryStatus", () => {
  const at = (expiresAt: string, exact = true) => ({ secretExpiry: { expiresAt, exact, checkedAt: NOW.toISOString() } });

  it("is quiet when the secret has more than 30 days left", () => {
    expect(getSecretExpiryStatus(at("2027-01-01T00:00:00Z"), NOW)).toMatchObject({ state: "ok", daysLeft: 92, label: "Secret valid until 2027-01-01" });
  });

  it("warns inside 30 days and counts the days", () => {
    expect(getSecretExpiryStatus(at("2026-10-13T00:00:00Z"), NOW)).toMatchObject({ state: "expiring", daysLeft: 12, label: "Secret expires in 12 days" });
    expect(getSecretExpiryStatus(at("2026-10-02T06:00:00Z"), NOW)).toMatchObject({ state: "expiring", label: "Secret expires in 1 day" });
    expect(getSecretExpiryStatus(at("2026-10-01T18:00:00Z"), NOW)).toMatchObject({ state: "expiring", label: "Secret expires today" });
    expect(getSecretExpiryStatus(at("2026-10-31T00:00:00Z"), NOW)?.state).toBe("ok");
  });

  it("says expired once the date has passed", () => {
    expect(getSecretExpiryStatus(at("2026-09-30T00:00:00Z"), NOW)).toMatchObject({ state: "expired", label: "Secret expired" });
  });

  it("words the detail honestly when the exact secret could not be identified", () => {
    expect(getSecretExpiryStatus(at("2026-10-13T00:00:00Z", false), NOW)?.detail).toMatch(/^The app registration's soonest-expiring client secret/);
    expect(getSecretExpiryStatus(at("2026-10-13T00:00:00Z", true), NOW)?.detail).toMatch(/^The client secret Clarity365 uses/);
  });

  it("returns nothing when the expiry is unknown", () => {
    expect(getSecretExpiryStatus(undefined, NOW)).toBeUndefined();
    expect(getSecretExpiryStatus({}, NOW)).toBeUndefined();
  });
});
