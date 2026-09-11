import { describe, it, expect } from "vitest";
import { getCountryDisplayName, summarizeSignInsByCountry, detectMostCommonCountry } from "./sign-in-country";
import { SignInEvent } from "@/lib/types";

function makeEvent(country: string | undefined): SignInEvent {
  return {
    location: { city: "", state: "", country: country as string },
  } as SignInEvent;
}

describe("getCountryDisplayName", () => {
  it("resolves a known ISO-2 code to its full English name", () => {
    expect(getCountryDisplayName("US")).toBe("United States");
    expect(getCountryDisplayName("BG")).toBe("Bulgaria");
  });

  it("is case-insensitive on input", () => {
    expect(getCountryDisplayName("de")).toBe("Germany");
  });

  it("falls back to 'Unknown' for a missing or invalid code", () => {
    expect(getCountryDisplayName(undefined)).toBe("Unknown");
    expect(getCountryDisplayName("")).toBe("Unknown");
    expect(getCountryDisplayName("United States")).toBe("Unknown");
    expect(getCountryDisplayName("ZZ_not_a_code")).toBe("Unknown");
  });
});

describe("summarizeSignInsByCountry", () => {
  it("returns an empty array for no events", () => {
    expect(summarizeSignInsByCountry([])).toEqual([]);
  });

  it("groups by normalized code and counts add up to the input length", () => {
    const events = [makeEvent("US"), makeEvent("us"), makeEvent("BG"), makeEvent("US")];
    const summary = summarizeSignInsByCountry(events);
    const total = summary.reduce((sum, s) => sum + s.count, 0);
    expect(total).toBe(events.length);
    expect(summary.find((s) => s.code === "US")?.count).toBe(3);
    expect(summary.find((s) => s.code === "BG")?.count).toBe(1);
  });

  it("buckets missing/invalid country values as a distinct 'unknown' entry instead of dropping them", () => {
    const events = [makeEvent(undefined), makeEvent(""), makeEvent("US")];
    const summary = summarizeSignInsByCountry(events);
    expect(summary.find((s) => s.code === "unknown")?.count).toBe(2);
    expect(summary.find((s) => s.code === "US")?.count).toBe(1);
  });

  it("sorts by count descending", () => {
    const events = [makeEvent("BG"), makeEvent("US"), makeEvent("US"), makeEvent("US"), makeEvent("DE"), makeEvent("DE")];
    const summary = summarizeSignInsByCountry(events);
    expect(summary.map((s) => s.code)).toEqual(["US", "DE", "BG"]);
  });
});

describe("detectMostCommonCountry", () => {
  it("returns null for no events", () => {
    expect(detectMostCommonCountry([])).toBeNull();
  });

  it("returns null when every event is unresolved", () => {
    expect(detectMostCommonCountry([makeEvent(undefined), makeEvent("")])).toBeNull();
  });

  it("returns the clear most-frequent real country, ignoring the unknown bucket", () => {
    const events = [makeEvent(undefined), makeEvent("US"), makeEvent("US"), makeEvent("BG")];
    expect(detectMostCommonCountry(events)).toBe("US");
  });

  it("is deterministic on a tie (first-seen order)", () => {
    const events = [makeEvent("BG"), makeEvent("US")];
    expect(detectMostCommonCountry(events)).toBe("BG");
  });
});
