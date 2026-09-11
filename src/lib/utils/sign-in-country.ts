import { SignInEvent } from "@/lib/types";

export const UNKNOWN_COUNTRY = "unknown";

// Constructed once and reused - Intl.DisplayNames construction has real
// overhead, and this gets called once per row/chip.
let regionNames: Intl.DisplayNames | null = null;
function getRegionNamesInstance(): Intl.DisplayNames {
  if (!regionNames) regionNames = new Intl.DisplayNames(["en"], { type: "region" });
  return regionNames;
}

// Uppercases a valid-looking ISO-2 code; anything else (missing, malformed,
// a leftover full name) normalizes to UNKNOWN_COUNTRY rather than being
// passed through as-is - every consumer compares against this normalized
// form, never the raw stored value, so a casing or format slip can't
// silently fail to match.
export function normalizeCountryCode(code: string | undefined): string {
  const trimmed = (code || "").trim().toUpperCase();
  return /^[A-Z]{2}$/.test(trimmed) ? trimmed : UNKNOWN_COUNTRY;
}

// Turns "US" into "United States". Falls back to the raw code (or "Unknown"
// for a missing/invalid one) if Intl can't resolve it, so an unrecognized
// value still renders something sensible instead of throwing.
export function getCountryDisplayName(code: string | undefined): string {
  const normalized = normalizeCountryCode(code);
  if (normalized === UNKNOWN_COUNTRY) return "Unknown";
  try {
    return getRegionNamesInstance().of(normalized) || normalized;
  } catch {
    return normalized;
  }
}

// Groups events by normalized country code, treating a missing/invalid
// value as a distinct "unknown" bucket rather than crashing or silently
// dropping it - counts always add up to events.length. Sorted by count
// descending, mirroring SignInLogsModule.tsx's existing topErrorCodes
// convention.
export function summarizeSignInsByCountry(events: SignInEvent[]): { code: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const evt of events) {
    const code = normalizeCountryCode(evt.location?.country);
    counts.set(code, (counts.get(code) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count);
}

// The most frequent real (non-"unknown") country code, for the Home Country
// auto-detect default. Ties broken by first-seen order among tied codes -
// deterministic, not worth more complexity than that. Returns null if there
// is no resolvable country at all (e.g. every event is unresolved, or there
// are no events).
export function detectMostCommonCountry(events: SignInEvent[]): string | null {
  const summary = summarizeSignInsByCountry(events).filter((s) => s.code !== UNKNOWN_COUNTRY);
  return summary.length > 0 ? summary[0].code : null;
}
