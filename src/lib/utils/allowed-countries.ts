// The "allowed countries" list for the CA08 baseline (a country named
// location the policy excludes). Accepts an array or a comma/space separated
// string of ISO 3166-1 alpha-2 codes; anything else is rejected rather than
// guessed, because a wrong list blocks real users once the policy is on.

const ISO2 = /^[A-Z]{2}$/;

export function parseAllowedCountries(input: unknown): { countries?: string[]; error?: string } {
  const raw = Array.isArray(input) ? input : typeof input === "string" ? input.split(/[\s,;]+/) : [];
  const codes = raw.map((c) => String(c ?? "").trim().toUpperCase()).filter((c) => c.length > 0);
  if (codes.length === 0) return { error: "List at least one allowed country (two-letter code, for example ZA)." };
  const invalid = codes.filter((c) => !ISO2.test(c));
  if (invalid.length > 0) return { error: `Not two-letter country codes: ${invalid.join(", ")}.` };
  return { countries: [...new Set(codes)] };
}

export const CA08_ALLOWED_LOCATION_NAME = "CA08: Allowed countries";

export function buildCa08AllowedCountriesLocation(countries: string[]) {
  return {
    "@odata.type": "#microsoft.graph.countryNamedLocation",
    displayName: CA08_ALLOWED_LOCATION_NAME,
    countriesAndRegions: countries,
    includeUnknownCountriesAndRegions: false,
  };
}
