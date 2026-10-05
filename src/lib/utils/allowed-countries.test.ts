import { describe, expect, it } from "vitest";
import { parseAllowedCountries } from "./allowed-countries";

describe("parseAllowedCountries", () => {
  it("accepts arrays and comma or space separated text, uppercased and de-duplicated", () => {
    expect(parseAllowedCountries(["za", "NA"])).toEqual({ countries: ["ZA", "NA"] });
    expect(parseAllowedCountries("za, na  ZA;bw")).toEqual({ countries: ["ZA", "NA", "BW"] });
  });

  it("rejects an empty list and anything that isn't a two-letter code", () => {
    expect(parseAllowedCountries("").error).toMatch(/at least one/);
    expect(parseAllowedCountries(undefined).error).toMatch(/at least one/);
    expect(parseAllowedCountries("ZA, South Africa").error).toBe("Not two-letter country codes: SOUTH, AFRICA.");
  });
});
