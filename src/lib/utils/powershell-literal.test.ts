import { describe, expect, it } from "vitest";
import { toPowerShell } from "./powershell-literal";

describe("toPowerShell", () => {
  it("writes scalars", () => {
    expect(toPowerShell(true)).toBe("$true");
    expect(toPowerShell(false)).toBe("$false");
    expect(toPowerShell(null)).toBe("$null");
    expect(toPowerShell(4)).toBe("4");
    expect(toPowerShell("All")).toBe("'All'");
  });

  it("escapes quotes and never interpolates $ inside strings", () => {
    expect(toPowerShell("O'Brien")).toBe("'O''Brien'");
    expect(toPowerShell("$env:USERNAME")).toBe("'$env:USERNAME'");
  });

  it("writes simple arrays on one line and empty ones as @()", () => {
    expect(toPowerShell(["windows", "macOS"])).toBe("@('windows', 'macOS')");
    expect(toPowerShell([])).toBe("@()");
  });

  it("writes nested hashtables, quoting keys that aren't plain identifiers", () => {
    expect(toPowerShell({ "@odata.type": "#microsoft.graph.countryNamedLocation", countriesAndRegions: ["ZA"], includeUnknownCountriesAndRegions: false })).toBe(
      `@{
    "@odata.type" = '#microsoft.graph.countryNamedLocation'
    countriesAndRegions = @('ZA')
    includeUnknownCountriesAndRegions = $false
}`
    );
  });

  it("writes arrays of hashtables one per line and drops undefined values", () => {
    expect(toPowerShell({ reviewers: [{ query: "/users/1", queryType: "MicrosoftGraph" }], skip: undefined })).toBe(
      `@{
    reviewers = @(
        @{
            query = '/users/1'
            queryType = 'MicrosoftGraph'
        }
    )
}`
    );
  });
});
