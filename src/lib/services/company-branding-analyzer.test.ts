import { describe, it, expect } from "vitest";
import { hasCompanyBrandingConfigured, buildCompanyBrandingControl, COMPANY_BRANDING_CONTROL_ID } from "./company-branding-analyzer";

describe("hasCompanyBrandingConfigured", () => {
  it("returns true when the default localization has a real logo set", () => {
    expect(hasCompanyBrandingConfigured([{ bannerLogoRelativeUrl: "tenant/logintenantbranding/0/bannerlogo?ts=1" }])).toBe(true);
  });

  it("returns true when only a background image is set", () => {
    expect(hasCompanyBrandingConfigured([{ backgroundImageRelativeUrl: "tenant/logintenantbranding/0/illustration?ts=1" }])).toBe(true);
  });

  it("returns false when every localization has no logo/background at all (tenant default, unconfigured)", () => {
    expect(
      hasCompanyBrandingConfigured([{ bannerLogoRelativeUrl: null, squareLogoRelativeUrl: null, backgroundImageRelativeUrl: null }])
    ).toBe(false);
  });

  it("returns false for an empty list", () => {
    expect(hasCompanyBrandingConfigured([])).toBe(false);
  });

  it("returns true if any one of several localizations (e.g. a per-language variant) has a logo", () => {
    expect(
      hasCompanyBrandingConfigured([
        { bannerLogoRelativeUrl: null },
        { bannerLogoRelativeUrl: "tenant/logintenantbranding/fr-fr/bannerlogo?ts=1" },
      ])
    ).toBe(true);
  });
});

describe("buildCompanyBrandingControl", () => {
  it("marks the control Completed when branding is configured", () => {
    const control = buildCompanyBrandingControl([{ squareLogoRelativeUrl: "tenant/logintenantbranding/0/tilelogo?ts=1" }]);
    expect(control.id).toBe(COMPANY_BRANDING_CONTROL_ID);
    expect(control.status).toBe("Completed");
  });

  it("marks the control Unresolved when no branding is configured", () => {
    const control = buildCompanyBrandingControl([]);
    expect(control.status).toBe("Unresolved");
  });

  it("never contributes real points - always 0/0 regardless of status", () => {
    const configured = buildCompanyBrandingControl([{ bannerLogoRelativeUrl: "x" }]);
    const unconfigured = buildCompanyBrandingControl([]);
    expect(configured.scoreCurrent).toBe(0);
    expect(configured.scoreMax).toBe(0);
    expect(unconfigured.scoreCurrent).toBe(0);
    expect(unconfigured.scoreMax).toBe(0);
  });

  it("is guided, not auto-deployable - a logo file upload can't be one-click deployed", () => {
    expect(buildCompanyBrandingControl([]).deployment).toEqual({ type: "guided" });
  });

  it("has a description and remediation text, not the generic placeholders", () => {
    const control = buildCompanyBrandingControl([]);
    expect(control.description.length).toBeGreaterThan(20);
    expect(control.description).not.toBe("No description available for this control.");
    expect(control.remediationSummary).toContain("Company branding");
  });
});
