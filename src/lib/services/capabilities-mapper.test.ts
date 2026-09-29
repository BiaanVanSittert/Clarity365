import { describe, it, expect } from "vitest";
import { mapSubscribedSkusToCapabilities, isBusinessPremiumSku, isIntuneCapableSkuPartNumber } from "./capabilities-mapper";

describe("isIntuneCapableSkuPartNumber", () => {
  it("returns true for a genuinely Intune-capable SKU", () => {
    expect(isIntuneCapableSkuPartNumber(["SPE_E3"])).toBe(true);
    expect(isIntuneCapableSkuPartNumber(["SPB"])).toBe(true);
  });

  it("returns false for a licensed SKU with no Intune entitlement (e.g. Exchange Online Kiosk)", () => {
    expect(isIntuneCapableSkuPartNumber(["EXCHANGESTANDARD"])).toBe(false);
    expect(isIntuneCapableSkuPartNumber(["EXCHANGEDESKLESS"])).toBe(false);
  });

  it("does not fall for the O365_BUSINESS_PREMIUM legacy-branding trap", () => {
    expect(isIntuneCapableSkuPartNumber(["O365_BUSINESS_PREMIUM"])).toBe(false);
  });

  it("returns true if any one of several licenses is Intune-capable", () => {
    expect(isIntuneCapableSkuPartNumber(["EXCHANGESTANDARD", "SPE_E5"])).toBe(true);
  });

  it("returns false for an empty license list", () => {
    expect(isIntuneCapableSkuPartNumber([])).toBe(false);
  });
});

describe("isBusinessPremiumSku", () => {
  it("recognizes bare SPB and the Copilot bundle variant", () => {
    expect(isBusinessPremiumSku(["SPB"])).toBe(true);
    expect(isBusinessPremiumSku(["BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS"])).toBe(true);
  });

  it("rejects the O365_BUSINESS_PREMIUM legacy-branding trap", () => {
    expect(isBusinessPremiumSku(["O365_BUSINESS_PREMIUM"])).toBe(false);
  });
});

describe("capabilities-mapper", () => {
  it("detects M365 E5 / Entra P2 capabilities from SPE_E5 SKU", () => {
    const skus = [
      {
        skuPartNumber: "SPE_E5",
        capabilityStatus: "Enabled",
        consumedUnits: 50,
      },
    ];

    const caps = mapSubscribedSkusToCapabilities(skus);
    const entra = caps.find((c) => c.id === "cap-entra");
    const intune = caps.find((c) => c.id === "cap-intune");
    const mde = caps.find((c) => c.id === "cap-mde");
    const mdo = caps.find((c) => c.id === "cap-mdo");

    expect(entra?.licensed).toBe(true);
    expect(entra?.tier).toContain("P2");
    expect(intune?.licensed).toBe(true);
    expect(mde?.licensed).toBe(true);
    expect(mdo?.licensed).toBe(true);
  });

  it("handles empty or standard business skus without P2 features", () => {
    const skus = [
      {
        skuPartNumber: "O365_BUSINESS_ESSENTIALS",
        capabilityStatus: "Enabled",
        consumedUnits: 10,
      },
    ];

    const caps = mapSubscribedSkusToCapabilities(skus);
    const entra = caps.find((c) => c.id === "cap-entra");
    expect(entra?.licensed).toBe(false);
    expect(entra?.tier).toContain("Free");
  });

  it("detects Intune, Entra P1, Defender for Business, and Defender for Office 365 P1 from the SPB (Business Premium) SKU", () => {
    const skus = [
      {
        skuPartNumber: "SPB",
        capabilityStatus: "Enabled",
        consumedUnits: 25,
      },
    ];

    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-intune")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-mde")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-mdo")?.licensed).toBe(true);
  });

  it("detects Entra P2, Defender for Endpoint, and Defender for Office 365 from Microsoft 365 A5 for Faculty (EDU)", () => {
    const skus = [{ skuPartNumber: "M365EDU_A5_FACULTY", capabilityStatus: "Enabled", consumedUnits: 12 }];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-entra")?.tier).toContain("P2");
    expect(caps.find((c) => c.id === "cap-mde")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-mdo")?.licensed).toBe(true);
  });

  it("grants Entra P1 and Intune, but NOT P2/MDE/MDO, from Microsoft 365 A3 for Students (EDU)", () => {
    const skus = [{ skuPartNumber: "M365EDU_A3_STUDENT", capabilityStatus: "Enabled", consumedUnits: 200 }];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-entra")?.tier).toContain("P1");
    expect(caps.find((c) => c.id === "cap-intune")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-mde")?.licensed).toBe(false);
    expect(caps.find((c) => c.id === "cap-mdo")?.licensed).toBe(false);
  });

  it("detects a standalone Entra ID P2 add-on SKU sold to EDU tenants (AAD_PREMIUM_P2_FACULTY)", () => {
    const skus = [
      { skuPartNumber: "ENTERPRISEPACKPLUS_FACULTY", capabilityStatus: "Enabled", consumedUnits: 5 },
      { skuPartNumber: "AAD_PREMIUM_P2_FACULTY", capabilityStatus: "Enabled", consumedUnits: 5 },
      { skuPartNumber: "STANDARDWOFFPACK_STUDENT", capabilityStatus: "Enabled", consumedUnits: 300 },
    ];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-entra")?.tier).toContain("P2");
  });

  it("does NOT grant Entra P2 from Office 365 A5 for Faculty/Students - only Microsoft 365 A5 (EDU) includes P2", () => {
    const skus = [{ skuPartNumber: "ENTERPRISEPREMIUM_FACULTY", capabilityStatus: "Enabled", consumedUnits: 8 }];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(false);
  });

  it("still grants Entra P2 from the commercial Office 365 E5 SKU (bare ENTERPRISEPREMIUM, no EDU suffix)", () => {
    const skus = [{ skuPartNumber: "ENTERPRISEPREMIUM", capabilityStatus: "Enabled", consumedUnits: 40 }];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-entra")?.tier).toContain("P2");
  });

  it("detects Intune, Entra P1, Defender for Business, and MDO P1 from the Business Premium + Copilot bundle SKU - the live Coetzee Architects bug", () => {
    // Captured live: Coetzee Architects is on
    // BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS (8 consumed
    // seats), not bare "SPB" - a plain substring match on "BUSINESS_PREMIUM"
    // catches this and any future bundle variant.
    const skus = [
      { skuPartNumber: "BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS", capabilityStatus: "Enabled", consumedUnits: 8 },
    ];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-entra")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-intune")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-mde")?.licensed).toBe(true);
    expect(caps.find((c) => c.id === "cap-mdo")?.licensed).toBe(true);
  });

  it("does NOT grant Intune/MDE from O365_BUSINESS_PREMIUM - Microsoft's legacy branding for Business STANDARD, not Premium", () => {
    const skus = [{ skuPartNumber: "O365_BUSINESS_PREMIUM", capabilityStatus: "Enabled", consumedUnits: 5 }];
    const caps = mapSubscribedSkusToCapabilities(skus);
    expect(caps.find((c) => c.id === "cap-intune")?.licensed).toBe(false);
    expect(caps.find((c) => c.id === "cap-mde")?.licensed).toBe(false);
  });
});
