import { describe, it, expect } from "vitest";
import {
  getLicenseSkuMonthlyCost,
  getLicenseSkuCostInfo,
  FREE_LICENSE_SKUS,
  LICENSE_SKU_MONTHLY_COST_USD,
  DEFAULT_LICENSE_SKU_COST_USD,
} from "./license-sku-costs";

describe("getLicenseSkuMonthlyCost", () => {
  it("prices the free self-service/viral SKUs at $0 regardless of quantity", () => {
    expect(getLicenseSkuMonthlyCost("FLOW_FREE")).toBe(0);
    expect(getLicenseSkuMonthlyCost("POWER_BI_STANDARD")).toBe(0);
    expect(getLicenseSkuMonthlyCost("POWERAPPS_VIRAL")).toBe(0);
    expect(getLicenseSkuMonthlyCost("TEAMS_EXPLORATORY")).toBe(0);
  });

  it("prices the free education tier (Office 365 A1) at $0", () => {
    expect(getLicenseSkuMonthlyCost("STANDARDWOFFPACK_STUDENT")).toBe(0);
    expect(getLicenseSkuMonthlyCost("STANDARDWOFFPACK_FACULTY")).toBe(0);
  });

  it("prices a known paid SKU at its real estimated cost, not a flat tenant-tier rate", () => {
    expect(getLicenseSkuMonthlyCost("SPE_E5")).toBe(57);
    expect(getLicenseSkuMonthlyCost("SPB")).toBe(22);
  });

  it("falls back to a modest default for an unrecognized SKU, not a premium tier cost", () => {
    expect(getLicenseSkuMonthlyCost("SOME_UNKNOWN_FUTURE_SKU")).toBe(DEFAULT_LICENSE_SKU_COST_USD);
    expect(getLicenseSkuMonthlyCost("SOME_UNKNOWN_FUTURE_SKU")).toBeLessThan(LICENSE_SKU_MONTHLY_COST_USD.SPE_E5);
  });

  it("every entry in FREE_LICENSE_SKUS actually resolves to 0", () => {
    for (const sku of FREE_LICENSE_SKUS) {
      expect(getLicenseSkuMonthlyCost(sku)).toBe(0);
    }
  });

  it("prices real-world trial/preview/dev SKUs at $0 via the disclosed name heuristic", () => {
    // Observed live on a real tenant - not in the exact-match tables, but
    // unmistakably trial/dev/preview grants by Microsoft's own naming
    // convention, not an actual bulk purchase.
    expect(getLicenseSkuMonthlyCost("AX7_USER_TRIAL")).toBe(0);
    expect(getLicenseSkuMonthlyCost("CCIBOTS_PRIVPREV_VIRAL")).toBe(0);
    expect(getLicenseSkuMonthlyCost("POWERAPPS_DEV")).toBe(0);
  });

  it("prices Microsoft Stream (Classic) at $0 - large quantities are the trial grant, not a purchase", () => {
    expect(getLicenseSkuMonthlyCost("STREAM")).toBe(0);
  });

  it("does not let the trial/dev name heuristic misfire on an ordinary paid SKU", () => {
    expect(getLicenseSkuMonthlyCost("SPE_E5")).toBe(57);
    expect(getLicenseSkuMonthlyCost("EMSPREMIUM")).toBe(LICENSE_SKU_MONTHLY_COST_USD.EMSPREMIUM);
  });
});

describe("getLicenseSkuCostInfo", () => {
  it("distinguishes confirmed-free from likely-free-by-name from a known paid cost", () => {
    expect(getLicenseSkuCostInfo("FLOW_FREE").costBasis).toBe("confirmed-free");
    expect(getLicenseSkuCostInfo("AX7_USER_TRIAL").costBasis).toBe("likely-free-by-name");
    expect(getLicenseSkuCostInfo("SPE_E5").costBasis).toBe("known-cost");
    expect(getLicenseSkuCostInfo("SOME_UNKNOWN_FUTURE_SKU").costBasis).toBe("unknown-default");
  });
});
