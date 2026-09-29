import { describe, it, expect } from "vitest";
import { getTierEligibility } from "./data-protection-tier-gating";

describe("getTierEligibility", () => {
  it("every real tier meets the business_premium_e3 floor except the unconfirmed F3 case", () => {
    expect(getTierEligibility("M365_E5", "business_premium_e3")).toBe("eligible");
    expect(getTierEligibility("M365_E3", "business_premium_e3")).toBe("eligible");
    expect(getTierEligibility("M365_BP", "business_premium_e3")).toBe("eligible");
    expect(getTierEligibility("A5_EDU", "business_premium_e3")).toBe("eligible");
    expect(getTierEligibility("M365_F3", "business_premium_e3")).toBe("unknown");
  });

  it("only E5-class tiers meet the e5 floor", () => {
    expect(getTierEligibility("M365_E5", "e5")).toBe("eligible");
    expect(getTierEligibility("A5_EDU", "e5")).toBe("eligible");
    expect(getTierEligibility("M365_E3", "e5")).toBe("requires_e5");
    expect(getTierEligibility("M365_BP", "e5")).toBe("requires_e5");
  });

  it("never silently defaults an unconfirmed tier to eligible", () => {
    expect(getTierEligibility("M365_F3", "business_premium_e3")).not.toBe("eligible");
    expect(getTierEligibility("M365_F3", "e5")).not.toBe("eligible");
  });
});
