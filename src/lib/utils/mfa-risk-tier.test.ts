import { describe, it, expect } from "vitest";
import { classifyMfaRiskTier, MFA_RISK_TIER_SEVERITY } from "./mfa-risk-tier";

describe("classifyMfaRiskTier", () => {
  it("classifies a disabled account as disabled regardless of every other flag", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: false, isAdmin: true, mfaRegistered: false, isLicensed: true })
    ).toBe("disabled");
  });

  it("classifies a privileged account with no MFA as critical", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: true, mfaRegistered: false, isLicensed: false })
    ).toBe("critical");
  });

  it("critical overrides the license based rule: a licensed admin with no MFA is still critical, not red", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: true, mfaRegistered: false, isLicensed: true })
    ).toBe("critical");
  });

  it("classifies any account with MFA registered as green, licensed or not", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: false, mfaRegistered: true, isLicensed: true })
    ).toBe("green");
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: false, mfaRegistered: true, isLicensed: false })
    ).toBe("green");
  });

  it("classifies a licensed account with no MFA as red", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: false, mfaRegistered: false, isLicensed: true })
    ).toBe("red");
  });

  it("classifies an unlicensed account with no MFA as orange", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: false, mfaRegistered: false, isLicensed: false })
    ).toBe("orange");
  });

  it("an admin with MFA registered is green, not critical", () => {
    expect(
      classifyMfaRiskTier({ accountEnabled: true, isAdmin: true, mfaRegistered: true, isLicensed: true })
    ).toBe("green");
  });

  it("orders severity worst first: critical, red, orange, green, disabled", () => {
    expect(MFA_RISK_TIER_SEVERITY.critical).toBeLessThan(MFA_RISK_TIER_SEVERITY.red);
    expect(MFA_RISK_TIER_SEVERITY.red).toBeLessThan(MFA_RISK_TIER_SEVERITY.orange);
    expect(MFA_RISK_TIER_SEVERITY.orange).toBeLessThan(MFA_RISK_TIER_SEVERITY.green);
    expect(MFA_RISK_TIER_SEVERITY.green).toBeLessThan(MFA_RISK_TIER_SEVERITY.disabled);
  });
});
