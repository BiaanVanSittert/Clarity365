import { describe, it, expect } from "vitest";
import { evaluateMdoBaseline } from "./mdo-baseline-matcher";
import { MDO_BASELINE_STANDARDS } from "../data/mdo-baseline-definitions";
import { MdoThreatPolicy } from "../types";

function policy(overrides: Partial<MdoThreatPolicy> & Pick<MdoThreatPolicy, "policyType">): MdoThreatPolicy {
  return {
    id: `${overrides.policyType}-1`,
    displayName: `Default ${overrides.policyType}`,
    state: "Enabled",
    assignedScope: "Default (Organization-wide)",
    impersonationProtection: false,
    spoofIntelligence: false,
    zapEnabled: false,
    complianceRating: "substandard",
    realTimeScanning: false,
    blockingAction: false,
    commonAttachmentFilter: false,
    outboundNotify: false,
    ...overrides,
  };
}

describe("evaluateMdoBaseline", () => {
  it("scores 0% when no policies exist at all", () => {
    const { results, coveragePercent } = evaluateMdoBaseline([]);
    expect(coveragePercent).toBe(0);
    expect(results).toHaveLength(MDO_BASELINE_STANDARDS.length);
    expect(results.every((r) => !r.met && !r.policyFound)).toBe(true);
  });

  it("scores 100% when every policy fully meets every check it's responsible for", () => {
    const policies: MdoThreatPolicy[] = [
      policy({ policyType: "AntiPhishing", impersonationProtection: true, spoofIntelligence: true, zapEnabled: true }),
      policy({ policyType: "AntiSpamInbound", zapEnabled: true }),
      policy({ policyType: "AntiSpamOutbound", outboundNotify: true }),
      policy({ policyType: "AntiMalware", commonAttachmentFilter: true }),
      policy({ policyType: "SafeLinks", realTimeScanning: true }),
      policy({ policyType: "SafeAttachments", blockingAction: true }),
    ];
    const { results, coveragePercent } = evaluateMdoBaseline(policies);
    expect(coveragePercent).toBe(100);
    expect(results.every((r) => r.met)).toBe(true);
  });

  it("flags a specific field as unmet while the rest of the policy passes", () => {
    const policies: MdoThreatPolicy[] = [
      policy({ policyType: "AntiPhishing", impersonationProtection: true, spoofIntelligence: false, zapEnabled: true }),
    ];
    const { results } = evaluateMdoBaseline(policies);
    const mdo01 = results.find((r) => r.code === "MDO01")!;
    const mdo02 = results.find((r) => r.code === "MDO02")!;
    expect(mdo01.met).toBe(true);
    expect(mdo01.currentPolicyName).toBe("Default AntiPhishing");
    expect(mdo02.met).toBe(false);
    expect(mdo02.policyFound).toBe(true);
  });

  it("MDO09 requires all four core policies to be org-wide scoped", () => {
    const orgWide: MdoThreatPolicy[] = [
      policy({ policyType: "AntiPhishing" }),
      policy({ policyType: "AntiSpamInbound" }),
      policy({ policyType: "SafeLinks" }),
      policy({ policyType: "SafeAttachments" }),
    ];
    expect(evaluateMdoBaseline(orgWide).results.find((r) => r.code === "MDO09")!.met).toBe(true);

    const oneScoped: MdoThreatPolicy[] = [
      policy({ policyType: "AntiPhishing", assignedScope: "sales-team@contoso.com" }),
      policy({ policyType: "AntiSpamInbound" }),
      policy({ policyType: "SafeLinks" }),
      policy({ policyType: "SafeAttachments" }),
    ];
    expect(evaluateMdoBaseline(oneScoped).results.find((r) => r.code === "MDO09")!.met).toBe(false);

    const missingOne: MdoThreatPolicy[] = [
      policy({ policyType: "AntiPhishing" }),
      policy({ policyType: "SafeLinks" }),
      policy({ policyType: "SafeAttachments" }),
    ];
    const mdo09 = evaluateMdoBaseline(missingOne).results.find((r) => r.code === "MDO09")!;
    expect(mdo09.policyFound).toBe(false);
    expect(mdo09.met).toBe(false);
  });
});
