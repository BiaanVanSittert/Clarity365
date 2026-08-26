import { MdoThreatPolicy, MdoBaselineResult } from "../types";
import { MDO_BASELINE_STANDARDS } from "../data/mdo-baseline-definitions";
import { computeBaselineCoveragePercent } from "./ca-baseline-matcher";

// Scores live MdoThreatPolicy rows against MDO_BASELINE_STANDARDS. Unlike CA's
// matcher (which has to infer which baseline a policy structurally matches),
// each MDO check already names the exact policyType and field it inspects, so
// this is a direct per-code lookup rather than a cascade - reuses
// computeBaselineCoveragePercent from ca-baseline-matcher.ts rather than
// re-deriving the same pure percentage calculation.

const ORG_WIDE_SCOPE = "Default (Organization-wide)";

function findPolicies(policies: MdoThreatPolicy[], type: MdoThreatPolicy["policyType"]): MdoThreatPolicy[] {
  return policies.filter((p) => p.policyType === type);
}

function evaluateCode(code: string, policies: MdoThreatPolicy[]): MdoBaselineResult {
  // MDO09 is the one aggregate check - it spans every core policy type rather
  // than a single one, so it's handled separately from the direct 1:1 lookups below.
  // A tenant can legitimately run several policies of one core type (a preset
  // plus custom scoped ones); org-wide coverage only needs at least one of
  // them to apply to everyone, not all of them - computing whether several
  // scoped policies' union actually covers 100% of mailboxes is a much
  // larger problem this check doesn't attempt.
  if (code === "MDO09") {
    const coreTypes = ["AntiPhishing", "AntiSpamInbound", "SafeLinks", "SafeAttachments"] as const;
    const corePolicyGroups = coreTypes.map((t) => findPolicies(policies, t));
    const policyFound = corePolicyGroups.every((group) => group.length > 0);
    const met = policyFound && corePolicyGroups.every((group) => group.some((p) => p.assignedScope === ORG_WIDE_SCOPE));
    return { code, met, policyFound, policyCount: corePolicyGroups.reduce((sum, g) => sum + g.length, 0) };
  }

  const CHECKS: Record<string, { type: MdoThreatPolicy["policyType"]; field: keyof MdoThreatPolicy }> = {
    MDO01: { type: "AntiPhishing", field: "impersonationProtection" },
    MDO02: { type: "AntiPhishing", field: "spoofIntelligence" },
    MDO03: { type: "AntiSpamInbound", field: "zapEnabled" },
    MDO04: { type: "AntiPhishing", field: "zapEnabled" },
    MDO05: { type: "SafeLinks", field: "realTimeScanning" },
    MDO06: { type: "SafeAttachments", field: "blockingAction" },
    MDO07: { type: "AntiMalware", field: "commonAttachmentFilter" },
    MDO08: { type: "AntiSpamOutbound", field: "outboundNotify" },
  };

  const check = CHECKS[code];
  if (!check) return { code, met: false, policyFound: false, policyCount: 0 };

  const matchingPolicies = findPolicies(policies, check.type);
  if (matchingPolicies.length === 0) return { code, met: false, policyFound: false, policyCount: 0 };

  // A tenant can have more than one policy of the same type - the check is
  // only "met" if every one of them satisfies it, since a single compliant
  // policy alongside a misconfigured one still leaves a real gap.
  const unmetPolicies = matchingPolicies.filter((p) => !p[check.field]);
  const met = unmetPolicies.length === 0;

  return {
    code,
    met,
    policyFound: true,
    policyCount: matchingPolicies.length,
    currentPolicyName: matchingPolicies.length === 1 ? matchingPolicies[0].displayName : undefined,
    unmetPolicyNames: matchingPolicies.length > 1 && !met ? unmetPolicies.map((p) => p.displayName) : undefined,
  };
}

export function evaluateMdoBaseline(policies: MdoThreatPolicy[]): { results: MdoBaselineResult[]; coveragePercent: number } {
  const results = MDO_BASELINE_STANDARDS.map((standard) => evaluateCode(standard.code, policies));
  const metCount = results.filter((r) => r.met).length;
  return { results, coveragePercent: computeBaselineCoveragePercent(metCount, MDO_BASELINE_STANDARDS.length) };
}
