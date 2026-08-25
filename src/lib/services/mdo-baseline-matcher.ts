import { MdoThreatPolicy, MdoBaselineResult } from "../types";
import { MDO_BASELINE_STANDARDS } from "../data/mdo-baseline-definitions";
import { computeBaselineCoveragePercent } from "./ca-baseline-matcher";

// Scores live MdoThreatPolicy rows against MDO_BASELINE_STANDARDS. Unlike CA's
// matcher (which has to infer which baseline a policy structurally matches),
// each MDO check already names the exact policyType and field it inspects, so
// this is a direct per-code lookup rather than a cascade — reuses
// computeBaselineCoveragePercent from ca-baseline-matcher.ts rather than
// re-deriving the same pure percentage calculation.

const ORG_WIDE_SCOPE = "Default (Organization-wide)";

function findPolicy(policies: MdoThreatPolicy[], type: MdoThreatPolicy["policyType"]): MdoThreatPolicy | undefined {
  return policies.find((p) => p.policyType === type);
}

function evaluateCode(code: string, policies: MdoThreatPolicy[]): MdoBaselineResult {
  // MDO09 is the one aggregate check — it spans every core policy type rather
  // than a single one, so it's handled separately from the direct 1:1 lookups below.
  if (code === "MDO09") {
    const corePolicies = (["AntiPhishing", "AntiSpamInbound", "SafeLinks", "SafeAttachments"] as const).map((t) =>
      findPolicy(policies, t)
    );
    const policyFound = corePolicies.every((p) => !!p);
    const met = policyFound && corePolicies.every((p) => p!.assignedScope === ORG_WIDE_SCOPE);
    return { code, met, policyFound };
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
  if (!check) return { code, met: false, policyFound: false };

  const policy = findPolicy(policies, check.type);
  if (!policy) return { code, met: false, policyFound: false };

  return {
    code,
    met: !!policy[check.field],
    policyFound: true,
    currentPolicyName: policy.displayName,
  };
}

export function evaluateMdoBaseline(policies: MdoThreatPolicy[]): { results: MdoBaselineResult[]; coveragePercent: number } {
  const results = MDO_BASELINE_STANDARDS.map((standard) => evaluateCode(standard.code, policies));
  const metCount = results.filter((r) => r.met).length;
  return { results, coveragePercent: computeBaselineCoveragePercent(metCount, MDO_BASELINE_STANDARDS.length) };
}
