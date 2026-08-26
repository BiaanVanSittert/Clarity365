import { SharePointTenantPolicy, SharePointBaselineResult } from "../types";
import { SHAREPOINT_BASELINE_STANDARDS } from "../data/sharepoint-baseline-definitions";
import { computeBaselineCoveragePercent } from "./ca-baseline-matcher";

export interface SharePointBaselineInput {
  policy: SharePointTenantPolicy;
  // Lowercased UPNs of disabled or unlicensed-active accounts (Module 5's
  // accountClassification) - used by SP05 to cross-check site ownership.
  inactiveUserPrincipalNamesLower: Set<string>;
}

function evaluateCode(code: string, input: SharePointBaselineInput): SharePointBaselineResult {
  const { policy } = input;

  if (code === "SP01") return { code, met: policy.tenantSharingLevel !== "Anyone" };
  if (code === "SP02") return { code, met: policy.anonymousLinkExpirationDays > 0 };
  if (code === "SP03") return { code, met: policy.defaultLinkType !== "Anyone" };
  if (code === "SP04") {
    const offenders = policy.sites.filter(
      (s) => s.isSensitiveDataPresent && (s.sharingCapability === "Anyone" || s.sharingCapability === "NewAndExistingGuests")
    );
    return {
      code,
      met: offenders.length === 0,
      offendingSiteNames: offenders.length > 0 ? offenders.map((s) => s.siteName) : undefined,
    };
  }
  if (code === "SP05") {
    const offenders = policy.sites.filter(
      (s) => s.ownerUPN && input.inactiveUserPrincipalNamesLower.has(s.ownerUPN.toLowerCase())
    );
    return {
      code,
      met: offenders.length === 0,
      offendingSiteNames: offenders.length > 0 ? offenders.map((s) => s.siteName) : undefined,
    };
  }
  return { code, met: false };
}

export function evaluateSharePointBaseline(input: SharePointBaselineInput): {
  results: SharePointBaselineResult[];
  coveragePercent: number;
} {
  const results = SHAREPOINT_BASELINE_STANDARDS.map((standard) => evaluateCode(standard.code, input));
  const metCount = results.filter((r) => r.met).length;
  return { results, coveragePercent: computeBaselineCoveragePercent(metCount, SHAREPOINT_BASELINE_STANDARDS.length) };
}
