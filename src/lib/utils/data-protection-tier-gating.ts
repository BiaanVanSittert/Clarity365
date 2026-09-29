import { TenantLicenseType } from "@/lib/types";
import { LicenseTier } from "@/lib/data/data-protection-recommendations";

// Best-effort mapping from a tenant's user-set Tenant.tier label to whether it
// meets a DLP recommendation's minimumLicenseTier - NOT live-verified
// entitlement evidence, the same distinction capabilities-mapper.ts's live
// checks already draw (see ai-context-vault/Optimization/DLP Stage 5 - Fleet
// Rollout.md). Used only for the read-only fleet visibility matrix - never
// for gating a live write, since this feature has none.
export type TierEligibility = "eligible" | "requires_e5" | "unknown";

// Whether each tier meets the "business_premium_e3" floor (Exchange/
// SharePoint/OneDrive DLP + manual labels) that every recommendation in the
// catalog assumes as its minimum. M365_F3 (Frontline) is marked "unknown"
// deliberately - its real-world DLP entitlement wasn't confidently known
// when this was written, and defaulting it to "eligible" would be a guess
// dressed up as a fact.
const MEETS_BP_E3_BASELINE: Record<TenantLicenseType, TierEligibility> = {
  M365_E5: "eligible",
  M365_E3: "eligible",
  M365_BP: "eligible",
  A5_EDU: "eligible",
  M365_F3: "unknown",
};

// Whether each tier meets the "e5" floor. A5_EDU is marked eligible on the
// belief that Microsoft 365 A5 for Education bundles a Purview E5-equivalent
// capability set, mirroring capabilities-mapper.ts's own M365EDU_A5 handling
// for Entra P2/MDE/MDO - not independently re-confirmed for Purview
// specifically in this session.
const MEETS_E5: Record<TenantLicenseType, TierEligibility> = {
  M365_E5: "eligible",
  A5_EDU: "eligible",
  M365_E3: "requires_e5",
  M365_BP: "requires_e5",
  M365_F3: "unknown",
};

export function getTierEligibility(
  tenantTier: TenantLicenseType,
  minimumLicenseTier: LicenseTier
): TierEligibility {
  return minimumLicenseTier === "e5" ? MEETS_E5[tenantTier] : MEETS_BP_E3_BASELINE[tenantTier];
}
