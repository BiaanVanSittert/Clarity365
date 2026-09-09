import { TenantSecuritySnapshot } from "@/lib/types";

// Attack Surface Reduction is a Defender for Endpoint (or, for SMB tenants,
// Defender for Business) capability. Checking a single hardcoded capability
// id is not enough: mock tenants use "cap-mde-p1"/"cap-mde-p2" (split by
// tier), while a live-synced tenant's capabilities-mapper.ts always produces
// one generic "cap-mde" entry regardless of tier - a check for only the mock
// ids (as this module originally had) silently fails for every live tenant,
// which is exactly the bug this function exists to prevent from recurring.
// The tier fallback is a last-resort safety net matching the same pattern
// ConditionalAccessModule.tsx already uses for Entra P2 detection.
export function hasDefenderForEndpointCapability(snapshot: TenantSecuritySnapshot): boolean {
  const capabilityMatch = (snapshot.capabilities || []).some(
    (c) =>
      c.licensed &&
      (c.id === "cap-mde" ||
        c.id === "cap-mde-p1" ||
        c.id === "cap-mde-p2" ||
        c.name.toLowerCase().includes("defender for endpoint") ||
        c.name.toLowerCase().includes("defender for business"))
  );
  if (capabilityMatch) return true;

  // Business Premium and E5 both genuinely bundle real Defender for
  // Endpoint/Defender for Business - E3 does not by default, so it's
  // deliberately excluded here (matches this app's own mock data, where the
  // E3 demo tenant's cap-mde-p1 is licensed: false).
  return snapshot.tenant.tier === "M365_E5" || snapshot.tenant.tier === "M365_BP";
}
