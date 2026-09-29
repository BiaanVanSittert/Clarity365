import { TenantSecuritySnapshot } from "@/lib/types";

// Entra ID P2 is what Conditional Access risk-based policies (CA06/CA07 and
// others) and PIM depend on. Checking a single hardcoded capability id is
// not enough: mock tenants use "cap-entra-p2" while a live-synced tenant's
// capabilities-mapper.ts always produces one generic "cap-entra" entry
// covering both P1 and P2, distinguished only by its `tier` field ("Plan 2
// (P2)" vs "Plan 1 (P1)") - a check for only the mock id, or a name-substring
// match against "entra id p2", silently fails for every live tenant
// regardless of actual licensing, because the real generated name is
// "Microsoft Entra ID P1/P2" - which does NOT contain "entra id p2" as a
// contiguous substring (the "1/" sits in between). Confirmed against a real
// live tenant (Ashton John's Private School, licensed via a standalone
// AAD_PREMIUM_P2_FACULTY add-on) whose stored capabilities already correctly
// showed cap-entra licensed with tier "Plan 2 (P2)", yet every consumer of
// the old inline check still reported "no Entra P2" - this was the exact
// bug ConditionalAccessModule.tsx's original check had, silently copied
// forward into drift-analyzer.ts too.
export function hasEntraP2Capability(snapshot: TenantSecuritySnapshot): boolean {
  const capabilityMatch = (snapshot.capabilities || []).some(
    (c) =>
      c.licensed &&
      ((c.id === "cap-entra" && c.tier?.toLowerCase().includes("p2")) ||
        c.id === "cap-entra-p2" ||
        c.name.toLowerCase().includes("entra id p2") ||
        c.name.toLowerCase().includes("azure ad premium p2") ||
        c.name.toLowerCase().includes("identity protection"))
  );
  if (capabilityMatch) return true;

  return snapshot.tenant.tier === "M365_E5";
}
