import { TenantSecuritySnapshot } from "@/lib/types";

// Is Microsoft Intune licensed? Same shape and reason as entra-p2.ts and
// defender-for-endpoint.ts: live tenants get one generic "cap-intune"
// capability from capabilities-mapper.ts, while demo data uses tier-specific
// ids like "cap-intune-p1" - a check against only one of them silently
// fails for the other (the recurring bug class in ai-context-vault/
// Optimization/Optimization Plan.md item 7).
export function hasIntuneCapability(snapshot: Pick<TenantSecuritySnapshot, "capabilities">): boolean {
  return (snapshot.capabilities || []).some(
    (c) => c.licensed && (c.id === "cap-intune" || c.id.startsWith("cap-intune-") || c.name.toLowerCase().includes("intune"))
  );
}
