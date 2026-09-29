import { describe, expect, it } from "vitest";
import { MOCK_TENANT_DATA } from "./mock-tenants";
import { validateCaPolicyCompliance } from "../services/ca-baseline-matcher";

// Guards the demo Conditional Access data the Security Simulations views are
// demoed against (ai-context-vault/Optimization/Security Simulations Plan.md).
describe("demo tenant Conditional Access data", () => {
  it("Woodgrove (the zero-trust demo) passes validation for every CA01-CA10 policy (regression: 8 of 10 used to fail)", () => {
    const woodgrove = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
    const baselinePolicies = woodgrove.conditionalAccess.policies.filter((p) => p.baselineCode);
    expect(baselinePolicies).toHaveLength(10);
    for (const policy of baselinePolicies) {
      const result = validateCaPolicyCompliance(policy as any, policy.baselineCode!);
      expect({ policy: policy.name, ...result }).toMatchObject({ policy: policy.name, isValid: true });
    }
  });

  it("every demo tenant carries named locations and identity settings", () => {
    for (const [tenantId, snap] of Object.entries(MOCK_TENANT_DATA)) {
      expect(snap.conditionalAccess.namedLocations, tenantId).toBeDefined();
      expect(snap.identitySettings, tenantId).toBeDefined();
    }
  });

  it("every named-location id a demo policy references resolves to one of that tenant's named locations", () => {
    const builtIn = new Set(["All", "AllTrusted"]);
    for (const [tenantId, snap] of Object.entries(MOCK_TENANT_DATA)) {
      const known = new Set((snap.conditionalAccess.namedLocations || []).map((l) => l.id));
      for (const policy of snap.conditionalAccess.policies) {
        const refs = [...(policy.conditions.locations?.include || []), ...(policy.conditions.locations?.exclude || [])];
        for (const ref of refs.filter((r) => !builtIn.has(r))) {
          expect(known.has(ref), `${tenantId} / ${policy.name} references unknown location "${ref}"`).toBe(true);
        }
      }
    }
  });
});
