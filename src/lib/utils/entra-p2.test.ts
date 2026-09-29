import { describe, it, expect } from "vitest";
import { hasEntraP2Capability } from "./entra-p2";
import { TenantSecuritySnapshot } from "../types";

function makeSnapshot(overrides: {
  capabilities?: TenantSecuritySnapshot["capabilities"];
  tier?: TenantSecuritySnapshot["tenant"]["tier"];
}): TenantSecuritySnapshot {
  return {
    tenant: { tier: overrides.tier || "M365_E3" } as TenantSecuritySnapshot["tenant"],
    capabilities: overrides.capabilities || [],
  } as TenantSecuritySnapshot;
}

describe("hasEntraP2Capability", () => {
  it("recognizes the live-sync generic cap-entra id when its tier is Plan 2", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-entra", name: "Microsoft Entra ID P1/P2", category: "Identity", licensed: true, tier: "Plan 2 (P2)", description: "" }],
    });
    expect(hasEntraP2Capability(snapshot)).toBe(true);
  });

  it("does not treat the live generic cap-entra id as P2 when its tier is only Plan 1 - this is the exact bug being fixed", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-entra", name: "Microsoft Entra ID P1/P2", category: "Identity", licensed: true, tier: "Plan 1 (P1)", description: "" }],
    });
    expect(hasEntraP2Capability(snapshot)).toBe(false);
  });

  it("recognizes a real Ashton John's-style standalone P2 add-on tenant (cap-entra, licensed, Plan 2 tier, base tier not E5)", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-entra", name: "Microsoft Entra ID P1/P2", category: "Identity", licensed: true, tier: "Plan 2 (P2)", description: "" }],
      tier: "M365_E3",
    });
    expect(hasEntraP2Capability(snapshot)).toBe(true);
  });

  it("recognizes the mock-data cap-entra-p2 id", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-entra-p2", name: "Microsoft Entra ID P2", category: "Identity", licensed: true, tier: "Included (E5)", description: "" }],
    });
    expect(hasEntraP2Capability(snapshot)).toBe(true);
  });

  it("falls back to true for M365_E5 tier even with no matching capability entry", () => {
    const snapshot = makeSnapshot({ capabilities: [], tier: "M365_E5" });
    expect(hasEntraP2Capability(snapshot)).toBe(true);
  });

  it("does not fall back to true for M365_E3 with no matching capability", () => {
    const snapshot = makeSnapshot({ capabilities: [], tier: "M365_E3" });
    expect(hasEntraP2Capability(snapshot)).toBe(false);
  });

  it("returns false when the capability entry exists but is not licensed", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-entra", name: "Microsoft Entra ID P1/P2", category: "Identity", licensed: false, tier: "Plan 2 (P2)", description: "" }],
      tier: "M365_E3",
    });
    expect(hasEntraP2Capability(snapshot)).toBe(false);
  });
});
