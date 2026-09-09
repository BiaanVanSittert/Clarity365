import { describe, it, expect } from "vitest";
import { hasDefenderForEndpointCapability } from "./defender-for-endpoint";
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

describe("hasDefenderForEndpointCapability", () => {
  it("recognizes the live-sync generic cap-mde id", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-mde", name: "Defender for Endpoint", category: "Endpoint", licensed: true, tier: "Active", description: "" }],
    });
    expect(hasDefenderForEndpointCapability(snapshot)).toBe(true);
  });

  it("recognizes the mock-data cap-mde-p1/cap-mde-p2 ids", () => {
    const p1 = makeSnapshot({
      capabilities: [{ id: "cap-mde-p1", name: "Defender for Business / MDE P1", category: "Endpoint", licensed: true, tier: "", description: "" }],
    });
    const p2 = makeSnapshot({
      capabilities: [{ id: "cap-mde-p2", name: "Defender for Endpoint P2", category: "Endpoint", licensed: true, tier: "", description: "" }],
    });
    expect(hasDefenderForEndpointCapability(p1)).toBe(true);
    expect(hasDefenderForEndpointCapability(p2)).toBe(true);
  });

  it("falls back to true for M365_BP or M365_E5 tier even with no matching capability entry (the reported Business Premium bug)", () => {
    const bp = makeSnapshot({ capabilities: [], tier: "M365_BP" });
    const e5 = makeSnapshot({ capabilities: [], tier: "M365_E5" });
    expect(hasDefenderForEndpointCapability(bp)).toBe(true);
    expect(hasDefenderForEndpointCapability(e5)).toBe(true);
  });

  it("does not fall back to true for M365_E3, matching this app's own mock data assumption", () => {
    const e3 = makeSnapshot({ capabilities: [], tier: "M365_E3" });
    expect(hasDefenderForEndpointCapability(e3)).toBe(false);
  });

  it("returns false when a capability entry exists but is not licensed", () => {
    const snapshot = makeSnapshot({
      capabilities: [{ id: "cap-mde", name: "Defender for Endpoint", category: "Endpoint", licensed: false, tier: "Unlicensed", description: "" }],
      tier: "M365_E3",
    });
    expect(hasDefenderForEndpointCapability(snapshot)).toBe(false);
  });
});
