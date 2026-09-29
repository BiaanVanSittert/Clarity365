import { describe, expect, it } from "vitest";
import { mergeDemoCaPolicies } from "./demo-ca-policy-merge";
import { CAPolicyRule } from "../types";

function policy(id: string, overrides: Partial<CAPolicyRule> = {}): CAPolicyRule {
  return {
    id,
    name: `${id}: policy`,
    baselineCode: null,
    state: "enabled",
    modifiedDateTime: "2026-07-01T12:00:00Z",
    createdDateTime: "2024-01-01T00:00:00Z",
    grantControls: ["mfa"],
    conditions: { users: { include: ["All"], exclude: [] }, applications: { include: ["All"], exclude: [] }, clientAppTypes: ["all"] },
    matchesBaseline: false,
    ...overrides,
  };
}

describe("mergeDemoCaPolicies", () => {
  it("refreshes a stale stored shape from mock data (the Woodgrove repair case)", () => {
    const stored = [policy("ca-wg-ca01", { grantControls: ["mfa"] })];
    const mock = [policy("ca-wg-ca01", { grantControls: ["block"] })];
    expect(mergeDemoCaPolicies(stored, mock)[0].grantControls).toEqual(["block"]);
  });

  it("keeps the state of a policy a local demo deploy changed after the mock timestamp", () => {
    const stored = [policy("ca-1", { state: "enabledForReportingButNotEnforced", modifiedDateTime: "2026-09-29T10:00:00Z", grantControls: ["mfa"] })];
    const mock = [policy("ca-1", { grantControls: ["mfa", "compliantDevice"] })];
    const [merged] = mergeDemoCaPolicies(stored, mock);
    expect(merged.state).toBe("enabledForReportingButNotEnforced");
    expect(merged.modifiedDateTime).toBe("2026-09-29T10:00:00Z");
    expect(merged.grantControls).toEqual(["mfa", "compliantDevice"]);
  });

  it("keeps locally deployed policies that don't exist in mock data, after the mock ones", () => {
    const stored = [policy("ca-1"), policy("pol-ca-123-ca05")];
    const mock = [policy("ca-1"), policy("ca-2")];
    expect(mergeDemoCaPolicies(stored, mock).map((p) => p.id)).toEqual(["ca-1", "ca-2", "pol-ca-123-ca05"]);
  });
});
