import { describe, expect, it } from "vitest";
import { CAPolicyRule } from "../types";
import { CaEnvironment, CaSimUser, SignInContext } from "./ca-policy-evaluator";
import { meetsDesiredOutcome, recommendFixes } from "./ca-fix-recommender";

const user: CaSimUser = {
  id: "11111111-1111-1111-1111-111111111111",
  userPrincipalName: "sam@contoso.com",
  isGuest: false,
  roleTemplateIds: [],
  roleTemplateIdsComplete: true,
  groupIds: [],
};

const foreignSignIn: SignInContext = {
  user,
  target: { kind: "resource", resource: "Office365" },
  clientAppType: "browser",
  platform: "windows",
  device: "unmanaged",
  location: { country: "RU", ipNamedLocationIds: [] },
  signInRisk: "none",
  userRisk: "none",
  insiderRisk: "none",
};

function countryBlock(overrides: Partial<CAPolicyRule> = {}, exclude: string[] = []): CAPolicyRule {
  return {
    id: "ca08",
    name: "CA08: Block Access from Untrusted Countries",
    baselineCode: "CA08",
    state: "enabled",
    modifiedDateTime: "",
    createdDateTime: "",
    grantControls: ["block"],
    matchesBaseline: true,
    conditions: {
      users: { include: ["All"], exclude },
      applications: { include: ["All"], exclude: [] },
      clientAppTypes: ["all"],
      locations: { include: ["All"], exclude: ["loc-za"] },
    },
    ...overrides,
  };
}

const env = (policies: CAPolicyRule[]): CaEnvironment => ({
  policies,
  namedLocations: [{ id: "loc-za", displayName: "South Africa", kind: "country", countries: ["ZA"] }],
  groups: [],
  entraP2Licensed: true,
});

const options = { baselineCode: "CA08", baselineName: "Block Access from Untrusted Countries", newPolicyDescription: "Block all countries except the ones you operate in.", breakGlass: [] };

describe("recommendFixes", () => {
  it("returns nothing when the situation is already prevented", () => {
    expect(recommendFixes(foreignSignIn, env([countryBlock()]), "block", options)).toEqual([]);
  });

  it("recommends enabling a report-only policy that would block it", () => {
    const fixes = recommendFixes(foreignSignIn, env([countryBlock({ state: "enabledForReportingButNotEnforced" })]), "block", options);
    expect(fixes[0]).toMatchObject({ kind: "enableReportOnly", policyIds: ["ca08"] });
    // A report-only CA08 counts as "not deployed", so the baseline is offered too.
    expect(fixes.map((f) => f.kind)).toContain("deployBaseline");
  });

  it("recommends reviewing an exclusion, with a break-glass warning when it looks like one", () => {
    const excluded = countryBlock({}, [user.id!]);
    const plain = recommendFixes(foreignSignIn, env([excluded]), "block", options);
    expect(plain[0]).toMatchObject({ kind: "removeExclusion", policyIds: ["ca08"] });
    expect(plain[0].warning).toBeUndefined();

    const withBreakGlass = recommendFixes(foreignSignIn, env([excluded]), "block", {
      ...options,
      breakGlass: [{ ref: user.id!, kind: "user", excludedFromCount: 1, eligiblePolicyCount: 1, reasons: ["Named like an emergency-access account"] }],
    });
    expect(withBreakGlass[0].warning).toMatch(/break-glass/);
  });

  it("recommends the baseline when no policy exists, and a new policy when there's no baseline", () => {
    expect(recommendFixes(foreignSignIn, env([]), "block", options).map((f) => f.kind)).toEqual(["deployBaseline"]);
    const noBaseline = recommendFixes(foreignSignIn, env([]), "block", { ...options, baselineCode: undefined });
    expect(noBaseline).toEqual([{ kind: "createPolicy", title: "Create a new Conditional Access policy", detail: options.newPolicyDescription }]);
  });
});

describe("targeted vs broad fixes", () => {
  const compliantForAll: CAPolicyRule = {
    ...countryBlock(),
    id: "ca09",
    name: "CA09: Require compliant device",
    baselineCode: "CA09",
    state: "enabledForReportingButNotEnforced",
    grantControls: ["compliantDevice"],
    conditions: { users: { include: ["All"], exclude: [] }, applications: { include: ["All"], exclude: [] }, clientAppTypes: ["all"] },
  };
  const reportOnlyCountryBlock = countryBlock({ state: "enabledForReportingButNotEnforced" });
  const normalContext: SignInContext = { ...foreignSignIn, location: { country: "ZA", ipNamedLocationIds: [] } };

  it("flags a fix that would also block normal sign-ins and lists it after the targeted one (regression: CA09 offered for everything)", () => {
    const fixes = recommendFixes(foreignSignIn, env([compliantForAll, reportOnlyCountryBlock]), "block", { ...options, normalContext });
    const enables = fixes.filter((f) => f.kind === "enableReportOnly");
    expect(enables.map((f) => f.policyIds![0])).toEqual(["ca08", "ca09"]);
    expect(enables[0].sideEffect).toBeUndefined();
    expect(enables[1].sideEffect).toMatch(/normal sign-ins/);
  });

  it("still suggests a new policy when only broad fixes exist", () => {
    const fixes = recommendFixes(foreignSignIn, env([compliantForAll]), "block", { ...options, baselineCode: undefined, normalContext });
    expect(fixes.map((f) => f.kind)).toEqual(["createPolicy", "enableReportOnly"]);
  });

  it("leads with licensing for risk situations when Entra ID P2 is missing", () => {
    const risky: SignInContext = { ...normalContext, userRisk: "high" };
    const fixes = recommendFixes(risky, { ...env([]), entraP2Licensed: false }, "passwordChange", { ...options, baselineCode: "CA07" });
    expect(fixes[0].kind).toBe("licence");
    expect(fixes.map((f) => f.kind)).not.toContain("createPolicy");
  });
});

describe("meetsDesiredOutcome", () => {
  const challenged = (kinds: any[]) => ({ outcome: "challenged" as const, blockedBy: [], requirements: [], requirementKinds: kinds, sessionControls: [], uncertainPolicies: [], partialCoverage: [] });
  it("MFA meets strongAuth but not block or phishingResistant", () => {
    expect(meetsDesiredOutcome(challenged(["mfa"]), "strongAuth")).toBe(true);
    expect(meetsDesiredOutcome(challenged(["mfa"]), "block")).toBe(false);
    expect(meetsDesiredOutcome(challenged(["mfa"]), "phishingResistant")).toBe(false);
    expect(meetsDesiredOutcome(challenged(["phishingResistantMfa"]), "phishingResistant")).toBe(true);
  });
});
