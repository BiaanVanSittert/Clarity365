import { describe, it, expect } from "vitest";
import { evaluateSharePointBaseline, SharePointBaselineInput } from "./sharepoint-baseline-matcher";
import { SHAREPOINT_BASELINE_STANDARDS } from "../data/sharepoint-baseline-definitions";
import { SharePointSiteItem, SharePointTenantPolicy } from "../types";

function site(overrides: Partial<SharePointSiteItem> & Pick<SharePointSiteItem, "id" | "siteName">): SharePointSiteItem {
  return {
    siteUrl: `https://contoso.sharepoint.com/sites/${overrides.id}`,
    template: "TeamSite",
    storageUsedGB: 1,
    storageAllocatedGB: 100,
    sharingCapability: "OnlyPeopleInOrg",
    isSensitiveDataPresent: false,
    ownerUPN: "owner@contoso.com",
    lastActivityDate: new Date().toISOString(),
    ...overrides,
  };
}

function policy(overrides: Partial<SharePointTenantPolicy> = {}): SharePointTenantPolicy {
  return {
    tenantSharingLevel: "OnlyPeopleInOrg",
    defaultLinkType: "Internal",
    anonymousLinkExpirationDays: 30,
    totalStorageAllocatedTB: 1,
    totalStorageUsedTB: 0.1,
    sites: [],
    ...overrides,
  };
}

function baseInput(overrides: Partial<SharePointBaselineInput> = {}): SharePointBaselineInput {
  return {
    policy: policy(),
    inactiveUserPrincipalNamesLower: new Set(),
    ...overrides,
  };
}

describe("evaluateSharePointBaseline", () => {
  it("scores 100% when everything is compliant", () => {
    const { results, coveragePercent } = evaluateSharePointBaseline(baseInput());
    expect(coveragePercent).toBe(100);
    expect(results).toHaveLength(SHAREPOINT_BASELINE_STANDARDS.length);
    expect(results.every((r) => r.met)).toBe(true);
  });

  it("SP01 fails when the tenant ceiling is Anyone", () => {
    const result = evaluateSharePointBaseline(baseInput({ policy: policy({ tenantSharingLevel: "Anyone" }) })).results.find(
      (r) => r.code === "SP01"
    )!;
    expect(result.met).toBe(false);
  });

  it("SP02 fails when anonymous links never expire", () => {
    const result = evaluateSharePointBaseline(baseInput({ policy: policy({ anonymousLinkExpirationDays: 0 }) })).results.find(
      (r) => r.code === "SP02"
    )!;
    expect(result.met).toBe(false);
  });

  it("SP03 fails when the default link type is Anyone", () => {
    const result = evaluateSharePointBaseline(baseInput({ policy: policy({ defaultLinkType: "Anyone" }) })).results.find(
      (r) => r.code === "SP03"
    )!;
    expect(result.met).toBe(false);
  });

  it("SP04 flags a sensitive-data site that also allows open sharing", () => {
    const sites = [site({ id: "s1", siteName: "Clinical Records", isSensitiveDataPresent: true, sharingCapability: "Anyone" })];
    const result = evaluateSharePointBaseline(baseInput({ policy: policy({ sites }) })).results.find((r) => r.code === "SP04")!;
    expect(result.met).toBe(false);
    expect(result.offendingSiteNames).toEqual(["Clinical Records"]);
  });

  it("SP04 does not flag a sensitive-data site that's locked down", () => {
    const sites = [site({ id: "s2", siteName: "Clinical Records", isSensitiveDataPresent: true, sharingCapability: "OnlyPeopleInOrg" })];
    expect(evaluateSharePointBaseline(baseInput({ policy: policy({ sites }) })).results.find((r) => r.code === "SP04")!.met).toBe(true);
  });

  it("SP04 does not flag open sharing on a non-sensitive site", () => {
    const sites = [site({ id: "s3", siteName: "Marketing", isSensitiveDataPresent: false, sharingCapability: "Anyone" })];
    expect(evaluateSharePointBaseline(baseInput({ policy: policy({ sites }) })).results.find((r) => r.code === "SP04")!.met).toBe(true);
  });

  it("SP05 flags sites owned by a disabled/departed account", () => {
    const sites = [site({ id: "s4", siteName: "Old Project", ownerUPN: "former.employee@contoso.com" })];
    const result = evaluateSharePointBaseline(
      baseInput({ policy: policy({ sites }), inactiveUserPrincipalNamesLower: new Set(["former.employee@contoso.com"]) })
    ).results.find((r) => r.code === "SP05")!;
    expect(result.met).toBe(false);
    expect(result.offendingSiteNames).toEqual(["Old Project"]);
  });

  it("SP05 does not flag a site with no resolvable owner", () => {
    const sites = [site({ id: "s5", siteName: "Unowned", ownerUPN: "" })];
    expect(
      evaluateSharePointBaseline(baseInput({ policy: policy({ sites }), inactiveUserPrincipalNamesLower: new Set([""]) })).results.find(
        (r) => r.code === "SP05"
      )!.met
    ).toBe(true);
  });
});
