import { describe, expect, it } from "vitest";
import {
  DIRECTORY_ROLE_TEMPLATES,
  GLOBAL_ADMIN_TEMPLATE_ID,
  getRoleTemplateByName,
  isGlobalAdminRoleName,
  resolveCaRoleReference,
  roleNamesToTemplateIds,
} from "./directory-role-templates";

describe("DIRECTORY_ROLE_TEMPLATES", () => {
  it("has no duplicate template ids", () => {
    const ids = DIRECTORY_ROLE_TEMPLATES.map((r) => r.templateId.toLowerCase());
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("marks exactly Microsoft's 14 admin-MFA template roles as privileged", () => {
    expect(DIRECTORY_ROLE_TEMPLATES.filter((r) => r.isPrivileged)).toHaveLength(14);
  });
});

describe("resolveCaRoleReference", () => {
  it("resolves a live includeRoles template GUID (any case)", () => {
    expect(resolveCaRoleReference("62E90394-69F5-4237-9190-012177145E10")).toEqual([GLOBAL_ADMIN_TEMPLATE_ID]);
  });

  it("resolves the demo/local-write DirectoryRole:<Alias> markers", () => {
    expect(resolveCaRoleReference("DirectoryRole:GlobalAdmin")).toEqual([GLOBAL_ADMIN_TEMPLATE_ID]);
    expect(resolveCaRoleReference("DirectoryRole:SecurityAdmin")).toEqual(["194ae4cb-b126-40b2-bd5b-6091b380977d"]);
    expect(resolveCaRoleReference("DirectoryRole:ExchangeAdmin")).toEqual(["29232cdf-9323-42fd-ade2-1d097af3e4de"]);
  });

  it("expands the demo AllAdmins marker to every privileged role", () => {
    const ids = resolveCaRoleReference("AllAdmins");
    expect(ids).toHaveLength(14);
    expect(ids).toContain(GLOBAL_ADMIN_TEMPLATE_ID);
  });

  it("returns [] for entries that are not role references", () => {
    expect(resolveCaRoleReference("All")).toEqual([]);
    expect(resolveCaRoleReference("GuestsOrExternalUsers")).toEqual([]);
    expect(resolveCaRoleReference("upn:breakglass01@contosopharm.com")).toEqual([]);
    expect(resolveCaRoleReference("DirectoryRole:NoSuchRole")).toEqual([]);
  });
});

describe("role name lookups", () => {
  it("accepts the legacy Company Administrator name for Global Administrator", () => {
    expect(getRoleTemplateByName("Company Administrator")?.templateId).toBe(GLOBAL_ADMIN_TEMPLATE_ID);
    expect(isGlobalAdminRoleName("global administrator")).toBe(true);
    expect(isGlobalAdminRoleName("Security Administrator")).toBe(false);
  });

  it("maps adminRoles display names to template ids, dropping unknown names", () => {
    expect(roleNamesToTemplateIds(["Global Administrator", "Exchange Administrator", "Some Custom Role"])).toEqual([
      GLOBAL_ADMIN_TEMPLATE_ID,
      "29232cdf-9323-42fd-ade2-1d097af3e4de",
    ]);
  });
});
