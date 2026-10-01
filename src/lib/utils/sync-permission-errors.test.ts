import { describe, expect, it } from "vitest";
import { resolveSyncErrors } from "./sync-permission-errors";
import { GRAPH_PERMISSIONS, REQUIRED_GRAPH_PERMISSION_NAMES, findPermissionForSyncError } from "../data/graph-permissions";

// The two errors every live tenant carried (2026-10-01), verbatim shape.
const INCIDENTS = "Security Incidents: Missing application roles. API required roles: SecurityIncident.Read.All,SecurityIncident.ReadWrite.All, application roles: Policy.Read.All,User.Read.All.";
const CONNECTOR =
  'MDE connector settings: {\n  "_version": 3,\n  "Message": "Application is not authorized to perform this operation. Application must have one of the following scopes: DeviceManagementServiceConfiguration.Read.All"}';
const ALL_REQUIRED = REQUIRED_GRAPH_PERMISSION_NAMES;
const without = (...names: string[]) => ALL_REQUIRED.filter((r) => !names.includes(r));

describe("resolveSyncErrors", () => {
  it("names the permission to grant instead of Microsoft's raw refusal", () => {
    const r = resolveSyncErrors([INCIDENTS, CONNECTOR], without("SecurityIncident.Read.All", "DeviceManagementServiceConfig.Read.All"));
    expect(r.errors).toEqual([
      "Security Incidents: not synced - the SecurityIncident.Read.All permission isn't granted. Add it under API permissions in Entra and grant admin consent.",
      "MDE connector settings: not synced - the DeviceManagementServiceConfig.Read.All permission isn't granted. Add it under API permissions in Entra and grant admin consent.",
    ]);
    expect(r.missingPermissions).toEqual(["SecurityIncident.Read.All", "DeviceManagementServiceConfig.Read.All"]);
  });

  it("keeps each step's own prefix so module banners still find their errors", () => {
    const r = resolveSyncErrors(['ASR Rules (Settings Catalog): {"ErrorCode":"Forbidden"}'], without("DeviceManagementConfiguration.Read.All"));
    expect(r.errors[0].startsWith("ASR Rules (Settings Catalog):")).toBe(true);
  });

  it("doesn't count a declined optional permission as a sync error", () => {
    const r = resolveSyncErrors(["OAuth consent grants: Insufficient privileges to complete the operation."], ALL_REQUIRED);
    expect(r).toEqual({ errors: [], missingPermissions: [] });
  });

  it("leaves a refusal alone when the permission is granted (licence or backend problem, not consent)", () => {
    const raw = 'Intune devices: {"ErrorCode":"Forbidden","Message":"An error has occurred"}';
    expect(resolveSyncErrors([raw], ALL_REQUIRED).errors).toEqual([raw]);
  });

  it("leaves non-permission errors alone even when the permission is missing", () => {
    const raw = "Sign-in logs: Request timed out: timeout after 30000ms";
    expect(resolveSyncErrors([raw], without("AuditLog.Read.All")).errors).toEqual([raw]);
  });

  it("accepts either alternative of a two-name permission", () => {
    const raw = "Tenant Licenses (SubscribedSkus): Insufficient privileges to complete the operation.";
    const r = resolveSyncErrors([raw], [...without("Organization.Read.All"), "Directory.Read.All"]);
    expect(r.errors).toEqual([raw]);
    expect(r.missingPermissions).toEqual([]);
  });

  it("changes nothing when the token's permissions can't be read", () => {
    expect(resolveSyncErrors([INCIDENTS], null)).toEqual({ errors: [INCIDENTS], missingPermissions: [] });
  });
});

describe("permission catalogue", () => {
  it("has every permission the sync needs as a required, read-only entry", () => {
    for (const name of ["SecurityIncident.Read.All", "DeviceManagementServiceConfig.Read.All", "Application.Read.All"]) {
      expect(REQUIRED_GRAPH_PERMISSION_NAMES).toContain(name);
    }
    expect(GRAPH_PERMISSIONS.filter((p) => !p.optional && p.isWriteAccess)).toEqual([]);
  });

  it("gives every optional permission a one-line purpose for onboarding", () => {
    expect(GRAPH_PERMISSIONS.filter((p) => p.optional && !p.purpose)).toEqual([]);
  });

  it("never maps one sync step to two permissions, and doesn't confuse Groups with Group Settings", () => {
    const steps = GRAPH_PERMISSIONS.flatMap((p) => p.syncSteps || []);
    expect(new Set(steps).size).toBe(steps.length);
    expect(findPermissionForSyncError("Group Settings: x")?.permission).toBe("Group.Read.All");
    expect(findPermissionForSyncError("Groupies: x")).toBeUndefined();
  });
});
