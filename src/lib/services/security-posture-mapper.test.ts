import { describe, expect, it } from "vitest";
import {
  aggregateOAuthGrants,
  buildAdminRoleMapsFromRoleAssignments,
  mapCasMailbox,
  mapPimAssignments,
  mapRoleAssignmentsFallback,
  mapSharePointSecuritySettings,
  readBooleanSetting,
  smtpAuthEnabledFor,
} from "./security-posture-mapper";

describe("mapSharePointSecuritySettings", () => {
  it("maps the v1.0 sharepointSettings security fields and flags missing link defaults", () => {
    const out = mapSharePointSecuritySettings({
      sharingCapability: "externalUserSharingOnly",
      isResharingByExternalUsersEnabled: true,
      isUnmanagedSyncAppForTenantRestricted: false,
      allowedDomainGuidsForSyncApp: [],
      sharingDomainRestrictionMode: "none",
      isLegacyAuthProtocolsEnabled: true,
      idleSessionSignOut: { isEnabled: false, warnAfterInSeconds: 0, signOutAfterInSeconds: 0 },
      isRequireAcceptingUserToMatchInvitedUserEnabled: true,
    });
    expect(out).toEqual({
      linkDefaultsReported: false,
      resharingByExternalUsersEnabled: true,
      unmanagedSyncAppRestricted: false,
      syncAllowedDomainCount: 0,
      sharingDomainRestrictionMode: "none",
      legacyAuthProtocolsEnabled: true,
      idleSessionSignOutEnabled: false,
      requireAcceptingUserToMatchInvitedUser: true,
    });
  });

  it("leaves unreported fields undefined rather than false", () => {
    expect(mapSharePointSecuritySettings({})).toEqual({ linkDefaultsReported: false });
    expect(mapSharePointSecuritySettings({ sharingLinkDefaultType: "direct" }).linkDefaultsReported).toBe(true);
  });
});

describe("Exchange settings", () => {
  it("reads booleans returned as booleans or as PowerShell strings", () => {
    expect(readBooleanSetting({ UnifiedAuditLogIngestionEnabled: true }, "UnifiedAuditLogIngestionEnabled")).toBe(true);
    expect(readBooleanSetting({ X: "False" }, "X")).toBe(false);
    expect(readBooleanSetting({}, "X")).toBeUndefined();
  });

  it("maps a CAS mailbox, keeping a missing SMTP AUTH override as null (follows org default)", () => {
    expect(mapCasMailbox({ PrimarySmtpAddress: "a@x.com", PopEnabled: true, ImapEnabled: false, ActiveSyncEnabled: true, SmtpClientAuthenticationDisabled: null })).toEqual({
      primarySmtpAddress: "a@x.com",
      popEnabled: true,
      imapEnabled: false,
      activeSyncEnabled: true,
      smtpClientAuthDisabled: null,
    });
    expect(mapCasMailbox({})).toBeNull();
  });

  it("resolves effective SMTP AUTH from the per-mailbox override or the org default", () => {
    const followsOrg = { primarySmtpAddress: "a", popEnabled: false, imapEnabled: false, activeSyncEnabled: false, smtpClientAuthDisabled: null };
    expect(smtpAuthEnabledFor(followsOrg, true)).toBe(false);
    expect(smtpAuthEnabledFor(followsOrg, false)).toBe(true);
    expect(smtpAuthEnabledFor(followsOrg, undefined)).toBeUndefined();
    expect(smtpAuthEnabledFor({ ...followsOrg, smtpClientAuthDisabled: false }, true)).toBe(true);
  });
});

describe("role assignments", () => {
  const ga = "62E90394-69F5-4237-9190-012177145E10";
  it("maps PIM eligible, activated, permanent and time-bound assignments, skipping AU-scoped ones", () => {
    const out = mapPimAssignments(
      [{ principalId: "u1", roleDefinitionId: ga, directoryScopeId: "/", endDateTime: "2027-01-01T00:00:00Z", principal: { "@odata.type": "#microsoft.graph.user", userPrincipalName: "a@x.com" } }],
      [
        { principalId: "u2", roleDefinitionId: ga, directoryScopeId: "/", assignmentType: "Assigned", endDateTime: null },
        { principalId: "u3", roleDefinitionId: ga, directoryScopeId: "/", assignmentType: "Assigned", endDateTime: "2026-12-01T00:00:00Z" },
        { principalId: "u1", roleDefinitionId: ga, directoryScopeId: "/", assignmentType: "Activated", endDateTime: "2026-09-30T08:00:00Z" },
        { principalId: "u4", roleDefinitionId: ga, directoryScopeId: "/administrativeUnits/au1", assignmentType: "Assigned" },
      ]
    );
    expect(out.map((a) => [a.principalId, a.kind])).toEqual([
      ["u1", "eligible"],
      ["u2", "activePermanent"],
      ["u3", "activeTimeBound"],
      ["u1", "activated"],
    ]);
    expect(out[0]).toMatchObject({ roleTemplateId: ga.toLowerCase(), principalType: "user", principalUserPrincipalName: "a@x.com" });
  });

  it("treats every non-PIM role assignment as permanent", () => {
    expect(mapRoleAssignmentsFallback([{ principalId: "g1", roleDefinitionId: ga, principal: { "@odata.type": "#microsoft.graph.group" } }])).toEqual([
      { principalId: "g1", roleTemplateId: ga.toLowerCase(), kind: "activePermanent", principalType: "group", principalDisplayName: undefined, principalUserPrincipalName: undefined },
    ]);
  });
});

describe("buildAdminRoleMapsFromRoleAssignments", () => {
  const ga = "62E90394-69F5-4237-9190-012177145E10";
  it("rebuilds who holds which role when directoryRoles is unavailable", () => {
    const { rolesByPrincipal, templateIdsByPrincipal } = buildAdminRoleMapsFromRoleAssignments([
      { principalId: "u1", roleDefinitionId: ga, directoryScopeId: "/" },
      { principalId: "u1", roleDefinitionId: ga, directoryScopeId: "/" }, // duplicate row
      { principalId: "u1", roleDefinitionId: "custom-1", directoryScopeId: "/", roleDefinition: { displayName: "Helpdesk Lite" } },
      { principalId: "u2", roleDefinitionId: ga, directoryScopeId: "/administrativeUnits/au1" }, // scoped: not tenant-wide
      { principalId: "u3", roleDefinitionId: "unknown-role" },
      { roleDefinitionId: ga },
    ]);
    expect(rolesByPrincipal.get("u1")).toEqual(["Global Administrator", "Helpdesk Lite"]);
    expect(templateIdsByPrincipal.get("u1")).toEqual([ga.toLowerCase(), "custom-1"]);
    expect(rolesByPrincipal.has("u2")).toBe(false);
    expect(rolesByPrincipal.get("u3")).toEqual(["Directory Role"]);
    expect(rolesByPrincipal.size).toBe(2);
  });
});

describe("aggregateOAuthGrants", () => {
  it("groups grants per app and consent type, counts consenting users and flags high-risk scopes", () => {
    const grants = aggregateOAuthGrants(
      [
        { clientId: "sp1", consentType: "Principal", principalId: "u1", scope: "openid profile Mail.Read" },
        { clientId: "sp1", consentType: "Principal", principalId: "u2", scope: "openid Files.ReadWrite.All" },
        { clientId: "sp2", consentType: "AllPrincipals", principalId: null, scope: "User.Read" },
      ],
      new Map([
        ["sp1", { displayName: "Shady PDF Tool", publisherName: "Unknown Ltd", verifiedPublisher: null, appOwnerOrganizationId: "11111111-1111-1111-1111-111111111111" }],
        ["sp2", { displayName: "Microsoft Graph Explorer", verifiedPublisher: { displayName: "Microsoft" }, appOwnerOrganizationId: "72F988BF-86F1-41AF-91AB-2D7CD011DB47" }],
      ])
    );
    expect(grants[0]).toMatchObject({
      servicePrincipalId: "sp1",
      appDisplayName: "Shady PDF Tool",
      publisherVerified: false,
      isMicrosoftApp: false,
      consentType: "Principal",
      highRiskScopes: ["Files.ReadWrite.All", "Mail.Read"],
      userCount: 2,
    });
    expect(grants[1]).toMatchObject({ consentType: "AllPrincipals", isMicrosoftApp: true, publisherVerified: true, highRiskScopes: [], userCount: 0 });
  });
});
