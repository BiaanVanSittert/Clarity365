import { describe, expect, it } from "vitest";
import { buildFixGuide, buildFixGuideContext } from "./scenario-fix-guide-builder";
import { FIX_GUIDES } from "../data/scenario-fix-guides";
import { evaluateScenarios } from "./security-scenarios";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { TenantSecuritySnapshot } from "../types";

const GA = "62e90394-69f5-4237-9190-012177145e10";
const EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de";
const BREAK_GLASS = "11111111-0000-0000-0000-000000000001";
const ANN = "11111111-0000-0000-0000-000000000002";
const BOB = "11111111-0000-0000-0000-000000000003";

const policy = (id: string, name: string, exclude: string[], state = "enabled") => ({
  id,
  name,
  state,
  conditions: { users: { include: ["All"], exclude }, applications: { include: ["All"], exclude: [] }, clientAppTypes: ["all"] },
  grantControls: ["mfa"],
});

function snapshot(overrides: Partial<TenantSecuritySnapshot> = {}): TenantSecuritySnapshot {
  return {
    tenant: { id: "t1", displayName: "Contoso", defaultDomainName: "contoso.com", credentials: { tenantId: "tenant-guid", clientId: "x", authMode: "secret" } },
    // The break-glass account is excluded everywhere; Ann only from one policy.
    conditionalAccess: { policies: [policy("p1", "MFA all", [BREAK_GLASS, ANN]), policy("p2", "Block legacy", [BREAK_GLASS]), policy("p3", "Old", [ANN], "disabled")] },
    mfaAudit: [
      { id: BREAK_GLASS, userPrincipalName: "breakglass@contoso.com", displayName: "Break Glass", accountEnabled: true, mfaRegistered: true, isAdmin: true, adminRoleTemplateIds: [GA] },
      { id: ANN, userPrincipalName: "o'brien@contoso.com", displayName: "Ann", accountEnabled: true, mfaRegistered: false, isAdmin: true, adminRoleTemplateIds: [GA, EXCHANGE_ADMIN] },
      { id: BOB, userPrincipalName: "bob@contoso.com", displayName: "Bob", accountEnabled: true, mfaRegistered: true, isAdmin: false },
    ],
    ...overrides,
  } as unknown as TenantSecuritySnapshot;
}

const STAGE3 = ["mfa-registration-drive", "remove-individual-exclusions", "revoke-risky-app-consent", "review-app-permissions", "right-size-global-admins", "make-admin-roles-eligible", "remove-role-group-owners", "stop-external-mailbox-forwarding", "disable-external-transport-rules"];

describe("Stage 3 catalogue", () => {
  it("has all nine review guides", () => {
    for (const id of STAGE3) expect(FIX_GUIDES.find((g) => g.id === id)?.kind, id).toBe("review");
  });

  it("works on items whenever the check that offers it lists some (every demo tenant)", () => {
    let compared = 0;
    for (const snap of Object.values(MOCK_TENANT_DATA)) {
      for (const r of evaluateScenarios(snap)) {
        for (const c of r.checks) {
          if (!c.guideId || !STAGE3.includes(c.guideId) || !c.items || c.items.length === 0 || c.status === "prevented") continue;
          compared++;
          expect(buildFixGuideContext(c.guideId, snap).items.length, `${snap.tenant.displayName}: ${r.id}/${c.id}`).toBeGreaterThan(0);
        }
      }
    }
    expect(compared).toBeGreaterThan(0);
  });
});

describe("remove-individual-exclusions", () => {
  it("removes only the named non-break-glass accounts, per policy, keeping the rest of the users section", () => {
    const g = buildFixGuide("remove-individual-exclusions", snapshot())!;
    const script = g.steps.find((s) => s.command)!.command!.script;
    expect(script).toContain("policies/p1");
    expect(script).toContain(`-notin @('${ANN}')`);
    expect(script).not.toContain(`'${BREAK_GLASS}'`);
    // The disabled policy isn't touched.
    expect(script).not.toContain("policies/p3");
    expect(script).toContain("(Invoke-MgGraphRequest -Method GET -Uri $uri).conditions.users");
  });
});

describe("mfa-registration-drive", () => {
  it("creates a one-time pass per unregistered member and quotes names safely", () => {
    const g = buildFixGuide("mfa-registration-drive", snapshot())!;
    const tap = g.steps.find((s) => s.command?.script.includes("New-MgUserAuthenticationTemporaryAccessPassMethod"))!.command!;
    expect(tap.script).toContain("-UserId 'o''brien@contoso.com'");
    expect(tap.script).not.toContain("bob@contoso.com");
    const campaign = g.steps.find((s) => s.command?.script.includes("authenticationMethodsRegistrationCampaign"))!.command!;
    expect(campaign.graphScopes).toEqual(["Policy.Read.All", "Policy.ReadWrite.AuthenticationMethod"]);
    expect(campaign.script).toContain(`@{ id = '${BREAK_GLASS}'; targetType = 'user' }`);
  });
});

describe("make-admin-roles-eligible", () => {
  it("makes each standing role eligible, then removes the active one, leaving break-glass alone", () => {
    const g = buildFixGuide("make-admin-roles-eligible", snapshot())!;
    const scripts = g.steps.map((s) => s.command?.script || "").join("\n");
    expect(scripts).toContain(`principalId      = '${ANN}'`);
    expect(scripts).toContain(`roleDefinitionId = '${EXCHANGE_ADMIN}'`);
    expect(scripts).toContain("action           = 'adminAssign'");
    expect(scripts).toContain("action           = 'adminRemove'");
    expect(scripts).not.toContain(BREAK_GLASS);
    const assign = g.steps.findIndex((s) => s.command?.script.includes("adminAssign"));
    const remove = g.steps.findIndex((s) => s.command?.script.includes("adminRemove"));
    expect(assign).toBeLessThan(remove);
  });
});

describe("right-size-global-admins", () => {
  it("offers removal commands when there are several Global Admins", () => {
    const g = buildFixGuide("right-size-global-admins", snapshot())!;
    expect(g.steps.some((s) => s.command?.script.includes("Remove-MgRoleManagementDirectoryRoleAssignment"))).toBe(true);
  });

  it("asks for a second emergency-access account, and removes nothing, when there is only one", () => {
    const one = snapshot({ mfaAudit: [{ id: ANN, userPrincipalName: "ann@contoso.com", displayName: "Ann", accountEnabled: true, mfaRegistered: true, isAdmin: true, adminRoleTemplateIds: [GA] }] } as any);
    const g = buildFixGuide("right-size-global-admins", one)!;
    expect(g.steps.some((s) => s.title === "Add an emergency-access account")).toBe(true);
    expect(g.steps.some((s) => s.command)).toBe(false);
  });
});

describe("stop-external-mailbox-forwarding", () => {
  it("disables inbox rules and clears mailbox forwarding, each with its own command", () => {
    const g = buildFixGuide(
      "stop-external-mailbox-forwarding",
      snapshot({
        emailForwarding: [
          { id: "1", scope: "inbox_rule", name: "Fwd 'all'", mailboxOwner: "ann@contoso.com", forwardingAddress: "x@evil.example", isExternal: true, ruleAction: "ForwardTo", state: "Enabled", dateCreated: "", alertLevel: "critical" },
          { id: "2", scope: "smtp_forward", name: "Mailbox-level auto-forward: Bob", mailboxOwner: "bob@contoso.com", forwardingAddress: "y@evil.example", isExternal: true, ruleAction: "RedirectTo", state: "Enabled", dateCreated: "", alertLevel: "critical" },
          { id: "3", scope: "inbox_rule", name: "Internal", mailboxOwner: "bob@contoso.com", forwardingAddress: "ann@contoso.com", isExternal: false, ruleAction: "ForwardTo", state: "Enabled", dateCreated: "", alertLevel: "info" },
        ],
      } as any)
    )!;
    const scripts = g.steps.map((s) => s.command?.script || "");
    expect(scripts).toContain("Disable-InboxRule -Mailbox 'ann@contoso.com' -Identity 'Fwd ''all''' -Confirm:$false");
    expect(scripts).toContain("Set-Mailbox -Identity 'bob@contoso.com' -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false");
    expect(scripts.join("\n")).not.toContain("'Internal'");
    // Session revocation is offered but commented out, for the operator to choose.
    expect(scripts.join("\n")).toContain("# Revoke-MgUserSignInSession -UserId 'ann@contoso.com'");
  });
});

describe("other review guides", () => {
  it("revokes a risky consented app by service principal id", () => {
    const g = buildFixGuide(
      "revoke-risky-app-consent",
      snapshot({ oauthConsentGrants: { truncated: false, grants: [{ servicePrincipalId: "sp-1", appDisplayName: "Mail Helper", consentType: "Principal", scopes: ["Mail.Read"], highRiskScopes: ["Mail.Read"], userCount: 2, publisherVerified: false }] } } as any)
    )!;
    const scripts = g.steps.map((s) => s.command?.script || "").join("\n");
    expect(scripts).toContain("Update-MgServicePrincipal -ServicePrincipalId 'sp-1' -AccountEnabled:$false");
    expect(scripts).toContain("$spId = 'sp-1'");
  });

  it("revokes only the listed Microsoft Graph application permissions", () => {
    const g = buildFixGuide(
      "review-app-permissions",
      snapshot({ appRegistrations: [{ id: "a", appId: "app-1", displayName: "Sync tool", highPrivilegePermissions: ["Directory.ReadWrite.All"], allPermissions: [], riskCategory: "critical" }] } as any)
    )!;
    const script = g.steps.find((s) => s.command)!.command!.script;
    expect(script).toContain(`Get-MgServicePrincipal -Filter "appId eq 'app-1'"`);
    expect(script).toContain("$remove = @('Directory.ReadWrite.All')");
  });

  it("removes non-admin owners of role-assignable groups only", () => {
    const g = buildFixGuide(
      "remove-role-group-owners",
      snapshot({ groups: [{ id: "g1", displayName: "Helpdesk admins", isAssignableToRole: true, owners: ["bob@contoso.com", "o'brien@contoso.com"] }] } as any)
    )!;
    const script = g.steps.find((s) => s.command)!.command!.script;
    expect(script).toContain("Get-MgUser -UserId 'bob@contoso.com'");
    expect(script).toContain("Remove-MgGroupOwnerDirectoryObjectByRef -GroupId 'g1'");
    expect(script).not.toContain("o''brien");
  });

  it("disables external transport rules by name", () => {
    const g = buildFixGuide("disable-external-transport-rules", snapshot({ mailflowTransportRules: [{ id: "r", name: "BCC finance", state: "Enabled", redirectsExternally: true, externalRedirectAddress: "z@evil.example" }] } as any))!;
    const scripts = g.steps.map((s) => s.command?.script || "").join("\n");
    expect(scripts).toContain("Disable-TransportRule -Identity 'BCC finance' -Confirm:$false");
    expect(scripts).toContain("Search-UnifiedAuditLog");
  });
});

describe("make-admin-roles-eligible licence warning", () => {
  it("warns when the tenant has no Entra ID P2", () => {
    const g = buildFixGuide("make-admin-roles-eligible", snapshot({ licenseSkus: [] } as any))!;
    expect(g.warnings.some((w) => /Entra ID P2/.test(w))).toBe(true);
  });
});

describe("system mailboxes", () => {
  it("leaves the built-in eDiscovery mailbox out of the POP/IMAP and SMTP AUTH lists", () => {
    const mailboxes = [
      { primarySmtpAddress: "DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@contoso.onmicrosoft.com", popEnabled: true, imapEnabled: true, activeSyncEnabled: false, smtpClientAuthDisabled: null },
      { primarySmtpAddress: "ann@contoso.com", popEnabled: true, imapEnabled: false, activeSyncEnabled: true, smtpClientAuthDisabled: null },
    ];
    const snap = snapshot({ exchangeSecurity: { smtpClientAuthDisabledOrgWide: false, casMailboxes: mailboxes } } as any);
    expect(buildFixGuideContext("disable-pop-imap", snap).items.map((i) => i.address)).toEqual(["ann@contoso.com"]);
    expect(buildFixGuideContext("restrict-smtp-auth-mailboxes", snap).items.map((i) => i.address)).toEqual(["ann@contoso.com"]);
    const popCheck = evaluateScenarios(snap).flatMap((r) => r.checks).find((c) => c.id === "pop-imap")!;
    expect((popCheck.items || []).join(" ")).not.toContain("DiscoverySearchMailbox");
  });
});

describe("token protection check", () => {
  it("shows a report-only token protection policy as partly prevented, not red", () => {
    const base = Object.values(MOCK_TENANT_DATA)[0] as TenantSecuritySnapshot;
    const pilot = {
      id: "tp",
      name: "Require token protection for admins (pilot)",
      state: "enabledForReportingButNotEnforced",
      conditions: { users: { include: ["All"], exclude: [] }, applications: { include: ["All"], exclude: [] }, clientAppTypes: ["mobileAppsAndDesktopClients"] },
      grantControls: [],
      sessionControls: { tokenProtection: true },
    };
    const policies = (base.conditionalAccess?.policies || []).map((p) => ({ ...p, sessionControls: { ...(p.sessionControls || {}), tokenProtection: false } }));
    const snap = { ...base, conditionalAccess: { ...base.conditionalAccess!, policies: [...policies, pilot] } } as unknown as TenantSecuritySnapshot;
    const check = evaluateScenarios(snap).flatMap((r) => r.checks).find((c) => c.id === "token-protection")!;
    expect(check.status).toBe("partial");
    expect(check.detail).toContain("Report-only");
    expect(check.guideId).toBe("require-token-protection");
  });
});
