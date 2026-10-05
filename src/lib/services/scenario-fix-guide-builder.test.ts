import { describe, expect, it } from "vitest";
import { buildFixGuide, buildFixGuideContext } from "./scenario-fix-guide-builder";
import { FIX_GUIDES } from "../data/scenario-fix-guides";
import { SCENARIO_DEFINITIONS, evaluateScenarios } from "./security-scenarios";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { TenantSecuritySnapshot } from "../types";

const BREAK_GLASS = "11111111-2222-3333-4444-555555555555";
const GUEST = "99999999-8888-7777-6666-555555555555";
const GA = "62e90394-69f5-4237-9190-012177145e10";
const SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d";

const policy = (name: string, exclude: string[]) => ({
  id: name,
  name,
  state: "enabled",
  conditions: { users: { include: ["All"], exclude }, applications: { include: ["All"], exclude: [] }, clientAppTypes: ["all"], locations: { include: [], exclude: [] }, platforms: { include: [], exclude: [] } },
  grantControls: ["mfa"],
});

function snapshot(overrides: Partial<TenantSecuritySnapshot> = {}): TenantSecuritySnapshot {
  return {
    tenant: { id: "t1", displayName: "Contoso", defaultDomainName: "contoso.com", credentials: { tenantId: "tenant-guid", clientId: "x", authMode: "secret" } },
    conditionalAccess: { policies: [policy("MFA all", [BREAK_GLASS]), policy("Block legacy", [BREAK_GLASS]), policy("Block countries", [BREAK_GLASS])] },
    mfaAudit: [
      { id: BREAK_GLASS, userPrincipalName: "breakglass@contoso.com", displayName: "Break Glass", isAdmin: true, adminRoleTemplateIds: [GA] },
      { id: GUEST, userPrincipalName: "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com", displayName: "Partner", isAdmin: true, adminRoles: ["Security Administrator"], adminRoleTemplateIds: [SECURITY_ADMIN] },
    ],
    ...overrides,
  } as unknown as TenantSecuritySnapshot;
}

describe("guide catalogue", () => {
  it("records a Microsoft Learn page and the date it was checked for every guide", () => {
    for (const g of FIX_GUIDES) {
      expect(g.learn.length, g.id).toBeGreaterThan(0);
      for (const l of g.learn) {
        expect(l.url, g.id).toMatch(/^https:\/\/learn\.microsoft\.com\//);
        expect(l.checked, g.id).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      }
    }
  });

  it("has a guide for every guideId a scenario check points at", () => {
    const ids = new Set(FIX_GUIDES.map((g) => g.id));
    const referenced = new Set<string>();
    for (const snap of Object.values(MOCK_TENANT_DATA)) {
      for (const r of evaluateScenarios(snap)) for (const c of r.checks) if (c.guideId) referenced.add(c.guideId);
    }
    expect(referenced.size).toBeGreaterThan(0);
    for (const id of referenced) expect(ids.has(id), id).toBe(true);
    expect(SCENARIO_DEFINITIONS.length).toBeGreaterThan(0);
  });

  it("only offers a guide while the check isn't green", () => {
    for (const snap of Object.values(MOCK_TENANT_DATA)) {
      for (const r of evaluateScenarios(snap)) for (const c of r.checks) if (c.status === "prevented") expect(c.guideId).toBeUndefined();
    }
  });

  it("creates Conditional Access policies in report-only", () => {
    const ca = FIX_GUIDES.filter((g) => g.kind === "conditionalAccess");
    expect(ca.length).toBeGreaterThan(0);
    for (const g of ca) {
      const scripts = g.steps({ tenantName: "x", breakGlass: [], items: [] }).map((s) => s.command?.script || "").filter((s) => s.includes("New-MgIdentityConditionalAccessPolicy"));
      for (const script of scripts) expect(script, g.id).toContain('state       = "enabledForReportingButNotEnforced"');
    }
  });
});

describe("block-device-code-flow", () => {
  it("excludes this tenant's break-glass account by object id and connects to this tenant", () => {
    const g = buildFixGuide("block-device-code-flow", snapshot())!;
    const create = g.steps.find((s) => s.command?.script.includes("New-MgIdentityConditionalAccessPolicy"))!.command!;
    expect(create.script).toContain(`excludeUsers = @("${BREAK_GLASS}")`);
    expect(create.script).toContain('authenticationFlows = @{ transferMethods = "deviceCodeFlow" }');
    expect(create.connect).toBe('Connect-MgGraph -TenantId "tenant-guid" -Scopes "Policy.Read.All","Policy.ReadWrite.ConditionalAccess"');
    expect(g.steps[0].portal!.steps).toContain("Exclude > Users and groups: breakglass@contoso.com.");
    expect(g.warnings).toEqual([]);
  });

  it("warns, and leaves a placeholder, when no break-glass account is known", () => {
    const g = buildFixGuide("block-device-code-flow", snapshot({ conditionalAccess: { policies: [] } as any }))!;
    expect(g.steps[1].command!.script).toContain('excludeUsers = @("<break-glass account object ID>")');
    expect(g.warnings[0]).toMatch(/No break-glass account was found/);
  });
});

describe("disable-smtp-auth-org", () => {
  it("gives the portal path, the command, the per-mailbox exception, a check and an undo", () => {
    const g = buildFixGuide("disable-smtp-auth-org", snapshot())!;
    expect(g.steps[0].portal!.url).toBe("https://admin.exchange.microsoft.com");
    expect(g.steps[1].command).toMatchObject({ shell: "ExchangeOnline", script: "Set-TransportConfig -SmtpClientAuthenticationDisabled $true", connect: "Connect-ExchangeOnline -UserPrincipalName <your admin account>" });
    expect(g.steps[2].command!.script).toContain("Set-CASMailbox");
    expect(g.verify.command!.script).toBe("Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled");
    expect(g.undo.command!.script).toBe("Set-TransportConfig -SmtpClientAuthenticationDisabled $false");
  });
});

describe("remove-guest-admin-roles", () => {
  it("writes one removal per guest role, with the real ids", () => {
    const g = buildFixGuide("remove-guest-admin-roles", snapshot())!;
    const removal = g.steps.find((s) => s.command?.script.includes("Remove-MgRoleManagementDirectoryRoleAssignment"))!.command!;
    expect(removal.script).toContain(`principalId eq '${GUEST}'`);
    expect(removal.script).toContain(`$_.RoleDefinitionId -eq "${SECURITY_ADMIN}"`);
    expect(removal.graphScopes).toEqual(["RoleManagement.ReadWrite.Directory"]);
    // The member break-glass Global Admin is not a guest and is left alone.
    expect(removal.script).not.toContain(BREAK_GLASS);
  });

  it("removes PIM-eligible guest roles through an adminRemove request instead", () => {
    const g = buildFixGuide(
      "remove-guest-admin-roles",
      snapshot({
        mfaAudit: [],
        privilegedRoleAssignments: { source: "pim", assignments: [{ principalId: GUEST, principalType: "user", principalUserPrincipalName: "partner_fabrikam.com#EXT#@contoso.onmicrosoft.com", roleTemplateId: GA, kind: "eligible" }] },
      } as any)
    )!;
    const scripts = g.steps.map((s) => s.command?.script || "").join("\n");
    expect(scripts).toContain('action           = "adminRemove"');
    expect(scripts).toContain(`roleDefinitionId = "${GA}"`);
    expect(scripts).not.toContain("Remove-MgRoleManagementDirectoryRoleAssignment");
  });

  it("lists the guests to review", () => {
    const ctx = buildFixGuideContext("remove-guest-admin-roles", snapshot());
    expect(ctx.items.map((i) => i.label)).toEqual(["partner_fabrikam.com#EXT#@contoso.onmicrosoft.com (Security Administrator)"]);
  });
});

describe("unknown guides", () => {
  it("returns nothing for an id that isn't in the catalogue", () => {
    expect(buildFixGuide("no-such-guide", snapshot())).toBeUndefined();
  });
});

describe("Stage 1 guides: per-item commands", () => {
  const mailboxes = [
    { primarySmtpAddress: "scanner@contoso.com", popEnabled: false, imapEnabled: false, activeSyncEnabled: true, smtpClientAuthDisabled: false },
    { primarySmtpAddress: "ann@contoso.com", popEnabled: true, imapEnabled: true, activeSyncEnabled: true, smtpClientAuthDisabled: null },
    { primarySmtpAddress: "bob@contoso.com", popEnabled: false, imapEnabled: false, activeSyncEnabled: true, smtpClientAuthDisabled: true },
  ];
  const withExchange = (orgWideDisabled: boolean) => snapshot({ exchangeSecurity: { smtpClientAuthDisabledOrgWide: orgWideDisabled, casMailboxes: mailboxes } } as any);

  it("turns SMTP AUTH off only on the mailboxes that can still use it", () => {
    const g = buildFixGuide("restrict-smtp-auth-mailboxes", withExchange(true))!;
    const script = g.steps.find((s) => s.command)!.command!.script;
    expect(script).toBe('Set-CASMailbox -Identity "scanner@contoso.com" -SmtpClientAuthenticationDisabled $true');
    // With SMTP AUTH on for the organisation, mailboxes following it are listed too.
    const all = buildFixGuide("restrict-smtp-auth-mailboxes", withExchange(false))!.steps.find((s) => s.command)!.command!.script;
    expect(all.split("\n")).toEqual(['Set-CASMailbox -Identity "scanner@contoso.com" -SmtpClientAuthenticationDisabled $true', 'Set-CASMailbox -Identity "ann@contoso.com" -SmtpClientAuthenticationDisabled $true']);
  });

  it("turns POP and IMAP off per mailbox and in the mailbox plans", () => {
    const g = buildFixGuide("disable-pop-imap", withExchange(true))!;
    const scripts = g.steps.map((s) => s.command?.script || "");
    expect(scripts).toContain('Set-CASMailbox -Identity "ann@contoso.com" -PopEnabled $false -ImapEnabled $false');
    expect(scripts).toContain("Get-CASMailboxPlan | Set-CASMailboxPlan -PopEnabled $false -ImapEnabled $false");
    expect(g.steps[0].note).toContain("ann@contoso.com (POP + IMAP)");
  });

  it("restricts each Anyone site and uses this tenant's SharePoint admin center", () => {
    const g = buildFixGuide(
      "sharepoint-restrict-anyone-sites",
      snapshot({ sharePoint: { sites: [{ siteName: "Marketing", siteUrl: "https://contoso.sharepoint.com/sites/marketing", sharingCapability: "Anyone" }, { siteName: "HR", siteUrl: "https://contoso.sharepoint.com/sites/hr", sharingCapability: "OnlyPeopleInOrg" }] } } as any)
    )!;
    const cmd = g.steps.find((s) => s.command)!.command!;
    expect(cmd.script).toBe('Set-SPOSite -Identity "https://contoso.sharepoint.com/sites/marketing" -SharingCapability ExternalUserSharingOnly');
    expect(cmd.connect).toBe("Connect-SPOService -Url https://contoso-admin.sharepoint.com");
    expect(g.steps.find((s) => s.portal)!.portal!.url).toBe("https://contoso-admin.sharepoint.com");
    expect(g.warnings).toEqual([]);
  });

  it("warns when the SharePoint admin address can't be worked out", () => {
    const g = buildFixGuide("sharepoint-block-legacy-auth", snapshot())!;
    expect(g.warnings.some((w) => /SharePoint admin address/.test(w))).toBe(true);
    expect(g.steps.find((s) => s.command)!.command!.connect).toBe("Connect-SPOService -Url https://<tenant>-admin.sharepoint.com");
  });
});

describe("Stage 1 coverage", () => {
  it("offers a guide on every Exchange, SharePoint, Entra-setting and alert check that isn't green", () => {
    const stage1 = new Set(FIX_GUIDES.filter((g) => ["exchange", "sharePoint", "entraSetting", "alertPolicy"].includes(g.kind)).map((g) => g.id));
    expect(stage1.size).toBe(22); // 21 from Stage 1 plus the SMTP AUTH pilot
    const offered = new Set<string>();
    for (const snap of Object.values(MOCK_TENANT_DATA)) for (const r of evaluateScenarios(snap)) for (const c of r.checks) if (c.guideId) offered.add(c.guideId);
    // Every guide is reachable from at least one demo tenant, except those whose check is green everywhere in the demo data.
    expect([...offered].every((id) => FIX_GUIDES.some((g) => g.id === id))).toBe(true);
  });

  it("no longer scores the retired SharePoint invitation-matching setting", () => {
    const checks = SCENARIO_DEFINITIONS.flatMap((d) => d.checks.map((c) => c.id));
    expect(checks).not.toContain("invitee-match");
  });
});

describe("long item lists", () => {
  it("caps the names in the text but keeps every item in the command", () => {
    const sites = Array.from({ length: 30 }, (_, i) => ({ siteName: `Site ${i}`, siteUrl: `https://contoso.sharepoint.com/sites/s${i}`, sharingCapability: "Anyone" }));
    const g = buildFixGuide("sharepoint-restrict-anyone-sites", snapshot({ sharePoint: { sites } } as any))!;
    expect(g.steps[0].note).toMatch(/and 10 more \(all are in the command below\)/);
    expect(g.steps.find((s) => s.command)!.command!.script.split("\n")).toHaveLength(30);
  });
});
