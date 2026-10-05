// "How to fix" guides for Security Scenarios checks (Scenario Fix Guides
// Plan, ai-context-vault/Optimization). Guides only: Clarity365 shows the
// portal steps and the commands, the operator runs them. Nothing here
// changes a tenant.
//
// Rules every guide follows:
//  - every command is checked on Microsoft Learn first; `learn` records the
//    page and the date it was checked;
//  - Conditional Access policies are created in report-only, with the
//    tenant's break-glass accounts excluded;
//  - a guide never marks a check fixed - the next sync reads it back.
//
// Steps are functions of a FixGuideContext so commands can carry this
// tenant's real values (object ids, break-glass accounts); the builder
// (scenario-fix-guide-builder.ts) creates the context from the snapshot.

export type GuideShell = "ExchangeOnline" | "MicrosoftGraph" | "SecurityCompliance" | "SharePointOnline";

export interface GuideCommand {
  shell: GuideShell;
  // Microsoft Graph only: the delegated scopes Connect-MgGraph must ask for.
  graphScopes?: string[];
  script: string;
}

export interface GuidePortalSteps {
  // Where to start, e.g. "https://entra.microsoft.com".
  url: string;
  steps: string[];
}

export interface FixGuideStep {
  title: string;
  portal?: GuidePortalSteps;
  command?: GuideCommand;
  note?: string;
}

export interface FixGuideLearnLink {
  title: string;
  url: string;
  // Date the guide was checked against this page (YYYY-MM-DD).
  checked: string;
}

export type FixGuideKind = "conditionalAccess" | "exchange" | "sharePoint" | "entraSetting" | "alertPolicy" | "review";

// One offending object a review guide acts on, e.g. a guest holding a role.
export interface FixGuideItem {
  label: string;
  principalId?: string;
  userPrincipalName?: string;
  roleTemplateId?: string;
  roleName?: string;
  // How the role is held: "eligible" (PIM) or one of the active kinds.
  assignmentKind?: string;
}

export interface FixGuideBreakGlass {
  objectId: string;
  label: string;
}

export interface FixGuideContext {
  tenantName: string;
  tenantId?: string;
  // Accounts Clarity365 believes are emergency-access accounts, with their object ids.
  breakGlass: FixGuideBreakGlass[];
  items: FixGuideItem[];
}

export interface FixGuideDefinition {
  id: string;
  kind: FixGuideKind;
  title: string;
  // What the fix does, in plain words.
  summary: string;
  // Which attack step it stops.
  stops: string;
  prerequisites: { licence?: string; adminRole: string; other?: string[] };
  // Who is affected / what can break.
  impact: string;
  // Staged rollout advice, where it applies.
  rollout?: string;
  steps: (ctx: FixGuideContext) => FixGuideStep[];
  verify: { inClarity: string; command?: GuideCommand };
  undo: { text: string; command?: GuideCommand };
  learn: FixGuideLearnLink[];
  // Values the guide needs that Clarity365 couldn't fill in; shown as warnings.
  missing?: (ctx: FixGuideContext) => string[];
}

// How to connect for each kind of command. Shown above the first command of that kind.
export const SHELL_CONNECT: Record<GuideShell, { label: string; install: string; connect: (ctx: { tenantId?: string; graphScopes?: string[] }) => string }> = {
  ExchangeOnline: {
    label: "Exchange Online PowerShell",
    install: "Install-Module ExchangeOnlineManagement",
    connect: () => "Connect-ExchangeOnline -UserPrincipalName <your admin account>",
  },
  SecurityCompliance: {
    label: "Security & Compliance PowerShell",
    install: "Install-Module ExchangeOnlineManagement",
    connect: () => "Connect-IPPSSession -UserPrincipalName <your admin account>",
  },
  MicrosoftGraph: {
    label: "Microsoft Graph PowerShell",
    install: "Install-Module Microsoft.Graph",
    connect: ({ tenantId, graphScopes }) =>
      `Connect-MgGraph -TenantId "${tenantId || "<tenant ID>"}" -Scopes ${(graphScopes || []).map((s) => `"${s}"`).join(",")}`,
  },
  SharePointOnline: {
    label: "SharePoint Online Management Shell",
    install: "Install-Module Microsoft.Online.SharePoint.PowerShell",
    connect: () => "Connect-SPOService -Url https://<tenant>-admin.sharepoint.com",
  },
};

const CHECKED = "2026-10-05";

// PowerShell array literal of break-glass object ids, or a placeholder.
function breakGlassArray(ctx: FixGuideContext): string {
  return ctx.breakGlass.length > 0 ? ctx.breakGlass.map((b) => `"${b.objectId}"`).join(", ") : `"<break-glass account object ID>"`;
}

// ------------------------------------------------------------------ guides

const blockDeviceCodeFlow: FixGuideDefinition = {
  id: "block-device-code-flow",
  kind: "conditionalAccess",
  title: "Block device code flow with Conditional Access",
  summary:
    "Creates a Conditional Access policy that blocks the device code sign-in flow for everyone except your break-glass accounts. Device code flow lets a sign-in on one device be completed on another, which is exactly what device-code phishing abuses.",
  stops: "An attacker sending a code to enter at microsoft.com/devicelogin and receiving a token that already satisfies MFA.",
  prerequisites: {
    licence: "Microsoft Entra ID P1 (Conditional Access)",
    adminRole: "Conditional Access Administrator (or Security Administrator)",
    other: ["At least one emergency-access (break-glass) account to exclude"],
  },
  impact:
    "Anything that genuinely signs in with a device code stops working once the policy is on: some command-line tools (for example `az login --use-device-code`), shared or meeting-room devices that show a code, and older IoT or kiosk apps. Microsoft recommends blocking it everywhere it isn't documented as needed. Review the report-only results before switching it on.",
  rollout:
    "The policy is created in report-only. Check Entra ID > Sign-in logs (Report-only tab) or the policy's impact for a week; if nothing legitimate would be blocked, switch it to On. If something is, exclude only that account or group.",
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          "Entra ID > Conditional Access > Policies > New policy.",
          'Name it "Block device code flow".',
          "Users or workload identities > Include: All users.",
          `Exclude > Users and groups: ${ctx.breakGlass.length > 0 ? ctx.breakGlass.map((b) => b.label).join(", ") : "your break-glass accounts"}.`,
          "Target resources > Resources > Include: All resources.",
          "Conditions > Authentication flows > Configure: Yes > tick Device code flow > Done.",
          "Grant > Block access > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    {
      title: "Or create it with Microsoft Graph PowerShell",
      command: {
        shell: "MicrosoftGraph",
        graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"],
        script: `$params = @{
    displayName = "Block device code flow"
    state       = "enabledForReportingButNotEnforced"   # report-only
    conditions  = @{
        clientAppTypes      = @("all")
        applications        = @{ includeApplications = @("All") }
        users               = @{
            includeUsers = @("All")
            excludeUsers = @(${breakGlassArray(ctx)})   # break-glass accounts
        }
        authenticationFlows = @{ transferMethods = "deviceCodeFlow" }
    }
    grantControls = @{ operator = "OR"; builtInControls = @("block") }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $params`,
      },
    },
    {
      title: "After a week in report-only, switch it on",
      portal: { url: "https://entra.microsoft.com", steps: ['Conditional Access > Policies > "Block device code flow" > Enable policy: On > Save.'] },
      note: "Authentication transfer (moving a session to a phone by QR code) is a separate check and a separate policy.",
    },
  ],
  verify: {
    inClarity:
      "Re-sync this tenant. While the policy is report-only, the device-code checks show it as report-only; once it is On they turn green.",
    command: {
      shell: "MicrosoftGraph",
      graphScopes: ["Policy.Read.All"],
      script: `Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.Conditions.AuthenticationFlows.TransferMethods -like "*deviceCodeFlow*" } | Select-Object DisplayName, State`,
    },
  },
  undo: {
    text: "Turn the policy off (Enable policy: Off) or delete it in Conditional Access > Policies.",
  },
  learn: [
    { title: "Block authentication flows with Conditional Access policy", url: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows", checked: CHECKED },
    { title: "conditionalAccessAuthenticationFlows resource type", url: "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-1.0", checked: CHECKED },
    { title: "New-MgIdentityConditionalAccessPolicy", url: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/new-mgidentityconditionalaccesspolicy?view=graph-powershell-1.0", checked: CHECKED },
  ],
  missing: (ctx) =>
    ctx.breakGlass.length === 0
      ? ["No break-glass account was found for this tenant. Create one (excluded from every policy) before switching any blocking policy on, and put its object ID in the command."]
      : [],
};

const disableSmtpAuthOrg: FixGuideDefinition = {
  id: "disable-smtp-auth-org",
  kind: "exchange",
  title: "Turn SMTP AUTH off for the organisation",
  summary:
    "Turns off authenticated SMTP submission for every mailbox, then switches it back on only for the mailboxes that genuinely need it (a printer, a line-of-business app). Modern Outlook clients don't use SMTP AUTH.",
  stops: "A stolen password being used to send mail through SMTP AUTH, which bypasses the protections of a normal Outlook sign-in.",
  prerequisites: { adminRole: "Exchange Administrator" },
  impact:
    "Devices and apps that send mail with SMTP AUTH (scanners, printers, some business apps, POP/IMAP clients) stop sending unless their mailbox is switched back on. The mailbox setting overrides the organisation setting.",
  rollout:
    "Before turning it off, list which mailboxes have actually used SMTP AUTH (Exchange admin center > Reports > Mail flow > SMTP AUTH clients report) and plan to re-enable just those.",
  steps: () => [
    {
      title: "Turn it off in the Exchange admin center",
      portal: {
        url: "https://admin.exchange.microsoft.com",
        steps: ["Settings > Mail flow.", 'Tick "Turn off SMTP AUTH protocol for your organization".', "Save."],
      },
    },
    {
      title: "Or with Exchange Online PowerShell",
      command: { shell: "ExchangeOnline", script: "Set-TransportConfig -SmtpClientAuthenticationDisabled $true" },
    },
    {
      title: "Switch it back on only where it's needed",
      command: { shell: "ExchangeOnline", script: "Set-CASMailbox -Identity <mailbox that must send with SMTP AUTH> -SmtpClientAuthenticationDisabled $false" },
      note: "Or in the Microsoft 365 admin center: Users > Active users > the user > Mail > Manage email apps > tick Authenticated SMTP. Better still, move those devices to OAuth or a mail-flow connector.",
    },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "SMTP AUTH is turned off organisation-wide" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled" },
  },
  undo: { text: "Turn it back on for the organisation.", command: { shell: "ExchangeOnline", script: "Set-TransportConfig -SmtpClientAuthenticationDisabled $false" } },
  learn: [{ title: "Enable or disable SMTP AUTH in Exchange Online", url: "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission", checked: CHECKED }],
};

const removeGuestAdminRoles: FixGuideDefinition = {
  id: "remove-guest-admin-roles",
  kind: "review",
  title: "Remove directory roles from guest accounts",
  summary:
    "Removes admin roles held by guest (external) accounts. A guest is secured by another organisation - their password, their MFA, their offboarding - so an admin role on a guest hands control of this tenant to someone else's security.",
  stops: "An attacker who compromises a partner's account inheriting admin rights in this tenant.",
  prerequisites: { adminRole: "Privileged Role Administrator", other: ["Confirm with the account owner that the access is no longer needed"] },
  impact:
    "The guest loses admin access immediately. If a partner genuinely needs to administer this tenant, give them a member account here (with MFA, ideally phishing-resistant, and the role made eligible in PIM) instead of a guest.",
  steps: (ctx) => {
    const active = ctx.items.filter((i) => i.principalId && i.roleTemplateId && i.assignmentKind !== "eligible");
    const eligible = ctx.items.filter((i) => i.principalId && i.roleTemplateId && i.assignmentKind === "eligible");
    const unknown = ctx.items.filter((i) => !i.principalId || !i.roleTemplateId);
    const steps: FixGuideStep[] = [
      {
        title: "Review each guest first",
        note: `${ctx.items.length} guest role assignment(s): ${ctx.items.map((i) => i.label).join("; ") || "none"}. Decide for each whether the access is still needed.`,
      },
      {
        title: "Remove the role in the Entra admin center",
        portal: {
          url: "https://entra.microsoft.com",
          steps: ["Entra ID > Users > All users > select the guest.", "Assigned roles > select the role > Remove assignment.", "For roles assigned through PIM: ID Governance > Privileged Identity Management > Microsoft Entra roles > Assignments > Remove."],
        },
      },
    ];
    if (active.length > 0) {
      steps.push({
        title: "Or remove standing assignments with Microsoft Graph PowerShell",
        command: {
          shell: "MicrosoftGraph",
          graphScopes: ["RoleManagement.ReadWrite.Directory"],
          script: active
            .map(
              (i) => `# ${i.label}
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '${i.principalId}'" |
    Where-Object { $_.RoleDefinitionId -eq "${i.roleTemplateId}" } |
    ForEach-Object { Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $_.Id }`
            )
            .join("\n\n"),
        },
        note: "If a removal fails because the assignment is managed by PIM, remove it in Privileged Identity Management instead (portal steps above).",
      });
    }
    if (eligible.length > 0) {
      steps.push({
        title: "Remove PIM-eligible assignments with Microsoft Graph PowerShell",
        command: {
          shell: "MicrosoftGraph",
          graphScopes: ["RoleEligibilitySchedule.ReadWrite.Directory"],
          script: eligible
            .map(
              (i) => `# ${i.label}
New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter @{
    action           = "adminRemove"
    principalId      = "${i.principalId}"
    roleDefinitionId = "${i.roleTemplateId}"
    directoryScopeId = "/"
    justification    = "Guest accounts must not hold directory roles"
}`
            )
            .join("\n\n"),
        },
      });
    }
    if (unknown.length > 0) {
      steps.push({ title: "Remove these in the portal", note: `Clarity365 couldn't read the role details for: ${unknown.map((i) => i.label).join("; ")}. Use the portal steps above.` });
    }
    return steps;
  },
  verify: {
    inClarity: 'Re-sync this tenant; "No guest holds an admin role" turns green.',
    command: {
      shell: "MicrosoftGraph",
      graphScopes: ["RoleManagement.Read.Directory"],
      script: `Get-MgRoleManagementDirectoryRoleAssignment -ExpandProperty "principal" -All |
    Where-Object { $_.Principal.AdditionalProperties.userType -eq "Guest" }`,
    },
  },
  undo: { text: "Re-assign the role in Entra ID > Roles and administrators (or in PIM as eligible) if it was removed by mistake." },
  learn: [
    { title: "Remove-MgRoleManagementDirectoryRoleAssignment", url: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.governance/remove-mgrolemanagementdirectoryroleassignment?view=graph-powershell-1.0", checked: CHECKED },
    { title: "List unifiedRoleAssignments", url: "https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0", checked: CHECKED },
    { title: "Create roleEligibilityScheduleRequest (adminRemove)", url: "https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleeligibilityschedulerequests?view=graph-rest-1.0", checked: CHECKED },
  ],
};

export const FIX_GUIDES: FixGuideDefinition[] = [blockDeviceCodeFlow, disableSmtpAuthOrg, removeGuestAdminRoles];

export function getFixGuideDefinition(id: string): FixGuideDefinition | undefined {
  return FIX_GUIDES.find((g) => g.id === id);
}
