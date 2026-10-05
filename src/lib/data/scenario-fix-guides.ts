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
  // A mailbox address or a site URL, for guides that act per mailbox or site.
  address?: string;
  url?: string;
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
  // https://<tenant>-admin.sharepoint.com, when it can be worked out from the synced sites.
  sharePointAdminUrl?: string;
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
export const SHELL_CONNECT: Record<GuideShell, { label: string; install: string; connect: (ctx: { tenantId?: string; graphScopes?: string[]; sharePointAdminUrl?: string }) => string }> = {
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
    connect: ({ sharePointAdminUrl }) => `Connect-SPOService -Url ${sharePointAdminUrl || "https://<tenant>-admin.sharepoint.com"}`,
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

// ================================================== Stage 1 (2026-10-05)
// Exchange Online, SharePoint / OneDrive, Entra tenant settings and alert
// policies. Each command checked on Microsoft Learn on CHECKED.

const LEARN = {
  smtpAuth: "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission",
  setCasMailbox: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-casmailbox?view=exchange-ps",
  setCasMailboxPlan: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-casmailboxplan?view=exchange-ps",
  auditOnOff: "https://learn.microsoft.com/en-us/purview/audit-log-enable-disable",
  mailboxAuditing: "https://learn.microsoft.com/en-us/purview/audit-mailboxes",
  externalForwarding: "https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding",
  setOutboundSpam: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-hostedoutboundspamfilterpolicy?view=exchange-ps",
  setRemoteDomain: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-remotedomain?view=exchange-ps",
  setSpoTenant: "https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/set-spotenant?view=sharepoint-ps",
  setSpoSite: "https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/set-sposite?view=sharepoint-ps",
  spoSyncRestriction: "https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/set-spotenantsyncclientrestriction?view=sharepoint-ps",
  spoSyncDomains: "https://learn.microsoft.com/en-us/sharepoint/allow-syncing-only-on-specific-domains",
  spoUnmanaged: "https://learn.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices",
  spoSharing: "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off",
  spoSiteSharing: "https://learn.microsoft.com/en-us/sharepoint/change-external-sharing-site",
  authorizationPolicy: "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0",
  updateAuthorizationPolicy: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/update-mgpolicyauthorizationpolicy?view=graph-powershell-1.0",
  externalCollaboration: "https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure",
  userConsent: "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent",
  adminConsentWorkflow: "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow",
  adminConsentApi: "https://learn.microsoft.com/en-us/graph/api/adminconsentrequestpolicy-update?view=graph-rest-1.0",
  newProtectionAlert: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-protectionalert?view=exchange-ps",
  alertPolicies: "https://learn.microsoft.com/en-us/defender-xdr/alert-policies",
};
const link = (title: string, url: string): FixGuideLearnLink => ({ title, url, checked: CHECKED });
// Names in the step text are capped; the commands still cover every item.
const ITEM_LIST_LIMIT = 20;
const itemList = (ctx: FixGuideContext, none: string) => {
  if (ctx.items.length === 0) return none;
  const shown = ctx.items.slice(0, ITEM_LIST_LIMIT).map((i) => i.label).join("; ");
  return ctx.items.length > ITEM_LIST_LIMIT ? `${shown}; and ${ctx.items.length - ITEM_LIST_LIMIT} more (all are in the command below)` : shown;
};

// ------------------------------------------------------- B. Exchange Online

const restrictSmtpAuthMailboxes: FixGuideDefinition = {
  id: "restrict-smtp-auth-mailboxes",
  kind: "exchange",
  title: "Turn SMTP AUTH off on mailboxes that don't need it",
  summary: "Switches SMTP AUTH off on each mailbox that can still use it, leaving it on only for the few that send through a device or app (a scanner, a line-of-business app).",
  stops: "A stolen password being used to send mail from that mailbox through SMTP AUTH.",
  prerequisites: { adminRole: "Exchange Administrator" },
  impact: "A device or app that sends as one of these mailboxes with SMTP AUTH stops sending. Check the list with the mailbox owners first.",
  rollout: "Exchange admin center > Reports > Mail flow > SMTP AUTH clients report shows which mailboxes actually used SMTP AUTH recently. Leave those on (or move them to OAuth or a connector) and turn the rest off.",
  steps: (ctx) => [
    { title: "Review the mailboxes", note: `Mailboxes that can use SMTP AUTH: ${itemList(ctx, "none listed")}.` },
    {
      title: "Turn it off in the Microsoft 365 admin center",
      portal: { url: "https://admin.microsoft.com", steps: ["Users > Active users > select the user.", "Mail > Manage email apps.", "Clear Authenticated SMTP > Save changes."] },
    },
    {
      title: "Or with Exchange Online PowerShell",
      command: {
        shell: "ExchangeOnline",
        script:
          ctx.items.length > 0
            ? ctx.items.map((i) => `Set-CASMailbox -Identity "${i.address}" -SmtpClientAuthenticationDisabled $true`).join("\n")
            : `Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $true`,
      },
      note: "$true turns it off for that mailbox; $null hands the mailbox back to the organisation setting.",
    },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "Only mailboxes that need SMTP AUTH have it" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } | Select-Object PrimarySmtpAddress" },
  },
  undo: { text: "Turn it back on for a mailbox that needs it.", command: { shell: "ExchangeOnline", script: "Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false" } },
  learn: [link("Enable or disable SMTP AUTH in Exchange Online", LEARN.smtpAuth), link("Set-CASMailbox", LEARN.setCasMailbox)],
};

const disablePopImap: FixGuideDefinition = {
  id: "disable-pop-imap",
  kind: "exchange",
  title: "Turn POP and IMAP off where they aren't used",
  summary: "Turns POP3 and IMAP4 off on the mailboxes that have them on, and in the mailbox plans so new mailboxes start with them off. Outlook, Outlook on the web and the mobile apps don't use them.",
  stops: "Mail being pulled out of a mailbox over a protocol few people use and fewer people watch.",
  prerequisites: { adminRole: "Exchange Administrator" },
  impact: "A mail client or app that reads mail over POP or IMAP stops working for that mailbox. Leave them on only for a mailbox that genuinely needs them.",
  steps: (ctx) => [
    { title: "Review the mailboxes", note: `POP or IMAP is on for: ${itemList(ctx, "none listed")}.` },
    {
      title: "Turn them off in the Microsoft 365 admin center",
      portal: { url: "https://admin.microsoft.com", steps: ["Users > Active users > select the user.", "Mail > Manage email apps.", "Clear POP and IMAP > Save changes."] },
    },
    {
      title: "Or with Exchange Online PowerShell (existing mailboxes)",
      command: {
        shell: "ExchangeOnline",
        script:
          ctx.items.length > 0
            ? ctx.items.map((i) => `Set-CASMailbox -Identity "${i.address}" -PopEnabled $false -ImapEnabled $false`).join("\n")
            : `Set-CASMailbox -Identity <mailbox> -PopEnabled $false -ImapEnabled $false`,
      },
    },
    {
      title: "And for new mailboxes",
      command: { shell: "ExchangeOnline", script: "Get-CASMailboxPlan | Set-CASMailboxPlan -PopEnabled $false -ImapEnabled $false" },
      note: "Mailbox plans apply when a user is licensed, so new mailboxes start with POP and IMAP off.",
    },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "POP and IMAP are off where they aren\'t used" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.PopEnabled -or $_.ImapEnabled } | Select-Object PrimarySmtpAddress, PopEnabled, ImapEnabled" },
  },
  undo: { text: "Turn a protocol back on for a mailbox that needs it.", command: { shell: "ExchangeOnline", script: "Set-CASMailbox -Identity <mailbox> -ImapEnabled $true" } },
  learn: [link("Set-CASMailbox", LEARN.setCasMailbox), link("Set-CASMailboxPlan", LEARN.setCasMailboxPlan)],
};

const enableUnifiedAuditLog: FixGuideDefinition = {
  id: "enable-unified-audit-log",
  kind: "exchange",
  title: "Turn the Microsoft 365 audit log on",
  summary: "Starts recording user and admin activity in the Microsoft 365 (Purview) audit log. Microsoft turns it on by default for most tenants, but not for Business Basic, Standard and Premium, and someone with the right role can turn it off.",
  stops: "An attacker's actions (new inbox rules, permission changes, mailbox access) going unrecorded.",
  prerequisites: { adminRole: "Audit Logs role in Exchange Online (Compliance Management or Organization Management role group)" },
  impact: "None for users. Recording can take up to 60 minutes to start and several hours before events can be searched.",
  steps: () => [
    {
      title: "Turn it on in the Microsoft Purview portal",
      portal: { url: "https://purview.microsoft.com", steps: ["Open the Audit solution (View all solutions > Audit if it isn't shown).", "Select the banner Start recording user and admin activity."] },
    },
    { title: "Or with Exchange Online PowerShell", command: { shell: "ExchangeOnline", script: "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true" } },
  ],
  verify: {
    inClarity: 'Re-sync this tenant (after the hour it can take); "The Microsoft 365 audit log is on" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled" },
  },
  undo: { text: "Turning auditing off isn't recommended. If it must be: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false." },
  learn: [link("Turn auditing on or off", LEARN.auditOnOff)],
};

const enableMailboxAuditing: FixGuideDefinition = {
  id: "enable-mailbox-auditing",
  kind: "exchange",
  title: "Turn mailbox auditing back on",
  summary: "Turns mailbox auditing on by default back on for the organisation, so mailbox actions (inbox rule changes, deletions, sends as another user) are recorded again.",
  stops: "Mailbox activity by an attacker, such as creating a forwarding inbox rule, leaving no audit record.",
  prerequisites: { adminRole: "Exchange Administrator" },
  impact: "None for users.",
  steps: () => [{ title: "Run in Exchange Online PowerShell (there is no portal switch)", command: { shell: "ExchangeOnline", script: "Set-OrganizationConfig -AuditDisabled $false" } }],
  verify: {
    inClarity: 'Re-sync this tenant; "Mailbox auditing is on" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-OrganizationConfig | Format-List AuditDisabled" },
  },
  undo: { text: "Not recommended. Set-OrganizationConfig -AuditDisabled $true turns it off for every mailbox." },
  learn: [link("Manage mailbox auditing", LEARN.mailboxAuditing)],
};

const blockAutoForwardOutbound: FixGuideDefinition = {
  id: "block-external-autoforward-outbound",
  kind: "exchange",
  title: "Block automatic forwarding to outside addresses",
  summary: "Sets automatic external forwarding to Off in the outbound spam filter policy. Inbox rules and mailbox forwarding that send mail outside then bounce instead of leaking it.",
  stops: "A compromised mailbox quietly forwarding every message to an attacker.",
  prerequisites: { adminRole: "Security Administrator or Exchange Administrator" },
  impact: "Every automatic forward to an external address bounces (NDR 5.7.520), including legitimate ones. Allow approved forwarders with a separate outbound spam policy set to On, scoped to just those users.",
  rollout: "Before switching it off, check Exchange admin center > Reports > Mail flow > Auto forwarded messages report to see who forwards today.",
  steps: () => [
    {
      title: "In the Microsoft Defender portal",
      portal: { url: "https://security.microsoft.com", steps: ["Email & collaboration > Policies & threats > Threat policies > Anti-spam.", "Open Anti-spam outbound policy (Default) > Edit protection settings.", "Forwarding rules > Automatic forwarding rules: Off - Forwarding is disabled > Save."] },
    },
    { title: "Or with Exchange Online PowerShell", command: { shell: "ExchangeOnline", script: "Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off" } },
    { title: "Allow approved forwarders only", note: 'Create a custom outbound spam policy with Automatic forwarding rules "On - Forwarding is enabled", applied only to those users.' },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "Outbound spam policy blocks automatic external forwarding" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-HostedOutboundSpamFilterPolicy | Format-Table Name, AutoForwardingMode" },
  },
  undo: { text: "Set it back to On.", command: { shell: "ExchangeOnline", script: "Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode On" } },
  learn: [link("Control external email forwarding", LEARN.externalForwarding), link("Set-HostedOutboundSpamFilterPolicy", LEARN.setOutboundSpam)],
};

const blockAutoForwardRemoteDomain: FixGuideDefinition = {
  id: "block-autoforward-remote-domain",
  kind: "exchange",
  title: "Stop auto-forwarded mail at the default remote domain",
  summary: "Turns off automatic forwarding on the built-in Default remote domain (every external domain), a second layer behind the outbound spam policy. When either blocks forwarding, the block wins.",
  stops: "Inbox-rule forwarding to outside domains getting through if the outbound spam policy is ever changed.",
  prerequisites: { adminRole: "Exchange Administrator" },
  impact: "Messages auto-forwarded by client rules to external recipients aren't delivered. Add a separate remote domain with forwarding allowed for a partner that genuinely needs it.",
  steps: () => [
    {
      title: "In the Exchange admin center",
      portal: { url: "https://admin.exchange.microsoft.com", steps: ["Mail flow > Remote domains > Default.", "Edit reply types > clear Allow automatic forwarding > Save."] },
    },
    { title: "Or with Exchange Online PowerShell", command: { shell: "ExchangeOnline", script: "Set-RemoteDomain -Identity Default -AutoForwardEnabled $false" } },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "The default remote domain blocks auto-forwarding" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-RemoteDomain Default | Format-List AutoForwardEnabled" },
  },
  undo: { text: "Turn it back on.", command: { shell: "ExchangeOnline", script: "Set-RemoteDomain -Identity Default -AutoForwardEnabled $true" } },
  learn: [link("Set-RemoteDomain", LEARN.setRemoteDomain), link("Control external email forwarding", LEARN.externalForwarding)],
};

// --------------------------------------------------- C. SharePoint / OneDrive

const spoConnectNote = "Connect with a SharePoint Administrator account.";

const sharePointBlockLegacyAuth: FixGuideDefinition = {
  id: "sharepoint-block-legacy-auth",
  kind: "sharePoint",
  title: "Block apps that don't use modern authentication in SharePoint",
  summary: "Stops apps that sign in to SharePoint and OneDrive with legacy authentication. Those apps can't do MFA or honour device-based Conditional Access.",
  stops: "A password alone opening SharePoint and OneDrive through an old client, bypassing MFA.",
  prerequisites: { adminRole: "SharePoint Administrator" },
  impact: "Office versions older than 2013, some third-party apps and anything using SharePointOnlineCredentials stop working. The change can take up to 24 hours.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Access control.", "Apps that don't use modern authentication > Block access > Save."] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: "Set-SPOTenant -LegacyAuthProtocolsEnabled $false" }, note: spoConnectNote },
  ],
  verify: {
    inClarity: 'Re-sync this tenant (it can take 24 hours); "SharePoint blocks apps that don\'t use modern authentication" turns green.',
    command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object LegacyAuthProtocolsEnabled" },
  },
  undo: { text: "Allow them again.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -LegacyAuthProtocolsEnabled $true" } },
  learn: [link("Set-SPOTenant", LEARN.setSpoTenant), link("Control access from unmanaged devices", LEARN.spoUnmanaged)],
};

const sharePointSyncDomainJoined: FixGuideDefinition = {
  id: "sharepoint-sync-domain-joined",
  kind: "sharePoint",
  title: "Allow OneDrive sync only on domain-joined PCs",
  summary: "Lets the OneDrive sync app sync only on computers joined to your Active Directory domains, so files can't be synced in bulk to a personal PC.",
  stops: "A user (or an attacker with their password) syncing whole libraries to an unmanaged computer.",
  prerequisites: {
    adminRole: "SharePoint Administrator",
    other: ["On-premises Active Directory, and the domain GUID of each domain your PCs join (Get-ADDomain on a domain-joined machine)"],
  },
  impact:
    "Sync stops working on PCs that aren't joined to those domains. This only works for Active Directory domains: it doesn't apply to Microsoft Entra joined devices, so a cloud-only tenant should use the unmanaged-devices access control (web-only access) or Conditional Access instead. Macs aren't blocked unless you also use -BlockMacSync.",
  steps: () => [
    { title: "Get the domain GUID", note: "On a domain-joined PC with the Active Directory module: (Get-ADDomain).ObjectGUID" },
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Settings > Sync.", "Tick Allow syncing only on computers joined to specific domains.", "Enter the domain GUID(s) > Save."] },
    },
    {
      title: "Or with SharePoint Online PowerShell",
      command: { shell: "SharePointOnline", script: 'Set-SPOTenantSyncClientRestriction -Enable -DomainGuids "<domain GUID>; <second domain GUID>"' },
      note: "It can take up to 24 hours to apply. Separate several GUIDs with a semicolon.",
    },
  ],
  verify: { inClarity: 'Re-sync this tenant; "OneDrive sync only works on domain-joined PCs" turns green.', command: { shell: "SharePointOnline", script: "Get-SPOTenantSyncClientRestriction" } },
  undo: { text: "Clear the check box in Settings > Sync (or remove the restriction in PowerShell)." },
  learn: [link("Allow syncing only on computers joined to specific domains", LEARN.spoSyncDomains), link("Set-SPOTenantSyncClientRestriction", LEARN.spoSyncRestriction)],
};

const sharePointLimitUnmanaged: FixGuideDefinition = {
  id: "sharepoint-limit-unmanaged-devices",
  kind: "sharePoint",
  title: "Give unmanaged devices web-only access to SharePoint and OneDrive",
  summary: "Users on devices that aren't compliant or hybrid-joined can still open files in the browser, but can't download, print or sync them. SharePoint creates the Conditional Access policies for you.",
  stops: "Files being downloaded or synced to a personal or attacker-controlled device.",
  prerequisites: { licence: "Microsoft Entra ID P1 (it relies on Conditional Access)", adminRole: "SharePoint Administrator" },
  impact:
    "On unmanaged devices: no download, print or sync, and no Office desktop apps for SharePoint content. Choosing this replaces any policy created earlier from this page. It can take up to 24 hours and doesn't affect users already signed in. Anyone links aren't affected, so turn those off where this is used.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Access control.", "Unmanaged devices > Allow limited, web-only access > Save."] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: "Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess" }, note: "Also block apps that don't use modern authentication (separate guide), or they can bypass this." },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Browsers on unmanaged devices get web-only access" turns green.', command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object ConditionalAccessPolicy" } },
  undo: { text: "Allow full access again.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -ConditionalAccessPolicy AllowFullAccess" } },
  learn: [link("Control access from unmanaged devices", LEARN.spoUnmanaged), link("Set-SPOTenant", LEARN.setSpoTenant)],
};

const sharePointRestrictAnyoneOrg: FixGuideDefinition = {
  id: "sharepoint-restrict-anyone-org",
  kind: "sharePoint",
  title: "Turn Anyone links off for the organisation",
  summary: 'Lowers the organisation-wide sharing level from "Anyone" to "New and existing guests", so files can only be shared with people who sign in or verify a code.',
  stops: "Links to sensitive files that work for whoever has them, with no sign-in and no record of who opened them.",
  prerequisites: { adminRole: "SharePoint Administrator" },
  impact: "Existing Anyone links stop working and users can't create new ones. Sharing with guests still works. File requests need Anyone links, so they stop too.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Sharing.", "External sharing: move the SharePoint (and OneDrive) slider to New and existing guests > Save."] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: "Set-SPOTenant -SharingCapability ExternalUserSharingOnly" } },
    { title: "If one site genuinely needs public links", note: "Keep the organisation at Anyone only if needed, and restrict every other site individually (the next guide)." },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Anyone links are off for the organisation" turns green.', command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object SharingCapability" } },
  undo: { text: "Allow Anyone links again.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -SharingCapability ExternalUserAndGuestSharing" } },
  learn: [link("Manage sharing settings", LEARN.spoSharing), link("Set-SPOTenant", LEARN.setSpoTenant)],
};

const sharePointRestrictAnyoneSites: FixGuideDefinition = {
  id: "sharepoint-restrict-anyone-sites",
  kind: "sharePoint",
  title: "Turn Anyone links off on these sites",
  summary: "Lowers the sharing level on each site that allows Anyone links, unless the site is genuinely public.",
  stops: "Unauthenticated links to the content of these sites.",
  prerequisites: { adminRole: "SharePoint Administrator" },
  impact: "Anyone links on these sites stop working. Sharing with guests who sign in still works.",
  steps: (ctx) => [
    { title: "Review the sites", note: `Sites that allow Anyone links: ${itemList(ctx, "none listed")}.` },
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Sites > Active sites > select the site.", "Settings tab > More sharing settings.", "Choose New and existing guests (or stricter) > Save."] },
    },
    {
      title: "Or with SharePoint Online PowerShell",
      command: {
        shell: "SharePointOnline",
        script:
          ctx.items.filter((i) => i.url).length > 0
            ? ctx.items.filter((i) => i.url).map((i) => `Set-SPOSite -Identity "${i.url}" -SharingCapability ExternalUserSharingOnly`).join("\n")
            : `Set-SPOSite -Identity <site URL> -SharingCapability ExternalUserSharingOnly`,
      },
    },
  ],
  verify: { inClarity: 'Re-sync this tenant; "No site allows Anyone links" turns green.', command: { shell: "SharePointOnline", script: "Get-SPOSite -Limit All | Where-Object { $_.SharingCapability -eq 'ExternalUserAndGuestSharing' } | Select-Object Url" } },
  undo: { text: "Set a site back to Anyone (Set-SPOSite -SharingCapability ExternalUserAndGuestSharing) if it must be public." },
  learn: [link("Change the sharing settings for a site", LEARN.spoSiteSharing), link("Set-SPOSite", LEARN.setSpoSite)],
};

const sharePointAnyoneLinkExpiry: FixGuideDefinition = {
  id: "sharepoint-anyone-link-expiry",
  kind: "sharePoint",
  title: "Make Anyone links expire",
  summary: "Requires every new Anyone link to expire within 30 days.",
  stops: "Old Anyone links working forever, long after the file should have stopped being shared.",
  prerequisites: { adminRole: "SharePoint Administrator" },
  impact: "New Anyone links expire after at most 30 days. Shortening the limit also shortens existing links that are longer.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Sharing.", 'Advanced settings for "Anyone" links: tick These links must expire within this many days > 30 > Save.'] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: "Set-SPOTenant -RequireAnonymousLinksExpireInDays 30" } },
    { title: "Then confirm it here", note: "Microsoft's Graph API doesn't report this setting, so after changing it use \"I've checked: it's in place\" on the check." },
  ],
  verify: { inClarity: "Confirm it on the check (Clarity365 can't read this setting).", command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object RequireAnonymousLinksExpireInDays" } },
  undo: { text: "Remove the requirement.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -RequireAnonymousLinksExpireInDays 0" } },
  learn: [link("Manage sharing settings", LEARN.spoSharing), link("Set-SPOTenant", LEARN.setSpoTenant)],
};

const sharePointDefaultLinkType: FixGuideDefinition = {
  id: "sharepoint-default-link-type",
  kind: "sharePoint",
  title: "Make the default sharing link internal or specific people",
  summary: "Changes the link type offered first when users share, from Anyone to Only people in your organization (or Specific people).",
  stops: "Users creating Anyone links by accident because it was the default.",
  prerequisites: { adminRole: "SharePoint Administrator" },
  impact: "Users can still pick another link type when sharing; only the default changes.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Sharing.", "File and folder links: choose Only people in your organization (or Specific people) > Save."] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: "Set-SPOTenant -DefaultSharingLinkType Internal" }, note: "Use Direct for Specific people." },
    { title: "Then confirm it here", note: "Microsoft's Graph API doesn't report this setting, so after changing it use \"I've checked: it's in place\" on the check." },
  ],
  verify: { inClarity: "Confirm it on the check (Clarity365 can't read this setting).", command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object DefaultSharingLinkType" } },
  undo: { text: "Set the default back.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -DefaultSharingLinkType AnonymousAccess" } },
  learn: [link("Manage sharing settings", LEARN.spoSharing), link("Set-SPOTenant", LEARN.setSpoTenant)],
};

const sharePointPreventGuestReshare: FixGuideDefinition = {
  id: "sharepoint-prevent-guest-reshare",
  kind: "sharePoint",
  title: "Stop guests re-sharing files they don't own",
  summary: "Prevents guests from sharing files, folders and sites they don't own with further people.",
  stops: "Content spreading from a guest to people nobody in the organisation invited.",
  prerequisites: { adminRole: "SharePoint Administrator" },
  impact: "Guests can still work on what's shared with them, but can't pass it on.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Sharing > More external sharing settings.", "Clear Allow guests to share items they don't own > Save."] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: "Set-SPOTenant -PreventExternalUsersFromResharing $true" } },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Guests can\'t re-share files they don\'t own" turns green.', command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object PreventExternalUsersFromResharing" } },
  undo: { text: "Allow it again.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -PreventExternalUsersFromResharing $false" } },
  learn: [link("Manage sharing settings", LEARN.spoSharing), link("Set-SPOTenant", LEARN.setSpoTenant)],
};

const sharePointDomainAllowList: FixGuideDefinition = {
  id: "sharepoint-domain-allowlist",
  kind: "sharePoint",
  title: "Limit external sharing to partner domains",
  summary: "Allows sharing with external people only from the email domains you list (your partners).",
  stops: "Files being shared to any external address, including an attacker's.",
  prerequisites: { adminRole: "SharePoint Administrator", other: ["The list of partner domains that must keep working"] },
  impact: "Sharing with anyone outside the listed domains fails. Entra ID collaboration restrictions (allowed or blocked domains) also apply to site sharing.",
  steps: () => [
    {
      title: "In the SharePoint admin center",
      portal: { url: "https://admin.microsoft.com/sharepoint", steps: ["Policies > Sharing > More external sharing settings.", "Tick Limit external sharing by domain > Add domains > Allow only specific domains.", "Enter each partner domain > Save."] },
    },
    { title: "Or with SharePoint Online PowerShell", command: { shell: "SharePointOnline", script: 'Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList "partner1.com partner2.com"' }, note: "Separate domains with a space." },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Sharing is limited to approved domains" turns green.', command: { shell: "SharePointOnline", script: "Get-SPOTenant | Select-Object SharingDomainRestrictionMode, SharingAllowedDomainList" } },
  undo: { text: "Remove the restriction.", command: { shell: "SharePointOnline", script: "Set-SPOTenant -SharingDomainRestrictionMode None" } },
  learn: [link("Manage sharing settings", LEARN.spoSharing), link("Set-SPOTenant", LEARN.setSpoTenant)],
};

// ------------------------------------------------------ D. Entra tenant settings

const restrictGuestDirectoryAccess: FixGuideDefinition = {
  id: "restrict-guest-directory-access",
  kind: "entraSetting",
  title: "Restrict what guests can see in the directory",
  summary: "Sets guest access to the most restrictive level: guests can see only their own profile, not other users, groups or memberships.",
  stops: "A guest (or a compromised guest account) mapping your users, groups and admins.",
  prerequisites: { adminRole: "Global Administrator or External Identity Provider Administrator (portal); Privileged Role Administrator for PowerShell" },
  impact: "Guests can no longer browse the directory, for example to look up colleagues in Teams by name outside the teams they're in.",
  steps: () => [
    {
      title: "In the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: ["Entra ID > External Identities > External collaboration settings.", "Guest user access: Guest user access is restricted to properties and memberships of their own directory objects (most restrictive) > Save."],
      },
    },
    {
      title: "Or with Microsoft Graph PowerShell",
      command: { shell: "MicrosoftGraph", graphScopes: ["Policy.ReadWrite.Authorization"], script: 'Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "2af84b1e-32c8-42b7-82bc-daa82404023b"   # Restricted Guest User' },
    },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "Guest access to directory data is restricted" turns green.',
    command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All"], script: "(Get-MgPolicyAuthorizationPolicy).GuestUserRoleId   # 2af84b1e-... = most restrictive" },
  },
  undo: {
    text: "Set it back to Microsoft's default (limited access).",
    command: { shell: "MicrosoftGraph", graphScopes: ["Policy.ReadWrite.Authorization"], script: 'Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "10dae51f-b6af-4016-8d66-8c2a99b929b3"   # Guest User (default)' },
  },
  learn: [link("Configure external collaboration settings", LEARN.externalCollaboration), link("authorizationPolicy resource type", LEARN.authorizationPolicy), link("Update-MgPolicyAuthorizationPolicy", LEARN.updateAuthorizationPolicy)],
};

const restrictGuestInvites: FixGuideDefinition = {
  id: "restrict-guest-invites",
  kind: "entraSetting",
  title: "Only admins and Guest Inviters can invite guests",
  summary: "Limits who can invite guests to users with the User Administrator or Guest Inviter role (and Global Administrators).",
  stops: "Any user, or a guest, inviting outside accounts into the tenant.",
  prerequisites: { adminRole: "Global Administrator or External Identity Provider Administrator (portal); Privileged Role Administrator for PowerShell" },
  impact: "Users who invite guests today (for example team owners adding partners) need the Guest Inviter role or to ask an admin. This also governs SharePoint site sharing with new guests.",
  steps: () => [
    {
      title: "In the Entra admin center",
      portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > External Identities > External collaboration settings.", "Guest invite settings: Only users assigned to specific admin roles can invite guest users > Save."] },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.ReadWrite.Authorization"], script: 'Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsAndGuestInviters"' } },
    { title: "Let named people keep inviting", note: "Give the users who should invite guests the Guest Inviter role (Entra ID > Roles and administrators > Guest Inviter)." },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "Only admins and guest inviters can invite guests" turns green.',
    command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All"], script: "(Get-MgPolicyAuthorizationPolicy).AllowInvitesFrom" },
  },
  undo: { text: "Allow members to invite again.", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.ReadWrite.Authorization"], script: 'Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsGuestInvitersAndAllMembers"' } },
  learn: [link("Configure external collaboration settings", LEARN.externalCollaboration), link("authorizationPolicy resource type", LEARN.authorizationPolicy)],
};

const restrictUserConsent: FixGuideDefinition = {
  id: "restrict-user-consent",
  kind: "entraSetting",
  title: "Allow user consent only for verified publishers and low-impact permissions",
  summary: "Users can still approve apps from verified publishers (and apps registered in your own tenant) for permissions you classify as low impact; everything else needs an admin.",
  stops: "A user being tricked into granting a malicious app access to their mail or files (consent phishing).",
  prerequisites: { adminRole: "Privileged Role Administrator (Global Administrator in the portal)", other: ["Classify which permissions count as low impact (Enterprise apps > Consent and permissions > Permission classifications)"] },
  impact: "Users can't approve other apps themselves. Turn on the admin consent workflow (separate guide) so they can ask instead of looking for workarounds. Existing consents aren't removed.",
  steps: () => [
    {
      title: "In the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: ["Entra ID > Enterprise apps > Consent and permissions > User consent settings.", "User consent for applications: Allow user consent for apps from verified publishers, for selected permissions > Save."],
      },
    },
    {
      title: "Or with Microsoft Graph PowerShell",
      command: {
        shell: "MicrosoftGraph",
        graphScopes: ["Policy.ReadWrite.Authorization"],
        script: `# Keep any developer-consent policies already assigned, replace the user-consent one.
$current = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
$keep = @($current | Where-Object { $_ -like "ManagePermissionGrantsForOwnedResource.*" })
$params = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @("managePermissionGrantsForSelf.microsoft-user-default-low") + $keep } }
Update-MgPolicyAuthorizationPolicy -BodyParameter $params`,
      },
    },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "User consent is restricted" turns green.',
    command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All"], script: "(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned" },
  },
  undo: { text: 'Set User consent for applications back to "Allow user consent for apps" in the portal (not recommended).' },
  learn: [link("Configure how users consent to applications", LEARN.userConsent), link("Update-MgPolicyAuthorizationPolicy", LEARN.updateAuthorizationPolicy)],
};

const enableAdminConsentWorkflow: FixGuideDefinition = {
  id: "enable-admin-consent-workflow",
  kind: "entraSetting",
  title: "Turn on the admin consent workflow",
  summary: "Lets users request admin approval for an app they can't consent to themselves; named reviewers get the request by email.",
  stops: "Blocked users looking for workarounds (or approving a lookalike app) instead of asking.",
  prerequisites: { adminRole: "Global Administrator (portal); Cloud Application Administrator or Application Administrator for the API", other: ["Who should review requests"] },
  impact: "None for users beyond being able to ask. Reviewers can only approve apps their own role allows. It can take up to an hour to switch on.",
  steps: () => [
    {
      title: "In the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          "Entra ID > Enterprise apps > Consent and permissions > Admin consent settings.",
          "Users can request admin consent to apps they are unable to consent to: Yes.",
          "Who can review admin consent requests: add the reviewers.",
          "Turn on email notifications and expiration reminders; set Consent request expires after (days) > Save.",
        ],
      },
    },
    {
      title: "Or with Microsoft Graph PowerShell",
      command: {
        shell: "MicrosoftGraph",
        graphScopes: ["Policy.ReadWrite.ConsentRequest"],
        script: `$body = @{
    isEnabled             = $true
    notifyReviewers       = $true
    remindersEnabled      = $true
    requestDurationInDays = 14
    reviewers             = @(@{ query = "/users/<reviewer object ID>"; queryType = "MicrosoftGraph" })
}
Invoke-MgGraphRequest -Method PUT -Uri "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy" -Body ($body | ConvertTo-Json -Depth 5)`,
      },
    },
  ],
  verify: {
    inClarity: 'Re-sync this tenant; "Users can request admin approval for apps" turns green.',
    command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All"], script: 'Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"' },
  },
  undo: { text: "Set Users can request admin consent... to No in Admin consent settings." },
  learn: [link("Configure the admin consent workflow", LEARN.adminConsentWorkflow), link("Update adminConsentRequestPolicy", LEARN.adminConsentApi)],
};

// ------------------------------------------------------------ E. Alert policies

const alertAuditConfig: FixGuideDefinition = {
  id: "alert-audit-config-changes",
  kind: "alertPolicy",
  title: "Alert when the audit log configuration is changed",
  summary: "Creates a Microsoft 365 alert policy that emails you whenever someone changes the audit log configuration (Set-AdminAuditLogConfig), which is how auditing gets turned off.",
  stops: "An attacker switching auditing off without anyone noticing.",
  prerequisites: { adminRole: "Security Administrator or Compliance Administrator", other: ["A mailbox that someone reads, for the alerts"] },
  impact: "None for users. A per-event alert works on any licence; threshold-based alerts need E5.",
  steps: () => [
    {
      title: "Create it with Security & Compliance PowerShell",
      command: {
        shell: "SecurityCompliance",
        script:
          'New-ProtectionAlert -Name "Audit logging changed" -Category ThreatManagement -ThreatType Activity -Operation "Set-AdminAuditLogConfig" -AggregationType None -Severity High -NotifyUser "<alert mailbox>"',
      },
      note: "Proven on a live tenant: Clarity365 recognises this policy and turns the check green after the next sync.",
    },
    { title: "Using Sentinel or another SIEM instead?", note: 'Create the rule there, then use "I\'ve checked: it\'s in place" on the check; Clarity365 can only read Microsoft 365 alert policies.' },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Someone is alerted if auditing is changed" turns green, naming the policy.', command: { shell: "SecurityCompliance", script: 'Get-ProtectionAlert -Identity "Audit logging changed" | Format-List Name, Operation, Disabled, NotifyUser' } },
  undo: { text: "Remove the policy.", command: { shell: "SecurityCompliance", script: 'Remove-ProtectionAlert -Identity "Audit logging changed"' } },
  learn: [link("New-ProtectionAlert", LEARN.newProtectionAlert), link("Alert policies in the Microsoft Defender portal", LEARN.alertPolicies)],
};

const alertUserDeletion: FixGuideDefinition = {
  id: "alert-user-deletion",
  kind: "alertPolicy",
  title: "Alert when users are deleted",
  summary: "Creates a Microsoft 365 alert policy that emails you when a user account is deleted.",
  stops: "Mass deletion of accounts (a destructive or ransom step) going unnoticed until people can't sign in.",
  prerequisites: { adminRole: "Security Administrator or Compliance Administrator", other: ["A mailbox that someone reads, for the alerts"] },
  impact: "One email per deletion. With an E5 licence you can alert only on bulk deletion instead (see the note).",
  steps: () => [
    {
      title: "Create it with Security & Compliance PowerShell",
      command: {
        shell: "SecurityCompliance",
        script: 'New-ProtectionAlert -Name "User deleted" -Category AccessGovernance -ThreatType Activity -Operation "Delete user." -AggregationType None -Severity Medium -NotifyUser "<alert mailbox>"',
      },
      note: "With E5, alert only on bulk deletion: replace -AggregationType None with -AggregationType SimpleAggregation -Threshold 5 -TimeWindow 60. Proven on a live tenant: Clarity365 recognises the per-event policy.",
    },
    { title: "Using Sentinel or another SIEM instead?", note: 'Create the rule there, then use "I\'ve checked: it\'s in place" on the check.' },
  ],
  verify: { inClarity: 'Re-sync this tenant; "User deletion raises an alert" turns green, naming the policy.', command: { shell: "SecurityCompliance", script: 'Get-ProtectionAlert -Identity "User deleted" | Format-List Name, Operation, Disabled, NotifyUser' } },
  undo: { text: "Remove the policy.", command: { shell: "SecurityCompliance", script: 'Remove-ProtectionAlert -Identity "User deleted"' } },
  learn: [link("New-ProtectionAlert", LEARN.newProtectionAlert), link("Alert policies in the Microsoft Defender portal", LEARN.alertPolicies)],
};

export const FIX_GUIDES: FixGuideDefinition[] = [
  blockDeviceCodeFlow,
  disableSmtpAuthOrg,
  removeGuestAdminRoles,
  restrictSmtpAuthMailboxes,
  disablePopImap,
  enableUnifiedAuditLog,
  enableMailboxAuditing,
  blockAutoForwardOutbound,
  blockAutoForwardRemoteDomain,
  sharePointBlockLegacyAuth,
  sharePointSyncDomainJoined,
  sharePointLimitUnmanaged,
  sharePointRestrictAnyoneOrg,
  sharePointRestrictAnyoneSites,
  sharePointAnyoneLinkExpiry,
  sharePointDefaultLinkType,
  sharePointPreventGuestReshare,
  sharePointDomainAllowList,
  restrictGuestDirectoryAccess,
  restrictGuestInvites,
  restrictUserConsent,
  enableAdminConsentWorkflow,
  alertAuditConfig,
  alertUserDeletion,
];

export function getFixGuideDefinition(id: string): FixGuideDefinition | undefined {
  return FIX_GUIDES.find((g) => g.id === id);
}
