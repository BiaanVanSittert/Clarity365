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

import { CaNamedLocation } from "../types";
import { DIRECTORY_ROLE_TEMPLATES } from "../utils/directory-role-templates";
import { toPowerShell } from "../utils/powershell-literal";

export type GuideShell = "ExchangeOnline" | "MicrosoftGraph" | "MicrosoftGraphBeta" | "SecurityCompliance" | "SharePointOnline";

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
  // Stage 3 review guides.
  policyId?: string;
  policyName?: string;
  // The exact value in the policy's excludeUsers list (object id or upn).
  excludeRef?: string;
  groupId?: string;
  ownerUpn?: string;
  appId?: string;
  permissions?: string[];
  ruleName?: string;
  // Mailbox forwarding: an inbox rule or mailbox-level forwarding.
  forwardKind?: "inboxRule" | "mailboxForwarding";
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
  // Most common country of successful sign-ins (ISO alpha-2), for the country allow list.
  homeCountry?: string;
  // Other countries successful sign-ins came from, busiest first.
  observedCountries: { code: string; count: number }[];
  // Entra ID P2 (or Governance) detected; undefined when unknown. PIM needs it.
  entraP2Licensed?: boolean;
}

// A Conditional Access policy a guide proposes, as the Microsoft Graph body
// the command sends. The builder replays the tenant's sign-ins against the
// same body (ca-policy-impact.ts).
export interface ProposedCaPolicy {
  body: Record<string, unknown>;
  // A named location the command creates first; the policy refers to it by
  // NEW_LOCATION_ID until it exists.
  namedLocation?: { body: Record<string, unknown>; preview: CaNamedLocation };
  // false when the policy's condition isn't in the synced data (user actions,
  // token binding, authentication transfer...).
  previewable: boolean;
  previewNote?: string;
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
  // Conditional Access guides: the policy the command creates.
  proposedPolicy?: (ctx: FixGuideContext) => ProposedCaPolicy;
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
  MicrosoftGraphBeta: {
    label: "Microsoft Graph PowerShell (beta)",
    install: "Install-Module Microsoft.Graph.Beta",
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

// ================================================== Stage 2 (2026-10-05)
// Conditional Access. Each policy is built ONCE as a Microsoft Graph object
// (proposedPolicy); the command is written from that object
// (toPowerShell) and the impact preview replays the tenant's sign-ins
// against the same object, so the two can't disagree. Every policy is
// created in report-only with the break-glass accounts excluded.

const REPORT_ONLY = "enabledForReportingButNotEnforced";
const NEW_LOCATION_ID = "{{NEW_LOCATION_ID}}";
const MFA_STRENGTH_ID = "00000000-0000-0000-0000-000000000002";
const PHISHING_RESISTANT_STRENGTH_ID = "00000000-0000-0000-0000-000000000004";
const EXCHANGE_ONLINE_APP_ID = "00000002-0000-0ff1-ce00-000000000000";
const SHAREPOINT_ONLINE_APP_ID = "00000003-0000-0ff1-ce00-000000000000";
const TEAMS_SERVICES_APP_ID = "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe";
// The 14 roles Microsoft's "Require MFA for administrators" template targets.
const ADMIN_ROLE_IDS = DIRECTORY_ROLE_TEMPLATES.filter((t) => t.isPrivileged).map((t) => t.templateId);

const CA_LEARN = {
  blockByLocation: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location",
  newNamedLocation: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/new-mgidentityconditionalaccessnamedlocation?view=graph-powershell-1.0",
  newPolicy: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/new-mgidentityconditionalaccesspolicy?view=graph-powershell-1.0",
  policyResource: "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0",
  deviceRegistration: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-registration",
  securityInfo: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration",
  tokenProtection: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection",
  tokenProtectionWindows: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/deployment-guide-token-protection-windows",
  reauthentication: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-persistent-browser",
  sessionControls: "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-1.0",
  authStrengths: "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths",
  cae: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation",
  riskUser: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user",
  protectedActions: "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/protected-actions-add",
};

// Excluded accounts for every policy: the tenant's break-glass accounts.
function excludedUsers(ctx: FixGuideContext): string[] {
  return ctx.breakGlass.length > 0 ? ctx.breakGlass.map((b) => b.objectId) : ["<break-glass account object ID>"];
}

const breakGlassMissing = (ctx: FixGuideContext) =>
  ctx.breakGlass.length === 0
    ? ["No break-glass account was found for this tenant. Create one (excluded from every policy) before switching any blocking policy on, and put its object ID in the command."]
    : [];

const breakGlassStep = (ctx: FixGuideContext) =>
  `Exclude > Users and groups: ${ctx.breakGlass.length > 0 ? ctx.breakGlass.map((b) => b.label).join(", ") : "your break-glass accounts"}.`;

// The command for a proposed policy (and the named location it needs, if any).
export function caCreateScript(proposed: ProposedCaPolicy, beta = false): string {
  const cmdlet = beta ? "New-MgBetaIdentityConditionalAccessPolicy" : "New-MgIdentityConditionalAccessPolicy";
  const parts: string[] = [];
  if (proposed.namedLocation) {
    parts.push(`$location = New-MgIdentityConditionalAccessNamedLocation -BodyParameter ${toPowerShell(proposed.namedLocation.body)}`);
  }
  const policy = toPowerShell(proposed.body).replace(`'${NEW_LOCATION_ID}'`, "$location.Id");
  parts.push(`$policy = ${policy}\n${cmdlet} -BodyParameter $policy`);
  return parts.join("\n\n");
}

const switchOnStep = (name: string): FixGuideStep => ({
  title: "After a week in report-only, switch it on",
  portal: { url: "https://entra.microsoft.com", steps: [`Conditional Access > Policies > "${name}": check its report-only results, then Enable policy: On > Save.`] },
});

const caVerify = (name: string): FixGuideDefinition["verify"] => ({
  inClarity: "Re-sync this tenant. While the policy is report-only the check shows it as report-only; once it is On the check turns green.",
  command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All"], script: `Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '${name.replace(/'/g, "''")}'" | Select-Object DisplayName, State` },
});

const caUndo = (name: string): FixGuideDefinition["undo"] => ({ text: `Turn "${name}" off (Enable policy: Off) or delete it in Conditional Access > Policies.` });

// -------------------------------------------------------- A. Conditional Access

const FOREIGN_POLICY = "Block sign-ins from outside allowed countries";
function proposeBlockForeign(ctx: FixGuideContext): ProposedCaPolicy {
  const allowed = ctx.homeCountry ? [ctx.homeCountry] : ["<two-letter country code>"];
  return {
    namedLocation: {
      body: { "@odata.type": "#microsoft.graph.countryNamedLocation", displayName: "Allowed countries", countriesAndRegions: allowed, includeUnknownCountriesAndRegions: false },
      preview: { id: NEW_LOCATION_ID, displayName: "Allowed countries", kind: "country", countries: allowed, includeUnknownCountries: false },
    },
    body: {
      displayName: FOREIGN_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
        locations: { includeLocations: ["All"], excludeLocations: [NEW_LOCATION_ID] },
      },
      grantControls: { operator: "OR", builtInControls: ["block"] },
    },
    previewable: !!ctx.homeCountry,
    previewNote: ctx.homeCountry ? undefined : "The tenant's home country couldn't be worked out from its sign-ins, so the preview isn't available. Put the allowed countries in the command first.",
  };
}

const blockForeignCountries: FixGuideDefinition = {
  id: "block-foreign-countries",
  kind: "conditionalAccess",
  title: "Block sign-ins from outside your allowed countries",
  summary:
    "Creates an \"Allowed countries\" named location (starting with this tenant's home country) and a policy that blocks sign-ins from everywhere else. Addresses that don't map to any country are blocked too.",
  stops: "A stolen password being used from a country your organisation doesn't work in.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator", other: ["At least one break-glass account to exclude", "The list of countries your users genuinely sign in from"] },
  impact:
    "Users travelling to, or working from, a country not on the list are blocked, and so are VPNs that exit abroad. Check the preview and the countries listed in step 1, and add every legitimate one before switching the policy on.",
  rollout: "Created in report-only. Review a week of report-only results, add any missing countries to the named location, then switch it on.",
  proposedPolicy: proposeBlockForeign,
  steps: (ctx) => [
    {
      title: "Decide which countries to allow",
      note: `Starting list: ${ctx.homeCountry || "(not detected)"}.${ctx.observedCountries.length > 0 ? ` Successful sign-ins in the synced period also came from: ${ctx.observedCountries.map((c) => `${c.code} (${c.count})`).join(", ")}. Add any that are legitimate.` : ""}`,
    },
    {
      title: "Create the named location and policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          "Entra ID > Conditional Access > Named locations > Countries location: name it \"Allowed countries\", tick the allowed countries (leave \"Include unknown countries/regions\" off) > Create.",
          `Conditional Access > Policies > New policy: name it "${FOREIGN_POLICY}".`,
          "Users > Include: All users.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Network (Locations) > Configure: Yes > Include: Any network or location > Exclude: Selected networks and locations > Allowed countries.",
          "Grant > Block access > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or create both with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeBlockForeign(ctx)) } },
    switchOnStep(FOREIGN_POLICY),
  ],
  verify: caVerify(FOREIGN_POLICY),
  undo: caUndo(FOREIGN_POLICY),
  learn: [link("Block access by location", CA_LEARN.blockByLocation), link("New-MgIdentityConditionalAccessNamedLocation", CA_LEARN.newNamedLocation), link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy)],
  missing: (ctx) => [...breakGlassMissing(ctx), ...(ctx.homeCountry ? [] : ["The home country couldn't be worked out; replace <two-letter country code> with your allowed countries."])],
};

const includeUnknownCountries: FixGuideDefinition = {
  id: "include-unknown-countries",
  kind: "conditionalAccess",
  title: "Cover addresses that don't map to a country",
  summary: "Makes sure sign-ins from IP addresses that Microsoft can't place in any country (common with anonymisers) are blocked along with the countries you block.",
  stops: "An attacker dodging a country block by using an address with no known country.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact: "Sign-ins from addresses with no known country are blocked by the same policy. These are rare for normal users.",
  steps: (ctx) => [
    {
      title: "If you use an allow list (recommended)",
      note: 'With "Block sign-ins from outside your allowed countries" (its own guide), unknown addresses are already blocked, because they aren\'t in the allowed list. Nothing else is needed.',
    },
    {
      title: "If you block a list of countries instead",
      portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Conditional Access > Named locations > open the blocked-countries location.", "Tick Include unknown countries/regions > Save."] },
    },
    ...(ctx.items.length > 0
      ? [
          {
            title: "Or with Microsoft Graph PowerShell",
            command: {
              shell: "MicrosoftGraph" as GuideShell,
              graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"],
              script: ctx.items
                .map((i) => `# ${i.label}\nUpdate-MgIdentityConditionalAccessNamedLocation -NamedLocationId "${i.principalId}" -BodyParameter ${toPowerShell({ "@odata.type": "#microsoft.graph.countryNamedLocation", includeUnknownCountriesAndRegions: true })}`)
                .join("\n\n"),
            },
          },
        ]
      : []),
  ],
  verify: { inClarity: 'Re-sync this tenant; "Addresses that don\'t map to any country are covered" turns green.' },
  undo: { text: "Untick Include unknown countries/regions on the named location." },
  learn: [link("Block access by location", CA_LEARN.blockByLocation), link("New-MgIdentityConditionalAccessNamedLocation", CA_LEARN.newNamedLocation)],
};

const DEVICE_REG_POLICY = "Require MFA to register or join devices";
function proposeDeviceRegistration(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: DEVICE_REG_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: excludedUsers(ctx) },
        applications: { includeUserActions: ["urn:user:registerdevice"] },
        clientAppTypes: ["all"],
      },
      grantControls: { operator: "OR", authenticationStrength: { id: MFA_STRENGTH_ID } },
    },
    previewable: false,
    previewNote: "Device registrations aren't in the synced sign-in data, so this can't be previewed.",
  };
}

const requireMfaDeviceRegistration: FixGuideDefinition = {
  id: "require-mfa-device-registration",
  kind: "conditionalAccess",
  title: "Require MFA to register or join a device",
  summary: "A Conditional Access policy on the \"Register or join devices\" user action, requiring the built-in Multifactor authentication strength, plus the device setting Microsoft says must be turned off for it to work.",
  stops: "An attacker with a stolen password registering their own device, which can then look \"managed\" or satisfy device-based policies.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator (policy); Cloud Device Administrator or Global Administrator (device setting)" },
  impact: "Users must complete MFA when they register or join a device. Nothing changes for normal sign-ins.",
  proposedPolicy: proposeDeviceRegistration,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${DEVICE_REG_POLICY}".`,
          "Users > Include: All users.",
          breakGlassStep(ctx),
          "Target resources > User actions > Register or join devices.",
          "Grant > Require authentication strength > Multifactor authentication > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeDeviceRegistration(ctx)) } },
    {
      title: "Then change the device setting (required)",
      portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Devices > Overview > Device settings.", "Require Multifactor Authentication to register or join devices with Microsoft Entra: No > Save."] },
      note: "Microsoft: with this user-action policy in place the device setting must be No, otherwise the policy isn't properly enforced. The policy now does the job the setting used to.",
    },
    switchOnStep(DEVICE_REG_POLICY),
  ],
  verify: caVerify(DEVICE_REG_POLICY),
  undo: caUndo(DEVICE_REG_POLICY),
  learn: [link("Require MFA for device registration", CA_LEARN.deviceRegistration), link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy)],
  missing: breakGlassMissing,
};

const TOKEN_POLICY = "Require token protection for admins (pilot)";
function proposeTokenProtection(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: TOKEN_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeRoles: ADMIN_ROLE_IDS, excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: [EXCHANGE_ONLINE_APP_ID, SHAREPOINT_ONLINE_APP_ID, TEAMS_SERVICES_APP_ID] },
        platforms: { includePlatforms: ["windows"] },
        clientAppTypes: ["mobileAppsAndDesktopClients"],
      },
      sessionControls: { secureSignInSession: { isEnabled: true } },
    },
    previewable: false,
    previewNote: "Whether a sign-in used a device-bound token isn't in the synced data, so this can't be previewed. Use the policy's report-only results.",
  };
}

const requireTokenProtection: FixGuideDefinition = {
  id: "require-token-protection",
  kind: "conditionalAccess",
  title: "Require token protection (start with admins)",
  summary:
    "A session control that only accepts sign-in tokens bound to the device they were issued to, for the Outlook, Teams, OneDrive and Office desktop apps on Windows talking to Exchange Online, SharePoint Online and Teams. Starts with admin roles as the pilot group.",
  stops: "A stolen session token (for example from an AiTM phishing kit or malware) being replayed from the attacker's machine.",
  prerequisites: {
    licence: "Microsoft Entra ID P1",
    adminRole: "Conditional Access Administrator",
    other: ["Windows 10 or later devices that are Entra joined, hybrid joined or registered", "Microsoft Graph PowerShell beta module (the setting is beta-only in Graph)"],
  },
  impact:
    "Unsupported clients are blocked from Exchange, SharePoint and Teams for the users in scope: Office perpetual clients, PowerShell modules accessing SharePoint, some VS Code extensions, Teams Rooms and Surface Hub, and some VM or Cloud PC registrations. Browsers aren't affected (the policy targets desktop apps only).",
  rollout: "Microsoft's advice: pilot group first, report-only, review interactive and non-interactive sign-in logs long enough to cover normal use, then enforce for known-good users and widen.",
  proposedPolicy: proposeTokenProtection,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${TOKEN_POLICY}".`,
          "Users > Include: Select users and groups > Directory roles: the admin roles (or a pilot group).",
          breakGlassStep(ctx),
          "Target resources > Select resources: Office 365 Exchange Online, Office 365 SharePoint Online, Microsoft Teams Services (not the Office 365 group).",
          "Conditions > Device platforms: Windows. Client apps: only Mobile apps and desktop clients.",
          "Session > Require token protection for sign-in sessions > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    {
      title: "Or with Microsoft Graph PowerShell (beta)",
      command: { shell: "MicrosoftGraphBeta", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeTokenProtection(ctx), true) },
    },
    switchOnStep(TOKEN_POLICY),
  ],
  verify: caVerify(TOKEN_POLICY),
  undo: caUndo(TOKEN_POLICY),
  learn: [link("Token protection in Conditional Access", CA_LEARN.tokenProtection), link("Token protection deployment guide - Windows", CA_LEARN.tokenProtectionWindows)],
  missing: breakGlassMissing,
};

const ADMIN_DEVICE_POLICY = "Require a compliant or hybrid-joined device for admins";
function proposeAdminDevice(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: ADMIN_DEVICE_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeRoles: ADMIN_ROLE_IDS, excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
      },
      grantControls: { operator: "OR", builtInControls: ["compliantDevice", "domainJoinedDevice"] },
    },
    previewable: true,
  };
}

const requireCompliantDeviceAdmins: FixGuideDefinition = {
  id: "require-compliant-device-admins",
  kind: "conditionalAccess",
  title: "Require a compliant or hybrid-joined device for admins",
  summary: "Admin roles can only sign in from a device that Intune marks compliant or that is hybrid Entra joined.",
  stops: "An admin's stolen password or session being used from an attacker's (or a personal) device.",
  prerequisites: { licence: "Microsoft Entra ID P1, plus Microsoft Intune for compliant devices", adminRole: "Conditional Access Administrator", other: ["Admins' devices already enrolled and compliant"] },
  impact: "Admins on personal or unmanaged devices (including unmanaged Macs and phones) are blocked from everything, not just admin portals. Make sure each admin has a compliant device first.",
  rollout: "Created in report-only. Check the preview and report-only results for each admin before switching on.",
  proposedPolicy: proposeAdminDevice,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${ADMIN_DEVICE_POLICY}".`,
          "Users > Include: Select users and groups > Directory roles: Global Administrator and the other admin roles.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Grant > Grant access > Require device to be marked as compliant + Require Microsoft Entra hybrid joined device > Require one of the selected controls > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeAdminDevice(ctx)) } },
    switchOnStep(ADMIN_DEVICE_POLICY),
  ],
  verify: caVerify(ADMIN_DEVICE_POLICY),
  undo: caUndo(ADMIN_DEVICE_POLICY),
  learn: [link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy), link("conditionalAccessPolicy resource type", CA_LEARN.policyResource)],
  missing: breakGlassMissing,
};

const DESKTOP_POLICY = "Require a compliant device for desktop and mobile apps";
function proposeDesktopCompliant(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: DESKTOP_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: [...excludedUsers(ctx), "GuestsOrExternalUsers"] },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["mobileAppsAndDesktopClients"],
      },
      grantControls: { operator: "OR", builtInControls: ["compliantDevice", "domainJoinedDevice"] },
    },
    previewable: true,
  };
}

const requireCompliantDeviceDesktop: FixGuideDefinition = {
  id: "require-compliant-device-desktop",
  kind: "conditionalAccess",
  title: "Require a compliant device for desktop and mobile apps",
  summary: "Desktop and mobile apps (OneDrive sync, Outlook, Teams, Office) only work on compliant or hybrid-joined devices; browsers are left alone, so pair this with SharePoint's web-only access for unmanaged devices.",
  stops: "Bulk download or sync of company data to an unmanaged or attacker-controlled device.",
  prerequisites: { licence: "Microsoft Entra ID P1 and Microsoft Intune", adminRole: "Conditional Access Administrator", other: ["Users' devices enrolled in Intune with compliance policies"] },
  impact: "Users on personal devices can't use the desktop or mobile apps (including Outlook on personal phones) until the device is enrolled. Guests are excluded because they can't have a compliant device in your tenant.",
  rollout: "Created in report-only. Check how many users the preview shows before switching on; plan Intune enrolment for them first.",
  proposedPolicy: proposeDesktopCompliant,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${DESKTOP_POLICY}".`,
          "Users > Include: All users. Exclude: Guest or external users, and the break-glass accounts.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Conditions > Client apps: Configure Yes, only Mobile apps and desktop clients.",
          "Grant > Require device to be marked as compliant + Require Microsoft Entra hybrid joined device > Require one of the selected controls > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeDesktopCompliant(ctx)) } },
    switchOnStep(DESKTOP_POLICY),
  ],
  verify: caVerify(DESKTOP_POLICY),
  undo: caUndo(DESKTOP_POLICY),
  learn: [link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy), link("conditionalAccessPolicy resource type", CA_LEARN.policyResource)],
  missing: breakGlassMissing,
};

const ADMIN_SESSION_POLICY = "Admin sessions: sign in every 4 hours, no persistent browser";
function proposeAdminSession(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: ADMIN_SESSION_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeRoles: ADMIN_ROLE_IDS, excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
      },
      sessionControls: {
        signInFrequency: { isEnabled: true, value: 4, type: "hours", authenticationType: "primaryAndSecondaryAuthentication", frequencyInterval: "timeBased" },
        persistentBrowser: { isEnabled: true, mode: "never" },
      },
    },
    previewable: false,
    previewNote: "This only shortens sessions; it doesn't block or challenge a sign-in, so there's nothing to preview.",
  };
}

const adminSessionLimits: FixGuideDefinition = {
  id: "admin-session-limits",
  kind: "conditionalAccess",
  title: "Time-limit admin sessions",
  summary: "Admin roles sign in again every 4 hours and browser sessions don't stay signed in after the browser closes.",
  stops: "A stolen admin session staying usable for days.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact: "Admins are prompted to sign in more often. Persistent browser only works with All resources targeted, which this policy does.",
  proposedPolicy: proposeAdminSession,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${ADMIN_SESSION_POLICY}".`,
          "Users > Include: Directory roles: Global Administrator and the other admin roles.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Session > Sign-in frequency: Periodic reauthentication, 4 Hours. Persistent browser session: Never persistent > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeAdminSession(ctx)) } },
    switchOnStep(ADMIN_SESSION_POLICY),
  ],
  verify: caVerify(ADMIN_SESSION_POLICY),
  undo: caUndo(ADMIN_SESSION_POLICY),
  learn: [link("Require reauthentication with Conditional Access", CA_LEARN.reauthentication), link("conditionalAccessSessionControls resource type", CA_LEARN.sessionControls)],
  missing: breakGlassMissing,
};

const PHISHING_POLICY = "Require phishing-resistant MFA for admins";
function proposePhishingResistant(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: PHISHING_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeRoles: ADMIN_ROLE_IDS, excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
      },
      grantControls: { operator: "OR", authenticationStrength: { id: PHISHING_RESISTANT_STRENGTH_ID } },
    },
    previewable: true,
  };
}

const requirePhishingResistantAdmins: FixGuideDefinition = {
  id: "require-phishing-resistant-admins",
  kind: "conditionalAccess",
  title: "Require phishing-resistant MFA for admins",
  summary: "Admin roles must sign in with a passkey (FIDO2), Windows Hello for Business or certificate-based authentication. Push notifications and codes no longer satisfy the policy for them.",
  stops: "Adversary-in-the-middle phishing that relays an admin's push or code approval.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator", other: ["Every admin has registered a passkey, Windows Hello for Business or a certificate first"] },
  impact: "An admin without a phishing-resistant method can't sign in once the policy is on. Register methods for every admin (a Temporary Access Pass helps) before switching it on.",
  rollout: "Created in report-only. The preview shows which admins would have been asked for more; get each of them registered, then switch it on.",
  proposedPolicy: proposePhishingResistant,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${PHISHING_POLICY}".`,
          "Users > Include: Directory roles: Global Administrator and the other admin roles.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Grant > Require authentication strength > Phishing-resistant MFA > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposePhishingResistant(ctx)) } },
    switchOnStep(PHISHING_POLICY),
  ],
  verify: caVerify(PHISHING_POLICY),
  undo: caUndo(PHISHING_POLICY),
  learn: [link("Authentication strengths", CA_LEARN.authStrengths), link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy)],
  missing: breakGlassMissing,
};

const keepCaeOn: FixGuideDefinition = {
  id: "keep-cae-on",
  kind: "conditionalAccess",
  title: "Stop disabling continuous access evaluation",
  summary: "Continuous access evaluation (CAE) is on by default and lets Exchange, SharePoint and Teams cut a session within minutes when a user is disabled, their password changes or risk is detected. A policy here turns it off.",
  stops: "A session staying alive for up to an hour (or longer) after the account was disabled or the password reset.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact: "None for most users. CAE can cause extra prompts on networks whose outbound IP addresses change often; that's usually why it was disabled, so check with whoever set it.",
  steps: (ctx) => [
    { title: "Find the policy", note: `Policies that disable CAE: ${itemList(ctx, "none listed")}.` },
    {
      title: "Remove the setting in the Entra admin center",
      portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Conditional Access > Policies > open the policy.", "Session > Customize continuous access evaluation: untick it (or delete the policy if that's all it does) > Save."] },
      note: "This session control is only in Microsoft Graph beta, so Clarity365 gives the portal steps.",
    },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Continuous access evaluation revokes sessions quickly" turns green.' },
  undo: { text: "Set Customize continuous access evaluation back to Disable on the policy." },
  learn: [link("Continuous access evaluation", CA_LEARN.cae)],
};

const GUEST_MFA_POLICY = "Require MFA for guests";
function proposeGuestMfa(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: GUEST_MFA_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["GuestsOrExternalUsers"], excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
      },
      grantControls: { operator: "OR", builtInControls: ["mfa"] },
    },
    previewable: true,
  };
}

const requireMfaGuests: FixGuideDefinition = {
  id: "require-mfa-guests",
  kind: "conditionalAccess",
  title: "Require MFA for guests",
  summary: "Guests and external users must complete MFA to reach anything in this tenant.",
  stops: "A guest account with a stolen or weak password getting into your Teams, SharePoint and files.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact: "Guests are asked for MFA (in your tenant, or their own if you trust their MFA in cross-tenant access settings).",
  proposedPolicy: proposeGuestMfa,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${GUEST_MFA_POLICY}".`,
          "Users > Include: Guest or external users (all types, all organisations).",
          "Target resources > Resources > Include: All resources.",
          "Grant > Require multifactor authentication > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeGuestMfa(ctx)) } },
    switchOnStep(GUEST_MFA_POLICY),
  ],
  verify: caVerify(GUEST_MFA_POLICY),
  undo: caUndo(GUEST_MFA_POLICY),
  learn: [link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy), link("conditionalAccessPolicy resource type", CA_LEARN.policyResource)],
};

const ALL_MFA_POLICY = "Require MFA for all users";
function proposeAllUsersMfa(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: ALL_MFA_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
      },
      grantControls: { operator: "OR", builtInControls: ["mfa"] },
    },
    previewable: true,
  };
}

const requireMfaAllUsers: FixGuideDefinition = {
  id: "require-mfa-all-users",
  kind: "conditionalAccess",
  title: "Require MFA for all users",
  summary: "Every user must complete MFA for every app. The single most effective control against password attacks.",
  stops: "Password spray and stolen passwords being enough to sign in.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator", other: ["Users registered for MFA (see the MFA registration check)"] },
  impact: "Users without an MFA method are asked to register at their next sign-in. Service accounts that sign in interactively break; exclude them (or move them to managed identities) first.",
  rollout: "Created in report-only. The preview shows who would have been asked for MFA that wasn't before.",
  proposedPolicy: proposeAllUsersMfa,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [`Entra ID > Conditional Access > Policies > New policy: name it "${ALL_MFA_POLICY}".`, "Users > Include: All users.", breakGlassStep(ctx), "Target resources > Resources > Include: All resources.", "Grant > Require multifactor authentication > Select.", "Enable policy: Report-only > Create."],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeAllUsersMfa(ctx)) } },
    switchOnStep(ALL_MFA_POLICY),
  ],
  verify: caVerify(ALL_MFA_POLICY),
  undo: caUndo(ALL_MFA_POLICY),
  learn: [link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy), link("conditionalAccessPolicy resource type", CA_LEARN.policyResource)],
  missing: breakGlassMissing,
};

const LEGACY_POLICY = "Block legacy authentication";
function proposeBlockLegacy(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: LEGACY_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["exchangeActiveSync", "other"],
      },
      grantControls: { operator: "OR", builtInControls: ["block"] },
    },
    previewable: true,
  };
}

const blockLegacyAuth: FixGuideDefinition = {
  id: "block-legacy-auth",
  kind: "conditionalAccess",
  title: "Block legacy authentication",
  summary: "Blocks the client types that can't do MFA (Exchange ActiveSync with basic auth and \"other clients\" such as IMAP, POP and SMTP with a password).",
  stops: "Password spray against protocols that ignore MFA.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact: "Old mail clients, scanners and scripts using basic authentication stop working. The preview lists who used them recently.",
  proposedPolicy: proposeBlockLegacy,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${LEGACY_POLICY}".`,
          "Users > Include: All users.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Conditions > Client apps: Configure Yes, select only Exchange ActiveSync clients and Other clients.",
          "Grant > Block access > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeBlockLegacy(ctx)) } },
    switchOnStep(LEGACY_POLICY),
  ],
  verify: caVerify(LEGACY_POLICY),
  undo: caUndo(LEGACY_POLICY),
  learn: [link("New-MgIdentityConditionalAccessPolicy", CA_LEARN.newPolicy), link("conditionalAccessPolicy resource type", CA_LEARN.policyResource)],
  missing: breakGlassMissing,
};

const AUTH_TRANSFER_POLICY = "Block authentication transfer";
function proposeBlockAuthTransfer(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: AUTH_TRANSFER_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: excludedUsers(ctx) },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
        authenticationFlows: { transferMethods: "authenticationTransfer" },
      },
      grantControls: { operator: "OR", builtInControls: ["block"] },
    },
    previewable: false,
    previewNote: "Authentication transfers aren't in the synced sign-in data, so this can't be previewed.",
  };
}

const blockAuthenticationTransfer: FixGuideDefinition = {
  id: "block-authentication-transfer",
  kind: "conditionalAccess",
  title: "Block authentication transfer",
  summary: "Blocks moving a signed-in session from a PC to a phone by QR code (authentication transfer).",
  stops: "A session on a compromised PC being carried over to another device.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact: "Users can't use \"Sign in on your phone\" style transfers (for example from Outlook desktop to Outlook mobile); they sign in on the phone normally instead.",
  proposedPolicy: proposeBlockAuthTransfer,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${AUTH_TRANSFER_POLICY}".`,
          "Users > Include: All users.",
          breakGlassStep(ctx),
          "Target resources > Resources > Include: All resources.",
          "Conditions > Authentication flows > Configure: Yes > tick Authentication transfer > Done.",
          "Grant > Block access > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeBlockAuthTransfer(ctx)) } },
    switchOnStep(AUTH_TRANSFER_POLICY),
  ],
  verify: caVerify(AUTH_TRANSFER_POLICY),
  undo: caUndo(AUTH_TRANSFER_POLICY),
  learn: [link("Block authentication flows with Conditional Access", "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows"), link("conditionalAccessAuthenticationFlows resource type", "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-1.0")],
  missing: breakGlassMissing,
};

const SECURITY_INFO_POLICY = "Secure security info registration";
function proposeSecurityInfo(ctx: FixGuideContext): ProposedCaPolicy {
  return {
    body: {
      displayName: SECURITY_INFO_POLICY,
      state: REPORT_ONLY,
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: [...excludedUsers(ctx), "GuestsOrExternalUsers"] },
        applications: { includeUserActions: ["urn:user:registersecurityinfo"] },
        clientAppTypes: ["all"],
        locations: { includeLocations: ["All"], excludeLocations: ["AllTrusted"] },
      },
      grantControls: { operator: "OR", authenticationStrength: { id: MFA_STRENGTH_ID } },
    },
    previewable: false,
    previewNote: "Security-info registrations aren't in the synced sign-in data, so this can't be previewed.",
  };
}

const protectSecurityInfoRegistration: FixGuideDefinition = {
  id: "protect-security-info-registration",
  kind: "conditionalAccess",
  title: "Protect MFA and security-info registration",
  summary: "Registering or changing MFA methods requires MFA (or a Temporary Access Pass) unless the user is on a trusted network.",
  stops: "An attacker with only a password registering their own MFA method on the account.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator", other: ["Temporary Access Pass enabled, so new users can register their first method"] },
  impact: "New users need a Temporary Access Pass from an admin to register outside a trusted network. Guests are excluded (Temporary Access Pass doesn't work for them). From 6 July 2026 Microsoft also applies these policies to Windows Hello for Business and macOS Platform SSO registration.",
  proposedPolicy: proposeSecurityInfo,
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          `Entra ID > Conditional Access > Policies > New policy: name it "${SECURITY_INFO_POLICY}".`,
          "Users > Include: All users. Exclude: All guest and external users, and the break-glass accounts.",
          breakGlassStep(ctx),
          "Target resources > User actions > Register security information.",
          "Conditions > Locations: Configure Yes, Include Any location, Exclude All trusted locations.",
          "Grant > Require authentication strength > Multifactor authentication > Select.",
          "Enable policy: Report-only > Create.",
        ],
      },
    },
    { title: "Or with Microsoft Graph PowerShell", command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], script: caCreateScript(proposeSecurityInfo(ctx)) } },
    switchOnStep(SECURITY_INFO_POLICY),
  ],
  verify: caVerify(SECURITY_INFO_POLICY),
  undo: caUndo(SECURITY_INFO_POLICY),
  learn: [link("Control security information registration with Conditional Access", CA_LEARN.securityInfo)],
  missing: breakGlassMissing,
};

const requireRiskRemediation: FixGuideDefinition = {
  id: "require-risk-remediation",
  kind: "conditionalAccess",
  title: "Require risk remediation for high-risk users",
  summary: "When Microsoft Entra ID Protection rates a user as high risk (for example leaked credentials), the user must remediate (secure sign-in and reset or prove the account) before getting in. Covers password and passwordless users.",
  stops: "An account with known-leaked credentials continuing to be used.",
  prerequisites: { licence: "Microsoft Entra ID P2", adminRole: "Conditional Access Administrator" },
  impact: "High-risk users are interrupted until they remediate. Users who can't complete MFA can't self-remediate and need an admin.",
  steps: (ctx) => [
    {
      title: "Create the policy in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          'Entra ID > Conditional Access > New policy: name it "Require risk remediation for high-risk users".',
          "Users > Include: All users.",
          breakGlassStep(ctx),
          "Target resources > Include: All resources.",
          "Conditions > User risk: Configure Yes > High > Done.",
          "Grant > Grant access > Require risk remediation (Require authentication strength is selected automatically; choose the strength) > Select.",
          "Session: Sign-in frequency Every time is applied automatically.",
          "Enable policy: Report-only > Create.",
        ],
      },
      note: "Microsoft documents this policy in the portal only, so Clarity365 doesn't give a command for it.",
    },
  ],
  verify: { inClarity: 'Re-sync this tenant; "High user risk forces remediation" turns green once the policy is on.' },
  undo: { text: "Turn the policy off or delete it in Conditional Access > Policies." },
  learn: [link("Require remediation for risky users", CA_LEARN.riskUser)],
  missing: breakGlassMissing,
};

const protectSensitiveAdminActions: FixGuideDefinition = {
  id: "protect-sensitive-admin-actions",
  kind: "conditionalAccess",
  title: "Require step-up authentication for sensitive admin actions",
  summary: "Uses protected actions: deleting or changing Conditional Access policies (and other permissions you choose) asks for phishing-resistant MFA at that moment, even for an admin already signed in.",
  stops: "An attacker with a hijacked admin session quietly deleting the policies that protect the tenant.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator or Security Administrator", other: ["Admins able to complete phishing-resistant MFA"] },
  impact: "Admins are re-prompted when they perform the protected actions. Microsoft: do the steps in this order, and the policy must be On (not report-only) before you add protected actions, or admins get repeated prompts. If that happens, https://aka.ms/MSALProtectedActions opens Conditional Access.",
  steps: (ctx) => [
    {
      title: "1. Create an authentication context",
      portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Conditional Access > Authentication context > New authentication context.", 'Name it (for example "Sensitive admin actions"), tick Publish to apps > Save.'] },
    },
    {
      title: "2. Create a policy for that context",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          'Conditional Access > Policies > New policy: name it "Step-up for sensitive admin actions".',
          "Users > Include: Directory roles: the admin roles.",
          breakGlassStep(ctx),
          "Target resources > Authentication context > select the context from step 1.",
          "Grant > Require authentication strength > Phishing-resistant MFA > Select.",
          "Enable policy: On > Create. (Protected actions need it On.)",
        ],
      },
    },
    {
      title: "3. Add the protected actions",
      portal: {
        url: "https://entra.microsoft.com",
        steps: ["Entra ID > Roles & admins > Protected actions > Add protected actions.", "Select the authentication context from step 1.", "Select permissions: at least the Conditional Access policy delete and update permissions > Add > Save."],
      },
    },
    { title: "Test it", note: "Open a Conditional Access policy as an admin: editing shows \"Editing is protected by an additional access requirement\" until the admin reauthenticates." },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Sensitive admin actions need step-up authentication" turns green.' },
  undo: { text: "Roles & admins > Protected actions > select the permission > Remove." },
  learn: [link("Add, test, or remove protected actions", CA_LEARN.protectedActions)],
  missing: breakGlassMissing,
};

// ================================================== Stage 3 (2026-10-05)
// Review and clean-up guides (kind F). Each works on the offending items the
// check found, with one command per item. The judgement (is this rule
// approved? does this admin still need the role?) stays with the operator:
// every guide starts with "review first", and where a reversible step exists
// (disable a rule, disable an app) it comes before the irreversible one.

const S3_LEARN = {
  registrationCampaign: "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign",
  tap: "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass",
  updateCaPolicy: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/update-mgidentityconditionalaccesspolicy?view=graph-powershell-1.0",
  emergencyAccess: "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
  appPermissions: "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions",
  disableAppSignIn: "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/disable-user-sign-in-portal",
  removeAppRoleAssignment: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/remove-mgserviceprincipalapproleassignment?view=graph-powershell-1.0",
  eligibilityRequest: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.governance/new-mgrolemanagementdirectoryroleeligibilityschedulerequest?view=graph-powershell-1.0",
  assignmentRequest: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.governance/new-mgrolemanagementdirectoryroleassignmentschedulerequest?view=graph-powershell-1.0",
  pimSettings: "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings",
  removeGroupOwner: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.groups/remove-mggroupownerdirectoryobjectbyref?view=graph-powershell-1.0",
  disableInboxRule: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disable-inboxrule?view=exchange-ps",
  setMailbox: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-mailbox?view=exchange-ps",
  revokeSessions: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users.actions/revoke-mgusersigninsession?view=graph-powershell-1.0",
  disableTransportRule: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disable-transportrule?view=exchange-ps",
  searchAuditLog: "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog?view=exchange-ps",
};

// Single-quoted PowerShell literal (no interpolation) for names, UPNs and ids.
const ps = (value: string) => toPowerShell(value);

// --------------------------------------------------------- MFA registration

const mfaRegistrationDrive: FixGuideDefinition = {
  id: "mfa-registration-drive",
  kind: "review",
  title: "Get every user registered for MFA",
  summary:
    "Gets the accounts without an MFA method registered, safely. A user without a method is asked to register at their next MFA prompt, and whoever holds the password can register first. Accounts that aren't used are disabled; real users get a one-time Temporary Access Pass from an admin to register with, and the registration page itself is protected.",
  stops: "An attacker with a sprayed or leaked password registering their own MFA method on an account that never had one.",
  prerequisites: {
    adminRole: "Authentication Policy Administrator (TAP policy, registration campaign); Authentication Administrator (create a TAP for a member)",
    other: ["Microsoft Entra ID Free supports TAP and the registration campaign; the Conditional Access steps need P1"],
  },
  impact:
    "Users given a Temporary Access Pass sign in with it once and register Microsoft Authenticator or a passkey. The registration campaign nudges users who already do MFA by text or call to move to Authenticator; it doesn't reach accounts with no method at all, which is why the TAP step exists.",
  steps: (ctx) => [
    {
      title: "Review the list",
      note: `${ctx.items.length} enabled member account(s) without an MFA method: ${itemList(ctx, "none")}. For each: is it a person who signs in, a shared or service account, or unused? Disable unused accounts (Entra ID > Users > the user > Edit properties > Account enabled: off) rather than registering them.`,
    },
    {
      title: "1. Protect the registration page first",
      note: 'Use the guide "Protect MFA and security-info registration" (on the MFA tampering scenario) so that registering a method outside a trusted network needs MFA or a Temporary Access Pass. Without it, the password alone is enough to register.',
    },
    {
      title: "2. Turn on Temporary Access Pass",
      portal: {
        url: "https://entra.microsoft.com",
        steps: ["Entra ID > Authentication methods > Policies > Temporary Access Pass.", "Enable, Include: All users (or a group for new joiners) > Save.", "Defaults: 1 hour lifetime, one-time use off. Configure to change them."],
      },
    },
    ...(ctx.items.length > 0
      ? [
          {
            title: "3. Create a one-time pass for each person who should register",
            command: {
              shell: "MicrosoftGraph" as GuideShell,
              graphScopes: ["UserAuthenticationMethod.ReadWrite.All"],
              script: ctx.items
                .map((i) => `# ${i.label}\n$tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId ${ps(i.userPrincipalName || i.principalId || "")} -BodyParameter @{ isUsableOnce = $true; lifetimeInMinutes = 480 }\n"${(i.userPrincipalName || "").replace(/["`$]/g, "")}: $($tap.TemporaryAccessPass)"`)
                .join("\n\n"),
            },
            note: "Delete the lines for accounts you disabled or that shouldn't register. Give each pass to its user over a channel you trust (in person or by phone, not to the mailbox of that account); they sign in at https://mysignins.microsoft.com/security-info and register Authenticator or a passkey. 480 minutes must be within the TAP policy's maximum lifetime (default 8 hours). A pass can't be issued to an external guest.",
          },
        ]
      : []),
    {
      title: "4. Nudge everyone else to Microsoft Authenticator",
      portal: {
        url: "https://entra.microsoft.com",
        steps: ["Entra ID > Authentication methods > Registration campaign > Edit.", "State: Microsoft managed (or Enabled with Authentication method: Microsoft Authenticator).", "Include: All users. Exclude: the break-glass accounts > Save."],
      },
      command: {
        shell: "MicrosoftGraph",
        graphScopes: ["Policy.Read.All", "Policy.ReadWrite.AuthenticationMethod"],
        script: `$body = @{
    registrationEnforcement = @{
        authenticationMethodsRegistrationCampaign = @{
            snoozeDurationInDays = 1
            enforceRegistrationAfterAllowedSnoozes = $true
            state = 'enabled'
            excludeTargets = @(${ctx.breakGlass.map((b) => `@{ id = ${ps(b.objectId)}; targetType = 'user' }`).join(", ")})
            includeTargets = @(@{ id = 'all_users'; targetType = 'group'; targetedAuthenticationMethod = 'microsoftAuthenticator' })
        }
    }
}
Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json'`,
      },
      note: "Users must be enabled for Microsoft Authenticator (mode Any or Push) in the authentication methods policy to be nudged.",
    },
    { title: "5. Require MFA", note: 'Once people are registered, "Require MFA for all users" (on the Password spray scenario) makes MFA mandatory.' },
  ],
  verify: { inClarity: 'Re-sync this tenant; "Every enabled user has MFA registered" lists fewer accounts, and turns green when none are left.' },
  undo: { text: "Delete an unused pass under the user > Authentication methods; set the registration campaign State to Disabled." },
  learn: [link("Temporary Access Pass", S3_LEARN.tap), link("Registration campaign", S3_LEARN.registrationCampaign)],
};

// ------------------------------------------------- Individual CA exclusions

const removeIndividualExclusions: FixGuideDefinition = {
  id: "remove-individual-exclusions",
  kind: "review",
  title: "Remove individual exclusions from Conditional Access policies",
  summary:
    "Takes named accounts (other than break-glass) out of the exclude list of each policy that excludes them, so the policy protects them again. The command reads each policy, removes only these accounts from its excluded users, and writes the same users section back.",
  stops: "An attacker targeting the one account that MFA, device or location policies skip.",
  prerequisites: { licence: "Microsoft Entra ID P1", adminRole: "Conditional Access Administrator" },
  impact:
    "The accounts become subject to the policy: they may be asked for MFA, a compliant device, or be blocked. Service accounts that sign in with a password break; move them to a managed identity or workload identity instead of keeping the exclusion. If someone genuinely needs an exception, exclude a group instead and review its members regularly.",
  rollout: "Check each account's recent sign-ins (Sign-in Logs module) first, so you know what the policy will do to it.",
  steps: (ctx) => {
    const byPolicy = new Map<string, FixGuideItem[]>();
    for (const i of ctx.items) if (i.policyId && i.excludeRef) byPolicy.set(i.policyId, [...(byPolicy.get(i.policyId) || []), i]);
    const steps: FixGuideStep[] = [
      { title: "Review each exclusion", note: `${ctx.items.length} exclusion(s): ${itemList(ctx, "none")}. Ask why each was added; keep only emergency-access (break-glass) accounts.` },
      {
        title: "Remove them in the Entra admin center",
        portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Conditional Access > Policies > open the policy.", "Users > Exclude > remove the account > Save.", "Repeat for each policy listed."] },
      },
    ];
    if (byPolicy.size > 0) {
      steps.push({
        title: "Or with Microsoft Graph PowerShell",
        command: {
          shell: "MicrosoftGraph",
          graphScopes: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"],
          script: [...byPolicy.entries()]
            .map(([policyId, items]) => {
              const refs = items.map((i) => ps(i.excludeRef!)).join(", ");
              return `# ${items[0].policyName}: ${items.map((i) => i.userPrincipalName || i.excludeRef).join(", ")}
$uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${policyId}'
$users = (Invoke-MgGraphRequest -Method GET -Uri $uri).conditions.users
$users.excludeUsers = @($users.excludeUsers | Where-Object { $_ -notin @(${refs}) })
Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body (@{ conditions = @{ users = $users } } | ConvertTo-Json -Depth 10) -ContentType 'application/json'`;
            })
            .join("\n\n"),
        },
        note: "Reads the policy's current users section and writes it back with only these accounts removed, so other includes and excludes (groups, roles, guests) are kept as they are.",
      });
    }
    return steps;
  },
  verify: {
    inClarity: 'Re-sync this tenant; "No account is individually excluded from policies" (and "No Global Admin is individually excluded") turn green.',
    command: { shell: "MicrosoftGraph", graphScopes: ["Policy.Read.All"], script: "Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, @{ n = 'ExcludedUsers'; e = { $_.Conditions.Users.ExcludeUsers -join ', ' } }" },
  },
  undo: { text: "Add the account back under the policy's Users > Exclude." },
  learn: [link("Update-MgIdentityConditionalAccessPolicy", S3_LEARN.updateCaPolicy), link("Manage emergency access accounts (exclusions)", S3_LEARN.emergencyAccess)],
};

// ---------------------------------------------------- Risky consented apps

const revokeRiskyAppConsent: FixGuideDefinition = {
  id: "revoke-risky-app-consent",
  kind: "review",
  title: "Review and revoke risky user-consented apps",
  summary:
    "For each unverified app that users consented to with access to mail, files or the directory: check what it is, then stop it signing in and revoke what it was granted. Disabling sign-in is reversible and immediate; revoking removes the permissions.",
  stops: "A consent-phishing app reading mail or files with tokens that survive a password reset.",
  prerequisites: { adminRole: "Cloud Application Administrator (or Application Administrator)" },
  impact: "Users of the app lose access through it at once. If the app turns out to be legitimate, re-enable sign-in and have an admin grant the permissions it needs.",
  steps: (ctx) => [
    { title: "Review each app", note: `${ctx.items.length} app(s): ${itemList(ctx, "none")}. In Entra ID > Enterprise apps > the app > Permissions (User consent tab) and Sign-in logs, check who uses it and since when. Unknown publisher plus mail or file access plus few users is the consent-phishing pattern.` },
    {
      title: "Disable sign-in (reversible)",
      portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Enterprise apps > All applications > the app > Properties.", "Enabled for users to sign-in?: No > Save."] },
      ...(ctx.items.length > 0
        ? {
            command: {
              shell: "MicrosoftGraph" as GuideShell,
              graphScopes: ["Application.ReadWrite.All"],
              script: ctx.items.map((i) => `# ${i.label}\nUpdate-MgServicePrincipal -ServicePrincipalId ${ps(i.principalId || "")} -AccountEnabled:$false`).join("\n\n"),
            },
          }
        : {}),
    },
    ...(ctx.items.length > 0
      ? [
          {
            title: "Revoke the permissions it was granted",
            command: {
              shell: "MicrosoftGraph" as GuideShell,
              graphScopes: ["Application.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"],
              script: ctx.items
                .map(
                  (i) => `# ${i.label}
$spId = ${ps(i.principalId || "")}
Get-MgOauth2PermissionGrant -All | Where-Object { $_.ClientId -eq $spId } | ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -All | ForEach-Object { Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId -AppRoleAssignmentId $_.Id }`
                )
                .join("\n\n"),
            },
            note: "User-consent grants can't be revoked in the portal; Microsoft documents this script for it. Revoking doesn't stop users consenting again: keep user consent restricted (the \"User consent is restricted\" check).",
          },
        ]
      : []),
  ],
  verify: { inClarity: 'Re-sync this tenant; "No user has consented to a risky unverified app" turns green.' },
  undo: { text: "Set Enabled for users to sign-in back to Yes; permissions have to be consented again." },
  learn: [link("Review permissions granted to enterprise applications", S3_LEARN.appPermissions), link("Disable user sign-in for an application", S3_LEARN.disableAppSignIn)],
};

// ------------------------------------------------ App registration permissions

const reviewAppPermissions: FixGuideDefinition = {
  id: "review-app-permissions",
  kind: "review",
  title: "Remove high-privilege permissions from app registrations",
  summary:
    "For each app registration holding high-privilege application permissions (for example Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, Mail.ReadWrite): confirm with its owner what it actually needs, remove the rest from the granted permissions, and take them off the registration so nobody consents them again.",
  stops: "A leaked app secret being enough to read every mailbox or make anyone an admin.",
  prerequisites: { adminRole: "Cloud Application Administrator (Privileged Role Administrator for directory-role permissions)" },
  impact: "The app stops being able to do what the removed permission allowed. Integrations that relied on it break; agree a narrower permission (for example Sites.Selected instead of Sites.ReadWrite.All) with the owner first.",
  steps: (ctx) => [
    { title: "Review each app with its owner", note: `${ctx.items.length} app registration(s): ${itemList(ctx, "none")}. Also check its credentials: prefer certificates over secrets and remove unused secrets.` },
    {
      title: "Remove the permission in the Entra admin center",
      portal: {
        url: "https://entra.microsoft.com",
        steps: [
          "Entra ID > Enterprise apps > the app > Permissions > Admin consent tab > the permission > ... > Revoke permission.",
          "Entra ID > App registrations > the app > API permissions > the permission > ... > Remove permission, so it isn't consented again.",
        ],
      },
    },
    ...(ctx.items.some((i) => i.appId && (i.permissions || []).length > 0)
      ? [
          {
            title: "Or revoke the granted permissions with Microsoft Graph PowerShell",
            command: {
              shell: "MicrosoftGraph" as GuideShell,
              graphScopes: ["Application.Read.All", "AppRoleAssignment.ReadWrite.All"],
              script: `$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

${ctx.items
  .filter((i) => i.appId && (i.permissions || []).length > 0)
  .map(
    (i) => `# ${i.label}
# Delete the permissions this app still needs from the list before running.
$remove = @(${(i.permissions || []).map(ps).join(", ")})
$sp = Get-MgServicePrincipal -Filter "appId eq '${i.appId}'"
$roleIds = $graph.AppRoles | Where-Object { $_.Value -in $remove } | ForEach-Object { $_.Id }
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All |
    Where-Object { $_.ResourceId -eq $graph.Id -and $_.AppRoleId -in $roleIds } |
    ForEach-Object { Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleAssignmentId $_.Id }`
  )
  .join("\n\n")}`,
            },
            note: "This revokes Microsoft Graph application permissions only. Remove them from the registration's API permissions too (portal step above). Permissions on other APIs (Exchange, SharePoint) are removed the same way in the portal.",
          },
        ]
      : []),
  ],
  verify: { inClarity: 'Re-sync this tenant; "No app registration holds critical permissions" and "No app can assign roles or permissions" turn green when nothing high-privilege is left.' },
  undo: { text: "Add the permission back on the registration's API permissions page and grant admin consent." },
  learn: [link("Review permissions granted to enterprise applications", S3_LEARN.appPermissions), link("Remove-MgServicePrincipalAppRoleAssignment", S3_LEARN.removeAppRoleAssignment)],
};

// ----------------------------------------------------- Global Admin count

const rightSizeGlobalAdmins: FixGuideDefinition = {
  id: "right-size-global-admins",
  kind: "review",
  title: "Keep between two and five Global Administrators",
  summary:
    "Too many Global Admins: move day-to-day admins to the least-privileged role that covers their work (Exchange, SharePoint, User, Helpdesk, Security Administrator...) and remove Global Administrator. Only one: add a second, emergency-access account so one lost account can't lock the tenant.",
  stops: "Every extra Global Admin being another account whose compromise gives an attacker the whole tenant.",
  prerequisites: { adminRole: "Privileged Role Administrator" },
  impact: "Admins moved to a narrower role lose Global Administrator rights; check what they do first so the new role covers it.",
  steps: (ctx) => {
    const holders = ctx.items;
    const steps: FixGuideStep[] = [{ title: "Who holds Global Administrator", note: `${holders.length} account(s): ${itemList(ctx, "none")}.` }];
    if (holders.length < 2) {
      steps.push({
        title: "Add an emergency-access account",
        portal: {
          url: "https://entra.microsoft.com",
          steps: [
            "Entra ID > Users > New user: a cloud-only account on the .onmicrosoft.com domain, not tied to any person's phone.",
            "Assign Global Administrator (permanent active, not eligible).",
            "Register a passkey (FIDO2 security key) for it, different from your normal admin method.",
            "Exclude it from Conditional Access policies that block or restrict sign-in.",
            "Store the key and password securely, alert on every sign-in, and test it every 90 days.",
          ],
        },
        note: "Microsoft recommends two or more emergency-access accounts.",
      });
      return steps;
    }
    steps.push(
      {
        title: "Move each day-to-day admin to a narrower role",
        portal: {
          url: "https://entra.microsoft.com",
          steps: [
            "Decide the role each person needs (Roles & admins lists what each role can do).",
            "Entra ID > Roles & admins > the new role > Add assignments > the user (or make it eligible in PIM).",
            "Then Roles & admins > Global Administrator > the user > Remove assignment.",
            "Keep two emergency-access accounts and at most a few named Global Admins.",
          ],
        },
      },
      {
        title: "Remove Global Administrator with Microsoft Graph PowerShell (after the new role is in place)",
        command: {
          shell: "MicrosoftGraph",
          graphScopes: ["RoleManagement.ReadWrite.Directory"],
          script: holders
            .filter((i) => i.principalId)
            .map(
              (i) => `# ${i.label}  (delete this block if they keep Global Administrator)
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '${i.principalId}'" |
    Where-Object { $_.RoleDefinitionId -eq '62e90394-69f5-4237-9190-012177145e10' } |
    ForEach-Object { Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $_.Id }`
            )
            .join("\n\n"),
        },
        note: "Delete the blocks for break-glass accounts and the admins who keep the role. If a removal fails because the assignment is managed by PIM, remove it in Privileged Identity Management.",
      }
    );
    return steps;
  },
  verify: { inClarity: 'Re-sync this tenant; "Between two and five Global Admins" turns green.' },
  undo: { text: "Re-assign Global Administrator under Roles & admins." },
  learn: [link("Manage emergency access accounts", S3_LEARN.emergencyAccess), { title: "Remove-MgRoleManagementDirectoryRoleAssignment", url: "https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.governance/remove-mgrolemanagementdirectoryroleassignment?view=graph-powershell-1.0", checked: CHECKED }],
};

// -------------------------------------------------- Standing admin -> PIM

const makeAdminRolesEligible: FixGuideDefinition = {
  id: "make-admin-roles-eligible",
  kind: "review",
  title: "Make admin roles just-in-time with PIM",
  summary:
    "Turns permanent admin role assignments into eligible ones in Privileged Identity Management: the person keeps the role but has to activate it (with MFA and a reason) for a few hours when they need it. Break-glass accounts stay permanent active, as Microsoft recommends.",
  stops: "A stolen admin session or password giving standing admin rights at any moment (deleting users, adding mail flow rules, assigning roles).",
  prerequisites: { licence: "Microsoft Entra ID P2 (or Microsoft Entra ID Governance) for each admin", adminRole: "Privileged Role Administrator" },
  impact: "Admins activate their role before admin work (Entra ID > My roles, or PIM). Scripts and service accounts that rely on a standing role break; give them an app with the least permission it needs instead.",
  rollout:
    "Set the role settings first (step 1), then make the assignments eligible, then remove the active ones. Don't require approval without naming approvers: if every Global and Privileged Role Administrator is eligible and approval has no approvers, nobody can activate and the tenant is locked. The break-glass accounts prevent that.",
  steps: (ctx) => {
    const steps: FixGuideStep[] = [
      { title: "Review the standing assignments", note: `${ctx.items.length} permanent assignment(s) outside break-glass: ${itemList(ctx, "none")}.` },
      {
        title: "1. Set the activation rules for each role",
        portal: {
          url: "https://entra.microsoft.com",
          steps: [
            "ID Governance > Privileged Identity Management > Microsoft Entra roles > Roles > the role (start with Global Administrator) > Role settings > Edit.",
            "Activation maximum duration: 4 hours or less. On activation, require: Azure MFA (or a Conditional Access authentication context). Require justification on activation.",
            "Require approval for Global Administrator and Privileged Role Administrator, with at least two named approvers > Update.",
          ],
        },
      },
    ];
    const withIds = ctx.items.filter((i) => i.principalId && i.roleTemplateId);
    if (withIds.length > 0) {
      steps.push(
        {
          title: "2. Make each assignment eligible",
          command: {
            shell: "MicrosoftGraph",
            graphScopes: ["RoleEligibilitySchedule.ReadWrite.Directory"],
            script: withIds
              .map(
                (i) => `# ${i.label}
New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter @{
    action           = 'adminAssign'
    justification    = 'Move standing admin access to just-in-time'
    roleDefinitionId = '${i.roleTemplateId}'
    directoryScopeId = '/'
    principalId      = '${i.principalId}'
    scheduleInfo     = @{ startDateTime = (Get-Date).ToUniversalTime(); expiration = @{ type = 'noExpiration' } }
}`
              )
              .join("\n\n"),
          },
          note: "If the role setting requires eligible assignments to expire, use expiration @{ type = 'afterDateTime'; endDateTime = ... } instead.",
        },
        {
          title: "3. Then remove the permanent active assignment",
          command: {
            shell: "MicrosoftGraph",
            graphScopes: ["RoleAssignmentSchedule.ReadWrite.Directory"],
            script: withIds
              .map(
                (i) => `# ${i.label}
New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter @{
    action           = 'adminRemove'
    justification    = 'Replaced by an eligible assignment'
    roleDefinitionId = '${i.roleTemplateId}'
    directoryScopeId = '/'
    principalId      = '${i.principalId}'
}`
              )
              .join("\n\n"),
          },
          note: "Run step 3 only after step 2 succeeded for that person. If the active assignment was made outside PIM and this fails, remove it under Roles & admins > the role > Remove assignment.",
        }
      );
    }
    return steps;
  },
  verify: { inClarity: 'Re-sync this tenant; "Admin roles are just-in-time (PIM), not standing", "Admin roles need activation (PIM)", "Few accounts can delete users at any moment" and "Few accounts can change mail flow rules" improve.' },
  undo: { text: "In PIM > Microsoft Entra roles > Assignments, assign the role as Active again, or remove the eligible assignment." },
  learn: [link("New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest", S3_LEARN.eligibilityRequest), link("New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest", S3_LEARN.assignmentRequest), link("Configure Microsoft Entra role settings in PIM", S3_LEARN.pimSettings)],
  missing: (ctx) => [
    ...(ctx.entraP2Licensed === false
      ? ['This tenant doesn\'t appear to have Microsoft Entra ID P2, so PIM isn\'t available and these commands will fail. Without P2, reduce standing admins instead: "Keep between two and five Global Administrators" and narrower roles.']
      : []),
    ...(ctx.items.some((i) => !i.principalId || !i.roleTemplateId) ? ["Some assignments came from role names only (PIM data not synced), so their commands are missing; use the portal for those."] : []),
  ],
};

// --------------------------------------------- Role-assignable group owners

const removeRoleGroupOwners: FixGuideDefinition = {
  id: "remove-role-group-owners",
  kind: "review",
  title: "Remove non-admin owners from role-assignable groups",
  summary: "Owners of a role-assignable group can add members, and every member gets the group's admin role. Removes owners who aren't admins themselves.",
  stops: "A compromised ordinary account adding itself to a group that holds an admin role.",
  prerequisites: { adminRole: "Privileged Role Administrator" },
  impact: "The removed owners can no longer manage the group's members. A group's last owner can't be removed; add an admin as owner first.",
  steps: (ctx) => [
    { title: "Review the owners", note: `${ctx.items.length} owner(s): ${itemList(ctx, "none")}.` },
    { title: "Remove them in the Entra admin center", portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Groups > the group > Owners.", "Add an admin as owner if needed, then select the non-admin owner > Remove."] } },
    ...(ctx.items.length > 0
      ? [
          {
            title: "Or with Microsoft Graph PowerShell",
            command: {
              shell: "MicrosoftGraph" as GuideShell,
              graphScopes: ["Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory"],
              script: ctx.items
                .map((i) => `# ${i.label}\n$owner = Get-MgUser -UserId ${ps(i.ownerUpn || "")}\nRemove-MgGroupOwnerDirectoryObjectByRef -GroupId '${i.groupId}' -DirectoryObjectId $owner.Id`)
                .join("\n\n"),
            },
          },
        ]
      : []),
  ],
  verify: { inClarity: 'Re-sync this tenant; "Role-assignable groups are owned by admins only" turns green.' },
  undo: { text: "Add the owner back under the group's Owners." },
  learn: [link("Remove-MgGroupOwnerDirectoryObjectByRef", S3_LEARN.removeGroupOwner)],
};

// ------------------------------------------------- External mailbox forwarding

const stopExternalMailboxForwarding: FixGuideDefinition = {
  id: "stop-external-mailbox-forwarding",
  kind: "review",
  title: "Stop inbox rules and mailbox forwarding that send mail outside",
  summary:
    "Treats each external forward as a possible compromise: check it with the mailbox owner, disable the inbox rule or clear the mailbox forwarding, and if it wasn't theirs, reset the password and sign the account out everywhere.",
  stops: "An attacker's hidden rule quietly copying a mailbox's mail to an outside address.",
  prerequisites: { adminRole: "Exchange Administrator (rules); User Administrator or Authentication Administrator (password and sessions)" },
  impact: "Forwarding stops at once. A forward the user set up on purpose (for example to a personal address) stops too, which is usually the right outcome; approved business forwarding should go through a mail flow rule or connector instead.",
  steps: (ctx) => {
    const rules = ctx.items.filter((i) => i.forwardKind === "inboxRule" && i.address && i.ruleName);
    const mailboxes = ctx.items.filter((i) => i.forwardKind === "mailboxForwarding" && i.address);
    const steps: FixGuideStep[] = [
      { title: "Review each forward with the mailbox owner", note: `${ctx.items.length} external forward(s): ${itemList(ctx, "none")}. A rule the owner doesn't recognise means the mailbox was compromised: do the last step for it too.` },
    ];
    if (rules.length > 0) {
      steps.push({
        title: "Disable the inbox rules (reversible)",
        command: { shell: "ExchangeOnline", script: rules.map((i) => `Disable-InboxRule -Mailbox ${ps(i.address!)} -Identity ${ps(i.ruleName!)} -Confirm:$false`).join("\n") },
        note: "Changing inbox rules from PowerShell removes that mailbox's Outlook client-side rules (Microsoft warns about this). Once confirmed unwanted, delete the rule in Outlook on the web (Settings > Mail > Rules) or with Remove-InboxRule.",
      });
    }
    if (mailboxes.length > 0) {
      steps.push({
        title: "Clear mailbox-level forwarding",
        command: { shell: "ExchangeOnline", script: mailboxes.map((i) => `Set-Mailbox -Identity ${ps(i.address!)} -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false`).join("\n") },
      });
    }
    if (ctx.items.length > 0) {
      steps.push({
        title: "If it wasn't the owner: secure the account",
        portal: { url: "https://entra.microsoft.com", steps: ["Entra ID > Users > the user > Reset password.", "Revoke sessions (same page), then check their sign-ins in the Sign-in Logs module and their MFA methods for anything they didn't add."] },
        command: {
          shell: "MicrosoftGraph",
          graphScopes: ["User.RevokeSessions.All"],
          script: [...new Set(ctx.items.map((i) => i.address).filter(Boolean) as string[])].map((a) => `# Only for compromised mailboxes:\n# Revoke-MgUserSignInSession -UserId ${ps(a)}`).join("\n"),
        },
        note: "The revoke lines are commented out; uncomment the ones for mailboxes that were compromised. Reset the password first, or the attacker signs straight back in.",
      });
    }
    return steps;
  },
  verify: {
    inClarity: 'Re-sync this tenant; "No mailbox forwards mail outside" turns green.',
    command: { shell: "ExchangeOnline", script: "Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | Format-Table UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress" },
  },
  undo: { text: "Enable-InboxRule re-enables a disabled rule; mailbox forwarding is set again with Set-Mailbox -ForwardingSmtpAddress." },
  learn: [link("Disable-InboxRule", S3_LEARN.disableInboxRule), link("Set-Mailbox", S3_LEARN.setMailbox), link("Revoke-MgUserSignInSession", S3_LEARN.revokeSessions)],
};

// ------------------------------------------------- External transport rules

const disableExternalTransportRules: FixGuideDefinition = {
  id: "disable-external-transport-rules",
  kind: "review",
  title: "Disable mail flow rules that copy or redirect mail outside",
  summary: "For each enabled organisation-wide mail flow rule that copies (BCC) or redirects mail to an outside address: check who created it and why, disable it, and remove it once confirmed unwanted.",
  stops: "A compromised Exchange admin silently copying the organisation's mail to an attacker.",
  prerequisites: { adminRole: "Exchange Administrator" },
  impact: "The copy or redirect stops for all mail the rule matched. An approved journaling or archiving rule should use a connector or journaling instead; agree that with its owner before disabling.",
  steps: (ctx) => [
    { title: "Review each rule", note: `${ctx.items.length} rule(s): ${itemList(ctx, "none")}.` },
    ...(ctx.items.length > 0
      ? [
          {
            title: "See who created or changed them",
            command: {
              shell: "ExchangeOnline" as GuideShell,
              script: `# Who created or changed mail flow rules in the last 90 days (needs the audit log on):
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) -Operations New-TransportRule, Set-TransportRule, Enable-TransportRule -ResultSize 5000 | Format-Table CreationDate, UserIds, Operations`,
            },
          },
          {
            title: "Disable them (reversible)",
            command: { shell: "ExchangeOnline" as GuideShell, script: ctx.items.map((i) => `Disable-TransportRule -Identity ${ps(i.ruleName || "")} -Confirm:$false`).join("\n") },
            note: "Once confirmed unwanted, remove the rule in the Exchange admin center (Mail flow > Rules) or with Remove-TransportRule. If an admin you don't know created it, treat that admin account as compromised.",
          },
        ]
      : []),
    { title: "Or in the Exchange admin center", portal: { url: "https://admin.exchange.microsoft.com", steps: ["Mail flow > Rules > the rule > Disable (or Delete once confirmed)."] } },
  ],
  verify: { inClarity: 'Re-sync this tenant; "No mail flow rule sends mail outside" turns green.' },
  undo: { text: "Enable-TransportRule -Identity <rule name> re-enables it." },
  learn: [link("Disable-TransportRule", S3_LEARN.disableTransportRule), link("Search-UnifiedAuditLog", S3_LEARN.searchAuditLog)],
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
  blockForeignCountries,
  includeUnknownCountries,
  requireMfaDeviceRegistration,
  requireTokenProtection,
  requireCompliantDeviceAdmins,
  requireCompliantDeviceDesktop,
  adminSessionLimits,
  requirePhishingResistantAdmins,
  keepCaeOn,
  requireMfaGuests,
  requireMfaAllUsers,
  blockLegacyAuth,
  blockAuthenticationTransfer,
  protectSecurityInfoRegistration,
  requireRiskRemediation,
  protectSensitiveAdminActions,
  mfaRegistrationDrive,
  removeIndividualExclusions,
  revokeRiskyAppConsent,
  reviewAppPermissions,
  rightSizeGlobalAdmins,
  makeAdminRolesEligible,
  removeRoleGroupOwners,
  stopExternalMailboxForwarding,
  disableExternalTransportRules,
];

export function getFixGuideDefinition(id: string): FixGuideDefinition | undefined {
  return FIX_GUIDES.find((g) => g.id === id);
}
