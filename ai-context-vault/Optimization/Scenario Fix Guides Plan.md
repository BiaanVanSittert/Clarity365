---
tags: [optimization, plan, security-simulations]
---

# Scenario Fix Guides Plan

Status: **Stages 0, 1 and 2 done 2026-10-05** (40 guides). Stage 3 (review and clean-up guides) next.

## Decisions (user, 2026-10-05)
- **Guides only.** Clarity365 shows the portal steps and the commands; the operator runs them. Stage 5 ("apply from Clarity365") is dropped.
- **Portal steps and commands, both**, plus the steps in between.
- **Order as recommended:** stage 0, then 1, then 2, then 3 and 4.

## What this is for
[[Security Scenarios]] says whether an attack would be prevented and gives a one-line fix. The request: for every scenario, a real **guide to put the recommended policy or setting in place**, the way the alert check now shows the exact PowerShell command to run. The operator should be able to go from a red check to a green one without leaving the screen to work out how.

Scope rule (unchanged): every guide and every action is for **one tenant**. No "apply to all tenants".

## What a guide contains
One guide per check, opened from a "How to fix" button on any check that isn't green:

1. **What it does**, in one or two sentences, and which attack step it stops.
2. **Before you start**: licence needed (Entra ID P1/P2, Intune, E5), the admin role needed to make the change, and anything that must exist first (a named location, a break-glass account).
3. **Who is affected**: plain warning about lockout or disruption. For Conditional Access guides this uses the simulation engine and the synced sign-ins: "in the last 30 days this policy would have blocked 14 sign-ins by 3 users".
4. **Steps**, both ways:
   - the portal path, click by click;
   - a **copyable command** (Exchange Online, Security & Compliance, SharePoint Online or Microsoft Graph PowerShell), already filled in with this tenant's own values where Clarity365 knows them (break-glass accounts to exclude, the home country, the offending mailboxes).
5. **Safe rollout** where it applies: Conditional Access policies are created in **report-only** first, with the break-glass accounts excluded.
6. **How to confirm**: re-sync; which check turns green.
7. **How to undo it**: the reverse command.
8. Link to the Microsoft Learn page the guide was checked against, with the date it was checked.

Each scenario also gets a **Prevention plan**: its outstanding fixes in a sensible order (biggest protection for least disruption first), which can be printed or downloaded as a checklist plus one script file. A tenant-wide **Hardening plan** does the same across all scenarios for that one tenant.

## The checks, by kind of fix
About 70 checks across the 17 scenarios. They fall into six kinds, which is also the build order:

| Kind | Roughly | Examples | Guide gives |
|---|---|---|---|
| **A. Conditional Access policy** | 26 | block foreign countries, block legacy auth, MFA for all / guests, compliant device for admins, block device code flow and authentication transfer, token protection, admin sign-in frequency, phishing-resistant MFA for admins, protect security-info registration, user-risk remediation, protected actions | For the ten baseline policies (CA01 to CA10): the existing in-app "Deploy" for this tenant, where the optional write permission is granted, otherwise the script. For the rest: a Graph PowerShell command that creates the policy in report-only with break-glass excluded, plus the impact preview. |
| **B. Exchange Online setting** | 10 | SMTP AUTH off org-wide, POP/IMAP off, audit log on, mailbox auditing on, outbound spam policy blocks auto-forwarding, default remote domain blocks auto-forwarding | One command each (`Set-TransportConfig`, `Set-CASMailbox`, `Set-AdminAuditLogConfig`, `Set-OrganizationConfig`, `Set-HostedOutboundSpamFilterPolicy`, `Set-RemoteDomain`) and the admin-center path. |
| **C. SharePoint / OneDrive setting** | 10 | block legacy auth, sync only on domain-joined PCs, web-only access on unmanaged devices, sharing level, Anyone-link expiry, default link type, guest re-share, domain allow list, invitee must match | `Set-SPOTenant` commands and the SharePoint admin center path. |
| **D. Entra tenant setting** | 6 | guest access level, who can invite guests, user consent, admin consent workflow | Graph PowerShell (`Update-MgPolicyAuthorizationPolicy` and related) and the Entra admin center path. |
| **E. Alert policy** | 2 | alert on audit changes, alert on user deletion | **Done 2026-10-02** (`New-ProtectionAlert`). The pattern for everything else. |
| **F. Review and clean-up** | 15 | guests holding admin roles, too many Global Admins, standing admin roles (PIM), accounts excluded from policies, risky app consents, apps that can grant roles, external forwarding rules, mail-flow rules sending mail out, SMTP AUTH mailboxes | Not one setting: a short procedure, the list of offending items from the sync, and a per-item command with the real object filled in (for example the exact `Remove-MgDirectoryRoleMemberByRef` for that guest). |

Two checks are information only (Intune licensed, sign-in logs available) and get a short "what you need" note.

## Rules that keep it reliable
- **Every command is checked on Microsoft Learn before it ships**, and the guide records the page and the date. No command from memory. (The alert commands were checked this way and then proven on a live tenant.)
- **Guides first, buttons later.** By default Clarity365 shows the command and the operator runs it. That needs no extra permission and can't change a tenant by accident.
- **Conditional Access is report-only by default**, with break-glass excluded and a lockout warning. Turning it on is a second, deliberate step.
- **Nothing is marked fixed until a sync reads it back.** The guide never turns a check green by itself.
- Each guide is tried on **Crimson Line Live Demo** before it is trusted, and the result recorded here.
- Where Microsoft doesn't let the app read the result (SharePoint link settings), the guide ends with the existing "confirm once" button.

## How it would be built
- `src/lib/data/scenario-fix-guides.ts`: the guide catalogue (plain data, like `graph-permissions.ts`), each guide with its steps, commands as templates, prerequisites, undo, Learn link and checked date.
- `src/lib/services/scenario-fix-guide-builder.ts` (pure, tested): fills a guide's templates from the snapshot (break-glass accounts, home country, named locations, offending items) and, for Conditional Access, asks the existing [[CA Simulation Engine]] and fix recommender for the impact preview.
- Each check result carries a `guideId`; the catalogue test fails if a check with a fix has no guide.
- UI: "How to fix" on each check opens a drawer (same pattern as `RemediationDrawer`); "Prevention plan" on each scenario; "Hardening plan" for the tenant, printable and downloadable (checklist + one `.ps1`).
- Reuses: `remediation-generator.ts` (script output), the per-tenant CA deploy route, `ca-fix-recommender.ts`, `SCENARIO_DOCS` / `CA_DOCS`.

## Stages
| # | Stage | Result | Size |
|---|---|---|---|
| 0 | **Inventory and format.** Table of every check: kind, command, Learn page. Build three pilot guides end to end (one A, one B, one F) and agree the format. | The format is settled before 70 guides are written. | S |
| 1 | **One-command settings** (kinds B, C, D): about 26 guides, the drawer, copy buttons, undo, confirm. | Most Exchange, SharePoint and Entra-setting checks become "copy, run, re-sync". | M |
| 2 | **Conditional Access guides** (kind A): baseline policies link to the existing per-tenant deploy; the others get a generated report-only policy command; impact preview from real sign-ins. | The identity scenarios, where most red is, become actionable. | L |
| 3 | **Review and clean-up guides** (kind F): procedures with per-item commands. | The "who has too much access" checks get concrete steps. | M |
| 4 | **Prevention plan and Hardening plan**: ordered, printable, downloadable, per tenant. | One document to work through per tenant; also usable as a client deliverable. | M |
| 5 | *Optional:* **Apply from Clarity365** for Exchange settings on tenants where the app holds Exchange Administrator. One tenant, a confirmation dialog, audit-logged, off by default. | Fewer trips to PowerShell. Needs an explicit decision (see below). | M |
| 6 | **Live check** of each guide on Crimson Line Live Demo; results recorded here. | Guides are proven, not assumed. | runs alongside 1 to 3 |

## Stage 0 record (2026-10-05)

**Format built**
- `src/lib/data/scenario-fix-guides.ts`: the catalogue. A guide has `summary`, `stops`, `prerequisites` (licence, admin role, other), `impact`, `rollout`, `steps(ctx)`, `verify`, `undo`, `learn` (page + date checked) and `missing(ctx)` warnings. Steps are functions of a `FixGuideContext` (tenant id, break-glass accounts with object ids, offending items) so commands carry the tenant's real values. `SHELL_CONNECT` gives the install and connect line per shell (Exchange Online, Security & Compliance, Microsoft Graph with the exact scopes, SharePoint Online).
- `src/lib/services/scenario-fix-guide-builder.ts` (pure): `buildFixGuide(guideId, snapshot)` resolves a guide for one tenant. Break-glass accounts come from `detectLikelyBreakGlassAccounts` and are turned into object ids; when none is found the command keeps a placeholder and the guide warns.
- Checks point at guides with `guideId` on the check definition; the result carries it only while the check isn't green.
- UI: "How to fix" on the check opens `FixGuideModal` (summary, warnings, before you start, who is affected, numbered steps with portal path and copyable connect + run blocks, confirm, undo, Learn links with dates).
- Tests: `scenario-fix-guide-builder.test.ts` (catalogue rules: Learn link and date on every guide, every referenced guide exists, no guide on green checks, CA scripts are report-only; per-guide resolution) and `FixGuideModal.test.ts` (every guide renders for every demo tenant).

**Pilot guides** (one per hard kind), each command checked on Microsoft Learn 2026-10-05:
| Guide | Kind | Used by | Commands |
|---|---|---|---|
| `block-device-code-flow` | A, Conditional Access | device-code users / admins / guests | `New-MgIdentityConditionalAccessPolicy` with `authenticationFlows.transferMethods = "deviceCodeFlow"`, `state = "enabledForReportingButNotEnforced"`, break-glass excluded |
| `disable-smtp-auth-org` | B, Exchange | legacy-mailbox / smtp-auth-org | `Set-TransportConfig -SmtpClientAuthenticationDisabled $true`, per-mailbox `Set-CASMailbox`, verify `Get-TransportConfig` |
| `remove-guest-admin-roles` | F, review | guest-admin / no-guest-admins | per guest: active roles via `Get-`/`Remove-MgRoleManagementDirectoryRoleAssignment`; PIM-eligible via `New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest` (`adminRemove`) |

**Checked against the live data (read-only, local database):** device-code guide offered on 9 tenants; break-glass object ids found on 8 of 10 (dmafrica and Worldwide Advisory Services have none detected, so the guide warns); SMTP AUTH guide offered on 9 (off already on Crimson Line Live Demo). No live tenant has a guest holding a role, so the per-item commands are proven by tests only. **Not yet run by the operator** on Crimson Line Live Demo.

**Learned for the next stages**
- Some guides apply to several checks (one device-code guide for three personas); guides are keyed by fix, not by check.
- Removal of PIM-managed active assignments can fail through `Remove-MgRoleManagementDirectoryRoleAssignment`; the guide says to use PIM in that case. Stage 3 should look at `roleAssignmentScheduleRequests` (`adminRemove`) for active PIM assignments.
- A guide is offered on "not assessed" checks too (for example SMTP AUTH where Exchange isn't connected); the verify command lets the operator check first.

## Stage 1 record (2026-10-05)

**21 guides added** (24 in total), every command checked on Microsoft Learn on 2026-10-05:
- **Exchange Online (6):** `restrict-smtp-auth-mailboxes` (per mailbox, `Set-CASMailbox -SmtpClientAuthenticationDisabled $true`), `disable-pop-imap` (per mailbox + `Set-CASMailboxPlan`), `enable-unified-audit-log` (`Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`, Purview Audit banner), `enable-mailbox-auditing` (`Set-OrganizationConfig -AuditDisabled $false`), `block-external-autoforward-outbound` (`Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off`), `block-autoforward-remote-domain` (`Set-RemoteDomain -Identity Default -AutoForwardEnabled $false`).
- **SharePoint / OneDrive (9):** legacy auth (`-LegacyAuthProtocolsEnabled $false`), sync on domain-joined PCs (`Set-SPOTenantSyncClientRestriction -Enable -DomainGuids`; AD domains only, the guide says so), web-only access on unmanaged devices (`-ConditionalAccessPolicy AllowLimitedAccess`, needs Entra ID P1), organisation sharing level (`-SharingCapability ExternalUserSharingOnly`), per-site (`Set-SPOSite -SharingCapability`), Anyone-link expiry (`-RequireAnonymousLinksExpireInDays 30`, ends with confirm-once), default link type (`-DefaultSharingLinkType Internal`, ends with confirm-once), guest re-share (`-PreventExternalUsersFromResharing $true`), domain allow list (`-SharingDomainRestrictionMode AllowList -SharingAllowedDomainList "a.com b.com"`, space-separated).
- **Entra settings (4):** guest directory access (`Update-MgPolicyAuthorizationPolicy -GuestUserRoleId 2af84b1e-...` Restricted Guest User), guest invites (`-AllowInvitesFrom adminsAndGuestInviters`), user consent (`permissionGrantPoliciesAssigned = managePermissionGrantsForSelf.microsoft-user-default-low`, keeping existing `ManagePermissionGrantsForOwnedResource.*` entries), admin consent workflow (`Invoke-MgGraphRequest PUT /policies/adminConsentRequestPolicy`; Learn shows no dedicated cmdlet example).
- **Alert policies (2):** the two `New-ProtectionAlert` commands moved out of the checks into guides (with verify and undo).

**Builder additions:** per-item sources for SMTP AUTH mailboxes, POP/IMAP mailboxes and Anyone sites; the SharePoint admin URL (`https://<tenant>-admin.sharepoint.com`) is worked out from the synced site URLs and used in the connect line and portal link; names in step text are capped at 20 (commands keep every item).

**Found while checking:** Microsoft has **deprecated** `Set-SPOTenant -RequireAcceptingAccountMatchInvitedAccount` (SharePoint invitations now use Entra B2B). The "Invitations can only be redeemed by the invited account" check was removed from Guest re-share sprawl rather than given a guide for a dead setting.

**Live data (read-only, local database):** 13 to 23 guides offered per tenant; the SharePoint admin URL was worked out on all 10; per-item lists filled in (for example 37 SMTP AUTH and POP/IMAP mailboxes on one tenant, 13 to 250 Anyone sites on six). The 250s are the sync caps. No guide has been run by the operator yet.

## Stage 2 record (2026-10-05)

**16 Conditional Access guides added** (40 in total). Every setting checked on Microsoft Learn on 2026-10-05; built-in authentication strength ids read from a live tenant (MFA `...0002`, passwordless `...0003`, phishing-resistant `...0004`).

**One object, two uses.** Each policy guide has `proposedPolicy(ctx)`: the Microsoft Graph body, built once. The command is written from it (`toPowerShell`, `src/lib/utils/powershell-literal.ts`; `caCreateScript` in the catalogue) and the impact preview replays the tenant's sign-ins against the same body, so the command and the preview can't describe different policies. All are `enabledForReportingButNotEnforced` with break-glass object ids excluded (placeholder + warning when none is found).

**Change from the plan:** baseline policies (CA01, CA02, CA04, CA07, CA08, CA09) do **not** link to the in-app deploy. The user chose "guide only", so they get the same generated report-only command as the rest.

| Guide | Checks | Preview |
|---|---|---|
| `block-foreign-countries` | foreign-country users / admins / guests | yes; creates an "Allowed countries" named location (home country from sign-ins) first, policy excludes it via `$location.Id`; step 1 lists the other countries sign-ins came from |
| `include-unknown-countries` | unknown-country | portal + per-location `Update-MgIdentityConditionalAccessNamedLocation` (items: country locations without unknown) |
| `require-mfa-device-registration` | device-registration | no (user action); also the device setting "Require MFA to register or join devices" = No |
| `require-token-protection` | token-protection | no; beta `New-MgBetaIdentityConditionalAccessPolicy` (new shell `MicrosoftGraphBeta`), admins pilot, EXO/SPO/Teams Services, Windows, desktop clients only |
| `require-compliant-device-admins` | admin-device (x2), desktop, macos | yes |
| `require-compliant-device-desktop` | desktop-blocked | yes; guests excluded |
| `admin-session-limits` | admin-frequency | no (doesn't block); 4 hours + never persistent |
| `require-phishing-resistant-admins` | admin-phishing-resistant (x2) | yes |
| `keep-cae-on` | cae | portal only (beta-only setting); items: policies disabling CAE |
| `require-mfa-guests` | guest-mfa | yes |
| `require-mfa-all-users` | mfa-enforced | yes |
| `block-legacy-auth` | legacy-blocked, ca-legacy | yes |
| `block-authentication-transfer` | auth-transfer | no |
| `protect-security-info-registration` | registration-protected | no; excludes guests, excludes all trusted locations |
| `require-risk-remediation` | user-risk | portal only (Microsoft documents it in the portal only), P2 |
| `protect-sensitive-admin-actions` | protected-actions | portal only: authentication context, then policy **On**, then protected actions (order matters) |

**Impact preview** (`src/lib/services/ca-policy-impact.ts`, see [[CA Simulation Engine]]): replays successful synced sign-ins through `evaluateSignIn` with only the proposed policy, switched on. It reports blocked, asked for more, already met (MFA / phishing-resistant MFA the sign-in already did, from the beta authentication details) and undecided. It also flags challenged sign-ins synced before authentication details were read. The approximations are stated in the modal: every sign-in is treated as Office 365, and only the synced period is covered. Guides whose condition isn't in the data say why instead of showing "no impact".

**Proof test:** `ca-policy-impact.test.ts` takes every demo tenant, removes its policies, adds only the guide's policy (switched on), and asserts that every check the guide is offered on stops being "not prevented". All 12 policy guides pass. Two gaps it found were fixed before commit: the strength name and the beta session controls are now mapped the way the sync maps them (`mapProposedPolicy`).

**Live data (read-only, local database, 11 snapshots):**
- Country allow-list (home country only) would have blocked: dmafrica 763 of 1,889 sign-ins, Axiomatic 360 of 4,604, Coetzee 16, Worldwide Advisory 14. None on Crimson Line, Zubat Nine or Gustav Barkhuysen. The guide lists the other countries to add.
- Compliant device for admins would block admins on every tenant (for example Coetzee 227 sign-ins); phishing-resistant MFA would challenge admins on most (Wauko: 513, with 53 already met).
- MFA for all users: Worldwide Advisory 784 challenged and 2,704 already met; Gustav Barkhuysen 240 challenged.
- Token protection, device registration, authentication transfer and security-info registration correctly show "can't be previewed".
- dmafrica and Worldwide Advisory still have no break-glass account detected, so every CA guide warns there.
- Not yet run by the operator.

## Inventory (all checks)
Kind letters as in the table above. "Stage" is when its guide gets built. Commands are the planned ones; each is checked on Microsoft Learn when its guide is written.

| Scenario | Check | Kind | Planned fix | Stage |
|---|---|---|---|---|
| Sign-in from outside allowed countries | users / admins / guests | A | CA08 (in-app deploy) or a named-location block policy | 2 |
| | unknown-country | A | Named location: include unknown countries/regions (`Update-MgIdentityConditionalAccessNamedLocation`) | 2 |
| | device-registration | A + D | "Register or join devices" user-action policy requiring MFA; device setting "Require MFA to register or join devices" = No | 2 |
| Stolen session token replay | token-protection | A | Token protection session control (report-only, admins first) | 2 |
| | admin-device | A | CA09 scoped to admin roles | 2 |
| | admin-frequency | A | Sign-in frequency + no persistent browser for admin roles | 2 |
| | admin-phishing-resistant | A | Authentication strength "Phishing-resistant MFA" for admin roles | 2 |
| | cae | D | Continuous access evaluation (strict location enforcement) | 2 |
| Guest account holding a directory role | no-guest-admins | F | **pilot** `remove-guest-admin-roles` | 0 |
| | guest-access-level | D | `Update-MgPolicyAuthorizationPolicy -GuestUserRoleId` (most restrictive) | 1 |
| | guest-invites | D | `Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom adminsAndGuestInviters` | 1 |
| | guest-mfa | A | CA04 (in-app deploy) | 2 |
| Password spray on an account without MFA | mfa-registered | F | Registration campaign, Temporary Access Pass, list of unregistered users | 3 |
| | mfa-enforced | A | CA02 (in-app deploy) | 2 |
| | legacy-blocked | A | CA01 (in-app deploy) | 2 |
| | no-individual-exclusions | F | Per policy and account: remove the exclusion | 3 |
| Legacy authentication mailbox access | ca-legacy | A | CA01 | 2 |
| | smtp-auth-org | B | **pilot** `disable-smtp-auth-org` | 0 |
| | smtp-auth-mailboxes | B | `Set-CASMailbox -SmtpClientAuthenticationDisabled $true` per mailbox | 1 |
| | pop-imap | B | `Set-CASMailbox -PopEnabled $false -ImapEnabled $false`, `Set-CASMailboxPlan` | 1 |
| | sharepoint-legacy | C | `Set-SPOTenant -LegacyAuthProtocolsEnabled $false` | 1 |
| Global admin on a non-compliant device | admin-device / desktop / macos | A | CA09 scoped to admins | 2 |
| | no-excluded-ga | F | Remove the GA's individual exclusion (keep break-glass only) | 3 |
| | intune | info | Licence note | 1 |
| Malicious OAuth app consent | user-consent | D | `Update-MgPolicyAuthorizationPolicy` (permission grant policy: verified publishers / low impact) | 1 |
| | admin-workflow | D | Admin consent workflow (`Update-MgPolicyAdminConsentRequestPolicy`) | 1 |
| | risky-grants | F | Review and revoke per grant (`Remove-MgOauth2PermissionGrant`) | 3 |
| | app-registrations | F | Remove critical permissions per app | 3 |
| Device-code phishing | users / admins / guests | A | **pilot** `block-device-code-flow` | 0 |
| | auth-transfer | A | Authentication-transfer block policy | 2 |
| Privilege escalation by role assignment | ga-count | F | Move GAs to least-privileged roles; add a second break-glass | 3 |
| | standing-access | F | Convert to PIM eligible (`New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest`) | 3 |
| | role-assignable-groups | F | Remove non-admin owners | 3 |
| | apps-grant-roles | F | Remove the permission per app | 3 |
| | admin-phishing-resistant | A | as above | 2 |
| MFA tampering after compromise | registration-protected | A | "Register security information" user-action policy | 2 |
| | user-risk | A | CA07 (in-app deploy) | 2 |
| | ual | B | `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true` | 1 |
| Silent tenant: auditing turned off | ual | B | as above | 1 |
| | mailbox-auditing | B | `Set-OrganizationConfig -AuditDisabled $false` | 1 |
| | signin-logs | info | Entra ID P1 + AuditLog.Read.All note | 1 |
| | alerting | E | **done** 2026-10-02 (`New-ProtectionAlert`); to be moved into a guide | 1 |
| Mass user deletion | standing-deleters / pim | F | PIM eligible for the deleting roles | 3 |
| | protected-actions | A | Authentication context + policy + protected actions | 2 |
| | alerting | E | **done**; to be moved into a guide | 1 |
| Mailbox rule exfiltration | no-external-rules | F | Per rule: `Remove-InboxRule` / `Set-Mailbox -ForwardingSmtpAddress $null` | 3 |
| | outbound-policy | B | `Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode Off` | 1 |
| | remote-domain | B | `Set-RemoteDomain Default -AutoForwardEnabled $false` | 1 |
| | mailbox-auditing | B | `Set-OrganizationConfig -AuditDisabled $false` | 1 |
| Transport-rule exfiltration | no-external-rules | F | Per rule: `Disable-TransportRule` / `Remove-TransportRule` | 3 |
| | exchange-admins | F | Reduce standing Exchange / Global Admins | 3 |
| | ual | B | as above | 1 |
| Bulk sync to an unmanaged device | sync-restricted | C | `Set-SPOTenantSyncClientRestriction -Enable -DomainGuids ...` | 1 |
| | desktop-blocked | A | CA09 or app-enforced restrictions | 2 |
| | browser-limited | C | `Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess` | 1 |
| Anyone link on a sensitive site | tenant-level | C | `Set-SPOTenant -SharingCapability ExternalUserSharingOnly` | 1 |
| | sites | C | Per site: `Set-SPOSite -SharingCapability` | 1 |
| | expiry | C | `Set-SPOTenant -RequireAnonymousLinksExpireInDays 30` (+ confirm once) | 1 |
| | default-link | C | `Set-SPOTenant -DefaultSharingLinkType Internal` (+ confirm once) | 1 |
| Guest re-share sprawl | reshare | C | `Set-SPOTenant -PreventExternalUsersFromResharing $true` | 1 |
| | domains | C | `Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList ...` | 1 |
| | ~~invitee-match~~ | - | Removed 2026-10-05: setting deprecated by Microsoft | - |
| | invites | D | as guest-invites | 1 |

Stage 1 therefore covers about 26 guides (B, C, D, the two alert checks moved into guides, and the info notes).

## Known limits to state up front
- Licences decide what is possible: PIM and risk policies need Entra ID P2, device compliance needs Intune, threshold alerts need E5. Guides say so and give the best available alternative.
- Clean-up guides (kind F) can list and script, but the judgement (is this forwarding rule approved?) stays with the operator.
- Some results can't be read back (SharePoint link settings); those end in "confirm once".

Part of [[Clarity365 MOC]]. See also [[Security Scenarios]], [[Security Simulations Plan]], [[Recommendations Plan]].
