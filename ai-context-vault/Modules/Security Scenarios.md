---
tags: [module, simulation]
---

# Security Scenarios

`src/components/modules/SecurityScenariosModule.tsx`, view id `sim_scenarios`, first entry of the sidebar's **Security Simulations** group, with a badge counting red scenarios. Stage 6 of the [[Security Simulations Plan]]. Read-only and tenant-scoped.

## What it does
17 attack scenarios in four sections (Identity & Conditional Access 9, Audit & Detection 3, Exchange & Email 2, SharePoint & Data 3). Each is a list of **checks**, the defensive layers that would stop it, and each check returns prevented / partial / not prevented / not assessed with a detail, the offending items (capped at 12), a fix, a verified Microsoft Learn link, and optionally "Simulate sign-ins" for the persona involved. Each scenario card shows "N checks: X prevented · Y partial · Z not prevented · W not assessed" and its gap count (partial + not prevented).

**Verdict roll-up** (`rollUpVerdict`): red if **any** check is not prevented (a single open path lets the attack through), green only when every check is prevented, orange otherwise (partial or not-assessed checks). Chosen to match the user's "green and red mainly" decision. On live tenants this makes most scenarios red, because checks like token protection and a device-registration policy are rarely in place.

## Logic: `src/lib/services/security-scenarios.ts`
`evaluateScenarios(snapshot)` builds one context: the CA environment, the [[CA Gap Analysis]] result, the account lists, break-glass candidates, and a cached [[Sign-in Situations]] runner. **Checks that are really sign-in questions reuse those** (`fromSituation`, `fromCell`, plus direct engine probes for device registration, security-info registration, unknown countries and authentication transfer), so the three views can't disagree. Non-CA checks read Stage 5 data: Exchange audit and protocol settings, SharePoint security settings, PIM role assignments, OAuth consent grants, identity settings, mail forwarding, transport rules, MDO outbound policies, app registrations.

Not-assessed is used, never green, when: Exchange isn't connected, data wasn't synced, the OAuth permission is missing (names DelegatedPermissionGrant.Read.All), PIM data is unavailable, Graph doesn't report a SharePoint link default, or a check is manual (alert policies for audit changes and mass deletion; Clarity365 can't read alert policies).

The **Anyone link** scenario always shows the user-decided warning that sensitivity labels aren't synced, so every site is checked. It deliberately does **not** use `SharePointSiteItem.isSensitiveDataPresent`, which is a site-name keyword heuristic.

New helper: `src/lib/utils/intune-capability.ts` (`hasIntuneCapability`), recognising both the live `cap-intune` and demo `cap-intune-*` ids.

## Engine changes made in Stage 6 (see [[CA Simulation Engine]])
- **Partial resource coverage.** A policy covering only part of Office 365 (for example SharePoint only) no longer counts as blocking or challenging the whole sign-in; it's reported as `partialCoverage`. Found in Stage 6 testing: Northwind's SharePoint-only compliant-device policy read as "guests from abroad are blocked" while Exchange and Teams stayed open. Sign-in Situations shows these as orange "Partly blocked"; the gap grid doesn't count them as covering a persona.
- **Synthetic users' group membership is complete.** For the hypothetical persona users (scenarios, gap grid), a group missing from the capped synced group list is a definite "no", not "unknown". Found live: a tenant with more groups than the sync fetches read "can't confirm" on almost every tenant-wide question.

Tests: `security-scenarios.test.ts` (catalog, roll-up, demo tenants), `SecurityScenariosModule.test.ts` (render smoke test), `intune-capability.test.ts`.

## Alert checks read automatically, and "confirm once" (2026-10-02)

**Alert policies.** The two "someone is alerted" checks (`silent-tenant.alerting`, `mass-deletion.alerting`) no longer say "Manual check". `alertPolicyCheck()` answers them from `snapshot.alertPolicies`, which the sync reads through Security & Compliance PowerShell (`scc-client.ts`, see [[Core Graph Layer]]). Matching (`alert-policy-mapper.ts`, `findAlertCoverage`) is on the policy's `Operation` only, never its name:

| What was found | Result |
|---|---|
| Enabled policy on the activity that emails someone | Prevented, naming the policy |
| Enabled, but no email recipient (or notifications off) | Partly prevented |
| Only a disabled policy | Not prevented |
| Policies read, none on the activity | Not prevented, with the `New-ProtectionAlert` command and a confirm button (it may be covered in Sentinel) |
| Couldn't be read (not synced, Exchange app access not set up, error) | Not assessed, with a confirm button |

Activities: `Set-AdminAuditLogConfig` for auditing (not `Set-OrganizationConfig`, which is too broad to mean anything), `Delete user` for deletion (case, spacing and Entra's trailing full stop ignored). The deletion check was renamed "User deletion raises an alert": any enabled policy on that activity counts, aggregated or per event.

**Confirm once.** Four checks rest on things Clarity365 can't see: the two alert checks when no policy is found or they can't be read, and SharePoint's Anyone-link expiry and default link type (absent from Graph v1.0 and beta). Each carries a `confirmKey`. The operator records "it's in place" or "not in place" for that one tenant; `applyManualConfirmation()` then turns the check green or red. Stored on the tenant record (`Tenant.scenarioConfirmations`) in Clarity365 only, nothing is sent to Microsoft 365. Valid for 365 days (`scenario-confirmations.ts`), after which it stops counting and the check says so. A confirmation never overrides something Clarity365 read for itself.

**Verified live (read-only, 2026-10-02):** the app's own reader returned 48 to 55 policies on the 3 tenants with Exchange app access (7 to 14 seconds each) and "not set up" on the other 7. No tenant has an audit or deletion alert, so the green path has only been seen on demo data and tests. **Verified against real policies the same day:** the user created both alerts on Crimson Line Live Demo with the commands the checks show. After a sync they are stored as `Operation: ["Set-AdminAuditLogConfig"]` and `["Delete user."]`, both checks read Prevented, and the "Silent tenant" scenario is fully green.

Demo tenants cover each outcome: Woodgrove (both alerting), Contoso (no recipient / switched off), Northwind (none), Fabrikam (not set up).

## How to fix guides (2026-10-05)
Checks can point at a guide (`guideId` on the check definition; carried on the result only while the check isn't green). "How to fix" opens `FixGuideModal` with the portal path, copyable commands filled in with this tenant's values, confirm and undo steps. Guides only: Clarity365 never makes the change. Pilots: device code flow, SMTP AUTH, guest admin roles. See [[Scenario Fix Guides Plan]].

**2026-10-05, Stage 1 guides:** 24 checks across Exchange, SharePoint, Entra settings and alerts now have "How to fix" guides. The alert checks no longer carry the `New-ProtectionAlert` command themselves; it is in their guides. The Guest re-share sprawl check "Invitations can only be redeemed by the invited account" was **removed**: Microsoft deprecated `RequireAcceptingAccountMatchInvitedAccount` when SharePoint moved to Entra B2B invitations.

Part of [[Clarity365 MOC]].
