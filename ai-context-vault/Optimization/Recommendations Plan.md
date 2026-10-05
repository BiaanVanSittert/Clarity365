---
tags: [optimization, plan, recommendation]
---

# Recommendations Plan

Status: **in progress.** Built 2026-10-01: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1 and 3.2.1 (see Progress below). Everything else is still a recommendation. Everything listed was observed while building Security Simulations and Exchange app-only access (2026-09-29 to 2026-10-01), mostly from read-only checks against the 10 live tenants; each item says what the evidence is. Sizes: **S** under an hour, **M** a few hours, **L** a day or more.

Scope reminder: every action stays scoped to one tenant; fleet views are read-only (see memory "no cross-tenant actions").

## Progress (2026-10-01)

All of this needs **one sync per tenant** (after restarting the server) to take effect; sync schema version is now 4.

- **1.1 + 1.2 done.** One permission list, `src/lib/data/graph-permissions.ts` (`GRAPH_PERMISSIONS`), read by the onboarding checklist, the Permissions check and the sync. Three permissions added as **required** (all read-only): `SecurityIncident.Read.All`, `DeviceManagementServiceConfig.Read.All` (names confirmed on Microsoft Learn) and `Application.Read.All`. The sync now compares its errors with the permissions the access token actually carries (`sync-permission-errors.ts`): a refused step whose required permission is missing becomes one plain line ("not synced - the X permission isn't granted..."), a declined optional permission is not an error, and everything else passes through. `syncHealth.missingPermissions` lists what to grant; the header shows "N permissions missing" and opens the Permissions check. **Tenants stay "degraded" until the missing permissions are granted** - that is now accurate rather than unexplained. Read-only check on the live data: all 10 tenants lack the first two, 2 lack `Application.Read.All`.
- **1.3 done.** Sign-ins are fetched for an explicit 30-day window with a 90-second page timeout (a live read took 29s for 63 rows on v1.0 and 41s on beta, which is why 30s timed out). Reaching the 20-page limit is no longer a sync error; instead `signInCoverage` records the period really covered, shown in [[Sign-In Logs & CA Diagnostics]], in [[Sign-in Situations]]' evidence line and on the report. `getSignInCoverage()` also works on older snapshots.
- **1.4 done.** Directory roles: one retry, then the same user → roles map is rebuilt from `roleManagement/directory/roleAssignments?$expand=roleDefinition` (`buildAdminRoleMapsFromRoleAssignments`). Checked live: same principals and roles as `directoryRoles`, plus two implicit Microsoft roles on a non-user principal, which are harmless.
- **1.5 done.** The placeholder is now "Administrator (role not confirmed)" (`UNCONFIRMED_ADMIN_ROLE_LABEL`), never a real role name.
- **3.1 done.** See [[Sign-in Report]].
- **3.2.1 done.** The sync finds Clarity365's own app registration and records when the secret in use expires (`credentials.secretExpiry`, matched by the secret's 3-character hint; `credential-expiry.ts`). Warning 30 days ahead in the header, the fleet table (read-only) and the Permissions check. Checked live on one tenant (exact match). Needs `Application.Read.All`.

- **Sync all tenants** (added on request): a button on the fleet overview that syncs every live tenant one at a time on the server, with progress and Stop. See [[Security Infra]] (`sync-all.ts`).

- **Security Incidents page size (found and fixed 2026-10-02).** Once `SecurityIncident.Read.All` was granted, the step failed with "The limit of '50' for Top query has been exceeded": the query used `$top=100`. Now `$top=50`; checked live on the two tenants that have the permission. It was hidden until then by the missing-permission error.

**New findings from this work**
- **Busy tenants: 5,000 sign-ins is only a few days.** Live: 3 days on the largest tenant, 10 and 13 days on two others. The report says so, but can't cover a month there. Raising the limit means a slimmer stored record (a sign-in is roughly 1 KB and the whole snapshot is sent to the browser) or a separate on-demand fetch for the report.
- **The sign-in log endpoint is slow** (29 to 41 seconds for one small page). Sync time for sign-ins on a busy tenant is now bounded by 20 pages x up to 90s.
- **Beta dependency.** MFA details come only from Microsoft's beta sign-in log; if beta refuses, the sync falls back to v1.0 and the report says the MFA method isn't available.

## Alert policies can be read without sign-in (test 2026-10-02; **built the same day**, see [[Security Scenarios]])

Question: can the two "Someone is alerted if ..." checks in [[Security Scenarios]] (auditing changed, bulk user deletion) be automated instead of "Manual check"? Read-only test, `Get-ProtectionAlert` only.

- **Works.** Security & Compliance PowerShell's REST endpoint accepts an app-only token from the **client secret** (scope `https://ps.compliance.protection.outlook.com/.default`). The token carried `Exchange.ManageAsApp` and the Global Reader role on every tenant that already has Exchange app access; nothing extra was granted. Read 48 to 55 alert policies on 3 of 3 such tenants, in two regions.
- **Routing matters.** The global host fails ("Could not find the organization container"). First POST to `ps.compliance.protection.outlook.com/adminapi/beta/{tenantId}/InvokeCommand` with header `X-AnchorMailbox: UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@<initial onmicrosoft domain>` (the tenant GUID in the anchor does not work); it answers 302 to `<region>.admin.protection.outlook.com:446`, which is not reachable. Take `<region>` (seen: zaf01b, eur01b, eur02b, eur03b) and call `https://<region>.ps.compliance.protection.outlook.com/adminapi/beta/{tenantId}/InvokeCommand`. Region discovery worked on all 10 tenants. This mapping is observed, not documented.
- **The 7 tenants without Exchange app access get 401.** Same prerequisite as [[Exchange App-Only Access Plan]].
- **Fields returned:** `Name`, `Operation` (array; the audit-log activity name, per Microsoft Learn's New-ProtectionAlert), `Disabled`, `IsSystemRule`, `NotifyUser`, `NotificationEnabled`, `AggregationType`, `Threshold`, `TimeWindow`, `Severity`, `Category`, `Filter`.
- **No tenant has an alert for audit changes or user deletion.** Custom policies found were DLP, forwarding, sending limit, Exchange privilege and quarantine release. So the matching rule (enabled policy whose `Operation` is `Set-AdminAuditLogConfig`, or `Delete user`) rests on the documentation only; it has not been seen against a real policy.
- **Not reachable this way:** Sentinel or third-party SIEM rules; SharePoint default link type and Anyone-link expiry (absent from Graph v1.0 and beta, confirmed on Microsoft Learn).

## 1. Fix first: things that are wrong today

| # | Problem | Evidence | Fix | Size |
|---|---|---|---|---|
| 1.1 | **Every live tenant is permanently "degraded".** | 10 of 10 tenants carry the same two sync errors: *Security Incidents* needs `SecurityIncident.Read.All`, *MDE connector settings* needs `DeviceManagementServiceConfig.Read.All`. Neither permission is in the onboarding list or the Permissions check, so nobody is ever told to grant them, and the health badge can never turn green. | Add both to the Permissions check and the onboarding list (decide: required or optional). Stop counting a missing **optional** permission as a sync error (the OAuth-grants handling from Stage 5 is the pattern). | S |
| 1.2 | **Two permission lists that can drift.** | `AddTenantModal`'s `REQUIRED_GRAPH_PERMISSIONS` and `graph-client.ts`'s self-test list are maintained separately; 1.1 is what drift looks like. `Application.Read.All` (App Registrations step; failed on 1 tenant) is in neither as required. | One shared permission catalogue (name, required/optional, what it's for) that the onboarding checklist, the Permissions check and the sync's error handling all read. | M |
| 1.3 | **Sign-in logs are incomplete on 4 of 10 tenants.** | "Request timed out after 30000ms" or "Stopped after 20 pages (safety cap)". Sign-In Logs, Sign-in Situations' evidence, and any report built on sign-ins silently cover less than they appear to. | Fetch by time window (e.g. last 7 / 30 days with `$filter` on `createdDateTime`), longer timeout for this call, and show "covers <from> to <to>" wherever sign-ins are used. | M |
| 1.4 | **Directory roles fail intermittently.** | 3 of 10 tenants: "Encountered an internal server error" on `directoryRoles?$expand=members`. When it fails there are no role ids, so admins fall back to the placeholder role below and [[Sign-in Situations]] marks them "inferred". | Retry once; on failure fall back to `roleManagement/directory/roleAssignments` (already fetched in sync step 24) to build the same user → roles map. | S |
| 1.5 | **A made-up "Global Administrator" label.** | When only the MFA registration report says a user is an admin, the sync writes `adminRoles: ["Global Administrator"]`. [[Privileged Access Review]] and [[MFA Enforcement & Auth Audit]] show it as fact. Security Simulations already ignores it (uses template ids). | Label it "Administrator (role unknown)" instead, or leave roles empty and flag the account for review. | S |
| 1.6 | **SharePoint link settings shown as real when they aren't.** | v1.0 `sharepointSettings` has no default link type or Anyone-link expiry, so every live tenant shows "Internal" / "0 days". Now flagged by `linkDefaultsReported: false`, but [[SharePoint & Storage Policies]] and its baseline still present and score the placeholders. | Show "not reported by Microsoft" in the module and mark the affected baseline checks not assessed; check whether the beta endpoint exposes them. | S |
| 1.7 | **"Sensitive data present" is a site-name guess.** | `SharePointSiteItem.isSensitiveDataPresent` is a keyword heuristic ("Finance" in the name), shown as Yes/No in the SharePoint module and used by baseline check SP-sensitive. | Rename in the UI to "Name suggests sensitive data" until real sensitivity labels are synced ([[Sensitivity Labels Catalog Plan]]). | S |
| 1.8 | **Silent caps.** | Groups (3 tenants) and SharePoint sites (2 tenants) stop at 250; mailboxes and CAS mailboxes at 250. The engine now handles a missing group honestly, but the modules don't say results are partial. | Show "first 250 of N" in each affected module; raise the cap or page properly where the per-item calls allow. | M |

## 2. Verify: built, not yet proven live

| # | What | How to verify |
|---|---|---|
| 2.1 | **PIM role data** (Stage 5 fix: `$expand` removed). On the first sync every tenant fell back to the non-PIM list. | Sync a tenant with Entra ID P2; `privilegedRoleAssignments.source` should be `pim`. If not, `pimUnavailableReason` now says why. |
| 2.2 | **Exchange changes without sign-in.** Reads are proven; writes under **Exchange Administrator** aren't. | Assign Exchange Administrator to one tenant's app, turn on the write switch, add and remove a test Allow/Block List entry. |
| 2.3 | **OAuth consent check.** Needs `DelegatedPermissionGrant.Read.All` granted. | Grant it on one tenant, sync, open [[Security Scenarios]] → Malicious OAuth app consent. |
| 2.4 | **Overwrite guard in practice.** No "sync skipped" audit entry has been seen yet. | Leave an old server running across a schema bump (next time the sync shape changes) and check the audit log. |

## 3. Recommended features

### 3.1 Sign-in report download (requested)
A short, client-ready report built from the synced sign-in logs, plus the data behind it.

**What it would show** (for a chosen period and optional user / country filter):
- **Summary:** total sign-ins, successes, failures, blocked by Conditional Access, distinct users, countries and IP addresses, and the period actually covered.
- **By country:** sign-ins, users, success / failure, with countries outside the tenant's allowed list highlighted (uses named locations from Stage 1).
- **By IP address:** top addresses with country, users seen, and whether the address is inside a trusted named location.
- **By user:** sign-ins, countries, IP addresses, MFA methods used, failures, risky sign-ins, last sign-in.
- **By MFA method:** Authenticator push / passkey / SMS / phone call and so on, and **single-factor successes** (sign-ins that got in without MFA).
- **By app and client:** which apps were signed in to, and any **legacy protocol** sign-ins.
- **By device:** managed / compliant vs unmanaged, by operating system.
- **Worth a look:** successful single-factor sign-ins, legacy-auth successes, sign-ins from outside the allowed countries, a user appearing in two countries within a short time, a user's first sign-in from a new country, repeated failures followed by a success.

**Format:** a "Download report" button in [[Sign-In Logs & CA Diagnostics]] opening a printable one- to two-page summary (the existing report-preview pattern, print to PDF), and a "Download data" CSV for each table. No new library needed.

**What it needs first:**
- **MFA details aren't synced today.** The sign-in sync keeps status, location, client app, device, risk and CA results, but not *how* the user authenticated. Add the sign-in's authentication requirement (single- vs multi-factor) and the method used. These fields are on Microsoft's **beta** sign-in resource (`authenticationDetails`, `authenticationRequirement`); **confirm on Microsoft Learn before building**, and fall back to "MFA satisfied: yes / no / unknown" from the CA results if they aren't available.
- Item 1.3 (complete sign-in windows), or the report would understate activity on busy tenants.
- No new permission: `AuditLog.Read.All` already covers it.

Size: **M** for the data + summary, **+S** for the "worth a look" rules. Pure functions (aggregations) with tests, like the other analyzers.

### 3.2 Other features, in suggested order

| # | Feature | Why | Size |
|---|---|---|---|
| 3.2.1 | **Credential expiry warnings.** Show when each tenant's client secret (and later certificate) expires, 30 days ahead, in the header, the Permissions check and Fleet Posture. | When a secret expires every module for that tenant stops, and with Exchange now on the secret too it matters more. Needs the app's own credential list (`Application.Read.All`, already used by App Registrations). | S-M |
| 3.2.2 | **Security Simulations report for clients.** One PDF per tenant: CA score, the persona grid, red scenarios with their fixes. | The three screens are built for an engineer; clients need a page they can read. Reuses the executive report pattern. | M |
| 3.2.3 | **Score history.** Store the CA score and scenario counts at each sync; show the trend and add it to [[Executive Reporting (QBR)]]. | "We went from 4/10 to 8/10" is the point of the exercise, and nothing records it today. | M |
| 3.2.4 | **Scenario strictness: core vs hardening.** Mark each scenario check as core or hardening; red only when a core check fails. | With "red if any check fails", 10 to 16 of 17 scenarios are red on real tenants, largely from checks few tenants pass (token protection, protected actions). | S |
| 3.2.5 | **Fix scripts from findings.** "Copy PowerShell" on each scenario / gap fix, using the existing remediation generator. | Turns a finding into an action without leaving the screen. Read-only on Clarity365's side; the operator runs it. | M |
| 3.2.6 | **Fleet read-only overview.** One table: tenant, CA score, red scenarios, Exchange access mode, credential expiry. | Shows where to spend time across clients. Read-only, per the no-cross-tenant-actions rule. | M |
| 3.2.7 | **Break-glass monitoring.** List the accounts flagged as likely break-glass and their recent sign-ins; flag any use. | Microsoft's guidance is to alert on every use; today the accounts are only detected. | S |
| 3.2.8 | **Trusted location suggestions.** Propose office IP ranges from the most common successful sign-in addresses. | Only 1 of 10 tenants defines trusted locations, so "known location" situations can't be assessed elsewhere. | S |
| 3.2.9 | **Exchange certificate upgrade** (Phase 1 of [[Exchange App-Only Access Plan]]). | Moves Exchange onto Microsoft's documented method; optional while the secret path works. | M |
| 3.2.10 | Stage 7 leftovers from [[Security Simulations Plan]]: MCP tools (`simulate_signin`, `get_ca_gap_analysis`), live Microsoft "What If" cross-check. | Nice to have. | S-M each |

## 4. Housekeeping (lower urgency, real risk)

| # | Item | Note | Size |
|---|---|---|---|
| 4.1 | **Next.js 14 security advisories** (5 high in `npm audit`, already in [[Optimization Plan]] P0). | Needs a planned 14 → 15/16 upgrade; lower stakes while the app is localhost-only. | L |
| 4.2 | **Token-refresh retry for the sync.** `withFreshTokenOnLifetimeError` covers 5 functions, not the ~25 calls in `fetchLiveTenantSnapshot`. | Same failure can hit any of them. | M |
| 4.3 | **One builder for locally-written CA policies.** The same payload is copied in `tenant-store.ts`, `drift-analyzer.ts`, `fleet-operations.ts`, in the marker dialect the engine has to translate. | Copied-literal bug class; write live-shaped policies from one function. | S |
| 4.4 | **Snapshot migrations.** New required fields still crash on old snapshots unless each consumer defends itself; the schema version now exists to hang a migration step on. | Add a small "upgrade snapshot from version N" step in `backfillSnapshot()`. | M |
| 4.5 | **Sidebar does the heavy analysis twice.** `analyzeCaGaps` and `evaluateScenarios` (which runs the gap analysis again) both run in the sidebar for badges. | Compute once per snapshot and share. | S |
| 4.6 | **Licence detection by SKU name.** Developer E5 tenants read as unlicensed; service plans are discarded (already in [[Optimization Plan]]). | Use `servicePlans`. | M |
| 4.7 | **Tests for the riskiest files**: `auth.ts`, `fleet-operations.ts`, the sync orchestration (already in [[Optimization Plan]] P1). The render smoke-test pattern is now available for modules. | | M-L |
| 4.8 | **Vault counts are stale** (module / route / line counts in the MOC and hub notes). | Refresh in one pass. | S |

## Suggested order
1. ~~1.1 and 1.2~~ done 2026-10-01.
2. ~~1.3, 1.4, 1.5~~ done 2026-10-01.
3. ~~3.1 sign-in report~~ done 2026-10-01.
4. ~~3.2.1 credential expiry~~ done 2026-10-01. **2.x verifications** still open (they need tenant-side changes).
5. Next by appetite: 1.6 to 1.8, a 30-day sign-in window for busy tenants (see new findings), 3.2.2 onwards; **4.1** as its own planned upgrade.

Part of [[Clarity365 MOC]]. See also [[Optimization Plan]], [[Security Simulations Plan]], [[Exchange App-Only Access Plan]].
