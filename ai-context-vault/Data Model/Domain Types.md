---
tags: [data-model]
---

# Domain Types

`src/lib/types/index.ts`, ~1044 lines. Links back to [[Clarity365 MOC]].

## The hub type

**`TenantSecuritySnapshot`** is a god object :  one full tenant's aggregated state (sign-ins, CA policies, secure score, mailboxes, incidents, groups, SharePoint, etc). Nearly every [[Modules/index|module]] reads or writes a slice of this one type, and [[Services/Tenant Store|Tenant Store]] is what persists it. Any time this type grows, check whether it should split before it does :  see [[Optimization Plan]].

## By domain

| Type | Domain |
|---|---|
| `Tenant` / `TenantCredentials` | Core :  one MSP client org, incl. `authMode: mock\|secret\|certificate`, encrypted `clientSecret`/`exoRefreshToken`. `Tenant.connectionStatus`: `healthy \| degraded \| disconnected \| error` :  render via the shared `getConnectionStatusDisplay()` (`src/lib/utils/tenant-connection-status.ts`), never a one-off ternary - two independent copies of that logic previously drifted apart (see [[Services/Tenant Store\|Tenant Store]]). |
| `CAPolicyRule` / `CABaselineItem` | Conditional Access :  live policy vs. the CA01 to CA10 baseline it should match |
| `SignInEvent` | Sign-in log entry incl. applied CA policies, report-only failure tracking |
| `TenantSecureScore` / `SecureScoreControl` / `SecureScoreControlDeployment` | Microsoft Secure Score, 90-day history, and per-control deployability - see [[Secure Score & Timeline]] for the full field list (live-verified `description`/`actionUrl`/`remediationImpact`/`threats`, and why `userImpact`/`implementationCost` include `"Unknown"` rather than defaulting unclassified controls to `"Moderate"`) and the Auto/Guided/Manual deploy-mapping design |
| `UserMfaProfile` | MFA/auth-strength per user (phishing_resistant / strong / weak / none) |
| `TenantAccountSummary` | Licensed / unlicensed-active (orphan) / disabled / guest classification |
| `MailboxItem` / `MailboxDelegation` | Exchange mailbox + FullAccess/SendAs/SendOnBehalf grants |
| `EmailForwardingRule` / `MailflowTransportRule` / `MailflowConnector` | Forwarding + org-wide transport rule/connector hygiene |
| `DomainAuthStatus` | SPF/DKIM/DMARC per domain :  remediated via raw DNS guidance text, not an API call |
| `MdoThreatPolicy` / `TablEntry` / `MdoThreatAlert` | Defender for Office 365 policies, Tenant Allow/Block List, alerts |
| `SecurityIncidentItem` | Incident Response :  MITRE techniques, impacted users/devices |
| `AppRegistrationItem` | App registrations, high-privilege Graph scopes, expiring creds |
| `IntuneDevice` / `IntunePolicySummary` | Endpoint compliance, AV/EDR/BitLocker onboarding. `IntunePolicySummary.mdeConnectorSettings`/`.onboardingStates`/`.defenderAvPolicy`/`.edrPolicy`/`.bitLockerPolicy` and `Tenant.endpointSecurityWriteMode` are [[Defender Configuration & Onboarding]]'s Phase 1/2 additions - see `MdeConnectorSettings`, `AtpOnboardingDeviceState`, `DefenderAvPolicySettings`, `EdrPolicySettings`, `BitLockerPolicySettings`, `IntuneAssignmentTarget`, `EndpointSecurityWriteMode`, `IntuneCoverageGaps` below. `.clarity365AsrPolicyId` (string, optional) is a later addition - the id of the ASR Settings Catalog policy *this app itself* created via `deployAsrRules`, tracked separately from the merged multi-surface `asrRules` read because that read can legitimately see other policies this app never made (see [[Attack Surface Reduction Rules]]'s update-in-place fix) |
| `MdeConnectorSettings` / `AtpOnboardingDeviceState` | MDE connector's own config + per-device onboarding status - both real Graph data (beta), not mock-only |
| `DefenderAvPolicySettings` | The Defender Antivirus Settings Catalog policy toggles (Real-time protection/Scan/Updates/Exclusions/User experience groups, mirroring Microsoft's own doc) - read/write via [[Defender Configuration & Onboarding]]'s Phase 2. Field->settingDefinitionId map confirmed live against a real tenant's own catalog metadata, not just docs - see that module's note for two ids and one missing field a live check corrected. |
| `EdrPolicySettings` | `{ autoFromConnector?, sampleSharingAll? }` - the Endpoint Detection and Response policy's "Auto from connector" and "Sample Sharing" settings, confirmed live to be real assignable Settings Catalog settings (an earlier claim that they weren't Graph-configurable was wrong) - see [[Defender Configuration & Onboarding]] |
| `BitLockerPolicySettings` / `RECOMMENDED_BITLOCKER_POLICY` | `{ requireDeviceEncryption?, allowStandardUserEncryption?, allowWarningForOtherDiskEncryption?, recoveryPasswordRotation?: "off"\|"entraIdOnly"\|"entraIdAndHybrid" }` - the direct BitLocker CSP category's settings (not the separate Administrative Templates/GPO "BitLocker Drive Encryption" category), confirmed live. The recommended-baseline constant lives here rather than `graph-client.ts` deliberately, since that file is server-only and the UI needs this constant directly - see [[Defender Configuration & Onboarding]] |
| `IntuneAssignmentTarget` | `{ mode: none\|allDevices\|allUsers\|allUsersAndDevices\|group, groupId?, excludeGroupId? }` - the standard Intune assignment shape, shared by the Defender AV, EDR, and ASR rule deploy paths. `allUsersAndDevices` sends both target types in one `assignments` array - added so the UI's picker could offer Microsoft's actual four canonical assignment choices instead of three. |
| `IntuneCoverageGaps` | Licensed users missing from Intune + devices missing EDR/AV coverage - see [[Defender Configuration & Onboarding]] |
| `AsrRuleState` (`AsrRuleMode`) | Per-tenant Attack Surface Reduction rule state (not_configured/audit/warn/block), stored on the snapshot :  see [[Attack Surface Reduction Rules]]. The 19-rule catalog itself (GUIDs, descriptions) lives outside this file, in `asr-rule-definitions.ts`. Phase 2 (deploy) reuses this same type for the write path - no separate "desired mode" type. |
| `AsrRuleActivitySummary` / `AsrDetectionEvent` | On-demand Advanced Hunting detection data for the same module :  deliberately **not** stored on `TenantSecuritySnapshot`, fetched fresh per request |
| `TenantGroup` | Groups incl. `isAssignableToRole` (role-assignable = admin grant) |
| `SharePointSiteItem` / `SharePointTenantPolicy` | Storage + external-sharing tiers |
| `AuditLogEntry` | Mutating-action audit trail |
| `FleetTenantPosture` / `FleetPostureSummary` / `FleetTopFailingBaseline` | Cross-tenant rollup |
| `GoldenBaselineTemplate` / `TenantDriftFinding` / `TenantDriftAssessment` | Golden-baseline drift detection + realignment |
| `LicensedGlobalAdminRisk` | Cross-reference of `UserMfaProfile` (admin role) + `TenantAccountSummary` (license) :  a privileged account with a daily-use license |
| `PrivilegedAccountRecord` | General superset of `LicensedGlobalAdminRisk` :  every admin account (licensed or not), full role list, auth strength, `isUnprotected` |
| `FleetLicenseOptimizationItem` | Cost-waste findings (orphaned/inactive/shared-mailbox/disabled licenses, plus `unassigned_license_sku`: purchased seats nobody's assigned to) |
| `TenantLicenseSku` | Per-SKU purchased-vs-consumed seat counts from `/subscribedSkus` (`consumedUnits`, `enabledUnits`, `availableUnits`) :  what [[Fleet License Optimization]]/[[Tenant License Optimization]] price the unassigned-seat waste from |
| `ExecutiveQbrReport` | QBR generator output (health score, cost savings, achievements) |
| `ComplianceControlItem` / `TenantComplianceAssessment` | CIS M365 v3 / NIST CSF v2 / Essential 8 scoring |
| `UserMfaProfile.adminRoleTemplateIds` | Role template GUIDs from real directory-role membership (Security Simulations Stage 2). Never set for the placeholder "Global Administrator" name the sync infers from the MFA registration report. Active assignments only (not PIM-eligible, not role-assignable-group grants) |
| `ExchangeSecuritySettings` / `CasMailboxProtocols` / `PrivilegedRoleAssignments` / `OAuthConsentGrantSummary` | Security Simulations Stage 5, on the snapshot as `exchangeSecurity`, `privilegedRoleAssignments`, `oauthConsentGrants`. `SharePointTenantPolicy` gained resharing, unmanaged sync, domain restriction, legacy auth, idle sign-out and `linkDefaultsReported`. All optional: undefined = not synced |
| `CaSessionControls` / `CaNamedLocation` / `TenantIdentitySettings` | Added for [[Security Simulations Plan]] Stage 1. `CAPolicyRule` also gained optional `includeGroupIds`, `excludeRoles`, guest types, `userActions`, `authenticationContexts`, `authenticationFlows`, `insiderRiskLevels`, `deviceFilter`, `clientApplications`, `servicePrincipalRiskLevels`, `grantOperator` and `sessionControls`. On the snapshot: `conditionalAccess.namedLocations` and top-level `identitySettings`. All optional: undefined means "not synced yet". |

## Added 2026-10-01 (all optional)
- `SignInEvent.authentication` (`SignInAuthentication`: `requirement`, `methods`, `fromExistingSession`), `userType`, `asn`: from the beta sign-in log. See [[Sign-in Report]].
- `TenantSecuritySnapshot.signInCoverage` (`SignInCoverage`): period the synced sign-ins cover, `complete`, `incompleteReason`, `hasAuthDetails`. Read it through `getSignInCoverage()`.
- `SyncHealth.missingPermissions`: required Graph permissions the app registration didn't have at sync time.
- `TenantCredentials.secretExpiry` (`SecretExpiry`: `expiresAt`, `exact`, `checkedAt`) and `FleetTenantPosture.secretExpiry` (read-only fleet visibility).

## Added 2026-10-02 (all optional)
- `TenantSecuritySnapshot.alertPolicies` (`AlertPolicyInventory`: `policies`, `unavailable`, `detail`, `checkedAt`; `AlertPolicySummary` keeps the watched `operations`, `disabled`, recipient **count**, aggregation). Empty `policies` with `unavailable` set means "couldn't be read", not "none".
- `Tenant.scenarioConfirmations` (`ScenarioConfirmationKey` → `ScenarioConfirmation`: `status`, `confirmedAt`, `note`).

## See also
- [[Baseline Definitions & Mock Data]] :  the 39 baseline rules these types score against
- [[API Surface]] :  every route that reads/writes these types
- [[Services/Tenant Store|Tenant Store]] :  the one service touching almost all of them
