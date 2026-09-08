---
tags: [data-model]
---

# Domain Types

`src/lib/types/index.ts`, ~1044 lines. Links back to [[Clarity365 MOC]].

## The hub type

**`TenantSecuritySnapshot`** is a god object — one full tenant's aggregated state (sign-ins, CA policies, secure score, mailboxes, incidents, groups, SharePoint, etc). Nearly every [[Modules/index|module]] reads or writes a slice of this one type, and [[Services/Tenant Store|Tenant Store]] is what persists it. Any time this type grows, check whether it should split before it does — see [[Optimization Plan]].

## By domain

| Type | Domain |
|---|---|
| `Tenant` / `TenantCredentials` | Core — one MSP client org, incl. `authMode: mock\|secret\|certificate`, encrypted `clientSecret`/`exoRefreshToken` |
| `CAPolicyRule` / `CABaselineItem` | Conditional Access — live policy vs. the CA01–CA10 baseline it should match |
| `SignInEvent` | Sign-in log entry incl. applied CA policies, report-only failure tracking |
| `TenantSecureScore` / `SecureScoreControl` | Microsoft Secure Score, 90-day history |
| `UserMfaProfile` | MFA/auth-strength per user (phishing_resistant / strong / weak / none) |
| `TenantAccountSummary` | Licensed / unlicensed-active (orphan) / disabled / guest classification |
| `MailboxItem` / `MailboxDelegation` | Exchange mailbox + FullAccess/SendAs/SendOnBehalf grants |
| `EmailForwardingRule` / `MailflowTransportRule` / `MailflowConnector` | Forwarding + org-wide transport rule/connector hygiene |
| `DomainAuthStatus` | SPF/DKIM/DMARC per domain — remediated via raw DNS guidance text, not an API call |
| `MdoThreatPolicy` / `TablEntry` / `MdoThreatAlert` | Defender for Office 365 policies, Tenant Allow/Block List, alerts |
| `SecurityIncidentItem` | Incident Response — MITRE techniques, impacted users/devices |
| `AppRegistrationItem` | App registrations, high-privilege Graph scopes, expiring creds |
| `IntuneDevice` / `IntunePolicySummary` | Endpoint compliance, AV/EDR onboarding |
| `TenantGroup` | Groups incl. `isAssignableToRole` (role-assignable = admin grant) |
| `SharePointSiteItem` / `SharePointTenantPolicy` | Storage + external-sharing tiers |
| `AuditLogEntry` | Mutating-action audit trail |
| `FleetTenantPosture` / `FleetPostureSummary` / `FleetTopFailingBaseline` | Cross-tenant rollup |
| `GoldenBaselineTemplate` / `TenantDriftFinding` / `TenantDriftAssessment` | Golden-baseline drift detection + realignment |
| `LicensedGlobalAdminRisk` | Cross-reference of `UserMfaProfile` (admin role) + `TenantAccountSummary` (license) — a privileged account with a daily-use license |
| `PrivilegedAccountRecord` | General superset of `LicensedGlobalAdminRisk` — every admin account (licensed or not), full role list, auth strength, `isUnprotected` |
| `FleetLicenseOptimizationItem` | Cost-waste findings (orphaned/inactive/shared-mailbox licenses) |
| `ExecutiveQbrReport` | QBR generator output (health score, cost savings, achievements) |
| `ComplianceControlItem` / `TenantComplianceAssessment` | CIS M365 v3 / NIST CSF v2 / Essential 8 scoring |

## See also
- [[Baseline Definitions & Mock Data]] — the 39 baseline rules these types score against
- [[API Surface]] — every route that reads/writes these types
- [[Services/Tenant Store|Tenant Store]] — the one service touching almost all of them
