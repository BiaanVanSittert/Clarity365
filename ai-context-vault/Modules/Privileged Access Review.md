---
tags: [module, security]
---

# Privileged Access Review

Consolidated roster of every account holding an admin directory role :  full role list, auth strength, license exposure, and a least-privilege benchmark, in one place. Added because admin/privilege data was scattered thin across the app with no single view: [[MFA Enforcement & Auth Audit]] had a buried filter showing only the first role per admin, [[User & Account Classification]]'s "Licensed Admins" card only caught the admin+license subset, and the least-privilege count lived only inside [[Compliance Matrix (CIS-NIST-Essential 8)]]'s Essential Eight control.

- **Component:** `PrivilegedAccessModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Key types:** `PrivilegedAccountRecord` :  see [[Domain Types]]
- **Uses service:** [[Data Mappers]] (`admin-hygiene-matcher.getAllPrivilegedAccounts`)
- **Remediation button** reuses the existing `"unprotected_admins"` finding type from `remediation-generator.ts` as-is :  no new remediation logic.
- **Least-privilege card** duplicates `compliance-evaluator.ts`'s `E8.PRIV.1` one-line `adminCount <= 5` check intentionally (avoids a module→compliance-service cross-import) and credits that control in its caption.

## Four-tier risk model
Reuses the same traffic light system as [[MFA Enforcement & Auth Audit]], via `classifyPrivilegedAccessTier()` in `src/lib/utils/privileged-access-risk-tier.ts` (has a test), which imports the `MfaRiskTier` type and `MFA_RISK_TIER_SEVERITY` ordering from `mfa-risk-tier.ts` rather than duplicating them. Every row here is already an admin, so that module's "privileged + no MFA overrides everything" rule collapses to just "no MFA is Critical" :  the remaining axis is `isLicensedForDailyUse` (the account-isolation hygiene concern this module already tracked), not plain license possession the way the MFA module used it. Only four tiers are in use (`disabled`, `critical`, `red`, `green`) :  there's no natural Orange with just these two axes, the same way Yellow ended up unused on the MFA side.

| Tier | Condition | Color |
|---|---|---|
| `critical` | No MFA registered | Deep red, solid filled badge, distinct icon |
| `red` | MFA registered, also holds a daily-use Exchange/Teams license | Light red ("Dual Exposure") |
| `green` | MFA registered, no daily-use license | Emerald ("Secured") |
| `disabled` | `accountEnabled === false` | No color/neutral :  excluded by default, brought back via an "Include disabled accounts" checkbox |

Replaces the old overlapping "Unprotected Admins" / "Licensed for Daily Use" KPI cards and the three-way toggle button group with tier chips that double as the legend and the filter. The Least-Privilege Benchmark card is unchanged :  it's about admin headcount as a whole, not a per-row tier.

**v1 scope note:** only individual human admin accounts (`mfaAudit.isAdmin`). Role-assignable group membership (`TenantGroup.isAssignableToRole`, see [[Groups & Distribution Management]]) and service-principal privilege (`AppRegistrationItem.highPrivilegePermissions`, see [[App Registrations & Connected Services]]) are different privilege surfaces, explicitly deferred :  not correlated with this roster yet.

Part of [[Clarity365 MOC]].
