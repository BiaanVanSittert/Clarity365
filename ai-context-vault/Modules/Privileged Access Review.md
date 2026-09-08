---
tags: [module, security]
---

# Privileged Access Review

Consolidated roster of every account holding an admin directory role — full role list, auth strength, license exposure, and a least-privilege benchmark, in one place. Added because admin/privilege data was scattered thin across the app with no single view: [[MFA Enforcement & Auth Audit]] had a buried filter showing only the first role per admin, [[User & Account Classification]]'s "Licensed Admins" card only caught the admin+license subset, and the least-privilege count lived only inside [[Compliance Matrix (CIS-NIST-Essential 8)]]'s Essential Eight control.

- **Component:** `PrivilegedAccessModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Key types:** `PrivilegedAccountRecord` — see [[Domain Types]]
- **Uses service:** [[Data Mappers]] (`admin-hygiene-matcher.getAllPrivilegedAccounts`)
- **Remediation button** reuses the existing `"unprotected_admins"` finding type from `remediation-generator.ts` as-is — no new remediation logic.
- **Least-privilege card** duplicates `compliance-evaluator.ts`'s `E8.PRIV.1` one-line `adminCount <= 5` check intentionally (avoids a module→compliance-service cross-import) and credits that control in its caption.

**v1 scope note:** only individual human admin accounts (`mfaAudit.isAdmin`). Role-assignable group membership (`TenantGroup.isAssignableToRole`, see [[Groups & Distribution Management]]) and service-principal privilege (`AppRegistrationItem.highPrivilegePermissions`, see [[App Registrations & Connected Services]]) are different privilege surfaces, explicitly deferred — not correlated with this roster yet.

Part of [[Clarity365 MOC]].
