---
tags: [module]
---

# User & Account Classification

Classifies every account as licensed, unlicensed-active (orphan risk), disabled, or guest — plus a 4th critical lens: **licensed Global Admins** (privileged accounts also carrying a daily-use Exchange/Teams license, a break-glass hygiene anti-pattern).

- **Component:** `UserClassificationModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Key types:** `TenantAccountSummary`, `LicensedGlobalAdminRisk` — see [[Domain Types]]
- **Renders:** `StatusPill`, `EmptyStateRow`
- **Cross-references** `snapshot.mfaAudit` (admin role membership) against `accountClassification.users` (per-user licenses) via [[Data Mappers]]'s `admin-hygiene-matcher.findLicensedGlobalAdmins` — the one place in the codebase that joins those two otherwise-independent per-user arrays. Matching rows get a 4th summary card, a dedicated filter tab, a red row tint with a `border-l-4 border-l-red-500` accent, and a critical `StatusPill` in the Risk Assessment column. On row hover, the red highlight is preserved across both light and dark modes while rendering an alert outline (`outline: 1.5px solid #ef4444`).
- Also shows a lighter-weight "Privileged" tag next to any admin's name (via `admin-hygiene-matcher.getPrivilegedAccountUpns`) when that row isn't already covered by the critical Licensed-Admins pill — closes the gap where a plain admin with no daily-use license was otherwise invisible. The deeper roster (full role list, auth strength, least-privilege benchmark) lives in the dedicated [[Privileged Access Review]] module, not here.

Part of [[Clarity365 MOC]]. Feeds the "orphan risk" figure on the [[Overview Dashboard]] identity matrix, and the seat-waste math in [[Tenant License Optimization]] / [[Fleet License Optimization]]. The licensed-admin check is also enforced fleet-wide as a critical finding in [[Fleet Baseline Drift]] (`SEC-ADMIN-LICENSE`).
