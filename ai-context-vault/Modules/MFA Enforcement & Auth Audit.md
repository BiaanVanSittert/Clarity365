---
tags: [module]
---

# MFA Enforcement & Auth Audit

Per-user MFA/auth-method audit :  flags passkeys/FIDO2 and Authenticator as strong, SMS/Email OTP as weak.

- **Component:** `MfaAuditModule.tsx`
- **Reads:** `TenantSecuritySnapshot.mfaAudit`, `TenantSecuritySnapshot.accountClassification.users` (prop-driven)
- **Key types:** `UserMfaProfile`, `AuthMethodType` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `EmptyStateRow`
- **Cross-references** `snapshot.accountClassification.users` by UPN to detect accounts that carry paid licenses but have no registered MFA methods (`!user.mfaRegistered`). Matching accounts receive a distinct light red highlight, a `border-l-4 border-l-red-500` accent, a "Licensed · No MFA" tag, and a critical `StatusPill` in both light and dark modes. Also surfaces a dedicated filter tab and counter on the Missing MFA summary card.
- **Data origin:** [[Data Mappers]] (`mfa-classifier`)
- **Exposed to agents via:** [[MCP Server]] `audit_mfa_methods` tool

Part of [[Clarity365 MOC]].
