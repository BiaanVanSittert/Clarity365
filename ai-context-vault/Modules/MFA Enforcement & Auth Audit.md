---
tags: [module]
---

# MFA Enforcement & Auth Audit

Per-user MFA/auth-method audit :  flags passkeys/FIDO2 and Authenticator as strong, SMS/Email OTP as weak.

- **Component:** `MfaAuditModule.tsx`
- **Reads:** `TenantSecuritySnapshot.mfaAudit`, `TenantSecuritySnapshot.accountClassification.users` (prop-driven)
- **Key types:** `UserMfaProfile`, `AuthMethodType` :  see [[Domain Types]]
- **Renders:** `EmptyStateRow`
- **Cross-references** `snapshot.accountClassification.users` by UPN for license status, fed into the five-tier risk model below.
- **Data origin:** [[Data Mappers]] (`mfa-classifier`)
- **Exposed to agents via:** [[MCP Server]] `audit_mfa_methods` tool

## Five-tier risk model
Previously a muddy two-shade-of-red system with no legend and no way to tell "somewhat bad" from "critical" apart. Replaced with a pure classifier, `classifyMfaRiskTier()` in `src/lib/utils/mfa-risk-tier.ts` (has a test), used for the row color, the row's posture badge, and the legend/filter chip row all from one source so they can't drift apart:

| Tier | Condition | Color |
|---|---|---|
| `critical` | Privileged (`isAdmin`) with no MFA registered :  overrides every other rule | Deep red, solid filled badge, distinct icon (not just a darker red) |
| `red` | Licensed, no MFA | Light red |
| `orange` | Not licensed, no MFA | Orange |
| `green` | MFA is registered, licensed or not (method strength no longer affects color) | Emerald |
| `disabled` | `accountEnabled === false` (blocked sign-in) | No color/neutral :  excluded from the table and every count by default, brought back via an "Include disabled accounts" checkbox |

The table defaults to sorting by `MFA_RISK_TIER_SEVERITY` (critical first) so the accounts that matter float to the top without a separate sort control. A "Privileged only" checkbox is kept separate from the tier chips, since a privileged account can land in either `critical` or `green` depending on its MFA status.

Part of [[Clarity365 MOC]].
