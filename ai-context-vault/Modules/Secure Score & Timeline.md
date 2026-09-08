---
tags: [module]
---

# Secure Score & Timeline

Microsoft Secure Score card with 30/90-day deltas, benchmark comparison, and a historical trajectory + categorized improvement actions.

- **Component:** `SecureScoreModule.tsx`
- **Reads:** `TenantSecuritySnapshot.secureScore` (prop-driven)
- **Key types:** `TenantSecureScore`, `SecureScoreControl` — see [[Domain Types]]
- **Renders:** `StatusPill`, `EmptyStateRow`, `useTheme`
- **Data origin:** [[Data Mappers]] (`secure-score-mapper`), populated via [[Core Graph Layer]]
- **Exposed to agents via:** [[MCP Server]] `get_tenant_secure_score` tool

Part of [[Clarity365 MOC]]. Also summarized on the [[Overview Dashboard]] as one of the "Top 6 Priority Widgets."
