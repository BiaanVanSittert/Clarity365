---
tags: [module, conditional-access]
---

# Sign-In Logs & CA Diagnostics

Real-time sign-in log streamer with CA rule-chain inspector, error-code translation, timeframe presets/custom date range, and a KQL generator.

- **Component:** `SignInLogsModule.tsx`
- **Reads:** `TenantSecuritySnapshot.signIns` (prop-driven)
- **Key types:** `SignInEvent`, `TimeRangePreset`, `CustomDateRange` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `Drawer`, `Modal`, `Pagination`
- **Data origin:** [[Core Graph Layer]] (`graph-client.fetchLiveTenantSnapshot`) pulls sign-ins live with failure reasons and report-only evaluation

Part of [[Clarity365 MOC]]. Tightly coupled to [[Conditional Access Policy Scanner]] :  this is where a CA policy's report-only failures actually surface per-user.
