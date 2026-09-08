---
tags: [module]
---

# Defender for Office 365 (MDO) & TABL

Threat policy baseline (MDO01–MDO09) plus an interactive Tenant Allow/Block List (TABL) manager.

- **Component:** `MdoPoliciesModule.tsx`
- **API routes:** `POST /api/tenants/{id}/mdo-fix`, `POST`/`DELETE /api/tenants/{id}/tabl`
- **Key types:** `TablEntry`, `MdoThreatPolicy` — see [[Domain Types]]
- **Renders:** `StatusPill`, `Modal`, `LocalOnlyNotice`
- **Uses services:** [[Baseline Matchers]] (`mdo-baseline-matcher`), [[Data Mappers]] (`mdo-mapper`)
- **Baseline source:** [[Baseline Definitions & Mock Data]] — `MDO_BASELINE_STANDARDS` (9 rules; MDO09 has no auto-fix by design)
- **Exposed to agents via:** [[MCP Server]] `manage_tabl` tool — the only MCP tool with a live write path

Part of [[Clarity365 MOC]]. TABL entries set here are what [[Fleet TABL Sync]] broadcasts across the whole fleet.
