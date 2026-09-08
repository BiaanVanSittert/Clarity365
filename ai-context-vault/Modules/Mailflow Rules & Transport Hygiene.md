---
tags: [module, exchange]
---

# Mailflow Rules & Transport Hygiene

Baseline compliance for org-wide transport rules and connectors (MF01–MF08), with remediation for the subset that's auto-fixable.

- **Component:** `MailflowRulesModule.tsx`
- **API routes:** `POST /api/tenants/{id}/mailflow-baseline-fix`
- **Key types:** `MailflowTransportRule`, `MailflowConnector` — see [[Domain Types]]
- **Renders:** `StatusPill`, `Modal`
- **Uses service:** [[Baseline Matchers]] (`mailflow-baseline-matcher`)
- **Baseline source:** [[Baseline Definitions & Mock Data]] — `MAILFLOW_BASELINE_STANDARDS` (8 rules; MF03/MF05/MF06 are manual-review-only, no auto-fix)

Part of [[Clarity365 MOC]].
