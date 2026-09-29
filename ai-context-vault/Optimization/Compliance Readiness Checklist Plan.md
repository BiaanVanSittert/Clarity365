---
tags: [optimization, plan, data-protection, compliance]
---

# Compliance Readiness Checklist — Plan

Status: **planning only, no code written** (drafted 2026-09-22). Grew directly out of [[DLP & Sensitivity Labels Plan]] - the user asked whether DLP alone is enough to tell a client they're POPIA/GDPR/HIPAA compliant. It isn't. This plan is for the feature that closes that gap honestly. Part of [[Optimization Plan]] and [[Clarity365 MOC]].

## The problem, restated precisely
POPIA, GDPR and HIPAA each require two genuinely different kinds of things:
1. **Technical safeguards** - Clarity365 already computes most of this across many modules, not just DLP (see below).
2. **Organizational and legal requirements** - appointed roles, contracts, documented policies, training, rights-fulfillment processes. No security tool can verify these exist; only a human can attest to them.

Right now, nothing in the app gives a combined picture of both. [[Compliance Matrix (CIS-NIST-Essential 8)]] scores three *technical* frameworks. The DLP catalog gives *technical* recommendations for three *privacy* regulations. Neither says "is this client actually ready," because that question needs the organizational half too.

## Research

### Codebase findings
- `compliance-evaluator.ts`'s `ControlDefinition` pattern (used by Compliance Matrix) is **100% computed from `TenantSecuritySnapshot`** - every control has an `evaluator: (snapshot) => {...}` function. There is no manual-attestation mechanism anywhere in this codebase today. This feature needs a new one.
- **Reusable persistence precedent found**: `Tenant.endpointSecurityWriteMode?: "read_only" | "write_enabled"` (see [[Defender Configuration & Onboarding]]) is an optional field added to `Tenant` with no migration, persisted through the **already-existing generic `PUT /api/tenants/{id}` route** (`tenant-store.ts`'s `updateTenant(id, updates: Partial<Tenant>)`, which already does a partial merge). A new `Tenant.complianceAttestations` field can follow this exact pattern - **no new API route needed**.
- Browser `localStorage` (the pattern `Sidebar.tsx`'s dismissed-alert state uses) is **not appropriate** for attestation data - that's a per-viewer convenience; attestation is a real, shared business fact about the client that must survive across browsers and sessions. This needs real server-side persistence, matching the guidance that state which must persist reliably or be shared between viewers belongs in the actual data layer, not browser storage.
- `ComplianceFramework` (`"cis_m365_v3" | "nist_csf_v2" | "essential_eight"`) does not include POPIA/GDPR/HIPAA and deliberately **should not be extended to include them** - those three are pure technical frameworks with no attestation concept; conflating them with a hybrid technical+organizational regulation model would muddy what the type means. Keep this a parallel, separate concept.

### Regulatory facts verified against real sources (not asserted from memory this time)
Several of these correct or sharpen what I said in the previous conversation:

1. **Correction: Microsoft's HIPAA BAA is not something a client "gets signed."** It's included by default in the Microsoft Products and Services Data Protection Addendum for eligible customers - not a separate document requiring an active signing step. The correct checklist item is "confirm and download the BAA/DPA from the Service Trust Portal for the client's compliance records," not "get Microsoft to sign a BAA." ([Microsoft Learn Q&A](https://learn.microsoft.com/en-us/answers/questions/5811334/how-to-sign-a-business-associate-agreement-and-add), [accountableHQ](https://www.accountablehq.com/post/microsoft-hipaa-baa-covered-services-requirements-and-how-to-sign))
2. **POPIA Information Officer registration is mandatory** under s.55(2), done via the Information Regulator's own eServices portal (`eservices.inforegulator.org.za`), free, roughly 30 minutes. A concrete, checkable, source-linked item - and the regulator itself estimates millions of organizations haven't done it. ([Lexology](https://www.lexology.com/library/detail.aspx?g=a7cabf11-5ea0-49c3-b72f-fd388a7b46ba), [ClearComply](https://www.clearcomply.co.za/blog/popia-information-officer-registration-south-africa))
3. **POPIA ss.20-21 require a written contract with every operator** (payroll processor, IT support vendor, cloud provider, anyone processing data on the client's behalf) establishing the s.19 security measures and a breach-notification duty. Critically: **without a written contract, the responsible party (the client) remains accountable for the operator's own non-compliance.** High-value, concrete, and commonly missed. ([Fasken](https://www.fasken.com/en/knowledge/2023/09/beware-of-the-operator-contract-a-necessity-for-popia-compliance), [popia.co.za s.21](https://popia.co.za/section-21-security-measures-regarding-information-processed-by-operator/))
4. **GDPR Art. 30's <250-employee Records of Processing Activities exemption is real but narrow in practice.** All three conditions must hold simultaneously: processing isn't regular, no special-category data, no risk to data subjects' rights. Ordinary payroll/HR data processing alone is "regular," which disqualifies almost every real business regardless of headcount. Don't let a small client believe size alone exempts them. ([Privado](https://www.privado.ai/post/gdpr-article-30), [DPO Consulting](https://www.dpo-consulting.com/blog/gdpr-article-30-guide))
5. **GDPR Art. 37 DPO appointment is mandatory only for**: public authorities, large-scale systematic monitoring as a core activity, or large-scale special-category/criminal-data processing as a core activity. "Large-scale" has no fixed numeric definition. For most SME clients this genuinely won't apply - worth saying so plainly rather than over-scoping the checklist into something that scares a small client unnecessarily. ([Clym](https://www.clym.io/blog/data-protection-officer-dpo-requirements), [ISMS.online](https://www.isms.online/general-data-protection-regulation-gdpr/gdpr-article-37-compliance/))
6. **HIPAA's "addressable" specifications are not optional.** The entity must implement the addressable specification, implement an equivalent alternative, or document in writing why neither is reasonable - silence isn't a valid choice. Worth tagging each HIPAA technical item with required/addressable so a client doesn't assume "addressable" means "skip it." ([HHS.gov FAQ](https://www.hhs.gov/hipaa/for-professionals/faq/what-is-the-difference-between-addressable-and-required-implementation-specifications/index.html), [Compliancy Group](https://compliancy-group.com/hipaa-implementation-specifications/))

**Standing caveat, unchanged from every other citation in this codebase**: this is a technical-to-legal mapping for engineering purposes, verified against public secondary sources (not primary statute text or legal counsel), not legal advice. Every citation here should be confirmed by whoever owns compliance for a given client before it's presented to that client as authoritative.

## Design

### Two tiers, not one list
- **Tier 1 - Auto-computed.** Reuses signals the app already has: CA baseline coverage, MFA enforcement rate, audit logging status, DLP catalog adoption (from the work already shipped), Secure Score. Zero new data entry.
- **Tier 2 - Manual attestation.** Organizational/legal items a human must confirm: "has an Information Officer been registered," "is there a written operator agreement with this vendor," "has the BAA/DPA been downloaded for records." Clarity365 tracks **whether it's attested**, never **whether it's legally sufficient** - same non-legal-advice framing used throughout the DLP catalog.

### Data model
- New file `src/lib/data/compliance-readiness-checklist.ts`: a catalog per regulation, each item either `kind: "auto"` (references an existing computed signal) or `kind: "manual"` (needs attestation), with a `citation` field (statute reference + one-line explanation, in the same `RegulationReference` shape the DLP catalog already uses) and a `sourceUrl` where the research above grounds it.
- New optional field on `Tenant`: `complianceAttestations?: Record<string, { attested: boolean; attestedAt?: string; attestedBy?: string; note?: string }>`, keyed by checklist item id. Follows the `endpointSecurityWriteMode` precedent exactly - optional, no migration, persisted through the existing `PUT /api/tenants/{id}` route. **No new API route.**
- A new pure function `evaluateComplianceReadiness(snapshot, tenant, regulation)` in `compliance-readiness-evaluator.ts`, mirroring `compliance-evaluator.ts`'s shape, merging Tier 1's computed results with Tier 2's attestation state into one combined score and item list. Tested, following the `getTierEligibility()` convention of never silently defaulting an unconfirmed item to "compliant."

### Draft content (to review, not final)
**POPIA** - auto: CA baseline coverage, MFA enforcement, audit logging enabled, DLP catalog: POPIA-tagged recommendations adopted. Manual: Information Officer registered with the Information Regulator (s.55(2)); written operator agreements in place for all third-party processors (ss.20-21); PAIA manual published; data subject request process documented (ss.23-25); retention/disposal policy documented; direct marketing consent mechanism in place if applicable (s.69); breach notification procedure reaches the Information Regulator, not just internal alerting (s.22).

**GDPR/UK GDPR** - auto: same technical signals, plus DLP catalog's GDPR-tagged recommendations. Manual: Records of Processing Activities documented (Art. 30 - note the narrow-in-practice exemption from the research above); DPO appointed if any Art. 37 trigger applies, or a documented reason why not; Data Processing Agreements in place with all processors (Art. 28); data subject rights process documented (Art. 12-22); privacy notice published (Art. 13-14); international transfer legal basis documented (SCCs/adequacy) alongside the technical control already built (`popia-cross-border-transfer`'s domain-allowlist approach approximates the technical side; the legal instrument is separate).

**HIPAA** - auto: same technical signals, plus DLP catalog's HIPAA-tagged recommendation. Manual: BAA/DPA downloaded and retained (corrected item, see research above); Privacy Officer and Security Officer designated; documented risk analysis on file (§164.308(a)(1)); workforce training completed; contingency/backup plan documented (§164.308(a)(7)); Notice of Privacy Practices published; each "addressable" technical specification has a documented implement/alternative/justify decision (see research above).

### UI - open question, not decided
Two real options, not resolved yet:
1. Extend [[Compliance Matrix (CIS-NIST-Essential 8)]]'s existing framework-selector UI with these three as additional selectable items - less new UI, but mixes a pure-technical framework type with a hybrid technical+attestation one under one selector, which could read as inconsistent (a POPIA "score" behaves differently from a CIS "score").
2. A new module, reusing the same visual conventions - cleaner separation, more new code.

### QBR integration
Extend `ExecutiveQbrReport` with a `complianceReadinessSection` (or fold into the existing `dataProtectionSection` - needs a decision), so the report a client actually sees shows the full picture, not just DLP eligibility. Same house pattern as the last two additions to this report.

### Fleet visibility (later, not now)
A read-only "which clients have registered an Information Officer / signed nothing yet" aggregate view is a natural future addition, following the exact [[Fleet Data Protection Visibility]] precedent (read-only, no action, click-through to the single tenant). Not part of this plan's first version - noted so it isn't lost the way the QBR/MCP items almost were.

## Guardrails (carried forward from established norms)
- Every citation traces to a real source, not memory - see the research section above.
- No auto-attestation. A checkbox is only ever set by a human; the app cannot verify a contract was actually signed or a BAA actually downloaded.
- Single-tenant only for any write action, per the [[DLP & Sensitivity Labels Plan|no-cross-tenant-actions rule]] (also saved to memory as `no-cross-tenant-actions`) - attestation is inherently per-client, so this is naturally satisfied, but worth stating explicitly since a fleet-wide *view* of attestation state is planned later.
- This produces a **readiness checklist**, never a **compliance certificate** - the wording throughout the UI and any exported report should reflect that distinction plainly.

## Sequencing
1. Review and lock the checklist content above (regulation citations, auto vs. manual split).
2. Decide UI placement (extend Compliance Matrix vs. new module).
3. Types + `Tenant.complianceAttestations` (additive).
4. `compliance-readiness-checklist.ts` + `compliance-readiness-evaluator.ts`, tested.
5. UI.
6. QBR integration.
7. Vault docs.

## Decisions (2026-09-22) and shipped status
1. **UI placement: inside the existing Compliance Matrix** - user's explicit choice. Implemented exactly as decided, see [[Compliance Matrix (CIS-NIST-Essential 8)]].
2. **Checklist scope: the draft content above, built as-is** ("go with what you recommend") - 4 auto + 6 manual items per regulation, 30 controls total across the three.
3. **QBR integration: not built this pass** - the user's "go with what you recommend" covered scope and placement; QBR wiring for this readiness data (distinct from the DLP catalog's own `dataProtectionSection`, already in the QBR) is a reasonable next addition, not done yet. Noted here so it isn't lost the way the original Stage 5 QBR/MCP items almost were.

**Shipped**: `ComplianceFramework` extended with `popia`/`gdpr_uk_gdpr`/`hipaa`; `POPIA_READINESS_CONTROLS`/`GDPR_READINESS_CONTROLS`/`HIPAA_READINESS_CONTROLS` in `compliance-evaluator.ts`; `Tenant.complianceAttestations` (no new route - reuses `PUT /api/tenants/{id}`); three new tabs plus a live "Attest"/"Revert" control in `ComplianceMatrixModule.tsx`. Verified end-to-end live on Crimson Line Live Demo, including a genuine server round-trip and a clean revert. `tsc` clean; 4 new tests in `compliance-evaluator.test.ts` (47 files / 568 tests total). Full detail: [[Compliance Matrix (CIS-NIST-Essential 8)]].

Part of [[Clarity365 MOC]].
