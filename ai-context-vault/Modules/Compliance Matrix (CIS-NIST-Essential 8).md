---
tags: [module, compliance, reporting]
---

# Compliance Matrix (CIS M365 v3 / NIST CSF / Essential 8 / POPIA / GDPR / HIPAA)

Scores a tenant against six frameworks: three purely technical (CIS M365 v3, NIST CSF, Essential Eight) and three hybrid technical-plus-organizational readiness frameworks (POPIA, GDPR/UK GDPR, HIPAA), added 2026-09-22.

- **Component:** `ComplianceMatrixModule.tsx`
- **Backing call:** `compliance-evaluator.evaluateTenantCompliance` / `evaluateFleetCompliance` (same data as `GET /api/reports/compliance`)
- **Key types:** `ComplianceControlItem`, `TenantComplianceAssessment` :  see [[Domain Types]]
- **Uses service:** [[Analysis & Generation]] (`compliance-evaluator`, which composes `ca-baseline-matcher` + `drift-analyzer`)

## POPIA / GDPR / HIPAA Readiness (added 2026-09-22)
Grew out of [[DLP & Sensitivity Labels Plan]] - the user asked whether DLP alone is enough to call a client compliant with any of these three regulations. It isn't; see [[Compliance Readiness Checklist Plan]] for the full research trail (every organizational-item citation was checked against a real source, not asserted from memory - including a correction to an earlier claim about Microsoft's HIPAA BAA).

Deliberately built **inside this same module and type system**, not as a separate concept, per explicit user direction ("let it live inside the existing Compliance Matrix"):
- `ComplianceFramework` extended to include `"popia" | "gdpr_uk_gdpr" | "hipaa"` - each hybrid: section "1. Technical Safeguards" is auto-computed (CA baseline coverage, MFA enforcement, mailbox audit logging, and a DLP-catalog-eligibility check via `getTierEligibility()` - deliberately capped at `partially_compliant` even at 100% eligibility, since eligibility isn't deployment and there's no live Purview sync to confirm adoption); section "2. Organizational & Legal" is manual attestation.
- `ComplianceControlItem.attestationKey?: string` marks an item as manual (present only in section 2) and drives the UI's "Attest" control; `sourceUrl?: string` links the real citation.
- `Tenant.complianceAttestations?: Record<string, {attested, attestedAt?, attestedBy?, note?}>` - new, optional, no migration, following the exact `endpointSecurityWriteMode` precedent. **No new API route** - persisted through the existing generic `PUT /api/tenants/{id}` (`updateTenant`'s partial merge). Because that merge is shallow, the write always sends the *full* attestation map, never a single key - see `handleToggleAttestation` in the module.
- A checkbox is only ever set by a human clicking "Mark as Attested" (or "Revert to Not Attested") in the module - nothing infers or auto-sets it, since the app cannot verify a contract was signed or a registration filed. An unattested item defaults to `non_compliant`, never `compliant`.
- Attestation is single-tenant only - the fleet-wide scope selection disables the Attest control entirely ("Select a specific tenant... to attest this item"), consistent with the standing no-cross-tenant-actions rule (also saved to memory as `no-cross-tenant-actions`) - not because attestation could plausibly be a bulk action, but because there's no fleet-wide "fact" to attest to begin with.
- Verified live end-to-end on Crimson Line Live Demo: attesting an item flips its status, shows the real record (attester, date, note) in the evidence text, and a genuine server round-trip occurs (confirmed via the header's sync timestamp changing after `onRefresh`); reverting restores the original state cleanly.
- The shared `not_applicable` status badge previously read "Not Applicable (License Gated)" unconditionally - accurate for CIS/NIST/Essential Eight's own not-applicable cases (Entra P2 licensing) but wrong for the readiness frameworks' own not-applicable case (Exchange Online not connected, unrelated to licensing). Fixed to a reason-agnostic "Not Applicable" label; the expanded row's evidence text always has the real reason.

Tested: `compliance-evaluator.test.ts` covers all three frameworks' section structure, that every organizational item carries an `attestationKey`, that an unattested item never defaults to compliant, that a real attestation record flips it to compliant, and that the DLP-eligibility control never claims a full pass.

Part of [[Clarity365 MOC]]. Notable: for the three technical frameworks, this module doesn't introduce new source data - it's a lens over the same [[Baseline Definitions & Mock Data|39 baseline rules]] every other module scores against. The three readiness frameworks are the first exception - they introduce genuinely new data (attestation state) that only this module owns.
