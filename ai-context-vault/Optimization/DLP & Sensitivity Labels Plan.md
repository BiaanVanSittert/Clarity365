---
tags: [optimization, plan, data-protection]
---

# DLP & Sensitivity Labels Plan

Multi-stage plan for adding Microsoft Purview Data Loss Prevention (DLP) and sensitivity labels to Clarity365. Status: **planning only, no code written** (drafted 2026-09-21 against `5fcab76` plus the uncommitted working tree). Part of [[Optimization Plan]] and [[Clarity365 MOC]].

Stage 1 has its own in-depth note: [[DLP Stage 1 - Data Model & Licensing]].

## Starting position (verified in code)
- Nothing in the app reads or writes DLP policies or labels today. The only related code is mock capability entries, the audit-log parser, and `sharepoint-mapper.ts`'s `isSensitiveDataPresent`, which is a keyword guess rather than a real label or DLP signal ([[SharePoint & Storage Policies]]).
- DLP policies are, to the best of current knowledge, **not exposed through Microsoft Graph**. They live behind Security & Compliance (Purview) cmdlets: `Get-DlpCompliancePolicy`, `Get-DlpComplianceRule`, `Get-Label`, `Get-LabelPolicy`, `Get-AutoSensitivityLabelPolicy`. `exo-client.ts` only reaches `outlook.office365.com/.../InvokeCommand` with an Exchange-scoped token, so whether the same delegated refresh token can reach the compliance endpoint is **unverified**. Stage 0 exists to settle that ([[Core Graph Layer]]).
- `capabilities-mapper.ts` sets `hasPurview` only for E5-class SKUs, so E3 and Business Premium tenants (which include DLP for Exchange, SharePoint and OneDrive plus manual labels) read as unlicensed. Mock data uses tier-specific ids (`cap-purview-e5`, `-e3`, `-std`); the live mapper only ever emits generic `cap-purview`. This is the recurring mock-versus-live capability bug from [[Optimization Plan]] item 7.
- `tenant-store.ts` is 2681 lines and `exo-client.ts` has no tests, so new work should live in its own files and ship with tests ([[Tenant Store]], [[Testing]]).

## Stages

### Stage 0: Feasibility spike (no product code)
- Call `Get-DlpCompliancePolicy`, `Get-Label` and `Get-DlpSensitiveInformationType` against a live tenant using the existing delegated token and the compliance endpoint.
- Check the Graph beta label endpoints and their permissions.
- Confirm whether `New-` and `Set-DlpCompliancePolicy` work over REST, and which role group is required.
- Confirm the current licence matrix (it has changed before). Working assumption, to verify:

| Feature | Business Premium / E3 | E5 or Purview add-on |
|---|---|---|
| Manual labels | Yes | Yes |
| DLP for Exchange, SharePoint, OneDrive | Yes | Yes |
| Teams DLP | No | Yes |
| Endpoint DLP | No | Yes |
| Auto-labeling | No | Yes |
| Trainable classifiers, Exact Data Match | No | Yes |

- Capture real cmdlet output as redacted JSON fixtures. Stage 1 mappers are built from these, never from assumed shapes.
- **Exit:** written go or no-go, a cmdlet-to-JSON shape reference, the auth model decision, and the fallback if the REST route fails (read-only via Graph, or generated PowerShell scripts as the CA templates already do).

### Live findings (2026-09-22, against Crimson Line Live Demo, read-only, throwaway script, nothing persisted to the app)
Three device-code sign-ins with the tenant's GA account (`Biaan@crimsonsecure.onmicrosoft.com`), each redeemed once (Microsoft's refresh/auth-code grants are single-use, confirmed live by an `AADSTS54005` error on reuse).

1. **Token acquisition for the compliance resource works.** `POST /oauth2/v2.0/devicecode` and the subsequent token redemption both succeeded for `scope: https://ps.compliance.protection.outlook.com/.default offline_access`, using the same first-party public client id `exo-client.ts` already uses for Exchange (`fb78d390-0c51-40cd-8e17-fdbfab77341b`) - no new app-registration consent was needed, confirming that part of the design assumption.
2. **`ps.compliance.protection.outlook.com`'s `InvokeCommand` REST path never responded.** A plain `GET /` to the same host resolved and returned HTTP 404 in under a second (host is reachable), but every `POST .../adminapi/beta/{tenantId}/InvokeCommand` call to it - two attempts, 45s timeout each, `Accept-Encoding: identity` - failed with `UND_ERR_CONNECT_TIMEOUT` (a TCP-connect-level timeout, not an HTTP error). Given the root path connects instantly, this looks like a path- or method-specific block on this machine's network (this is a corporate Windows 11 Enterprise machine) rather than a Microsoft-side outage, but that is **not confirmed** - it needs testing from a different network before ruling out a real Microsoft-side cause.
3. **The same compliance-scoped token against the already-working `outlook.office365.com` `InvokeCommand` endpoint (the one `exo-client.ts` uses today) returned a fast, clean `HTTP 403`** with an empty/padded body - no connect-level failure, meaning that endpoint is fine and simply rejects a token whose audience is the compliance resource rather than Exchange. This is evidence the two workloads genuinely need separate endpoints (or at least separate tokens), not just a different scope on the same host - consistent with the original plan, not yet fully proven.

**Net result: inconclusive, not a no-go.** Token acquisition (the auth model) is confirmed working. Whether the compliance REST surface itself works could not be established from this network. **Does not block the chosen path** - per the 2026-09-21 decision, DLP/label recommendations are delivered as guided instructions, not live sync, so Stage 3 does not depend on this connectivity at all. This finding only affects the *optional* future automatic-sync enhancement (originally Stage 1's live pull), not the feature the user actually asked for.

**Next steps, not yet done:** retry the `ps.compliance.protection.outlook.com` POST from a different network (e.g. a personal connection, not this corporate machine) to separate "blocked here" from "blocked everywhere"; if it's genuinely unreachable, the documented alternative is `Connect-IPPSSession`'s own historical WinRM-based endpoint or a certificate-based app-only connection instead of the delegated device-code flow. Neither is scheduled - see decision below.

### Stage 1: Data model, licensing, mocks
See [[DLP Stage 1 - Data Model & Licensing]].

### Stage 2: Read-only posture module
- New "Data Protection" module, prop-driven like the others.
- `DLP_BASELINE_STANDARDS` and `LABEL_BASELINE_STANDARDS`, with `dlp-baseline-matcher.ts` and `label-baseline-matcher.ts` in the existing `evaluate*Baseline()` shape ([[Baseline Matchers]], [[Baseline Definitions & Mock Data]]). Example checks: DLP policy enabled and not stuck in test mode past 30 days; Exchange, SharePoint and OneDrive covered; label policy published; default label set; mandatory labeling on; containers labelled; Highly Confidential encrypted.
- Add CIS M365 v3 section 3 controls and NIST CSF PR.DS to `compliance-evaluator.ts` ([[Compliance Matrix (CIS-NIST-Essential 8)]]). The recalled CIS numbering (3.2.1 DLP enabled, 3.2.2 Teams DLP, 3.3.1 label policy published) needs checking.
- Sidebar badge; replace the SharePoint keyword heuristic with real label signals.
- Matchers must return **unknown**, not fail, for any section whose fetch state is not `ok` (see Stage 1).

### Stage 3: Recommendation engine
A versioned, data-driven catalog in `src/lib/data/data-protection-recommendations.ts` with two input axes, **regulation** and **data type**, resolved against the tenant's licence entitlements and current state.

Output per selection: locations, conditions (SIT, confidence, instance count), actions, a starting mode of test with notifications (the DLP equivalent of CA report-only), a gap list against what is deployed, "needs E5" flags with an E3-safe fallback (manual label plus DLP on the label), and the regulation reference behind each rule.

**By regulation** (technical mapping, not legal advice; citations need checking by whoever owns compliance):

| Regulation | Priority controls | Reference |
|---|---|---|
| GDPR / UK GDPR | EU and UK IDs, financial data; block or warn on external sharing; breach-evidence alerting | Arts. 5(1)(f), 25, 32, 33 |
| POPIA (South Africa) | SA ID number, financial and health data; security safeguards and compromise notification | s.19, s.22 |
| HIPAA | Health data: identifier combined with medical terms; encryption on send | 164.312(a)(2)(iv), (e) |
| PCI DSS v4 | Card numbers blocked from email and Teams; limit stored PAN | Req. 3, 4.2.2 |
| SOX / GLBA | Financial statements, customer financial data, audit trail | SOX 404, 16 CFR 314 |
| CCPA / CPRA | Bulk personal-information exfiltration, consumer records | n/a |
| ISO 27001:2022 | Labeling is itself the control | A.5.12, A.5.13, A.8.12 |

**By data type:**

| Data | Detect with | Recommended policy |
|---|---|---|
| Payment cards | Credit Card Number, EU Debit Card | 1 to 9 instances: warn. 10 or more: block external, alert compliance |
| Banking | SWIFT, IBAN, ABA routing | Block external with override plus justification; label "Confidential - Finance" |
| Government IDs | SSN, UK NINO, SA ID, passport | Block external; flag OneDrive and SharePoint external links |
| Health | ICD-9/10 plus patient identifier | Require both together to cut false positives; encrypt on send; label "Highly Confidential - PHI" |
| Credentials and secrets | All Credential Types, Azure keys | Block external in every framework |
| Bulk customer or HR records | Same SITs at 50+ instances | Alert on external sharing and mass download |
| IP, source code, contracts | Trainable classifiers (E5) | E5: auto-label. E3: manual label plus DLP on the label |
| Named customer data, project code names | Exact Data Match (E5), keyword lists | Custom pack |

**Label taxonomy recommendation:** four or five top-level labels (Public, General, Confidential, Highly Confidential), sublabels only where needed, General as default, mandatory labeling, justification on downgrade, encryption on Highly Confidential, container labels for Teams and sites (needs Entra ID P1; group-setting prerequisite to verify), auto-labeling reusing the same SIT packs, and DLP rules that trigger on labels.

Recommendations reference SITs by **GUID**, validated against the tenant's own synced SIT list, never by display name.

### Stage 4: Gated write path
- A `dataProtectionWriteMode` toggle per tenant, mirroring `endpointSecurityWriteMode` ([[Defender Configuration & Onboarding]]).
- Routes under `/api/tenants/[id]/data-protection/...`, each checking the gate; deploy in test mode, promote later; `ChangeConfirmationModal` and the existing audit log ([[Modals]]).
- Label and DLP changes take time to propagate, so "pending propagation" must not read as failure.
- Regression tests use error text captured from live tenants.
- Auth model (delegated device-code versus certificate app-only) is fixed in Stage 0.

### Stage 5: Fleet, reporting, integration
- ~~Fleet rollout of a pack through `fleet-operations.ts`~~ - **superseded**: rebuilt 2026-09-22 as a read-only cross-tenant matrix, no fleet-operations.ts involvement, no bulk action of any kind. See [[DLP Stage 5 - Fleet Rollout]].
- ~~A QBR report section~~ - **done 2026-09-22**: `ExecutiveQbrReport.dataProtectionSection`, see [[Data Protection (DLP & Sensitivity Labels)]].
- ~~A read-only MCP tool~~ - **done 2026-09-22**: `query_data_protection_recommendations`, see [[MCP Server]].
- Drift analyzer coverage, Audit Log Investigator templates for DLP rule-match events - **still blocked on live Purview sync (Stage 1)**, not built.
- Optional later: Copilot readiness, since labels and DLP govern what Copilot can surface.

## Cross-cutting rules
- Update the matching vault notes in the same turn as each change.
- Extract shared pure functions instead of repeating a check inline. This is the established convention, see `entra-p2.ts` and `defender-for-endpoint.ts`.
- Ship the live read path before polishing mock demos, so a feature does not merely look finished.
- Match on GUIDs, not display names.
- Treat "not fetched", "not connected", "unlicensed" and "fetch failed" as distinct from "none configured".
- **No cross-tenant actions, ever (user rule, 2026-09-22).** No button, export, or generated action in this feature may touch more than one tenant at a time - not a live write (already true by the guided-instructions decision), and not even a document-generation action, since that has the same one-action-many-tenants shape the user explicitly ruled out. The only permitted cross-tenant surface is **read-only aggregate visibility** (a "general score across all clients" view, e.g. [[DLP Stage 5 - Fleet Rollout]]'s matrix). This is stricter than the rest of the app - `fleet-operations.ts`'s existing bulk CA deploy is a pre-existing feature this rule does not retroactively apply to, but no new DLP work should follow that pattern.

## Decisions made (2026-09-21)
- `dataProtection` is optional on the snapshot.
- Purview gets its own connect step and refresh token, separate from Exchange Online.
- **Crimson Line Live Demo** (`tenant-mtsmi5hr`, Microsoft 365 E5 developer subscription) is the Stage 0 and Stage 1 test tenant. Read-only licence check passed; details in [[DLP Stage 1 - Data Model & Licensing]]. Anything that writes to it (Stage 0 write probes, Stage 4) needs a separate go-ahead.
- **Deploy method: guided instructions only.** Clarity365 generates exact Purview-portal steps and a best-effort PowerShell script; it never writes DLP or label config via API. **Stage 4 (gated write path) is dropped from this plan** - superseded by guided output built into Stage 3.
- **Regulations for v1: POPIA, GDPR/UK GDPR, HIPAA.** PCI DSS deliberately not in v1 scope despite the live PCI DSS example on Crimson Line (still useful as a validation case for the engine's mechanics, just not content priority).
- **Licence tier priority: Business Premium/E3 first**, E5 features (auto-labeling, trainable classifiers, Teams/Endpoint DLP) layered on as upsell notes, not the baseline design target. Matches the fleet's own composition (5 of 7 real client tenants are Business Premium).

## Module shipped (2026-09-22)
`DataProtectionModule.tsx` is live in the app - originally under Collaboration & Governance, moved same day to its own top-level sidebar category ("Data Protection") per explicit user request. Also restyled same day to match `SecureScoreModule.tsx`/`MfaAuditModule.tsx`'s actual house pattern (the first version had no light-mode support and didn't match the app's card/typography conventions - a real bug, not just a preference). See its own note, [[Data Protection (DLP & Sensitivity Labels)]].

**9 recommendations shipped (2026-09-22)**, covering all seven data categories from the original plan plus one added after a direct user review question ("is POPIA coverage really just the SA ID check?"). See [[Data Protection (DLP & Sensitivity Labels)]] for the full list, including `popia-cross-border-transfer` - the first entry in the catalog built around a data *destination* (a new `cross_border_transfer` category) rather than a data *type*, and a real example of the review-question-surfaces-a-genuine-gap pattern this catalog was built to invite. Detailed reasoning for `financial_banking`, `payment_card`, `bulk_pii`, `ip_contracts`: [[DLP Stage 3 - Remaining Data Categories]] - including the resolved decision to ship `ip_contracts` as E5-only with no Business Premium/E3 fallback, a call re-applied to the POPIA special-category/children's-data gap instead of shipping a weak keyword-based entry for either.

**Next stage: Fleet rollout, read-only.** With the catalog and its per-tenant module complete, and Stages 0/1/2 deferred without blocking anything, the next planned work is Stage 5 - revised 2026-09-22 to a **read-only cross-tenant visibility matrix only**, per explicit user direction: no action of any kind should ever touch more than one tenant at a time, including something as low-stakes as generating a guidance document. In-depth plan: [[DLP Stage 5 - Fleet Rollout]].

## Delivery order (revised 2026-09-22)
The compliance-endpoint connectivity result was inconclusive (see Stage 0 findings above) but **does not block v1**, because v1 needs no live connection at all. Actual build order:
1. **Recommendation catalog** (was Stage 3): regulation x data-type -> guided pack. In progress - see `src/lib/data/data-protection-recommendations.ts`.
2. **A wizard-style UI** over that catalog (new module, no live data dependency).
3. **Stage 1 (data model, licensing, live sync) and Stage 2 (posture scoring)**: deferred. Still useful later for automatic gap detection ("what's already deployed vs. recommended"), but no longer a prerequisite.
4. **Stage 0's unresolved network question**: open, not scheduled. Retest from a non-corporate network before picking it back up.
5. **Fleet rollout (Stage 5)**: now means "generate the same guided pack for every tenant in a chosen set," not an API-driven bulk deploy.

## Open decisions
Resolved: deploy method, regulations, tier priority (see above).
Still open: exact catalog content scope (which data categories ship in v1) - being scoped incrementally, one fully worked example first, reviewed before the rest are built.

## Related, broader plan (2026-09-22)
DLP is one technical control among many, and even together the technical controls are only half of what POPIA/GDPR/HIPAA actually require. The organizational/legal half (registered Information Officer, operator agreements, DPAs, BAAs, etc.) needed its own plan: [[Compliance Readiness Checklist Plan]].

## Gap found (2026-09-22): the module has never shipped any sensitivity-label content
Despite the module's own name ("Data Protection (DLP & Sensitivity Labels)"), all 9 catalog entries are DLP rules - nothing recommends a label taxonomy, label policy, or auto-labeling. Flagged directly by the user. Plan: [[Sensitivity Labels Catalog Plan]].

Part of [[Clarity365 MOC]].
