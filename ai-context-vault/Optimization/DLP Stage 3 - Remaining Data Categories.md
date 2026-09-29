---
tags: [optimization, plan, data-protection]
---

# DLP Stage 3: Remaining Data Categories

In-depth plan for the four data categories not yet built in `src/lib/data/data-protection-recommendations.ts`: `financial_banking`, `payment_card`, `bulk_pii`, `ip_contracts`. Status: **planning only, no code written** (drafted 2026-09-22, after the four shipped entries - see [[Data Protection (DLP & Sensitivity Labels)]]). Part of [[DLP & Sensitivity Labels Plan]].

## Why these four aren't just "four more of the same shape"
The four shipped entries (POPIA, HIPAA, GDPR/UK GDPR, credentials) all follow one mold: a named regulation, a small set of well-known built-in Sensitive Information Types, a single-instance trigger, single-item enforcement. Reading the remaining four closely, only one (`financial_banking`) actually fits that mold cleanly. The other three each break a different assumption:

| Category | What breaks the existing mold |
|---|---|
| `payment_card` | The obvious regulation (PCI DSS) is explicitly out of v1 scope - see the 2026-09-21 decision. Framing this under POPIA/GDPR instead is correct but must not read as a PCI-compliance claim. |
| `bulk_pii` | Not about a new SIT at all - about the same identifiers already shipped, at a much higher instance count, signaling mass export rather than a single reference. |
| `ip_contracts` | Not personal data, so POPIA/GDPR/HIPAA don't apply. No reliable built-in SIT exists for "this is a contract" or "this is source code" - real detection needs E5 (trainable classifiers), which cuts against the Business Premium/E3-first priority for the first time. |

Each is planned separately below rather than forced into the same template.

## 1. `financial_banking`
Closest to the existing shape, with one real gap worth flagging.

- **Regulations:** POPIA, GDPR/UK GDPR. Not HIPAA (out of its domain). Financial data is **not** a POPIA "special category" (those are religious/political/health/biometric/criminal-behaviour categories under s.26) or a GDPR Art. 9 special category either - so the citation here is the general safeguards provision (POPIA s.19, GDPR Art. 32), the same one the credentials pack already uses, not the special-category articles the POPIA/GDPR identity packs cite.
- **Sensitive Information Types:** `International Banking Account Number (IBAN)`, `SWIFT Code`, `ABA Routing Number (also known as ABA Number or Routing Transit Number)` - all believed-correct built-in Microsoft names, moderate-to-high confidence, not independently re-verified live (same caveat as every entry so far).
- **A real gap to flag, not paper over:** IBAN is a European standard - South African bank accounts don't use IBAN, and there is no known South-Africa-specific bank-account-number built-in SIT. For a POPIA-driven (South African) client, this pack is meaningfully weaker at catching *domestic* SA banking data than it is at catching international wire details. Ships anyway (SWIFT codes and international transfers are still a real, common leak path), but the caveat says this plainly rather than implying full coverage.
- **Rule logic:** single rule, same shape as the credentials pack - any of the three SITs found, shared externally -> notify + incident report (test mode), promote to block + override-with-justification. No elevated/combined variant needed (unlike the health packs, there's no natural "make it worse" pairing here).
- **E5 enhancement worth calling out specifically here:** Exact Data Match (EDM) is unusually well-suited to this category - a client's actual list of known account numbers can be matched exactly instead of a generic pattern, cutting false positives sharply. Worth its own line in `e5Enhancements`, not just the usual Teams/Endpoint boilerplate.

## 2. `payment_card`
Mechanically simple, but the framing needs to be right before any content is written.

- **Regulations:** POPIA, GDPR/UK GDPR - as personal information/personal data when the card number is tied to an identifiable person, **not as a PCI DSS compliance measure**. PCI DSS itself needs far more than a DLP rule (network segmentation, a QSA assessment, quarterly scans) - a DLP policy alone must never be presented as making a tenant "PCI compliant." This is not a judgment call, it's a correctness requirement: the entry's summary and caveats state this explicitly, the same way the HIPAA entry already states Clarity365 isn't a covered entity or business associate.
- **Crimson Line already has a live DLP policy literally named for PCI DSS**, in simulation mode (per the user, 2026-09-21). This entry should say so in its caveats: layer this personal-data-grounded pack alongside an existing PCI-named policy, don't treat one as a replacement for the other - they're answering different questions (is this personal information safe vs. is this tenant PCI compliant).
- **Sensitive Information Types:** `Credit Card Number` (one of Microsoft's oldest, checksum-validated built-in SITs - high confidence), `EU Debit Card Number` (moderate confidence).
- **Rule logic - this is the one category where the original plan's own table already specified a volume-tiered design**, worth honoring literally rather than reusing the single-instance-trigger shape: **1-9 instances -> notify/warn only; 10 or more instances -> block external sharing and alert compliance directly**, as two separate rules with different `minCount` thresholds and different action severity, both still starting in test mode per the established convention.

## 3. `bulk_pii`
Deliberately reuses existing SITs rather than inventing new ones - the novelty here is the threshold and the framing, not the detection.

- **Regulations:** POPIA, GDPR/UK GDPR (mass exposure of many people's data is squarely what both regimes' breach-notification triggers are built around - POPIA s.22, GDPR Art. 33 - both already cited elsewhere in the catalog).
- **Design decision: no new SIT.** Reuses the identifiers already shipped in the POPIA and GDPR entries (`South Africa Identification Number`, `UK National Insurance Number (NINO)`, `UK Passport Number`, `EU Passport Number`) plus the two `financial_banking` SITs once that entry exists, combined with `OR` logic across all of them. The signal isn't "which identifier" - it's "an unusually large number of *any* of these in one item."
- **Threshold:** 50+ combined instances in a single email or file, matching the number the original plan's data-type table already used. This is a **per-item** volume check (DLP's own `minCount` condition), not a **time-windowed** check (many small exports over days/weeks) - that second pattern is genuinely a different Microsoft capability (Insider Risk Management / Adaptive Protection's cumulative-exfiltration detection), E5-only, and belongs in `e5Enhancements` as an explicit upgrade path, not something this pack can approximate on Business Premium/E3.
- **Rule logic:** single rule, any qualifying identifier at 50+ instances, shared internally or externally (like the credentials pack, not restricted to external - a 50-instance internal bulk share to an over-permissioned group is still worth flagging) -> notify + incident report. Given the much lower false-positive risk of a 50-instance match compared to a 1-instance one, the recommended test-mode review window is shorter (1-2 weeks, matching the credentials pack's reasoning) before promoting straight to block, not just warn.
- **Sequencing implication:** because this entry's SIT list depends on `financial_banking` already existing, it should be built **after** `financial_banking`, not before.

## 4. `ip_contracts`
The one category that doesn't fit the pattern at all, and the one place where the Business Premium/E3-first design choice runs into a real ceiling.

- **Regulations: none.** POPIA/GDPR/HIPAA all govern personal data; intellectual property, contracts, and source code aren't personal data. There is no regulation citation to reach for here - `regulationRefs` for this entry would be empty or reference general confidentiality-obligation language (an NDA, an employment contract's IP clause) rather than a statute. This also means the entry won't be tagged with any of the three `Regulation` values, so it will only appear when the module's regulation filter is set to "All regulations" - correct behavior, not a bug, but worth confirming the UI's empty-state handling covers a zero-regulation entry cleanly (a quick check during build, not a redesign).
- **No reliable built-in Sensitive Information Type exists for "this is a contract" or "this is source code."** Microsoft's built-in SITs are pattern/checksum-based (an ID number, a card number); there is no semantic "document type" SIT. The two available mechanisms on Business Premium/E3 are:
  - A **keyword dictionary** condition (e.g., "Non-Disclosure Agreement", "This Agreement", "Confidential and Proprietary", "Trade Secret") for contracts.
  - A **file-extension/file-type** condition (`.py`, `.cs`, `.java`, `.sql`, `.ts`, etc.) for source code, optionally combined with a keyword condition for common code syntax fragments.
  - Both are meaningfully higher false-positive, lower-precision tools than a checksum-validated SIT. This must be stated up front in the entry's summary, not buried in caveats - presenting this pack with the same confidence as the identity-based ones would be misleading.
- **What actually works well here needs E5:** Trainable Classifiers (train on the client's own real contracts/source code, then match by content similarity, not keywords) and Exact Data Match (a known list of deal names or project code names). This is the one category in the whole catalog where the gap between Business Premium/E3 and E5 isn't a nice-to-have upgrade, it's the difference between a genuinely weak control and a genuinely strong one.

### Decision (2026-09-22): E5-only, no E3 version
Resolved: **`minimumLicenseTier: "e5"`, built on trainable classifiers and/or Exact Data Match, no Business Premium/E3 keyword/file-type fallback shipped for this category.** The explicit reasoning behind the choice: a keyword/file-extension approximation would be materially weaker than every other entry in the catalog, and shipping it under the same "recommendation" framing as the checksum-validated identity/financial packs risks giving a client false confidence in a control that doesn't actually work well. This is the one category in the catalog where the Business Premium/E3-first priority (set 2026-09-21) doesn't apply - a deliberate, acknowledged exception, not an oversight.

Practical effect: this entry won't render for a client on Business Premium/E3 filtered strictly, and the module's UI already shows a `minimumLicenseTier` badge per entry, so this reads as "requires E5" the same way the badge already works for entries that have E5-only sub-features - no UI change needed, just an entry with no BP/E3 path.

## Build sequence
Ordered by dependency and by which decision blocks which entry:

1. `financial_banking` - no dependencies, same shape as existing entries.
2. `payment_card` - no dependencies, but needs the PCI-framing caveat written carefully.
3. `bulk_pii` - **depends on `financial_banking` already existing** (reuses its two SITs).
4. `ip_contracts` - blocked on the Option A/B decision above; everything else about it can be drafted in parallel.

## What stays the same as the first four entries
- Guided-instructions-only output (portal steps + best-effort, explicitly-unverified PowerShell) - no change to the 2026-09-21 deploy-method decision.
- Every entry starts in test mode; enforcement is promoted, never deployed live by default.
- SIT names are believed-correct built-in Microsoft names, not independently re-verified against a live tenant in this session - same standing caveat as the first four.
- Vault notes ([[Data Protection (DLP & Sensitivity Labels)]], [[DLP & Sensitivity Labels Plan]]) updated in the same session the entries ship, per this repo's own convention.

Part of [[DLP & Sensitivity Labels Plan]] and [[Clarity365 MOC]].
