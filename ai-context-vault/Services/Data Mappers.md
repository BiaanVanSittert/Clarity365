---
tags: [service]
---

# Data Mappers

Eleven files that translate raw Graph/EXO/DNS API responses into the app's [[Domain Types|domain types]]. Each imports **only `../types`** :  fully independent leaf nodes, each with its own `.test.ts` (100% test coverage in this bucket, unlike [[Core Graph Layer]]):

- `app-registration-mapper` :  + risk categorization → [[App Registrations & Connected Services]]
- `capabilities-mapper` :  SKU → capability detection (Entra P1/P2, Intune, MDE, Purview, MDO)
- `groups-mapper` → [[Groups & Distribution Management]]
- `incident-mapper` :  + MITRE technique heuristics → [[Event Response (Incident Response)]]
- `intune-mapper` → [[Intune Endpoint Security]]
- `mailflow-mapper` :  the largest mapper (mailbox/delegation/forwarding/transport-rule/connector/DKIM) → [[Exchange Mailbox Permissions]], [[Email Forwarding Rules Audit]], [[Mailflow Rules & Transport Hygiene]]
- `mdo-alert-mapper` → alerts feeding [[Defender for Office 365 & TABL]]
- `mdo-mapper` :  + `defaultTablExpirationIso`, reused by [[MCP Server]] → [[Defender for Office 365 & TABL]]
- `mfa-classifier` → [[MFA Enforcement & Auth Audit]]
- `secure-score-mapper` → [[Secure Score & Timeline]]
- `sharepoint-mapper` → [[SharePoint & Storage Policies]]
- `ca-environment-mapper` :  the CA policy fields `mapConditionalAccessPolicy()` used to drop, v1.0 and beta session controls, named locations, and tenant identity settings (security defaults, user consent mode, guest access level, guest invites, admin consent workflow). Added for [[Security Simulations Plan]] Stage 1. Undefined always means "not synced", never "off"
- `domain-dns-checker` :  the only file that queries public DNS directly (Node `dns` module) instead of Graph/EXO → [[Domain Authentication]]

All are invoked from [[Core Graph Layer]]'s `fetchLiveTenantSnapshot` during a sync.

**`admin-hygiene-matcher`** is the odd one out :  it's not a Graph→type mapper, it's the only function that *cross-references two other mappers' output* (`mfaAudit`'s `isAdmin`/`adminRoles` against `accountClassification.users`' `licenses`) after both already exist on the snapshot. Exports `isDailyUseLicenseSku` (SKU-name matcher, same substring style as `capabilities-mapper`'s `hasSku`), `findLicensedGlobalAdmins` (narrow: admin + daily-use license), and `getAllPrivilegedAccounts`/`getPrivilegedAccountUpns` (general: every admin, licensed or not, with full role lists and precomputed `isUnprotected`/`isLicensedForDailyUse` flags). Has a test. Reused by [[Fleet Baseline Drift]] (`SEC-ADMIN-LICENSE` finding), [[User & Account Classification]] (card/tab + lightweight "Privileged" tag), and [[Privileged Access Review]] (the full roster). Depends on [[Core Graph Layer]]'s `graph-client.ts` resolving per-user license `skuId` GUIDs to `skuPartNumber` names (via the tenant-wide `subscribedSkus` fetch) :  without that resolution step, live-tenant syncs would carry raw GUIDs the SKU matcher can't recognize.

**Four separate SKU-name lists exist in the codebase on purpose, not by accident** (checked in a 2026-09-18 review specifically to make sure this wasn't the "same logic re-implemented, drifting apart" bug class - it isn't, since each answers a genuinely different question):
- `capabilities-mapper.ts`'s `hasSku`/`isIntuneCapableSkuPartNumber`/`isBusinessPremiumSku` - *tenant-wide* "does this tenant have capability X at all" - the latter two now exported and reused per-user by `intune-coverage-analyzer.ts` (see [[Defender Configuration & Onboarding]]'s Intune-coverage-gap SKU fix) so that per-user check applies the identical, live-verified rule rather than its own copy.
- `license-sku-names.ts` / `license-sku-costs.ts` - display names and cost-per-seat, for [[Tenant License Optimization]]/[[Fleet License Optimization]] - a pricing/labeling concern, not a capability check.
- `admin-hygiene-matcher.ts`'s `isDailyUseLicenseSku` - deliberately broad/over-matching (its own comment explains why): "does this admin have *any* daily-use license" is a different, looser question than "does this SKU specifically include Intune/MDE/etc," so it can't just call into `capabilities-mapper.ts`.
Don't consolidate these into one shared list without checking what each one is actually answering first.

Part of [[Clarity365 MOC]].
