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
- `domain-dns-checker` :  the only file that queries public DNS directly (Node `dns` module) instead of Graph/EXO → [[Domain Authentication]]

All are invoked from [[Core Graph Layer]]'s `fetchLiveTenantSnapshot` during a sync.

**`admin-hygiene-matcher`** is the odd one out :  it's not a Graph→type mapper, it's the only function that *cross-references two other mappers' output* (`mfaAudit`'s `isAdmin`/`adminRoles` against `accountClassification.users`' `licenses`) after both already exist on the snapshot. Exports `isDailyUseLicenseSku` (SKU-name matcher, same substring style as `capabilities-mapper`'s `hasSku`), `findLicensedGlobalAdmins` (narrow: admin + daily-use license), and `getAllPrivilegedAccounts`/`getPrivilegedAccountUpns` (general: every admin, licensed or not, with full role lists and precomputed `isUnprotected`/`isLicensedForDailyUse` flags). Has a test. Reused by [[Fleet Baseline Drift]] (`SEC-ADMIN-LICENSE` finding), [[User & Account Classification]] (card/tab + lightweight "Privileged" tag), and [[Privileged Access Review]] (the full roster). Depends on [[Core Graph Layer]]'s `graph-client.ts` resolving per-user license `skuId` GUIDs to `skuPartNumber` names (via the tenant-wide `subscribedSkus` fetch) :  without that resolution step, live-tenant syncs would carry raw GUIDs the SKU matcher can't recognize.

Part of [[Clarity365 MOC]].
