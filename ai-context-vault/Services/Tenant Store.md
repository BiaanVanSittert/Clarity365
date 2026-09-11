---
tags: [service, hub]
---

# Tenant Store

`src/lib/services/tenant-store.ts` :  **the central hub of the entire application.** ~1700 lines, ~30 public methods.

Every one of the 33 [[API Surface|API routes]] (except the fleet-operations ones, see below) reads or writes through this one file. It is the sole owner of persistence.

## Persistence
- Backed by **SQLite** (`better-sqlite3`, `data/clarity365.db`) :  new as of the auth-system rewrite, see [[Security & Auth]]
- **Auto-migrates** from the legacy flat file `data/clarity-store.json` on first run :  this is why a pre-upgrade install has that JSON file sitting in `data/` (gitignored local state)
- Owns operator auth config (delegates hashing to [[Security Infra]]'s `crypto.ts`) and encrypted tenant client secrets

## What it imports
`fleet-analyzer` ([[Analysis & Generation]]), `mock-tenants`/`default-snapshot`/`baseline-definitions` ([[Baseline Definitions & Mock Data]]), `crypto` ([[Security Infra]]), `graph-client` (4 functions) and `graph-fetch`/`exo-client` (7 functions) ([[Core Graph Layer]]), `mdo-mapper` ([[Data Mappers]]).

## What imports it
Every `src/app/api/**/route.ts` file, plus [[Fleet Operations]] and `scheduler.ts` ([[Security Infra]]).

## Representative methods
`getSnapshot`, `syncTenant` (live Graph pull, falls back to cache), `deployBaselinePolicy`, `addTablEntry`/`removeTablEntry`, `applyMdoBaselineFix`, `disableForwardingRule`, `revokeMailboxDelegation`, `containUserAccount`/`restoreUserAccount`, `isolateEndpointDevice`, `getAuditLog`, `getSettings`/`updateSettings`, `saveSnapshot`.

`getSnapshot`'s private `backfillSnapshot()` runs on every read, deserializing the stored row against `createBlankSnapshot()`'s defaults so no consumer needs to defend against a missing field. For `snapshot.tenant.isDemo` tenants specifically, a handful of fields (`accountClassification.users`, `mailboxes`, `intune.devices`, `incidents`, `signIns`) deliberately prefer whatever's *currently* in `mock-tenants.ts` over whatever's frozen in the database - since a mock tenant never re-syncs (`fetchLiveTenantSnapshot` short-circuits unchanged for `authMode === "mock"`), without this a demo tenant seeded before a mock-data edit would keep serving stale data forever. `signIns` was missing from this list until [[Sign-In Logs & CA Diagnostics]]'s country-code normalization work surfaced it - worth checking this same list first before assuming a `mock-tenants.ts` edit "isn't working" for any other field.

Also fixed: `syncTenant()`'s fully-failed path (Graph token acquisition fails entirely - bad/expired/revoked credentials) previously never updated `Tenant.connectionStatus`, so a tenant that was last "healthy" kept showing "healthy" everywhere indefinitely even while every subsequent sync attempt kept failing - the only trace was a toast at the moment of a manual sync. It now persists a new `"error"` status onto the raw tenant row (same `getTenantRow`/`putTenantRow` patch pattern as `persistExoRefreshToken()`) and reflects it in the stale-fallback snapshot returned to the caller, so a broken live tenant reads as broken everywhere, durably, not just in a dismissable toast.

A second, deeper instance of the same class of bug: `syncTenant()`'s **success** path only ever called `putSnapshotRow()` - persisting the freshly-computed `connectionStatus`/`lastSyncTimestamp` inside the *snapshot's* embedded tenant copy - and never `putTenantRow()`. `getAllTenants()`/`getTenant()` (what the Header badge, the tenant switcher, and `computeFleetPosture()`'s tenant list all actually read) only ever read the raw `tenants` table row, which was therefore frozen at whatever `connectionStatus` it had at creation forever, no matter how many times the tenant synced successfully afterward. Now `syncTenant()`'s success branch also calls `putTenantRow(snapshot.tenant)` (the already-re-encrypted tenant object) so the canonical row and the snapshot's embedded copy never diverge.

## Risk note
See [[Optimization Plan]] :  a 1700-line single file that's the transitive dependency of *everything* is the single highest-leverage place a bug or a slow query can hurt, and the one place a future split would pay off most.

Part of [[Clarity365 MOC]].
