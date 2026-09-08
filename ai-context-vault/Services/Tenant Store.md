---
tags: [service, hub]
---

# Tenant Store

`src/lib/services/tenant-store.ts` — **the central hub of the entire application.** ~1700 lines, ~30 public methods.

Every one of the 33 [[API Surface|API routes]] (except the fleet-operations ones, see below) reads or writes through this one file. It is the sole owner of persistence.

## Persistence
- Backed by **SQLite** (`better-sqlite3`, `data/clarity365.db`) — new as of the auth-system rewrite, see [[Security & Auth]]
- **Auto-migrates** from the legacy flat file `data/clarity-store.json` on first run — this is why a pre-upgrade install has that JSON file sitting in `data/` (gitignored local state)
- Owns operator auth config (delegates hashing to [[Security Infra]]'s `crypto.ts`) and encrypted tenant client secrets

## What it imports
`fleet-analyzer` ([[Analysis & Generation]]), `mock-tenants`/`default-snapshot`/`baseline-definitions` ([[Baseline Definitions & Mock Data]]), `crypto` ([[Security Infra]]), `graph-client` (4 functions) and `graph-fetch`/`exo-client` (7 functions) ([[Core Graph Layer]]), `mdo-mapper` ([[Data Mappers]]).

## What imports it
Every `src/app/api/**/route.ts` file, plus [[Fleet Operations]] and `scheduler.ts` ([[Security Infra]]).

## Representative methods
`getSnapshot`, `syncTenant` (live Graph pull, falls back to cache), `deployBaselinePolicy`, `addTablEntry`/`removeTablEntry`, `applyMdoBaselineFix`, `disableForwardingRule`, `revokeMailboxDelegation`, `containUserAccount`/`restoreUserAccount`, `isolateEndpointDevice`, `getAuditLog`, `getSettings`/`updateSettings`, `saveSnapshot`.

## Risk note
See [[Optimization Plan]] — a 1700-line single file that's the transitive dependency of *everything* is the single highest-leverage place a bug or a slow query can hurt, and the one place a future split would pay off most.

Part of [[Clarity365 MOC]].
