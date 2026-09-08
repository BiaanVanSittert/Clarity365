---
tags: [architecture]
---

# Data Flow

## Two authentication modes per tenant
`Tenant.authMode: mock | secret | certificate` ([[Domain Types]]). `mock` reads from [[Baseline Definitions & Mock Data|mock-tenants.ts]] and never calls Microsoft at all :  this is how the whole 24-module surface is demoable with zero real tenants configured. `secret`/`certificate` go through real Graph/EXO app registration credentials, encrypted at rest by `crypto.ts` ([[Security Infra]]).

## Sync pipeline (live tenants)
`POST /api/tenants/[id]/sync` → [[Tenant Store]].`syncTenant` → [[Core Graph Layer]].`fetchLiveTenantSnapshot`, which fans out to every [[Data Mappers|mapper]] and [[Baseline Matchers|matcher]] in one pass, assembles one `TenantSecuritySnapshot`, and Tenant Store persists it to SQLite. On failure, Tenant Store falls back to the last cached snapshot rather than blanking the UI.

## Read path
Every module receives its slice of `TenantSecuritySnapshot` as a prop from [[AppShell]] :  almost none of the 24 modules fetch on their own for *reads*; fetches are reserved for *writes* (deploy a policy, revoke a delegation, contain a user). This is a consistent pattern worth preserving in any new module.

## Fleet-scale reads
[[Fleet Operations]] and `fleet-analyzer` ([[Analysis & Generation]]) compute rollups by iterating `getAllTenants()` + `getSnapshot()` per tenant :  there is no separate fleet-level cache; fleet views are recomputed from the same per-tenant snapshots on each request.

## Background sync
`scheduler.ts` ([[Security Infra]]) runs `startAutoSyncScheduler()` from `instrumentation.ts` on process start, periodically re-running the sync pipeline above without user interaction.

Part of [[Clarity365 MOC]].
