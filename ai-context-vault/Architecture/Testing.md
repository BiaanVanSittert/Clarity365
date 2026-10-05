---
tags: [architecture]
---

# Testing

`npm test` → `vitest run` ([[Tech Stack]]). ~25 `*.test.ts` files, almost all in `src/lib/services/`, co-located with the file they test.

## Fully covered
Every [[Baseline Matchers|baseline matcher]], every [[Data Mappers|data mapper]], and every file in [[Analysis & Generation]] except `remediation-generator.ts` has a test. `crypto.ts` ([[Security Infra]]) has a test. `graph-fetch.ts`/`graph-pagination.ts` ([[Core Graph Layer]]) have tests.

## Untested (the gap list)
| File | Why it matters |
|---|---|
| `graph-client.ts` | [[Core Graph Layer]]'s ~1230-line master orchestrator :  the largest, highest-fan-out file in the app |
| `exo-client.ts` | Live Exchange Online writes + OAuth device-code flow |
| `fleet-operations.ts` | [[Fleet Operations]] :  highest blast-radius code path (one call can touch every tenant) |
| `auth.ts` | [[Security Infra]] :  the entire login session's cryptographic verification |
| `rate-limit.ts` | Brute-force protection on login/setup/change-password |
| `scheduler.ts` | Background auto-sync loop |
| `remediation-generator.ts` | Output is shown directly in the UI and returned by an MCP tool to external agents |

UI tests are almost absent (no React Testing Library, no Playwright/Cypress). The one exception is `SignInSituationsModule.test.ts`, a server-render smoke test (`react-dom/server`) that catches render-time crashes; it works because `vitest.config.mjs` compiles JSX with Oxc (`tsconfig.json`'s `jsx: preserve` is for Next.js and can't run under Vite). The same pattern is cheap to reuse for other modules. See [[Optimization Plan]] for prioritization.

**2026-10-01:** 810 tests in 72 files. New: `sync-permission-errors.test.ts` (also guards the permission list), `sign-in-coverage.test.ts`, `sign-in-authentication.test.ts`, `ip-range.test.ts`, `credential-expiry.test.ts`, `signin-report.test.ts` (aggregations, findings, HTML escaping, CSV shape, every demo tenant) and `SignInReportModal.test.ts` (render smoke test). Live behaviour was checked with temporary read-only probe tests (deleted afterwards): the filtered sign-in query, the beta authentication fields, the role-assignment fallback and the secret-expiry lookup.

**Sync all tenants (2026-10-01):** `sync-all.test.ts` (one at a time and in order, failures don't stop the pass, no second pass while running, stop after the current tenant) and `SyncAllTenantsControl.test.ts`. 820 tests in 74 files. Not exercised against live tenants yet.

**2026-10-02:** 855 tests in 77 files. New: `alert-policy-mapper.test.ts`, `scc-client.test.ts` (routing, caching, not-set-up and failure paths; only `fetch` mocked), `scenario-confirmations.test.ts`, and alert-check / confirm-once cases in `security-scenarios.test.ts`.

**2026-10-05:** 878 tests in 79 files. New: `scenario-fix-guide-builder.test.ts` (guide catalogue rules and per-guide resolution) and `FixGuideModal.test.ts` (every guide renders for every demo tenant).

**2026-10-05 (Stage 3 fix guides, CA08):** 1,125 tests in 85 files.
- New: `scenario-fix-guides-stage3.test.ts`. On every demo tenant, a review guide works on items whenever its check lists some. It also covers each guide's commands: exclusions per policy keep break-glass; PIM assigns eligible before removing active; names with quotes are escaped.
- New: `allowed-countries.test.ts`.
- `graph-client.test.ts` gains the CA08 deploy sequence: location, then policy, cleanup on failure, nothing written on bad input.

**2026-10-05 (Stage 2 fix guides):** 1,068 tests in 83 files. New: `ca-policy-impact.test.ts`. It covers sign-in mapping, preview counts and wording. It also proves that every Conditional Access guide's policy, switched on alone, turns the checks it is offered on away from "not prevented" on every demo tenant. Also new: `powershell-literal.test.ts`.

**2026-10-05 (later):** 978 tests in 81 files. `scenario-fix-guide-builder.test.ts` now also covers per-mailbox and per-site commands, the SharePoint admin URL and long-list capping; `single-flight.test.ts` and `sync-errors.test.ts` were added with the sync fixes.

Part of [[Clarity365 MOC]].
