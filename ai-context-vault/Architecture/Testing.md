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

Part of [[Clarity365 MOC]].
