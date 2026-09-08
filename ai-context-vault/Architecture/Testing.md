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
| `graph-client.ts` | [[Core Graph Layer]]'s ~1230-line master orchestrator — the largest, highest-fan-out file in the app |
| `exo-client.ts` | Live Exchange Online writes + OAuth device-code flow |
| `fleet-operations.ts` | [[Fleet Operations]] — highest blast-radius code path (one call can touch every tenant) |
| `auth.ts` | [[Security Infra]] — the entire login session's cryptographic verification |
| `rate-limit.ts` | Brute-force protection on login/setup/change-password |
| `scheduler.ts` | Background auto-sync loop |
| `remediation-generator.ts` | Output is shown directly in the UI and returned by an MCP tool to external agents |

No UI/component tests exist at all (no React Testing Library, no Playwright/Cypress) — all ~25 tests are service-layer unit tests. See [[Optimization Plan]] for prioritization.

Part of [[Clarity365 MOC]].
