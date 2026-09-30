---
tags: [module, simulation, ca]
---

# CA Gap Analysis

`src/components/modules/CaGapAnalysisModule.tsx`, view id `sim_ca_gaps`, sidebar group **Security Simulations**, with a badge counting critical + high findings. Stage 4 of the [[Security Simulations Plan]]; layout follows the user's reference screenshot (score card, "Coverage by persona" grid, "Policy findings" list). Read-only and tenant-scoped.

## Logic: `src/lib/services/ca-gap-analyzer.ts`
`analyzeCaGaps(snapshot, now, homeCountry)` → score, matrix, findings, severity and policy counts, `needsResync`.

**Matrix** (Admins, Users, Guests, Workload identities × MFA, Phishing-resistant, Managed device, Legacy auth blocked, Sign-in risk, User risk, Session limits, Location restrictions). Each user-persona cell runs a representative sign-in through the [[CA Simulation Engine]] with a synthetic user (matches "All users", guest and role targeting, never an individual exclusion), then asks whether an *applying* policy provides the control. So the grid can't disagree with [[Sign-in Situations]]. States: Enforced, Report-only (only when report-only would close the gap), No policy, Unlicensed (risk without P2; workload identities, whose Workload ID Premium licence can't be detected), Not applicable, Can't confirm.
- Legacy auth needs **both** Exchange ActiveSync and "other clients" blocked; blocking one is "No policy" with a note.
- Not applicable: guests' phishing-resistant, device and risk cells (guest risk is evaluated in the home tenant); users' phishing-resistant unless a policy enforces it (Microsoft recommends it for admins; optional for others).
- Security defaults count as enforced MFA / legacy block when no CA policy is enabled.
- Workload-identity cells come from policies targeting service principals directly (`clientApplications`), not from the engine.

**Score** /10: weighted enforced cells ÷ applicable, licensed cells. Admins MFA, admins phishing-resistant, users MFA, guests MFA, and admins/users legacy block count double. Report-only counts as not enforced. The workload identities row isn't scored. The formula is shown in the score label's tooltip.

**Findings**, most severe first, each with a source, policies, fix, and a Microsoft Learn link (every URL verified 2026-09-30, in `CA_DOCS`):
- Persona coverage: each No policy / Report-only cell (severity per cell).
- Emergency access: enforced policies that block or restrict everyone or every admin with no exclusion (critical if a block, else high); confirm likely break-glass accounts (low).
- Exclusions: accounts individually excluded from policies (high if any is an admin).
- Device registration not covered by location-based blocks (Microsoft: registration ignores location conditions; Clarity365 can't read the tenant device setting, so the finding says so). Security info registration unprotected.
- Microsoft guidance: risk remediation with an authentication strength can't be completed with an external MFA provider (the screenshot's finding).
- Hygiene: report-only over 30 days, disabled policies, risk policies without P2, dangling named-location references, trusted IP ranges larger than /16, security defaults on, device-filter policies (simulation limit).

## UI
Clicking a red, orange or can't-confirm cell, or "Simulate sign-ins" on a finding, opens Sign-in Situations on that persona (`AppShell`'s `simPersona` → `SignInSituationsModule`'s `initialPersona`).

## Live validation (2026-09-30, read-only, all nine tenants)
Scores from 0/10 (Gustav Barkhuysen, everything report-only) to 7/10 (Ashton John's); demo Woodgrove 9/10. Corrections made from the live run: users' phishing-resistant cell no longer scored as a gap; break-glass detection now also judges against enforced policies only (Crimson Line's account was excluded from all 3 enforced policies but only 3 of 10 overall).

Tests: `ca-gap-analyzer.test.ts`, `CaGapAnalysisModule.test.ts` (render smoke test).

Part of [[Clarity365 MOC]].
