---
tags: [service, module, security-simulations]
---

# Sign-in Report

A per-tenant summary of the synced sign-in log that can be printed (or saved as PDF) and downloaded as CSV. Built 2026-10-01 (item 3.1 of [[Recommendations Plan]]). Opened from the **Sign-in report** button in [[Sign-In Logs & CA Diagnostics]].

## Files
- `src/lib/services/signin-report.ts` (+ test): everything is a pure function of the snapshot. No Microsoft calls, so it works on demo tenants.
  - `buildSignInReport(snapshot, { days?, user?, homeCountry?, now? })` → `SignInReport`: headline numbers, tables by country, IP address, user, authentication, app, client and device, and the "worth a look" findings.
  - `signInReportCsvTables(report)` → one table per section (Users, Countries, IPAddresses, Authentication, Apps, Clients, Devices, WorthALook).
  - `renderSignInReportHtml(report)` → a self-contained page with a print button. Every value is HTML-escaped (user and app names come from the tenant).
- `src/components/modals/SignInReportModal.tsx` (+ smoke test): period (7 / 14 / 30 days / everything synced), optional user filter, headline numbers, findings, and the downloads.
- `src/lib/utils/sign-in-authentication.ts` (+ test): `mapSignInAuthentication(raw)` and `describeSignInAuthentication()`.
- `src/lib/utils/sign-in-coverage.ts` (+ test): `computeSignInCoverage`, `getSignInCoverage(snapshot)`, `describeSignInCoverage`.
- `src/lib/utils/ip-range.ts` (+ test): `isIpInCidr` (IPv4 and IPv6), used to match an address to the tenant's IP named locations.

## Where the MFA details come from
Only Microsoft's **beta** sign-in log reports how a sign-in was authenticated (`authenticationRequirement`, `authenticationDetails`); v1.0 has neither (confirmed on Microsoft Learn and with a live read, 2026-10-01). The sync in [[Core Graph Layer]] therefore tries beta first and falls back to v1.0. Stored per sign-in as `SignInEvent.authentication` (`requirement`, `methods`, `fromExistingSession`), plus `userType` and `asn`. `authenticationMethodDetail` (phone numbers, device names) is deliberately not stored. `authenticationMethodsUsed` was empty on every live record, so it isn't used.

Real values: most sign-ins are "Previously satisfied" (the factor came from an existing session), shown as "MFA (already done in this session)". "singleFactor" means MFA **was not required** for that sign-in, not that the account has no MFA; the report words it that way.

## Worth a look (thresholds are constants at the top of the file)
| Finding | Rule | Colour |
|---|---|---|
| Repeated failures then a success | 5+ failed sign-ins in 30 minutes, then a success | red |
| One user in two countries | successes from different countries within 2 hours | red |
| Legacy protocol successes | client isn't Browser / Mobile Apps and Desktop clients | red |
| Risky sign-ins | Microsoft's risk flag | red |
| Successes outside the home country | home = the module's home country (most common by default) | orange |
| New country for a user | first success from a country in the last 7 days of the period, with earlier history elsewhere | orange |
| Succeeded, MFA not required | needs the beta authentication details | orange |

## Honesty rules
- The report prints which period the sign-ins cover (`coverageNote`) and warns when the requested period reaches further back than what was synced (`periodWarning`).
- Without authentication details it says "not available" rather than showing zero.

## Known limit
The sync keeps the newest 5,000 sign-ins. On busy tenants that is a few days, not a month (see [[Recommendations Plan]], new findings).

Part of [[Clarity365 MOC]]. See also [[Sign-in Situations]], [[Domain Types]].
