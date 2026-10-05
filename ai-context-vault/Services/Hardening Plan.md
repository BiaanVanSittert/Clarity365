---
tags: [service, module, security-simulations]
---

# Hardening Plan

One tenant's outstanding "How to fix" guides, each listed once and in a sensible order. It comes as a printable checklist (HTML, print or save as PDF) and one PowerShell script. Built 2026-10-05 as Stage 4 of [[Scenario Fix Guides Plan]].
- **Hardening plan:** the whole tenant. Opened from the **Hardening plan** button at the top of [[Security Scenarios]].
- **Prevention plan:** one scenario. Opened from **Prevention plan** inside a scenario card.

Guides only: Clarity365 makes no change. The plan is scoped to one tenant. There is no multi-tenant plan, per the no-cross-tenant-actions rule.

## Files
- `src/lib/services/hardening-plan.ts` (+ test). Pure functions of the snapshot.
  - `PLAN_PHASES`: every guide placed in exactly one phase, in a curated order (for example, register MFA before requiring it). A test makes sure each guide is placed once. The phases:
    1. Investigate now
    2. Turn on visibility
    3. (Check what Clarity365 couldn't see)
    4. Close the doors attackers use most
    5. Strengthen sign-in (report-only first)
    6. Reduce standing privilege
    7. Tighten guest access and sharing
  - `buildHardeningPlan(snapshot, { scenarioId?, now? })` → `HardeningPlan`. Each outstanding guide appears once, with every check it addresses. Non-green checks without a guide go into `other`, so the counts always add up.
  - "Investigate now" entries whose checks are all *not assessed* (usually Exchange isn't connected) move to "Check what Clarity365 couldn't see", so an unread check isn't presented as a compromise.
  - `renderHardeningPlanScript(plan)`:
    - Connects once per tool. Microsoft Graph gets the union of every scope the plan needs.
    - Each scripted step sits behind `Confirm-Step` (y/N) and its own try/catch.
    - Portal-only steps appear as comments. Sections with a placeholder are marked `NEEDS EDITING`.
    - The modal downloads it as UTF-8 with a BOM and CRLF line endings, so Windows PowerShell 5.1 reads it too.
  - `renderHardeningPlanHtml(plan)`: one tick box per fix, with the checks it addresses, impact, prerequisites, warnings, every step (portal path, connect line, command), confirm and undo. Every value is HTML-escaped.
- `src/components/modules/HardeningPlanModal.tsx` (+ smoke test): the ordered list with "Open guide" on each entry, and the three downloads (open checklist, download checklist, download script).
- `src/components/common/Modal.tsx`: modals can now stack (a guide opened from the plan). Only the top modal answers Escape. The page scroll lock is released when the last modal closes, whatever order the cleanups run in.

## Verified
Each tenant's plan was generated from the local data (11 live tenants, 4 demo tenants, plus 15 Prevention plans) and parsed by PowerShell 7 and Windows PowerShell 5.1. After the fixes below, all 30 scripts parse cleanly. The scripts were parsed only, never run.

Found by that check and fixed:
- **Unquoted placeholders.** Values like `<your admin account>`, `-Identity <mailbox>`, `<site URL>` and `https://<tenant>-admin...` are a PowerShell parse error, so one of them would have stopped a downloaded script from running at all. The single-command guides were affected the same way. All are quoted now, and a test checks every guide command and plan script.
- **System mailbox listed.** Exchange's built-in `DiscoverySearchMailbox{…}` was listed as a POP/IMAP and SMTP AUTH mailbox to fix. It's now left out of those checks and guides (`isSystemMailbox`).

Part of [[Clarity365 MOC]]. See also [[Scenario Fix Guides Plan]], [[Security Scenarios]].
