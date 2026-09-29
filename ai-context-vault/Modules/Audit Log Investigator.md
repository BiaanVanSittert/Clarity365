---
tags: [module, security]
---

# Audit Log Investigator

Ingests a Microsoft Purview unified audit log CSV export and gives it a much better search than Purview's own audit search UI - specifically built for Session ID / client correlation, the technique Microsoft's own docs recommend for telling attacker activity apart from a legitimate user's activity in a compromised mailbox. This is a distinct concept from [[Audit Log Viewer]] (this app's own operator activity log) - the two share the word "audit" but nothing else; naming was deliberately kept apart (`UnifiedAuditLogRecord`/`UnifiedAuditLogImport` vs. `AuditLogEntry`, `ual_records`/`ual_imports` tables vs. `audit_log`) to avoid the confusion.

- **Component:** `AuditLogInvestigatorModule.tsx`
- **Key types:** `UnifiedAuditLogRecord`, `UnifiedAuditLogImport`, `UnifiedAuditLogSearchFilters`, `UnifiedAuditLogSearchResult`, `UnifiedAuditLogImportProgress` - see [[Domain Types]]
- **Parser:** `src/lib/services/audit-log-parser.ts` (new, tested) - pure `mapCsvRowToRecord()`, isolated from the actual streaming so per-record-type field hoisting is testable with hand-built fixtures, same convention as `asr-configuration-mapper.ts`/`sign-in-country.ts`
- **Storage:** two new [[Tenant Store]] tables, `ual_imports` and `ual_records` (indexed on tenant+session/user/operation/date) - a real relational table, not the JSON-blob-per-row convention the rest of this app uses, specifically because a single import can be up to 1,000,000 rows (Purview Audit Premium's own export cap) and needs indexed lookups, not a full JS-side scan
- **API routes (8, all under `/api/tenants/[id]/audit-log/`):** `upload` (POST, streaming ingest), `import-progress` (GET, polled), `imports` (GET list / DELETE one), `search` (GET, filtered+paginated+faceted), `session/[sessionId]` (GET, chronological timeline), `typeahead` (GET, autocomplete for Session ID/User/Client fields), `template-counts` (GET, Phase 2), `flags` (GET, Phase 3)
- **Templates:** `src/lib/data/audit-investigation-templates.ts` (new) - `AUDIT_INVESTIGATION_TEMPLATES`, same plain-data convention as `mdo-baseline-definitions.ts`/`asr-rule-definitions.ts`
- **Heuristics:** `src/lib/services/audit-log-heuristics.ts` (new, tested) - `flagMassDeletionBursts`, `flagPossibleBec`, pure functions over SQL-pre-aggregated input (never raw per-record scans)

## What the CSV actually looks like (verified against Microsoft's own docs, not assumed)

The Purview portal's export always has exactly four columns - `CreationDate`, `UserIds`, `Operations`, `AuditData` (a JSON string whose shape varies by `RecordType`). A PowerShell export (`Search-UnifiedAuditLog | Export-Csv`) may add a fifth `RecordType` column, but that value also always lives inside the `AuditData` JSON, so the parser never assumes any column exists except `AuditData`. One malformed row's JSON degrades to a best-effort record (`parseError: true`, hoisted fields fall back to the plain CSV columns) rather than aborting the whole import.

There is **no consistently-present structured Device ID** in Microsoft's general AuditData reference - checked specifically before building this. "Client / Device text" search works off whatever free-text client-identifying field each record type actually carries (`ClientInfoString`, `ClientIPAddress`/`ClientIP`, or an Entra ID `DeviceProperties`/`ExtendedProperties` array), not a guaranteed GUID.

## Session Timeline - the actual point of this module

`SessionId` + `ClientIPAddress` + `ClientInfoString` is Microsoft's own documented technique (from "Use MailItemsAccessed to investigate compromised accounts") for telling attacker activity apart from the legitimate user's own activity in one session. Clicking a Session ID anywhere in search opens a drawer showing every record sharing that session, chronological, with a banner that fires when the session spans 2+ distinct Client IPs - the direct automated version of that technique, framed as "worth investigating," not a verdict.

## Ingestion: genuine streaming, not a two-pass count

The upload route reads the multipart file as a Web `ReadableStream`, converts it with `Readable.fromWeb`, and feeds it directly into `Papa.parse()`'s Node-stream mode (`step` callback per row) - so a 1,000,000-row file is never materialized as one JS array of row objects. Rows are batched (500 at a time) into a `better-sqlite3` transaction before being discarded. Because the total row count isn't known until the stream ends, import progress (reused via the same globalThis-cached-Map polling convention as [[Tenant Store]]'s sync progress) reports a live rows-processed counter rather than a percentage - a deliberate, disclosed scope choice, not an oversight.

`UnifiedAuditLogImport.possiblyCapped`/`exportCapWarning` fires when a file's row count lands at or past Purview's own export caps (50,000 Standard / 1,000,000 Premium) - a nudge that the uploaded window may be an incomplete slice, not a claim about which plan produced the file.

## Phase 2 - Investigation Templates

Four one-click canned filters (`bec`, `mass_deletion`, `external_sharing`, `privilege_escalation`), each just an operation-name list. The External Sharing and Privilege Escalation operation lists were left vague in the original plan ("sharing-link and anonymous-access operations", "role/permission-grant operations") and got verified against Microsoft Learn before implementation - real values, not invented: `SharingInvitationCreated`/`AnonymousLinkCreated`/etc. for sharing, `Add member to role.`/`Consent to application.`/`Add-RoleGroupMember`/etc. for privilege escalation (spanning all three real M365 privilege-escalation vectors: Entra ID directory roles, Exchange RBAC, and OAuth consent-grant attacks).

A template sets `UnifiedAuditLogSearchFilters.operations` (plural, `operation IN (...)`) - deliberately kept separate from the pre-existing singular `operation` (the manual dropdown, exact-match) rather than merged, since the two are mutually exclusive in the UI but the store accepts either independently. `getAuditLogTemplateCounts()` runs one indexed `COUNT(*) WHERE operation IN (...)` per template so each button shows a real count, not a guess.

## Phase 3 - Heuristic Flags

Three flags, `getAuditLogFlags()` in [[Tenant Store]], each split the same way: SQL does the expensive aggregation over the whole imported dataset (up to 1,000,000 rows), a pure tested function in `audit-log-heuristics.ts` makes the actual flagging decision over the small aggregated result - the same "hoist a pure classification function out of the data-fetching" convention as `permission-license-check.ts`'s `applyLicenseAwareStatus`.

- **Session hijack / AiTM**: pure SQL (`GROUP BY session_id HAVING COUNT(DISTINCT client_ip) >= 2`) - no JS scoring needed. This is the same signal Phase 1's Session Timeline already showed ad hoc for one session; Phase 3 promotes it to a tenant-wide scan.
- **Mass deletion**: delete-flavored operations (same list as the Mass Deletion template) bucketed by user + hour (`strftime('%Y-%m-%dT%H', creation_date)`), scored by `flagMassDeletionBursts()` against `DEFAULT_MASS_DELETION_THRESHOLD` (10, a named starting-point constant, not statistically derived).
- **Possible BEC**: two SQL aggregations (inbox-rule/forwarding-change counts; `MailItemsAccessed` counts) joined by user+hour-bucket and scored by `flagPossibleBec()` against `DEFAULT_BEC_MAIL_ACCESS_THRESHOLD` (20) - flags only when BOTH signals land in the same bucket, since either alone is common and not suspicious by itself.

The hour-bucket grouping is a deliberate, disclosed simplification, not a precise sliding window - a burst spanning a bucket boundary (23:58-00:03) can be undercounted, split across two buckets that individually don't clear the threshold.

Part of [[Clarity365 MOC]]. See also [[Sign-In Logs & CA Diagnostics]] for the live, Graph-sourced counterpart this module deliberately doesn't try to replace - that module is the fuller picture for interactive sign-in brute-force analysis, this one is for whatever's in an uploaded Purview export.
