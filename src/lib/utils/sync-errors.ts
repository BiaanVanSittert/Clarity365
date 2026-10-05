import { TenantSecuritySnapshot } from "@/lib/types";

// Single source of truth for "does this module's data come from a sync step
// that just failed" - every module reading live-synced data should call this
// with the same prefix(es) graph-client.ts's syncErrors.push() uses for its
// data, rather than re-deriving its own filter (or, as most modules did
// until now, not checking at all and silently rendering stale cached data
// with no indication anything was wrong - see SyncErrorBanner's own comment).
export function getSyncErrorsForPrefixes(snapshot: TenantSecuritySnapshot, prefixes: string[]): string[] {
  const errors = snapshot.syncHealth?.errors || [];
  return errors.filter((e) => !isSyncLimitNotice(e) && prefixes.some((p) => e.startsWith(p)));
}

// A deliberate sync limit ("Groups: ... capped at the first 250 groups ...")
// is not a failure: the data that was read is current, there is just more of
// it than the sync reads. Recorded as a notice, so it no longer marks a
// tenant "degraded", and shown as "partial data" rather than "sync error".
const LIMIT_NOTICE = /capped at the first \d+/i;

export function isSyncLimitNotice(message: string): boolean {
  return LIMIT_NOTICE.test(message);
}

export function splitSyncLimitNotices(messages: string[]): { errors: string[]; notices: string[] } {
  return { errors: messages.filter((m) => !isSyncLimitNotice(m)), notices: messages.filter(isSyncLimitNotice) };
}

// Notices for a module. Snapshots synced before notices existed carry the
// same messages in `errors`; they're read from there too.
export function getSyncNoticesForPrefixes(snapshot: TenantSecuritySnapshot, prefixes: string[]): string[] {
  const all = [...(snapshot.syncHealth?.notices || []), ...(snapshot.syncHealth?.errors || []).filter(isSyncLimitNotice)];
  return [...new Set(all)].filter((m) => prefixes.some((p) => m.startsWith(p)));
}
