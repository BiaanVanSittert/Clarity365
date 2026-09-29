import { TenantSecuritySnapshot } from "@/lib/types";

// Single source of truth for "does this module's data come from a sync step
// that just failed" - every module reading live-synced data should call this
// with the same prefix(es) graph-client.ts's syncErrors.push() uses for its
// data, rather than re-deriving its own filter (or, as most modules did
// until now, not checking at all and silently rendering stale cached data
// with no indication anything was wrong - see SyncErrorBanner's own comment).
export function getSyncErrorsForPrefixes(snapshot: TenantSecuritySnapshot, prefixes: string[]): string[] {
  const errors = snapshot.syncHealth?.errors || [];
  return errors.filter((e) => prefixes.some((p) => e.startsWith(p)));
}
