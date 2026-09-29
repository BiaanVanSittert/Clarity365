// Phase 3 heuristic flags: pure, tested scoring functions over data
// tenant-store.ts's getAuditLogFlags() has already aggregated with SQL
// (GROUP BY user/hour-bucket) - never over raw per-record arrays, which
// keeps these fast even when the underlying import has up to 1,000,000 rows,
// and testable with small hand-built fixtures. Every flag is a "worth
// investigating" signal, never a verdict - the UI must always show the
// numbers that triggered it, not just a bare badge.
import { MassDeletionFlag, PossibleBecFlag } from "../types";

export interface DeleteCountBucket {
  userId: string;
  hourBucket: string;
  deleteCount: number;
}

export interface InboxRuleChangeBucket {
  userId: string;
  hourBucket: string;
  inboxRuleChangeCount: number;
}

export interface MailAccessCountBucket {
  userId: string;
  hourBucket: string;
  mailItemsAccessedCount: number;
}

// Starting-point thresholds, not statistically derived - deliberately named
// constants so they're easy to find and tune against a real tenant's normal
// activity volume rather than magic numbers buried in a query.
export const DEFAULT_MASS_DELETION_THRESHOLD = 10;
export const DEFAULT_BEC_MAIL_ACCESS_THRESHOLD = 20;

// Hour-bucket grouping is a deliberate simplification, not a precise
// sliding window - a burst spanning a bucket boundary (e.g. 23:58-00:03)
// can be undercounted, split across two buckets that individually don't
// clear the threshold. Documented here and in the plan rather than silently
// assumed to be exact.
export function flagMassDeletionBursts(
  buckets: DeleteCountBucket[],
  threshold: number = DEFAULT_MASS_DELETION_THRESHOLD
): MassDeletionFlag[] {
  return buckets
    .filter((b) => b.deleteCount >= threshold)
    .map((b) => ({ userId: b.userId, hourBucket: b.hourBucket, deleteCount: b.deleteCount }));
}

// Flags a user+hour-bucket only when BOTH signals are present in that same
// bucket: at least one inbox-rule/forwarding change, AND an elevated
// MailItemsAccessed volume. Either signal alone is common and not
// suspicious on its own (users legitimately create inbox rules; mail access
// volume varies) - it's the combination in the same window that's the BEC
// tell in Microsoft's own investigation guidance.
export function flagPossibleBec(
  inboxRuleChanges: InboxRuleChangeBucket[],
  mailAccessCounts: MailAccessCountBucket[],
  threshold: number = DEFAULT_BEC_MAIL_ACCESS_THRESHOLD
): PossibleBecFlag[] {
  const accessByKey = new Map<string, number>();
  for (const a of mailAccessCounts) {
    accessByKey.set(`${a.userId}|${a.hourBucket}`, a.mailItemsAccessedCount);
  }

  const flags: PossibleBecFlag[] = [];
  for (const change of inboxRuleChanges) {
    const key = `${change.userId}|${change.hourBucket}`;
    const accessCount = accessByKey.get(key) ?? 0;
    if (accessCount >= threshold) {
      flags.push({
        userId: change.userId,
        hourBucket: change.hourBucket,
        inboxRuleChangeCount: change.inboxRuleChangeCount,
        mailItemsAccessedCount: accessCount,
      });
    }
  }
  return flags;
}
