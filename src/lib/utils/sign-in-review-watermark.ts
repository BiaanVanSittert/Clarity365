import { SignInEvent } from "@/lib/types";

const STORAGE_KEY_PREFIX = "clarity365_alerts_cleared_";

// Sign-in logs are an event stream, not a point-in-time state (unlike e.g.
// "weak MFA count" or "orphaned users count") - a plain sticky "dismissed"
// flag means once cleared, the badge stays hidden forever even as new risky
// sign-ins keep happening, since nothing ever re-evaluates it. Instead, a
// "reviewed through <timestamp>" watermark is stored: clearing records the
// current moment, and the badge only counts events created after it - so it
// naturally reappears when something new shows up, without ever needing to
// be manually "restored" just to see new activity.
export function isFlaggedSignIn(s: SignInEvent): boolean {
  return s.isRisky || s.status === "ca_blocked" || s.status === "failed";
}

function readStore(tenantId: string): any {
  try {
    const stored = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenantId}`);
    return stored ? JSON.parse(stored) : {};
  } catch {
    return {};
  }
}

function writeStore(tenantId: string, parsed: any): void {
  try {
    localStorage.setItem(`${STORAGE_KEY_PREFIX}${tenantId}`, JSON.stringify(parsed));
    // Same convention modules already use to make the sidebar badge update
    // immediately instead of only on the next tenant switch/reload.
    window.dispatchEvent(new Event("storage"));
  } catch {
    // Ignore - the watermark just won't persist across reloads.
  }
}

export function getSignInLogsReviewedThrough(tenantId: string): string | null {
  return readStore(tenantId).signInLogsReviewedThrough || null;
}

// Records "everything currently flagged has been reviewed" - anything with
// this createdDateTime or earlier stops counting toward the badge.
export function markSignInLogsReviewed(tenantId: string, signIns: SignInEvent[]): void {
  const flaggedTimes = signIns.filter(isFlaggedSignIn).map((s) => new Date(s.createdDateTime).getTime());
  const latest = flaggedTimes.length > 0 ? Math.max(...flaggedTimes) : Date.now();
  const parsed = readStore(tenantId);
  parsed.signInLogsReviewedThrough = new Date(latest).toISOString();
  writeStore(tenantId, parsed);
}

export function clearSignInLogsReviewedWatermark(tenantId: string): void {
  const parsed = readStore(tenantId);
  delete parsed.signInLogsReviewedThrough;
  writeStore(tenantId, parsed);
}

// The sidebar badge count: flagged sign-ins that happened after the last
// review watermark (or all of them, if nothing has been reviewed yet).
export function countUnreviewedFlaggedSignIns(signIns: SignInEvent[], tenantId: string): number {
  const reviewedThrough = getSignInLogsReviewedThrough(tenantId);
  const reviewedThroughMs = reviewedThrough ? new Date(reviewedThrough).getTime() : null;
  return signIns.filter(
    (s) => isFlaggedSignIn(s) && (reviewedThroughMs === null || new Date(s.createdDateTime).getTime() > reviewedThroughMs)
  ).length;
}
