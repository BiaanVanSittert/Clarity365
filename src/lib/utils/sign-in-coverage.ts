import { SignInCoverage, SignInEvent, TenantSecuritySnapshot } from "../types";

// How much of the tenant's sign-in history the synced list actually covers.
// The sync loads the newest sign-ins first and stops at a page limit, so on a
// busy tenant "the sign-in log" can be a day or two, not the 30 days it looks
// like. Every screen or report built on sign-ins should say which period it
// covers - use getSignInCoverage() + describeSignInCoverage().

export const SIGN_IN_WINDOW_DAYS = 30;

export function computeSignInCoverage(
  signIns: Pick<SignInEvent, "createdDateTime">[],
  outcome: { hitLimit?: boolean; error?: string; windowDays?: number }
): SignInCoverage {
  const times = signIns.map((s) => Date.parse(s.createdDateTime)).filter((t) => !Number.isNaN(t));
  const coverage: SignInCoverage = {
    windowDays: outcome.windowDays ?? SIGN_IN_WINDOW_DAYS,
    count: signIns.length,
    complete: !outcome.hitLimit && !outcome.error,
  };
  if (times.length > 0) {
    coverage.from = new Date(Math.min(...times)).toISOString();
    coverage.to = new Date(Math.max(...times)).toISOString();
  }
  if (outcome.hitLimit) coverage.incompleteReason = "limit";
  else if (outcome.error) coverage.incompleteReason = "error";
  return coverage;
}

// The coverage the sync recorded, or - for demo tenants and snapshots synced
// before coverage was recorded - the best reading of what's stored: the
// period from the records themselves, incomplete if the sync reported a
// sign-in log problem.
export function getSignInCoverage(snapshot: Pick<TenantSecuritySnapshot, "signIns" | "signInCoverage" | "syncHealth">): SignInCoverage {
  if (snapshot.signInCoverage) return snapshot.signInCoverage;
  const signInError = (snapshot.syncHealth?.errors || []).find((e) => e.startsWith("Sign-in logs:"));
  return computeSignInCoverage(snapshot.signIns || [], {
    hitLimit: !!signInError && /safety cap/i.test(signInError),
    error: signInError,
  });
}

// Fixed month names and UTC, so the sentence reads the same on every machine.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const formatDay = (iso: string) => {
  const d = new Date(iso);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
};

// One plain sentence for the UI and reports.
export function describeSignInCoverage(coverage: SignInCoverage): string {
  if (coverage.count === 0 || !coverage.from || !coverage.to) {
    return coverage.complete ? `No sign-ins in the last ${coverage.windowDays} days.` : "No sign-ins were loaded - the sign-in log could not be read.";
  }
  const period = `${formatDay(coverage.from)} to ${formatDay(coverage.to)}`;
  const count = `${coverage.count.toLocaleString("en-US")} sign-in${coverage.count === 1 ? "" : "s"}`;
  if (coverage.complete) return `Covers ${period} (${count}) - everything Microsoft holds for the last ${coverage.windowDays} days.`;
  if (coverage.incompleteReason === "limit") return `Covers ${period} only: the newest ${count}. Older sign-ins were not loaded.`;
  return `Covers ${period} (${count}), but loading stopped early - some sign-ins are missing.`;
}
