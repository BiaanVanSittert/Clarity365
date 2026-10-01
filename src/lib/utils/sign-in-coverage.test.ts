import { describe, expect, it } from "vitest";
import { computeSignInCoverage, describeSignInCoverage, getSignInCoverage } from "./sign-in-coverage";

const at = (iso: string) => ({ createdDateTime: iso });
const THREE = [at("2026-09-30T10:00:00Z"), at("2026-09-28T08:00:00Z"), at("2026-09-29T23:59:00Z")];

describe("computeSignInCoverage", () => {
  it("reports the oldest and newest record and marks a clean fetch complete", () => {
    expect(computeSignInCoverage(THREE, {})).toEqual({
      windowDays: 30,
      count: 3,
      complete: true,
      from: "2026-09-28T08:00:00.000Z",
      to: "2026-09-30T10:00:00.000Z",
    });
  });

  it("marks the page limit as incomplete, not as an error", () => {
    expect(computeSignInCoverage(THREE, { hitLimit: true, error: "Stopped after 20 pages (safety cap)" })).toMatchObject({ complete: false, incompleteReason: "limit" });
  });

  it("marks a failed fetch incomplete with whatever was loaded", () => {
    expect(computeSignInCoverage(THREE, { error: "Request timed out" })).toMatchObject({ complete: false, incompleteReason: "error", count: 3 });
    expect(computeSignInCoverage([], { error: "Request timed out" })).toEqual({ windowDays: 30, count: 0, complete: false, incompleteReason: "error" });
  });
});

describe("getSignInCoverage", () => {
  it("uses what the sync recorded when present", () => {
    const stored = { windowDays: 30, count: 9, complete: true };
    expect(getSignInCoverage({ signIns: [], signInCoverage: stored })).toBe(stored);
  });

  it("reads older snapshots from their records and the sync's sign-in error", () => {
    const capped = getSignInCoverage({
      signIns: THREE as any,
      syncHealth: { isPartial: true, lastAttemptAt: "", errors: ["Sign-in logs: Stopped after 20 pages (safety cap) - more records may exist."] },
    });
    expect(capped).toMatchObject({ complete: false, incompleteReason: "limit", count: 3 });

    const timedOut = getSignInCoverage({ signIns: THREE as any, syncHealth: { isPartial: true, lastAttemptAt: "", errors: ["Sign-in logs: Request timed out"] } });
    expect(timedOut.incompleteReason).toBe("error");

    // An unrelated error doesn't make sign-ins look incomplete.
    expect(getSignInCoverage({ signIns: THREE as any, syncHealth: { isPartial: true, lastAttemptAt: "", errors: ["Groups: failed"] } }).complete).toBe(true);
  });
});

describe("describeSignInCoverage", () => {
  it("says plainly what period is covered and when it's only the newest records", () => {
    expect(describeSignInCoverage(computeSignInCoverage(THREE, {}))).toBe("Covers 28 Sep 2026 to 30 Sep 2026 (3 sign-ins) - everything Microsoft holds for the last 30 days.");
    expect(describeSignInCoverage(computeSignInCoverage(THREE, { hitLimit: true }))).toBe("Covers 28 Sep 2026 to 30 Sep 2026 only: the newest 3 sign-ins. Older sign-ins were not loaded.");
    expect(describeSignInCoverage(computeSignInCoverage(THREE, { error: "x" }))).toMatch(/loading stopped early/);
  });

  it("handles an empty log", () => {
    expect(describeSignInCoverage(computeSignInCoverage([], {}))).toBe("No sign-ins in the last 30 days.");
    expect(describeSignInCoverage(computeSignInCoverage([], { error: "x" }))).toMatch(/could not be read/);
  });
});
