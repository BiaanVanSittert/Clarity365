import { describe, it, expect, beforeEach } from "vitest";
import { SignInEvent } from "@/lib/types";
import {
  isFlaggedSignIn,
  markSignInLogsReviewed,
  clearSignInLogsReviewedWatermark,
  getSignInLogsReviewedThrough,
  countUnreviewedFlaggedSignIns,
} from "./sign-in-review-watermark";

// This suite runs under vitest's default Node environment (no DOM) - the
// module under test already guards every localStorage/window access in
// try/catch for exactly that reason, but that means without these minimal
// globals every write would silently no-op instead of actually exercising
// the watermark logic. A tiny in-memory shim is enough; no need for jsdom.
class MemoryStorage {
  private store: Record<string, string> = {};
  getItem(key: string) {
    return Object.prototype.hasOwnProperty.call(this.store, key) ? this.store[key] : null;
  }
  setItem(key: string, value: string) {
    this.store[key] = value;
  }
  removeItem(key: string) {
    delete this.store[key];
  }
  clear() {
    this.store = {};
  }
}
(globalThis as any).localStorage = new MemoryStorage();
(globalThis as any).window = { dispatchEvent: () => {} };

function makeSignIn(overrides: Partial<SignInEvent>): SignInEvent {
  return {
    id: "s1",
    createdDateTime: "2026-09-01T00:00:00Z",
    userPrincipalName: "user@contoso.com",
    userDisplayName: "User",
    userId: "u1",
    ipAddress: "1.2.3.4",
    location: { city: "", state: "", country: "" },
    clientApp: "browser",
    appDisplayName: "App",
    status: "success",
    errorCode: 0,
    isRisky: false,
    riskLevel: "none",
    deviceDetail: { operatingSystem: "", browser: "", isCompliant: false, isManaged: false },
    appliedConditionalAccessPolicies: [],
    hasReportOnlyFailure: false,
    reportOnlyFailedPolicies: [],
    ...overrides,
  } as SignInEvent;
}

describe("sign-in-review-watermark", () => {
  const tenantId = "test-tenant-watermark";

  beforeEach(() => {
    localStorage.clear();
  });

  it("isFlaggedSignIn flags risky, CA-blocked, and failed sign-ins only", () => {
    expect(isFlaggedSignIn(makeSignIn({ isRisky: true }))).toBe(true);
    expect(isFlaggedSignIn(makeSignIn({ status: "ca_blocked" }))).toBe(true);
    expect(isFlaggedSignIn(makeSignIn({ status: "failed" }))).toBe(true);
    expect(isFlaggedSignIn(makeSignIn({ status: "success" }))).toBe(false);
  });

  it("counts every flagged sign-in when nothing has been reviewed yet", () => {
    const signIns = [
      makeSignIn({ id: "a", isRisky: true, createdDateTime: "2026-09-01T00:00:00Z" }),
      makeSignIn({ id: "b", status: "failed", createdDateTime: "2026-09-02T00:00:00Z" }),
      makeSignIn({ id: "c", status: "success", createdDateTime: "2026-09-03T00:00:00Z" }),
    ];
    expect(countUnreviewedFlaggedSignIns(signIns, tenantId)).toBe(2);
    expect(getSignInLogsReviewedThrough(tenantId)).toBeNull();
  });

  it("drops the count to zero after marking reviewed, then only counts sign-ins newer than the watermark", () => {
    const signIns = [
      makeSignIn({ id: "a", isRisky: true, createdDateTime: "2026-09-01T00:00:00Z" }),
      makeSignIn({ id: "b", status: "failed", createdDateTime: "2026-09-02T00:00:00Z" }),
    ];
    markSignInLogsReviewed(tenantId, signIns);
    expect(countUnreviewedFlaggedSignIns(signIns, tenantId)).toBe(0);

    // A new flagged sign-in created after the watermark should surface again
    // without needing to be "restored" first.
    const withNewEvent = [
      ...signIns,
      makeSignIn({ id: "c", status: "ca_blocked", createdDateTime: "2026-09-03T00:00:00Z" }),
    ];
    expect(countUnreviewedFlaggedSignIns(withNewEvent, tenantId)).toBe(1);
  });

  it("restoring the watermark goes back to counting every flagged sign-in", () => {
    const signIns = [makeSignIn({ id: "a", isRisky: true })];
    markSignInLogsReviewed(tenantId, signIns);
    expect(countUnreviewedFlaggedSignIns(signIns, tenantId)).toBe(0);

    clearSignInLogsReviewedWatermark(tenantId);
    expect(getSignInLogsReviewedThrough(tenantId)).toBeNull();
    expect(countUnreviewedFlaggedSignIns(signIns, tenantId)).toBe(1);
  });

  it("marking reviewed with zero currently-flagged sign-ins still sets a watermark, so future ones still surface", () => {
    markSignInLogsReviewed(tenantId, []);
    expect(getSignInLogsReviewedThrough(tenantId)).not.toBeNull();

    const laterEvent = [makeSignIn({ id: "z", isRisky: true, createdDateTime: "2099-01-01T00:00:00Z" })];
    expect(countUnreviewedFlaggedSignIns(laterEvent, tenantId)).toBe(1);
  });
});
