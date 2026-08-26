import { describe, it, expect } from "vitest";
import { computeExchangeMailflowScore } from "./exchange-mailflow-score";
import { createBlankSnapshot } from "../data/default-snapshot";
import { Tenant } from "../types";

function blankTenant(): Tenant {
  return {
    id: "t1",
    displayName: "Test Tenant",
    defaultDomainName: "contoso.com",
    credentials: { authMode: "mock" },
  } as unknown as Tenant;
}

describe("computeExchangeMailflowScore", () => {
  it("computes a well-formed percentage on a fully blank snapshot", () => {
    const snapshot = createBlankSnapshot(blankTenant());
    const result = computeExchangeMailflowScore(snapshot);
    // MDO's checks all report "no policy found" (not met) with an empty
    // policy list, but the Mail Flow Rules "does anything violate this"
    // checks (MF01/02/03/05/06) are vacuously met when there are no rules or
    // connectors at all to violate them — so a blank snapshot doesn't score
    // literal 0%, it reflects that mix.
    expect(result.totalCount).toBeGreaterThan(0);
    expect(result.percent).toBeGreaterThanOrEqual(0);
    expect(result.percent).toBeLessThanOrEqual(100);
    expect(result.metCount).toBeLessThan(result.totalCount);
  });

  it("excludes the audit-logging gate from the total until it's actually synced", () => {
    const withoutAudit = computeExchangeMailflowScore(createBlankSnapshot(blankTenant()));
    const snapshotWithAudit = { ...createBlankSnapshot(blankTenant()), mailboxAuditingEnabled: true };
    const withAudit = computeExchangeMailflowScore(snapshotWithAudit);
    expect(withAudit.totalCount).toBe(withoutAudit.totalCount + 1);
    expect(withAudit.metCount).toBe(withoutAudit.metCount + 1);
  });
});
