import { describe, it, expect } from "vitest";
import { generateTenantQbrReport, DEFAULT_MSP_BRANDING } from "./report-generator";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { createBlankSnapshot } from "../data/default-snapshot";
import { INITIAL_TENANTS } from "../data/mock-tenants";

describe("report-generator service", () => {
  const contosoSnap = MOCK_TENANT_DATA["tenant-contoso-corp"];
  const blankSnap = createBlankSnapshot(INITIAL_TENANTS[0]);

  it("generates a comprehensive Executive QBR report for Contoso", () => {
    const report = generateTenantQbrReport(contosoSnap, "Q3 2026", {
      mspName: "Apex Cyber Solutions",
      preparedBy: "Sarah Jenkins, CISO",
    });

    expect(report.tenant.displayName).toBe(contosoSnap.tenant.displayName);
    expect(report.branding.mspName).toBe("Apex Cyber Solutions");
    expect(report.branding.preparedBy).toBe("Sarah Jenkins, CISO");
    expect(report.executiveSummary.overallHealthScore).toBeGreaterThanOrEqual(50);
    expect(report.executiveSummary.overallHealthScore).toBeLessThanOrEqual(100);
    expect(report.executiveSummary.keyAchievements.length).toBeGreaterThan(0);
    expect(report.executiveSummary.topActionItems.length).toBeGreaterThan(0);
    expect(report.identityMfaSection.totalUsers).toBeGreaterThan(0);
    expect(report.goldenBaselineSection.policies.length).toBe(10);
    expect(report.costOptimizationSection.reclaimableSeats).toBeDefined();
  });

  it("generates appropriate critical recommendations for a blank/unsecured tenant", () => {
    const report = generateTenantQbrReport(blankSnap, "August 2026");
    expect(report.executiveSummary.overallHealthScore).toBeLessThan(70);
    expect(["needs_attention", "critical_risk"]).toContain(report.executiveSummary.headlineStatus);
    expect(report.goldenBaselineSection.missingCount).toBeGreaterThan(5);
    expect(report.executiveSummary.topActionItems.some((a) => a.includes("missing"))).toBe(true);
  });
});
