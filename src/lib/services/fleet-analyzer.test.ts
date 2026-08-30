import { describe, it, expect } from "vitest";
import {
  computeTenantCompositeRiskScore,
  calculateTenantMonthlyWaste,
  aggregateFleetFailingBaselines,
  computeFleetPosture,
  computeFleetLicenseWaste,
  searchAcrossFleet,
  LICENSE_TIER_MONTHLY_COST,
} from "./fleet-analyzer";
import { INITIAL_TENANTS, MOCK_TENANT_DATA } from "../data/mock-tenants";
import { createBlankSnapshot } from "../data/default-snapshot";

describe("fleet-analyzer service", () => {
  const contosoSnap = MOCK_TENANT_DATA["tenant-contoso-corp"];
  const northwindSnap = MOCK_TENANT_DATA["tenant-northwind-health"];
  const fabrikamSnap = MOCK_TENANT_DATA["tenant-fabrikam-logistics"];
  const woodgroveSnap = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  const allSnapshots = [contosoSnap, northwindSnap, fabrikamSnap, woodgroveSnap];

  describe("computeTenantCompositeRiskScore", () => {
    it("computes reasonable composite risk score and level for Contoso", () => {
      const result = computeTenantCompositeRiskScore(contosoSnap);
      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(["critical", "high", "medium", "low"]).toContain(result.level);
      expect(result.factors).toBeDefined();
      expect(result.factors.secureScoreDeficit).toBeDefined();
      expect(result.factors.activeIncidents).toBeDefined();
    });

    it("evaluates a completely blank/pristine snapshot cleanly without crashing", () => {
      const blankSnap = createBlankSnapshot(INITIAL_TENANTS[0]);
      const result = computeTenantCompositeRiskScore(blankSnap);
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });

  describe("calculateTenantMonthlyWaste", () => {
    it("detects licensed shared mailboxes and computes dollar waste based on license tier", () => {
      const wasteResult = calculateTenantMonthlyWaste(contosoSnap);
      expect(wasteResult.monthlyWasteUsd).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(wasteResult.items)).toBe(true);

      const sharedMbWaste = wasteResult.items.filter((i) => i.category === "licensed_shared_mailbox");
      if (sharedMbWaste.length > 0) {
        expect(sharedMbWaste[0].estimatedMonthlyCostUsd).toBe(LICENSE_TIER_MONTHLY_COST["M365_E5"]);
        expect(sharedMbWaste[0].remediationModule).toBe("mailboxes");
      }
    });

    it("returns zero waste for a snapshot with no waste indicators", () => {
      const blankSnap = createBlankSnapshot(INITIAL_TENANTS[1]);
      blankSnap.mailboxes = [];
      blankSnap.accountClassification.users = [];
      const wasteResult = calculateTenantMonthlyWaste(blankSnap);
      expect(wasteResult.monthlyWasteUsd).toBe(0);
      expect(wasteResult.items.length).toBe(0);
    });
  });

  describe("aggregateFleetFailingBaselines", () => {
    it("aggregates and ranks failing baselines across all 4 mock tenants", () => {
      const failures = aggregateFleetFailingBaselines(allSnapshots);
      expect(failures.length).toBeGreaterThan(0);
      // Ensure sorted descending
      for (let i = 1; i < failures.length; i++) {
        expect(failures[i - 1].failingTenantsCount).toBeGreaterThanOrEqual(failures[i].failingTenantsCount);
      }
      expect(failures[0].failingTenantNames.length).toBe(failures[0].failingTenantsCount);
    });
  });

  describe("computeFleetPosture", () => {
    it("computes fleet-wide posture summary correctly", () => {
      const summary = computeFleetPosture(INITIAL_TENANTS, allSnapshots);
      expect(summary.totalTenants).toBe(4);
      expect(summary.totalManagedUsers).toBeGreaterThan(0);
      expect(summary.totalManagedDevices).toBeGreaterThan(0);
      expect(summary.averageSecureScore).toBeGreaterThan(0);
      expect(summary.tenants.length).toBe(4);
      expect(summary.recentCrossTenantIncidents.length).toBeGreaterThan(0);
      expect(summary.topFailingBaselines.length).toBeGreaterThan(0);
    });
  });

  describe("computeFleetLicenseWaste", () => {
    it("computes total monthly and annual license waste rollup across fleet", () => {
      const rollup = computeFleetLicenseWaste(allSnapshots);
      expect(rollup.totalMonthlyWasteUsd).toBeGreaterThanOrEqual(0);
      expect(rollup.totalAnnualWasteUsd).toBe(rollup.totalMonthlyWasteUsd * 12);
      expect(rollup.wasteByCategory).toBeDefined();
      expect(Array.isArray(rollup.items)).toBe(true);
    });
  });

  describe("searchAcrossFleet", () => {
    it("searches users by UPN or name across all tenants", () => {
      const results = searchAcrossFleet(allSnapshots, "sarah.chen");
      expect(results.length).toBeGreaterThan(0);
      const userMatch = results.find((r) => r.category === "user");
      expect(userMatch).toBeDefined();
      expect(userMatch?.tenantName).toBeDefined();
      expect(userMatch?.targetModule).toBe("user_class");
    });

    it("searches incidents by keyword or ID", () => {
      const results = searchAcrossFleet(allSnapshots, "token");
      expect(results.some((r) => r.category === "incident")).toBe(true);
    });

    it("searches devices by name or OS", () => {
      const results = searchAcrossFleet(allSnapshots, "CONTRACTOR-DELL");
      expect(results.some((r) => r.category === "device")).toBe(true);
    });

    it("respects category filter", () => {
      const userOnly = searchAcrossFleet(allSnapshots, "admin", "user");
      expect(userOnly.length).toBeGreaterThan(0);
      expect(userOnly.every((r) => r.category === "user")).toBe(true);
    });

    it("returns empty array for empty query or no match", () => {
      expect(searchAcrossFleet(allSnapshots, "")).toEqual([]);
      expect(searchAcrossFleet(allSnapshots, "nonexistent-xyz-indicator-999")).toEqual([]);
    });
  });

  describe("resolveUserLastSignIn and license inventory", () => {
    it("accurately classifies recent sign-in users (<90d) as active licensed users", () => {
      const wasteResult = calculateTenantMonthlyWaste(contosoSnap);
      const activeUsers = wasteResult.items.filter((i) => i.category === "active_licensed_user");
      expect(activeUsers.length).toBeGreaterThan(0);
      for (const u of activeUsers) {
        expect(u.accountState).toBe("active");
        expect(u.daysInactive).toBeDefined();
        expect(u.daysInactive!).toBeLessThanOrEqual(90);
      }
    });

    it("accurately classifies users without sign-ins for >90d as dormant/inactive licensed users", () => {
      const wasteResult = calculateTenantMonthlyWaste(contosoSnap);
      const dormantUsers = wasteResult.items.filter((i) => i.category === "inactive_licensed_user");
      expect(dormantUsers.length).toBeGreaterThan(0);
      for (const u of dormantUsers) {
        expect(u.accountState).toBe("dormant");
        expect(u.daysInactive).toBeDefined();
        expect(u.daysInactive!).toBeGreaterThan(90);
      }
    });

    it("identifies disabled accounts still holding paid licenses as waste", () => {
      const wasteResult = calculateTenantMonthlyWaste(contosoSnap);
      const disabledWithLicense = wasteResult.items.filter((i) => i.category === "disabled_licensed_user");
      expect(disabledWithLicense.length).toBeGreaterThan(0);
      for (const u of disabledWithLicense) {
        expect(u.accountState).toBe("disabled");
        expect(u.estimatedMonthlyCostUsd).toBe(LICENSE_TIER_MONTHLY_COST["M365_E5"]);
      }
    });
  });
});
