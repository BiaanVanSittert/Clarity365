import { describe, it, expect } from "vitest";
import {
  evaluateTenantDrift,
  evaluateFleetDrift,
  realignFindingLocally,
  tenantHasEntraP2,
  DEFAULT_GOLDEN_BASELINE,
} from "./drift-analyzer";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { createBlankSnapshot } from "../data/default-snapshot";
import { INITIAL_TENANTS } from "../data/mock-tenants";

describe("drift-analyzer service", () => {
  const contosoSnap = MOCK_TENANT_DATA["tenant-contoso-corp"];
  const northwindSnap = MOCK_TENANT_DATA["tenant-northwind-health"];
  const fabrikamSnap = MOCK_TENANT_DATA["tenant-fabrikam-logistics"];
  const woodgroveSnap = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  const allSnapshots = [contosoSnap, northwindSnap, fabrikamSnap, woodgroveSnap];

  describe("tenantHasEntraP2", () => {
    it("detects Entra ID P2 for Contoso (M365 E5) and Woodgrove (M365 E5)", () => {
      expect(tenantHasEntraP2(contosoSnap)).toBe(true);
      expect(tenantHasEntraP2(woodgroveSnap)).toBe(true);
    });

    it("evaluates false for Fabrikam (M365 E3) and Northwind (Business Premium)", () => {
      expect(tenantHasEntraP2(fabrikamSnap)).toBe(false);
      expect(tenantHasEntraP2(northwindSnap)).toBe(false);
    });
  });

  describe("evaluateTenantDrift", () => {
    it("evaluates Contoso and returns structured drift findings and alignment score", () => {
      const assessment = evaluateTenantDrift(contosoSnap);
      expect(assessment.tenantId).toBe("tenant-contoso-corp");
      expect(assessment.alignmentScore).toBeGreaterThanOrEqual(0);
      expect(assessment.alignmentScore).toBeLessThanOrEqual(100);
      expect(["in_sync", "minor_drift", "critical_drift"]).toContain(assessment.status);
      expect(Array.isArray(assessment.findings)).toBe(true);
    });

    it("evaluates a blank tenant cleanly with appropriate missing baseline findings", () => {
      const blankSnap = createBlankSnapshot(INITIAL_TENANTS[0]);
      const assessment = evaluateTenantDrift(blankSnap);
      expect(assessment.alignmentScore).toBeLessThan(70);
      expect(assessment.status).toBe("critical_drift");
      expect(assessment.findings.some((f) => f.ruleCode === "CA01")).toBe(true);
    });

    it("flags external forwarding rules as critical mailflow drift", () => {
      const snapWithFwd = JSON.parse(JSON.stringify(contosoSnap));
      snapWithFwd.emailForwarding = [
        {
          id: "fwd-test-01",
          scope: "transport_rule",
          name: "Exfil Rule",
          forwardingAddress: "attacker@external-evil.com",
          isExternal: true,
          state: "Enabled",
          dateCreated: "2026-08-20T00:00:00Z",
          alertLevel: "critical",
        },
      ];
      const assessment = evaluateTenantDrift(snapWithFwd);
      const fwdDrift = assessment.findings.find((f) => f.ruleCode === "SEC-FWD-01");
      expect(fwdDrift).toBeDefined();
      expect(fwdDrift?.severity).toBe("critical");
      expect(fwdDrift?.remediationSupported).toBe(true);
    });
  });

  describe("evaluateFleetDrift", () => {
    it("aggregates fleet drift across all 4 customer tenants", () => {
      const fleetSummary = evaluateFleetDrift(allSnapshots);
      expect(fleetSummary.totalTenantsEvaluated).toBe(4);
      expect(fleetSummary.overallFleetAlignmentPercentage).toBeGreaterThan(0);
      expect(fleetSummary.overallFleetAlignmentPercentage).toBeLessThanOrEqual(100);
      expect(fleetSummary.tenantAssessments.length).toBe(4);
      expect(fleetSummary.allFindings.length).toBeGreaterThan(0);
    });
  });

  describe("realignFindingLocally", () => {
    it("realigns a missing CA baseline finding by injecting report-only policy", () => {
      const blankSnap = createBlankSnapshot(INITIAL_TENANTS[0]);
      const initialAssessment = evaluateTenantDrift(blankSnap);
      const ca01Finding = initialAssessment.findings.find((f) => f.ruleCode === "CA01");
      expect(ca01Finding).toBeDefined();

      const realignedSnap = realignFindingLocally(blankSnap, ca01Finding!);
      const postAssessment = evaluateTenantDrift(realignedSnap);
      expect(postAssessment.findings.some((f) => f.ruleCode === "CA01" && f.actualState === "Missing (Not Deployed)")).toBe(false);
    });

    it("realigns external forwarding rules by disabling them", () => {
      const snapWithFwd = JSON.parse(JSON.stringify(contosoSnap));
      snapWithFwd.emailForwarding = [
        {
          id: "fwd-test-01",
          scope: "transport_rule",
          name: "Exfil Rule",
          forwardingAddress: "attacker@external-evil.com",
          isExternal: true,
          state: "Enabled",
          dateCreated: "2026-08-20T00:00:00Z",
          alertLevel: "critical",
        },
      ];
      const assessment = evaluateTenantDrift(snapWithFwd);
      const fwdFinding = assessment.findings.find((f) => f.ruleCode === "SEC-FWD-01")!;
      const realigned = realignFindingLocally(snapWithFwd, fwdFinding);
      expect(realigned.emailForwarding?.[0].state).toBe("Disabled");
    });
  });
});
