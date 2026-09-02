import { describe, it, expect } from "vitest";
import { evaluateTenantCompliance, evaluateFleetCompliance } from "./compliance-evaluator";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { createBlankSnapshot } from "../data/default-snapshot";
import { INITIAL_TENANTS } from "../data/mock-tenants";

describe("compliance-evaluator service", () => {
  const contosoSnap = MOCK_TENANT_DATA["tenant-contoso-corp"];
  const northwindSnap = MOCK_TENANT_DATA["tenant-northwind-health"];
  const fabrikamSnap = MOCK_TENANT_DATA["tenant-fabrikam-logistics"];
  const woodgroveSnap = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  const allSnaps = [contosoSnap, northwindSnap, fabrikamSnap, woodgroveSnap];

  describe("evaluateTenantCompliance - CIS Microsoft 365 v3.0", () => {
    it("evaluates Contoso and scores high compliance on CIS M365", () => {
      const assessment = evaluateTenantCompliance(contosoSnap, "cis_m365_v3");
      expect(assessment.framework).toBe("cis_m365_v3");
      expect(assessment.totalControls).toBeGreaterThanOrEqual(10);
      expect(assessment.scorePercentage).toBeGreaterThanOrEqual(55);
      expect(assessment.compliantCount).toBeGreaterThan(0);
      expect(assessment.level1ScorePercentage).toBeDefined();

      const modernAuthCtrl = assessment.controls.find((c) => c.controlNumber === "1.1.1");
      expect(modernAuthCtrl).toBeDefined();
      expect(modernAuthCtrl?.status).toBe("compliant");
    });

    it("evaluates a blank tenant with low compliance and actionable remediation", () => {
      const blankSnap = createBlankSnapshot(INITIAL_TENANTS[0]);
      const assessment = evaluateTenantCompliance(blankSnap, "cis_m365_v3");
      expect(assessment.scorePercentage).toBeLessThan(50);
      expect(assessment.nonCompliantCount).toBeGreaterThan(3);

      const failedCtrl = assessment.controls.find((c) => c.status === "non_compliant");
      expect(failedCtrl?.remediationGuide.length).toBeGreaterThan(0);
      expect(failedCtrl?.evidence.length).toBeGreaterThan(0);
    });

    it("flags non-compliance on external mail forwarding rules", () => {
      const snapWithExfil = JSON.parse(JSON.stringify(contosoSnap));
      snapWithExfil.emailForwarding = [
        {
          id: "fwd-exfil-test",
          scope: "transport_rule",
          name: "Exfil Rule",
          forwardingAddress: "attacker@external-leak.com",
          isExternal: true,
          state: "Enabled",
          dateCreated: "2026-08-01T00:00:00Z",
          alertLevel: "critical",
        },
      ];

      const assessment = evaluateTenantCompliance(snapWithExfil, "cis_m365_v3");
      const fwdCtrl = assessment.controls.find((c) => c.controlNumber === "2.1.1");
      expect(fwdCtrl?.status).toBe("non_compliant");
      expect(fwdCtrl?.evidence).toContain("exfiltrating messages");
    });

    it("marks P2 risk controls as not_applicable for tenants without Entra P2", () => {
      // Northwind lacks P2
      const assessment = evaluateTenantCompliance(northwindSnap, "cis_m365_v3");
      const userRiskCtrl = assessment.controls.find((c) => c.controlNumber === "1.1.4");
      expect(userRiskCtrl?.status).toBe("not_applicable");
      expect(userRiskCtrl?.evidence).toContain("lacks Microsoft Entra ID Plan 2");
    });
  });

  describe("evaluateTenantCompliance - NIST CSF 2.0 & Essential Eight", () => {
    it("evaluates NIST CSF 2.0 framework controls", () => {
      const assessment = evaluateTenantCompliance(contosoSnap, "nist_csf_v2");
      expect(assessment.framework).toBe("nist_csf_v2");
      expect(assessment.totalControls).toBeGreaterThan(0);
      expect(assessment.controls.some((c) => c.controlNumber === "PR.AC-1")).toBe(true);
    });

    it("evaluates Essential Eight framework controls", () => {
      const assessment = evaluateTenantCompliance(woodgroveSnap, "essential_eight");
      expect(assessment.framework).toBe("essential_eight");
      expect(assessment.totalControls).toBeGreaterThan(0);
      expect(assessment.controls.some((c) => c.controlNumber === "E8.MFA.1")).toBe(true);
    });
  });

  describe("evaluateFleetCompliance", () => {
    it("aggregates compliance across all fleet tenants and computes top failing controls", () => {
      const summary = evaluateFleetCompliance(allSnaps, "cis_m365_v3");
      expect(summary.totalTenantsEvaluated).toBe(4);
      expect(summary.overallFleetCompliancePercentage).toBeGreaterThan(0);
      expect(summary.overallFleetCompliancePercentage).toBeLessThanOrEqual(100);
      expect(summary.tenantAssessments.length).toBe(4);
      expect(Array.isArray(summary.topFailingControls)).toBe(true);
    });
  });
});
