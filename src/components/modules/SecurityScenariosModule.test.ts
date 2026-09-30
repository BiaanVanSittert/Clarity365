import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MOCK_TENANT_DATA } from "@/lib/data/mock-tenants";
import { evaluateScenarios } from "@/lib/services/security-scenarios";
import { ScenarioCard, SecurityScenariosModule } from "./SecurityScenariosModule";

// Server-render smoke test (same pattern as the other Security Simulations modules).
describe("SecurityScenariosModule (render smoke test)", () => {
  for (const [tenantId, snapshot] of Object.entries(MOCK_TENANT_DATA)) {
    it(`renders every section for ${tenantId}`, () => {
      const html = renderToStaticMarkup(React.createElement(SecurityScenariosModule, { snapshot, onOpenSituations: () => {} }));
      for (const label of ["Identity &amp; Conditional Access", "Audit &amp; Detection", "Exchange &amp; Email", "SharePoint &amp; Data"]) {
        expect(html).toContain(label);
      }
      expect(html).toContain("Stolen session token replay");
    });
  }

  it("renders every scenario card expanded without crashing", () => {
    for (const result of evaluateScenarios(MOCK_TENANT_DATA["tenant-northwind-health"])) {
      const html = renderToStaticMarkup(React.createElement(ScenarioCard, { result, expanded: true, onToggle: () => {}, onOpenSituations: () => {} }));
      const esc = (t: string) => t.replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
      expect(html).toContain(esc(result.title));
      for (const check of result.checks) expect(html).toContain(esc(check.label));
    }
  });
});
