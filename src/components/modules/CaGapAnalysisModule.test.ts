import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MOCK_TENANT_DATA } from "@/lib/data/mock-tenants";
import { CaGapAnalysisModule } from "./CaGapAnalysisModule";

// Server-render smoke test (same pattern as SignInSituationsModule.test.ts).
describe("CaGapAnalysisModule (render smoke test)", () => {
  for (const [tenantId, snapshot] of Object.entries(MOCK_TENANT_DATA)) {
    it(`renders the score, grid and findings for ${tenantId}`, () => {
      const html = renderToStaticMarkup(React.createElement(CaGapAnalysisModule, { snapshot, onOpenSituations: () => {} }));
      expect(html).toContain("Conditional Access Score");
      expect(html).toContain("Coverage by persona");
      expect(html).toContain("Workload identities");
      expect(html).toContain("Policy findings");
    });
  }

  it("links findings to Microsoft documentation in a new tab", () => {
    const html = renderToStaticMarkup(React.createElement(CaGapAnalysisModule, { snapshot: MOCK_TENANT_DATA["tenant-fabrikam-logistics"] }));
    expect(html).toContain('href="https://learn.microsoft.com/');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
  });
});
