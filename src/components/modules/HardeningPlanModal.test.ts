import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MOCK_TENANT_DATA } from "@/lib/data/mock-tenants";
import { HardeningPlanModal } from "./HardeningPlanModal";
import { buildHardeningPlan } from "@/lib/services/hardening-plan";

// Server-render smoke test: the plan renders for every demo tenant.
describe("HardeningPlanModal (render smoke test)", () => {
  for (const [tenantId, snapshot] of Object.entries(MOCK_TENANT_DATA)) {
    it(`renders the Hardening plan for ${tenantId}`, () => {
      const html = renderToStaticMarkup(React.createElement(HardeningPlanModal, { snapshot, onClose: () => {}, onOpenGuide: () => {} })).replace(/&#x27;/g, "'");
      expect(html).toContain("Hardening plan");
      const plan = buildHardeningPlan(snapshot);
      for (const e of plan.phases.flatMap((p) => p.entries)) expect(html).toContain(e.guide.title);
      expect(html).toContain("Download script (.ps1)");
    });
  }
});
