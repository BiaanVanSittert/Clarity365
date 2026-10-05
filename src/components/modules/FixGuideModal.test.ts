import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MOCK_TENANT_DATA } from "@/lib/data/mock-tenants";
import { FIX_GUIDES } from "@/lib/data/scenario-fix-guides";
import { buildFixGuide } from "@/lib/services/scenario-fix-guide-builder";
import { FixGuideModal } from "./FixGuideModal";

// Server-render smoke test: every guide renders for every demo tenant.
describe("FixGuideModal (render smoke test)", () => {
  for (const [tenantId, snapshot] of Object.entries(MOCK_TENANT_DATA)) {
    for (const def of FIX_GUIDES) {
      it(`renders ${def.id} for ${tenantId}`, () => {
        const guide = buildFixGuide(def.id, snapshot)!;
        const html = renderToStaticMarkup(React.createElement(FixGuideModal, { guide, onClose: () => {} }))
          .replace(/&#x27;/g, "'")
          .replace(/&quot;/g, '"')
          .replace(/&amp;/g, "&");
        expect(html).toContain(def.title);
        expect(html).toContain("Before you start");
        expect(html).toContain("Confirm it worked");
        expect(html).toContain("checked 2026-10-05");
        // Conditional Access guides always say what the policy would have done, or why they can't.
        if (def.proposedPolicy) expect(html).toContain("What this policy would have done");
        if (guide.preview?.available) expect(html).toContain("against this policy, as if it were on.");
      });
    }
  }
});
