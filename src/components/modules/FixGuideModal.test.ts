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
        const html = renderToStaticMarkup(React.createElement(FixGuideModal, { guide, onClose: () => {} }));
        expect(html).toContain(def.title);
        expect(html).toContain("Before you start");
        expect(html).toContain("Confirm it worked");
        expect(html).toContain("checked 2026-10-05");
      });
    }
  }
});
