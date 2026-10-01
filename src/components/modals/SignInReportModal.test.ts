import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MOCK_TENANT_DATA } from "@/lib/data/mock-tenants";
import { SignInReportModal } from "./SignInReportModal";

// Server-render smoke test (the repo has no browser test setup): the report
// screen renders for every demo tenant, open and closed.
describe("SignInReportModal (render smoke test)", () => {
  for (const [tenantId, snapshot] of Object.entries(MOCK_TENANT_DATA)) {
    it(`renders for ${tenantId}`, () => {
      const html = renderToStaticMarkup(React.createElement(SignInReportModal, { isOpen: true, onClose: () => {}, snapshot, homeCountry: "US" }));
      expect(html).toContain("Sign-in report");
      expect(html).toContain("Worth a look");
      expect(html).toContain("Open report (print or save as PDF)");
    });
  }

  it("renders nothing when closed", () => {
    const snapshot = Object.values(MOCK_TENANT_DATA)[0];
    expect(renderToStaticMarkup(React.createElement(SignInReportModal, { isOpen: false, onClose: () => {}, snapshot }))).toBe("");
  });
});
