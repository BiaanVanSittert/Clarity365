import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MOCK_TENANT_DATA } from "@/lib/data/mock-tenants";
import { buildSyntheticSimUser } from "@/lib/services/ca-sim-context";
import { runSituationsForPersona } from "@/lib/services/signin-situation-runner";
import { SignInSituationsModule, SituationCard } from "./SignInSituationsModule";

// Server-render smoke test: the repo has no browser/component test setup,
// so this catches render-time crashes and wiring mistakes across every demo
// tenant and every situation card in its expanded state.
describe("SignInSituationsModule (render smoke test)", () => {
  for (const [tenantId, snapshot] of Object.entries(MOCK_TENANT_DATA)) {
    it(`renders for ${tenantId}`, () => {
      const html = renderToStaticMarkup(React.createElement(SignInSituationsModule, { snapshot }));
      expect(html).toContain("Sign-in Situations");
      expect(html).toContain("Global Admin · Sign-in from a foreign country");
    });
  }

  it("renders every situation card expanded, for every persona, without crashing", () => {
    const snapshot = MOCK_TENANT_DATA["tenant-northwind-health"];
    for (const persona of ["globalAdmin", "user", "guest"] as const) {
      const results = runSituationsForPersona(snapshot, persona, buildSyntheticSimUser(persona), { homeCountry: "US", foreignCountry: "RU" });
      for (const result of results) {
        const html = renderToStaticMarkup(
          React.createElement(SituationCard, {
            result,
            titlePrefix: "Test",
            foreignCountry: "RU",
            expanded: true,
            onToggle: () => {},
            onNavigate: () => {},
            isSynthetic: true,
          })
        );
        expect(html).toContain(result.situation.label);
        if (result.fixes.length > 0) expect(html).toContain("What would prevent it");
      }
    }
  });
});
