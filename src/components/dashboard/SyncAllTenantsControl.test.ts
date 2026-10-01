import { describe, expect, it } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SyncAllTenantsControl } from "./SyncAllTenantsControl";

const render = (initialStatus?: any) => renderToStaticMarkup(React.createElement(SyncAllTenantsControl, { initialStatus }));
const base = { running: false, total: 0, completed: 0, stopRequested: false, stopped: false, results: [] };

// Server-render smoke test (no browser test setup in this repo).
describe("SyncAllTenantsControl (render smoke test)", () => {
  it("shows the start button when idle", () => {
    const html = render();
    expect(html).toContain("Sync all tenants");
    expect(html).not.toContain("Syncing");
  });

  it("shows which tenant is syncing and offers Stop while running", () => {
    const html = render({ ...base, running: true, source: "manual", total: 10, completed: 2, current: { tenantId: "t3", tenantName: "Contoso" }, currentStep: { step: "Sign-in logs", percent: 12 } });
    expect(html).toContain("Syncing 3 of 10: Contoso");
    expect(html).toContain("Sign-in logs (12%)");
    expect(html).toContain("Stop");
    expect(html).not.toContain("Sync all tenants");
  });

  it("summarises the last run and lists failures", () => {
    const html = render({
      ...base,
      total: 3,
      completed: 3,
      finishedAt: "2026-10-01T08:00:00Z",
      results: [
        { tenantId: "a", tenantName: "Alpha", outcome: "synced", finishedAt: "" },
        { tenantId: "b", tenantName: "Bravo", outcome: "failed", error: "Bad credentials", finishedAt: "" },
        { tenantId: "c", tenantName: "Charlie", outcome: "synced", finishedAt: "" },
      ],
    });
    expect(html).toContain("2 of 3 synced, 1 failed");
    expect(html).toContain("Bad credentials");
  });

  it("says when a run was stopped early", () => {
    const html = render({ ...base, total: 5, completed: 2, stopped: true, finishedAt: "2026-10-01T08:00:00Z", results: [] });
    expect(html).toContain("Stopped: 2 of 5 synced, 3 skipped");
  });
});
