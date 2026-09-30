import { describe, expect, it } from "vitest";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { SIGNIN_SITUATIONS } from "../data/signin-situation-definitions";
import { buildSyntheticSimUser } from "./ca-sim-context";
import { detectHomeCountry, runSituationsForPersona, summarizeVerdicts } from "./signin-situation-runner";

const opts = { homeCountry: "US", foreignCountry: "RU" };
const byId = (results: ReturnType<typeof runSituationsForPersona>, id: string) => results.find((r) => r.situation.id === id)!;

describe("situation definitions", () => {
  it("has the 26 requested situations (8 Global Admin, 11 standard user, 7 guest) with unique ids", () => {
    expect(SIGNIN_SITUATIONS).toHaveLength(26);
    expect(SIGNIN_SITUATIONS.filter((s) => s.persona === "globalAdmin")).toHaveLength(8);
    expect(SIGNIN_SITUATIONS.filter((s) => s.persona === "user")).toHaveLength(11);
    expect(SIGNIN_SITUATIONS.filter((s) => s.persona === "guest")).toHaveLength(7);
    expect(new Set(SIGNIN_SITUATIONS.map((s) => s.id)).size).toBe(26);
  });
});

describe("Woodgrove (strict demo tenant)", () => {
  const woodgrove = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  const ga = runSituationsForPersona(woodgrove, "globalAdmin", buildSyntheticSimUser("globalAdmin"), opts);
  const guests = runSituationsForPersona(woodgrove, "guest", buildSyntheticSimUser("guest"), opts);

  it("blocks a Global Admin from a foreign country (green) and names the policy", () => {
    const r = byId(ga, "ga-foreign");
    expect(r.verdict).toBe("prevented");
    expect(r.outcomeText).toMatch(/CA08/);
    expect(r.fixes).toEqual([]);
  });

  it("an admin from an untrusted address only faces phishing-resistant MFA: orange, per the MFA rule", () => {
    const r = byId(ga, "ga-hosting");
    expect(r.verdict).toBe("partial");
    expect(r.verdictLabel).toBe("Allowed after phishing-resistant MFA");
    expect(r.notes.join(" ")).toMatch(/no "hosting provider" condition/);
  });

  it("blocks an unmanaged device at a trusted location (CA09), because Woodgrove defines trusted IPs", () => {
    expect(byId(ga, "ga-unmanaged-known").verdict).toBe("prevented");
  });

  it("the guest good-path case is green when MFA is required", () => {
    const r = byId(guests, "guest-browser-known");
    expect(r.verdict).toBe("prevented");
    expect(r.verdictLabel).toBe("Working as intended");
  });

  it("guest high sign-in risk explains that guest risk isn't visible to this tenant", () => {
    const r = byId(guests, "guest-high-signin-risk");
    expect(r.verdict).toBe("partial");
    expect(r.notes.join(" ")).toMatch(/home organisation/);
  });
});

describe("weaker demo tenants", () => {
  it("Fabrikam has no trusted locations, so \"known location\" can't be simulated (orange, not a guess)", () => {
    const r = byId(runSituationsForPersona(MOCK_TENANT_DATA["tenant-fabrikam-logistics"], "globalAdmin", buildSyntheticSimUser("globalAdmin"), opts), "ga-unmanaged-known");
    expect(r.verdict).toBe("unknown");
    expect(r.verdictLabel).toBe("No trusted locations");
  });

  it("Northwind lets a user in from a foreign country (red) and recommends deploying CA08", () => {
    const r = byId(runSituationsForPersona(MOCK_TENANT_DATA["tenant-northwind-health"], "user", buildSyntheticSimUser("user"), opts), "user-foreign");
    expect(r.verdict).toBe("notPrevented");
    expect(r.fixes.map((f) => f.kind)).toContain("deployBaseline");
    expect(r.fixes.find((f) => f.kind === "deployBaseline")!.baselineCode).toBe("CA08");
  });

  it("Contoso's CA07 turns high user risk into a required password change (orange)", () => {
    const r = byId(runSituationsForPersona(MOCK_TENANT_DATA["tenant-contoso-corp"], "user", buildSyntheticSimUser("user"), opts), "user-high-user-risk");
    expect(r.verdict).toBe("partial");
    expect(r.verdictLabel).toBe("Password change required");
  });

  it("summarizes verdicts for the strip", () => {
    const counts = summarizeVerdicts(runSituationsForPersona(MOCK_TENANT_DATA["tenant-northwind-health"], "user", buildSyntheticSimUser("user"), opts));
    expect(counts.prevented + counts.partial + counts.notPrevented + counts.unknown).toBe(11);
  });
});

describe("detectHomeCountry", () => {
  it("prefers the most common sign-in country", () => {
    expect(detectHomeCountry(MOCK_TENANT_DATA["tenant-contoso-corp"])).toMatch(/^[A-Z]{2}$/);
  });
});
