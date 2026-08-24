import { describe, it, expect } from "vitest";
import { matchCaBaselineCode, computeBaselineCoveragePercent, RawGraphCaPolicy } from "./ca-baseline-matcher";

const AZURE_MGMT_APP_ID = "797f3427-79cd-4827-8132-47d473d450e4";

describe("matchCaBaselineCode", () => {
  it("matches CA01: block legacy authentication client app types", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { clientAppTypes: ["exchangeActiveSync"] },
      grantControls: { builtInControls: ["block"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA01");
  });

  it("matches CA02: MFA for all users", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { users: { includeUsers: ["All"] } },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA02");
  });

  it("matches CA03: MFA for admin roles", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { users: { includeRoles: ["role-global-admin"] } },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA03");
  });

  it("matches CA04: MFA for guests", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { users: { includeUsers: ["GuestsOrExternalUsers"] } },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA04");
  });

  it("matches CA05: MFA for Azure management (by app ID, not name)", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { applications: { includeApplications: [AZURE_MGMT_APP_ID] } },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA05");
  });

  it("matches CA06: MFA for risky sign-ins", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { signInRiskLevels: ["medium", "high"] },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA06");
  });

  it("matches CA07: risk remediation requiring both MFA and password change", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { userRiskLevels: ["high"] },
      grantControls: { builtInControls: ["mfa", "passwordChange"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA07");
  });

  it("does not match CA07 when only MFA is required (no password change control)", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { userRiskLevels: ["high"] },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).not.toBe("CA07");
  });

  it("matches CA08: block untrusted locations", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { locations: { includeLocations: ["All"], excludeLocations: ["trusted-loc"] } },
      grantControls: { builtInControls: ["block"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA08");
  });

  it("matches CA09: compliant or domain-joined device requirement", () => {
    const policy: RawGraphCaPolicy = {
      conditions: {},
      grantControls: { builtInControls: ["compliantDevice"] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA09");
  });

  it("matches CA10: phishing-resistant MFA (authentication strength) for admins", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { users: { includeRoles: ["role-global-admin"] } },
      grantControls: { authenticationStrength: { id: "00000000-0000-0000-0000-000000000004" }, builtInControls: [] },
    };
    expect(matchCaBaselineCode(policy)).toBe("CA10");
  });

  it("returns null for a custom policy matching no baseline shape", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { applications: { includeApplications: ["some-custom-app"] } },
      grantControls: { builtInControls: ["approvedApplication"] },
    };
    expect(matchCaBaselineCode(policy)).toBeNull();
  });

  it("returns null for a completely empty policy", () => {
    expect(matchCaBaselineCode({})).toBeNull();
  });

  it("ignores display name entirely — classification is structural only", () => {
    // RawGraphCaPolicy has no displayName field at all, so a policy named e.g.
    // "Require MFA for All Users" that doesn't actually target all users with MFA
    // cannot fool the matcher — there's nothing here for a misleading name to hook into.
    const policy: RawGraphCaPolicy = {
      conditions: { users: { includeUsers: ["some-specific-user-id"] } },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBeNull();
  });

  describe("most-specific-first disambiguation", () => {
    it("prefers CA10 over CA03 when a policy has both admin-role targeting and an authentication strength control", () => {
      const policy: RawGraphCaPolicy = {
        conditions: { users: { includeRoles: ["role-global-admin"] } },
        grantControls: { authenticationStrength: { id: "x" }, builtInControls: ["mfa"] },
      };
      expect(matchCaBaselineCode(policy)).toBe("CA10");
    });

    it("prefers CA07 over CA06 when both user risk and sign-in risk conditions are present", () => {
      const policy: RawGraphCaPolicy = {
        conditions: { userRiskLevels: ["high"], signInRiskLevels: ["medium"] },
        grantControls: { builtInControls: ["mfa", "passwordChange"] },
      };
      expect(matchCaBaselineCode(policy)).toBe("CA07");
    });

    it("prefers CA05 over CA02 when Azure management app scoping and all-users MFA overlap", () => {
      const policy: RawGraphCaPolicy = {
        conditions: {
          users: { includeUsers: ["All"] },
          applications: { includeApplications: [AZURE_MGMT_APP_ID] },
        },
        grantControls: { builtInControls: ["mfa"] },
      };
      expect(matchCaBaselineCode(policy)).toBe("CA05");
    });
  });

  it("does not match CA08 when locations are scoped but the grant control isn't block", () => {
    const policy: RawGraphCaPolicy = {
      conditions: { locations: { includeLocations: ["All"] } },
      grantControls: { builtInControls: ["mfa"] },
    };
    expect(matchCaBaselineCode(policy)).toBeNull();
  });
});

describe("computeBaselineCoveragePercent", () => {
  it("returns 0 when nothing is deployed", () => {
    expect(computeBaselineCoveragePercent(0, 10)).toBe(0);
  });

  it("returns 100 when everything is deployed", () => {
    expect(computeBaselineCoveragePercent(10, 10)).toBe(100);
  });

  it("rounds to the nearest whole percent", () => {
    expect(computeBaselineCoveragePercent(1, 3)).toBe(33);
    expect(computeBaselineCoveragePercent(2, 3)).toBe(67);
  });

  it("guards against divide-by-zero when there are no standards to cover", () => {
    expect(computeBaselineCoveragePercent(0, 0)).toBe(0);
  });
});
