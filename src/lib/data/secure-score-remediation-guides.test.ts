import { describe, it, expect } from "vitest";
import { SECURE_SCORE_REMEDIATION_GUIDES, getSecureScoreRemediationGuide } from "./secure-score-remediation-guides";

describe("getSecureScoreRemediationGuide", () => {
  it("returns the mapped guide for a known weak control, confirmed live to lack navigation guidance", () => {
    const guide = getSecureScoreRemediationGuide("mdo_phishthresholdlevel");
    expect(guide).toBeDefined();
    expect(guide!.portalName).toBe("Microsoft Defender Portal");
    expect(guide!.navPath).toContain("Anti-phishing");
  });

  it("returns undefined for a control that already explains itself (not in the map)", () => {
    expect(getSecureScoreRemediationGuide("spo_idle_session_timeout")).toBeUndefined();
  });

  it("groups every anti-phishing-policy control under the same shared guide object", () => {
    const ids = [
      "mdo_mailboxintelligenceprotection",
      "mdo_mailboxintelligenceprotectionaction",
      "mdo_enabledomainstoprotect",
      "mdo_phishthresholdlevel",
      "mdo_similardomainssafetytips",
      "mdo_similaruserssafetytips",
      "mdo_targeteddomainprotectionaction",
      "mdo_targeteduserprotectionaction",
      "mdo_targetedusersprotection",
      "mdo_unusualcharacterssafetytips",
    ];
    const guides = ids.map((id) => getSecureScoreRemediationGuide(id));
    expect(guides.every((g) => g === guides[0])).toBe(true);
  });
});

describe("SECURE_SCORE_REMEDIATION_GUIDES data quality", () => {
  it("gives every entry a non-empty portal name, a valid https url, and at least one nav step", () => {
    for (const [controlId, guide] of Object.entries(SECURE_SCORE_REMEDIATION_GUIDES)) {
      expect(guide.portalName.length, `${controlId}.portalName`).toBeGreaterThan(0);
      expect(guide.url, `${controlId}.url`).toMatch(/^https:\/\//);
      expect(guide.navPath.length, `${controlId}.navPath`).toBeGreaterThan(0);
      for (const step of guide.navPath) {
        expect(step.length, `${controlId}.navPath step`).toBeGreaterThan(0);
      }
    }
  });

  it("covers the 22 controls confirmed live to lack navigation guidance in Graph's own remediation text", () => {
    expect(Object.keys(SECURE_SCORE_REMEDIATION_GUIDES).sort()).toEqual(
      [
        "mdo_phisspamacation",
        "mdo_allowedsenderscombined",
        "mdo_bulkthreshold",
        "mdo_commonattachmentsfilter",
        "mdo_safeattachments",
        "mdo_safedocuments",
        "mdo_mailboxintelligenceprotection",
        "mdo_mailboxintelligenceprotectionaction",
        "mdo_enabledomainstoprotect",
        "mdo_phishthresholdlevel",
        "mdo_similardomainssafetytips",
        "mdo_similaruserssafetytips",
        "mdo_targeteddomainprotectionaction",
        "mdo_targeteduserprotectionaction",
        "mdo_targetedusersprotection",
        "mdo_unusualcharacterssafetytips",
        "mip_sensitivitylabelspolicies",
        "mip_autosensitivitylabelspolicies",
        "mip_purviewlabelconsent",
        "exo_mailtipsenabled",
        "exo_mailboxaudit",
        "exo_storageproviderrestricted",
      ].sort()
    );
  });
});
