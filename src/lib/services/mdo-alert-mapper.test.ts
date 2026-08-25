import { describe, it, expect } from "vitest";
import {
  normalizeAlertSeverity,
  normalizeAlertStatus,
  normalizeAlertClassification,
  extractAffectedUsers,
  mapMdoAlert,
} from "./mdo-alert-mapper";

describe("normalizeAlertSeverity", () => {
  it("maps known severities case-insensitively", () => {
    expect(normalizeAlertSeverity("High")).toBe("high");
    expect(normalizeAlertSeverity("MEDIUM")).toBe("medium");
  });

  it("defaults unrecognized or missing severity to informational rather than throwing", () => {
    expect(normalizeAlertSeverity("unknown")).toBe("informational");
    expect(normalizeAlertSeverity(undefined)).toBe("informational");
  });
});

describe("normalizeAlertStatus", () => {
  it("maps known statuses, including the differently-cased inProgress", () => {
    expect(normalizeAlertStatus("New")).toBe("new");
    expect(normalizeAlertStatus("inProgress")).toBe("inProgress");
    expect(normalizeAlertStatus("Resolved")).toBe("resolved");
  });

  it("defaults unrecognized status to new", () => {
    expect(normalizeAlertStatus("unknown")).toBe("new");
  });
});

describe("normalizeAlertClassification", () => {
  it("maps known classifications", () => {
    expect(normalizeAlertClassification("TruePositive")).toBe("truePositive");
    expect(normalizeAlertClassification("FalsePositive")).toBe("falsePositive");
  });

  it("defaults unrecognized/unset classification to unknown", () => {
    expect(normalizeAlertClassification(undefined)).toBe("unknown");
  });
});

describe("extractAffectedUsers", () => {
  it("pulls userPrincipalName/accountName from evidence entries and dedupes", () => {
    const evidence = [
      { userAccount: { userPrincipalName: "alex@contoso.com" } },
      { userAccount: { userPrincipalName: "alex@contoso.com" } },
      { userAccount: { accountName: "sam" } },
      { fileEvidence: { fileName: "invoice.exe" } },
    ];
    expect(extractAffectedUsers(evidence)).toEqual(["alex@contoso.com", "sam"]);
  });

  it("returns an empty array when evidence is missing or not an array", () => {
    expect(extractAffectedUsers(undefined)).toEqual([]);
    expect(extractAffectedUsers(null)).toEqual([]);
  });
});

describe("mapMdoAlert", () => {
  it("maps a full raw Graph alerts_v2 resource", () => {
    const raw = {
      id: "alert-1",
      title: "Phishing email detected",
      severity: "high",
      status: "new",
      classification: "truePositive",
      category: "Phishing",
      createdDateTime: "2026-08-20T10:00:00Z",
      description: "A phishing email was delivered and later removed.",
      evidence: [{ userAccount: { userPrincipalName: "alex@contoso.com" } }],
      alertWebUrl: "https://security.microsoft.com/alerts/alert-1",
    };
    expect(mapMdoAlert(raw)).toEqual({
      id: "alert-1",
      title: "Phishing email detected",
      severity: "high",
      status: "new",
      classification: "truePositive",
      category: "Phishing",
      createdDateTime: "2026-08-20T10:00:00Z",
      description: "A phishing email was delivered and later removed.",
      affectedUsers: ["alex@contoso.com"],
      webUrl: "https://security.microsoft.com/alerts/alert-1",
    });
  });

  it("fills in safe fallbacks for missing optional fields", () => {
    const mapped = mapMdoAlert({ id: "alert-2" });
    expect(mapped.title).toBe("Untitled alert");
    expect(mapped.category).toBe("Uncategorized");
    expect(mapped.description).toBe("");
    expect(mapped.affectedUsers).toEqual([]);
    expect(mapped.webUrl).toBeUndefined();
    expect(typeof mapped.createdDateTime).toBe("string");
  });
});
