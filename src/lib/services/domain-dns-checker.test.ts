import { describe, it, expect } from "vitest";
import { evaluateSpfTxtRecords, evaluateDmarcTxtRecords } from "./domain-dns-checker";

describe("evaluateSpfTxtRecords", () => {
  it("fails when no SPF record exists", () => {
    const result = evaluateSpfTxtRecords([]);
    expect(result.status).toBe("fail");
    expect(result.recommendation).toContain("spf.protection.outlook.com");
  });

  it("warns when the SPF record doesn't authorize Microsoft 365", () => {
    const result = evaluateSpfTxtRecords(["v=spf1 include:someothersender.com -all"]);
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("doesn't authorize Microsoft 365");
  });

  it("passes when Microsoft 365 is included and the record hard-fails", () => {
    const result = evaluateSpfTxtRecords(["v=spf1 include:spf.protection.outlook.com -all"]);
    expect(result.status).toBe("pass");
  });

  it("warns on a soft-fail (~all) qualifier", () => {
    const result = evaluateSpfTxtRecords(["v=spf1 include:spf.protection.outlook.com ~all"]);
    expect(result.status).toBe("warn");
    expect(result.recommendation).toContain("-all");
  });

  it("warns when there's no enforcement qualifier at all", () => {
    const result = evaluateSpfTxtRecords(["v=spf1 include:spf.protection.outlook.com"]);
    expect(result.status).toBe("warn");
  });

  it("ignores unrelated TXT records", () => {
    const result = evaluateSpfTxtRecords(["google-site-verification=abc123", "v=spf1 include:spf.protection.outlook.com -all"]);
    expect(result.status).toBe("pass");
  });
});

describe("evaluateDmarcTxtRecords", () => {
  it("fails when no DMARC record exists", () => {
    const result = evaluateDmarcTxtRecords([]);
    expect(result.status).toBe("fail");
    expect(result.recommendation).toContain("_dmarc");
  });

  it("passes on p=reject", () => {
    const result = evaluateDmarcTxtRecords(["v=DMARC1; p=reject; rua=mailto:reports@contoso.com"]);
    expect(result.status).toBe("pass");
  });

  it("passes on p=quarantine only when reporting is configured", () => {
    expect(evaluateDmarcTxtRecords(["v=DMARC1; p=quarantine; rua=mailto:reports@contoso.com"]).status).toBe("pass");
    const noReporting = evaluateDmarcTxtRecords(["v=DMARC1; p=quarantine"]);
    expect(noReporting.status).toBe("warn");
    expect(noReporting.recommendation).toContain("rua=");
  });

  it("warns on p=none as monitoring-only", () => {
    const result = evaluateDmarcTxtRecords(["v=DMARC1; p=none; rua=mailto:reports@contoso.com"]);
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("monitoring-only");
  });
});
