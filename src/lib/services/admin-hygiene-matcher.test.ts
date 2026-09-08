import { describe, it, expect } from "vitest";
import { isDailyUseLicenseSku, findLicensedGlobalAdmins, getAllPrivilegedAccounts, getPrivilegedAccountUpns } from "./admin-hygiene-matcher";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";

describe("admin-hygiene-matcher service", () => {
  const contosoSnap = MOCK_TENANT_DATA["tenant-contoso-corp"];

  describe("isDailyUseLicenseSku", () => {
    it("matches friendly display names used in mock data", () => {
      expect(isDailyUseLicenseSku("Microsoft 365 E5")).toBe(true);
      expect(isDailyUseLicenseSku("Microsoft 365 Business Premium")).toBe(true);
    });

    it("matches real Graph skuPartNumber codes used in live-sync mode", () => {
      expect(isDailyUseLicenseSku("SPE_E5")).toBe(true);
      expect(isDailyUseLicenseSku("EXCHANGESTANDARD")).toBe(true);
      expect(isDailyUseLicenseSku("TEAMS1")).toBe(true);
    });

    it("does not match licenses with no mailbox/Teams capability", () => {
      expect(isDailyUseLicenseSku("Microsoft Entra ID P2")).toBe(false);
      expect(isDailyUseLicenseSku("Defender for Endpoint P2")).toBe(false);
      expect(isDailyUseLicenseSku("")).toBe(false);
    });
  });

  describe("findLicensedGlobalAdmins", () => {
    it("flags a Global Admin already provisioned with a daily-use license in real mock data", () => {
      const risks = findLicensedGlobalAdmins(contosoSnap);
      const alex = risks.find((r) => r.userPrincipalName === "admin-alex@contosopharm.com");
      expect(alex).toBeDefined();
      expect(alex?.adminRoles).toContain("Global Administrator");
      expect(alex?.licenses).toContain("Microsoft 365 E5");
    });

    it("excludes a licensed user who is not an admin", () => {
      const risks = findLicensedGlobalAdmins(contosoSnap);
      expect(risks.some((r) => r.userPrincipalName === "sarah.chen@contosopharm.com")).toBe(false);
    });

    it("excludes an admin with no matching licensed account record", () => {
      const snap = JSON.parse(JSON.stringify(contosoSnap));
      snap.mfaAudit.push({
        id: "mfa-usr-test-unlicensed-admin",
        userPrincipalName: "breakglass-test@contosopharm.com",
        displayName: "Break Glass Test Admin",
        jobTitle: "N/A",
        department: "IT",
        accountEnabled: true,
        isAdmin: true,
        adminRoles: ["Global Administrator"],
        mfaRegistered: true,
        mfaEnforcedByPolicy: true,
        defaultMethod: "none",
        registeredMethods: [],
        isWeakAuth: false,
        passwordLastSetDateTime: "2026-01-01T00:00:00Z",
        lastSignInDateTime: "2026-01-01T00:00:00Z",
      });
      const risks = findLicensedGlobalAdmins(snap);
      expect(risks.some((r) => r.userPrincipalName === "breakglass-test@contosopharm.com")).toBe(false);
    });

    it("joins by userPrincipalName case-insensitively", () => {
      const snap = JSON.parse(JSON.stringify(contosoSnap));
      snap.mfaAudit = snap.mfaAudit.map((u: any) =>
        u.userPrincipalName === "admin-alex@contosopharm.com"
          ? { ...u, userPrincipalName: "ADMIN-ALEX@CONTOSOPHARM.COM" }
          : u
      );
      const risks = findLicensedGlobalAdmins(snap);
      expect(risks.some((r) => r.userPrincipalName.toLowerCase() === "admin-alex@contosopharm.com")).toBe(true);
    });
  });

  describe("getAllPrivilegedAccounts", () => {
    it("returns every admin regardless of license status", () => {
      const snap = JSON.parse(JSON.stringify(contosoSnap));
      snap.mfaAudit.push({
        id: "mfa-usr-test-unlicensed-admin",
        userPrincipalName: "breakglass-test@contosopharm.com",
        displayName: "Break Glass Test Admin",
        jobTitle: "N/A",
        department: "IT",
        accountEnabled: true,
        isAdmin: true,
        adminRoles: ["Global Administrator"],
        mfaRegistered: true,
        mfaEnforcedByPolicy: true,
        defaultMethod: "none",
        registeredMethods: [],
        isWeakAuth: false,
        passwordLastSetDateTime: "2026-01-01T00:00:00Z",
        lastSignInDateTime: "2026-01-01T00:00:00Z",
      });

      const accounts = getAllPrivilegedAccounts(snap);
      const alex = accounts.find((a) => a.userPrincipalName === "admin-alex@contosopharm.com");
      expect(alex).toBeDefined();
      expect(alex?.isLicensedForDailyUse).toBe(true);

      const breakglass = accounts.find((a) => a.userPrincipalName === "breakglass-test@contosopharm.com");
      expect(breakglass).toBeDefined();
      expect(breakglass?.licenses).toEqual([]);
      expect(breakglass?.isLicensedForDailyUse).toBe(false);
    });

    it("excludes non-admins", () => {
      const accounts = getAllPrivilegedAccounts(contosoSnap);
      expect(accounts.some((a) => a.userPrincipalName === "sarah.chen@contosopharm.com")).toBe(false);
    });

    it("preserves the full adminRoles array, not just the first role", () => {
      const snap = JSON.parse(JSON.stringify(contosoSnap));
      snap.mfaAudit = snap.mfaAudit.map((u: any) =>
        u.userPrincipalName === "admin-alex@contosopharm.com"
          ? { ...u, adminRoles: ["Global Administrator", "Exchange Administrator"] }
          : u
      );
      const accounts = getAllPrivilegedAccounts(snap);
      const alex = accounts.find((a) => a.userPrincipalName === "admin-alex@contosopharm.com");
      expect(alex?.adminRoles).toEqual(["Global Administrator", "Exchange Administrator"]);
    });

    it("computes isUnprotected the same way remediation-generator flags unprotected admins", () => {
      const snap = JSON.parse(JSON.stringify(contosoSnap));
      snap.mfaAudit = snap.mfaAudit.map((u: any) =>
        u.userPrincipalName === "admin-alex@contosopharm.com" ? { ...u, mfaRegistered: false } : u
      );
      let accounts = getAllPrivilegedAccounts(snap);
      expect(accounts.find((a) => a.userPrincipalName === "admin-alex@contosopharm.com")?.isUnprotected).toBe(true);

      const snap2 = JSON.parse(JSON.stringify(contosoSnap));
      snap2.mfaAudit = snap2.mfaAudit.map((u: any) =>
        u.userPrincipalName === "admin-alex@contosopharm.com" ? { ...u, mfaRegistered: true, isWeakAuth: true } : u
      );
      accounts = getAllPrivilegedAccounts(snap2);
      expect(accounts.find((a) => a.userPrincipalName === "admin-alex@contosopharm.com")?.isUnprotected).toBe(true);

      // Contoso's real fixture: mfaRegistered true, isWeakAuth false -> protected
      const baseline = getAllPrivilegedAccounts(contosoSnap);
      expect(baseline.find((a) => a.userPrincipalName === "admin-alex@contosopharm.com")?.isUnprotected).toBe(false);
    });

    it("joins by userPrincipalName case-insensitively", () => {
      const snap = JSON.parse(JSON.stringify(contosoSnap));
      snap.mfaAudit = snap.mfaAudit.map((u: any) =>
        u.userPrincipalName === "admin-alex@contosopharm.com"
          ? { ...u, userPrincipalName: "ADMIN-ALEX@CONTOSOPHARM.COM" }
          : u
      );
      const accounts = getAllPrivilegedAccounts(snap);
      const alex = accounts.find((a) => a.userPrincipalName.toLowerCase() === "admin-alex@contosopharm.com");
      expect(alex?.licenses).toContain("Microsoft 365 E5");
    });
  });

  describe("getPrivilegedAccountUpns", () => {
    it("returns a lowercased set containing admins and excluding non-admins", () => {
      const upns = getPrivilegedAccountUpns(contosoSnap);
      expect(upns.has("admin-alex@contosopharm.com")).toBe(true);
      expect(upns.has("sarah.chen@contosopharm.com")).toBe(false);
    });
  });
});
