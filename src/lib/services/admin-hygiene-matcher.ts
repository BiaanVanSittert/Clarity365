import { TenantSecuritySnapshot, LicensedGlobalAdminRisk, PrivilegedAccountRecord } from "../types";

/**
 * SKU tokens that indicate a daily-use Exchange/Teams-enabling license. Covers both
 * real Graph skuPartNumber codes (live-sync mode, after graph-client.ts resolves
 * assignedLicenses skuIds to names) and the friendly display names used in mock data.
 * Matching is intentionally broad - over-matching is the safe failure direction for a
 * critical security check.
 */
const DAILY_USE_LICENSE_TOKENS = [
  "SPE_E5",
  "SPE_E3",
  "SPB",
  "O365_BUSINESS_PREMIUM",
  "M365_BUSINESS_PREMIUM",
  "EXCHANGESTANDARD",
  "EXCHANGEENTERPRISE",
  "EXCHANGEONLINE",
  "TEAMS1",
  "MCOSTANDARD",
  "MCOEV",
  "STANDARDPACK",
  "ENTERPRISEPACK",
  "ENTERPRISEPREMIUM",
  "M365_E5",
  "M365_E3",
  "E5",
  "E3",
  "BUSINESS PREMIUM",
  "BUSINESS STANDARD",
  "EXCHANGE",
  "TEAMS",
];

export function isDailyUseLicenseSku(license: string): boolean {
  if (!license) return false;
  const upper = license.toUpperCase();
  return DAILY_USE_LICENSE_TOKENS.some((token) => upper.includes(token));
}

/**
 * Cross-references snapshot.mfaAudit (admin role membership) against
 * snapshot.accountClassification.users (per-user license assignment) by
 * userPrincipalName, returning every admin account that also carries a
 * daily-use Exchange/Teams license - the break-glass hygiene anti-pattern.
 */
export function findLicensedGlobalAdmins(snapshot: TenantSecuritySnapshot): LicensedGlobalAdminRisk[] {
  const admins = (snapshot.mfaAudit || []).filter((u) => u.isAdmin);
  if (admins.length === 0) return [];

  const accountsByUpn = new Map(
    (snapshot.accountClassification?.users || []).map((u) => [u.userPrincipalName.toLowerCase(), u])
  );

  const risks: LicensedGlobalAdminRisk[] = [];
  for (const admin of admins) {
    const account = accountsByUpn.get(admin.userPrincipalName.toLowerCase());
    if (!account) continue;
    if (!account.licenses.some(isDailyUseLicenseSku)) continue;

    risks.push({
      userId: account.id,
      userPrincipalName: admin.userPrincipalName,
      displayName: admin.displayName,
      adminRoles: admin.adminRoles || [],
      licenses: account.licenses,
    });
  }

  return risks;
}

/**
 * Every admin account (licensed for daily use or not), with full role lists and
 * precomputed status flags - the general privileged-account roster, as opposed to
 * findLicensedGlobalAdmins' narrower "admin + daily-use license" risk subset.
 */
export function getAllPrivilegedAccounts(snapshot: TenantSecuritySnapshot): PrivilegedAccountRecord[] {
  const admins = (snapshot.mfaAudit || []).filter((u) => u.isAdmin);
  if (admins.length === 0) return [];

  const accountsByUpn = new Map(
    (snapshot.accountClassification?.users || []).map((u) => [u.userPrincipalName.toLowerCase(), u])
  );

  return admins.map((admin) => {
    const account = accountsByUpn.get(admin.userPrincipalName.toLowerCase());
    const licenses = account?.licenses || [];

    return {
      userId: account?.id || admin.id,
      userPrincipalName: admin.userPrincipalName,
      displayName: admin.displayName,
      adminRoles: admin.adminRoles || [],
      accountEnabled: admin.accountEnabled,
      lastSignInDateTime: admin.lastSignInDateTime,
      mfaRegistered: admin.mfaRegistered,
      isWeakAuth: admin.isWeakAuth,
      defaultMethod: admin.defaultMethod,
      isUnprotected: !admin.mfaRegistered || admin.isWeakAuth,
      licenses,
      isLicensedForDailyUse: licenses.some(isDailyUseLicenseSku),
    };
  });
}

export function getPrivilegedAccountUpns(snapshot: TenantSecuritySnapshot): Set<string> {
  return new Set(getAllPrivilegedAccounts(snapshot).map((a) => a.userPrincipalName.toLowerCase()));
}
