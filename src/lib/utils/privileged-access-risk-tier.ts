// Traffic light risk tiering for Privileged Access Review, reusing the same
// tier vocabulary as the MFA and Auth Methods module (mfa-risk-tier.ts)
// rather than inventing a parallel one. Every account here is already an
// admin, so that module's "privileged account with no MFA is Critical,
// overriding everything else" rule collapses to simply "no MFA is Critical."
// That leaves one axis for the rest: whether the admin also holds a
// daily-use Exchange/Teams license (isLicensedForDailyUse) - a real account
// isolation hygiene concern, but not a "does this account matter" signal the
// way plain license possession was for the MFA module. There is no natural
// Orange here (only two real axes: has MFA, has a daily-use license), the
// same way Yellow ended up unused there.
import { MfaRiskTier, MFA_RISK_TIER_SEVERITY } from "./mfa-risk-tier";

export type PrivilegedAccessTier = Exclude<MfaRiskTier, "orange">;

export function classifyPrivilegedAccessTier(input: {
  accountEnabled: boolean;
  mfaRegistered: boolean;
  isLicensedForDailyUse: boolean;
}): PrivilegedAccessTier {
  if (!input.accountEnabled) return "disabled";
  if (!input.mfaRegistered) return "critical";
  return input.isLicensedForDailyUse ? "red" : "green";
}

export const PRIVILEGED_ACCESS_TIER_LABEL: Record<PrivilegedAccessTier, { label: string; description: string }> = {
  disabled: { label: "Disabled", description: "Account cannot sign in. Not a live risk." },
  critical: { label: "Critical", description: "Privileged account with no MFA registered." },
  red: { label: "Dual Exposure", description: "MFA is registered, but this admin also holds a daily-use Exchange/Teams license." },
  green: { label: "Secured", description: "MFA is registered and this admin carries no daily-use license." },
};

export { MFA_RISK_TIER_SEVERITY };
