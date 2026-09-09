// Traffic light risk tiering for the MFA and Auth Methods module. Deliberately
// a small, pure function: license status and admin status are already known
// by the caller (see MfaAuditModule's existing accountClassification cross
// reference), this only decides which of the five tiers an account lands in.
//
// Priority matters: a privileged account with no MFA is Critical regardless
// of its license status, so that check must run before the license based
// red/orange split.
export type MfaRiskTier = "disabled" | "critical" | "green" | "red" | "orange";

export function classifyMfaRiskTier(input: {
  accountEnabled: boolean;
  isAdmin: boolean;
  mfaRegistered: boolean;
  isLicensed: boolean;
}): MfaRiskTier {
  if (!input.accountEnabled) return "disabled";
  if (input.isAdmin && !input.mfaRegistered) return "critical";
  if (input.mfaRegistered) return "green";
  return input.isLicensed ? "red" : "orange";
}

export const MFA_RISK_TIER_LABEL: Record<MfaRiskTier, { label: string; description: string }> = {
  disabled: { label: "Disabled", description: "Account cannot sign in. MFA status is not a live risk." },
  critical: { label: "Critical", description: "Privileged account with no MFA registered." },
  green: { label: "Secured", description: "MFA is registered." },
  red: { label: "No MFA (Licensed)", description: "Paid seat with no MFA registered." },
  orange: { label: "No MFA (Unlicensed)", description: "No paid seat and no MFA registered." },
};

// Ascending badness: 0 is the tier that most needs attention.
export const MFA_RISK_TIER_SEVERITY: Record<MfaRiskTier, number> = {
  critical: 0,
  red: 1,
  orange: 2,
  green: 3,
  disabled: 4,
};
